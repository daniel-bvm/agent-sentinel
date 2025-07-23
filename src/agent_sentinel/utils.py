"""General utility functions for the agent sentinel."""

import os
import subprocess
import logging
import tomlkit
from typing import Any, Callable
import asyncio
from functools import partial
from typing import Any, Callable, Generator, AsyncGenerator
from starlette.concurrency import run_in_threadpool
from .models import Report, ErrorReport, SeverityLevel

logger = logging.getLogger(__name__)

def sync2async(sync_func: Callable):
    async def async_func(*args, **kwargs):
        res = run_in_threadpool(partial(sync_func, *args, **kwargs))

        if isinstance(res, (Generator, AsyncGenerator)):
            return res

        return await res

    return async_func if not asyncio.iscoroutinefunction(sync_func) else sync_func


def run_command(cmd: list[str], cwd: str = None) -> dict[str, Any]:
    """Execute a command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out",
            "success": False
        }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }


def detect_project_languages(repo_path: str) -> list[str]:
    """Detect programming languages used in the repository."""
    languages = []

    # Check for common file extensions
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden directories and git directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for file in files:
            if file.endswith(('.py', '.pyx')):
                languages.append('python')
            elif file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                languages.append('javascript')
            elif file.endswith(('.java', '.kt', '.scala')):
                languages.append('java')
            elif file.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp')):
                languages.append('cpp')
            elif file.endswith(('.cs', '.vb')):
                languages.append('csharp')
            elif file.endswith(('.rb', '.erb')):
                languages.append('ruby')
            elif file.endswith(('.go')):
                languages.append('go')
            elif file.endswith(('.php', '.phtml')):
                languages.append('php')
            elif file.endswith(('.swift')):
                languages.append('swift')
            elif file.endswith(('.rs')):
                languages.append('rust')
            elif file.endswith('.sol'):
                languages.append('solidity')

    return list(set(languages))


def patch_foundry_config(path: str) -> bool:
    """Patches foundry.toml to add via_ir and optimizer settings safely."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            toml_doc = tomlkit.parse(content)

        # Safely modify profile.default
        if "profile" not in toml_doc:
            toml_doc["profile"] = {}

        default = toml_doc["profile"].get("default", tomlkit.table())

        default["via_ir"] = True
        default["optimizer"] = True
        default["optimizer_runs"] = 200

        toml_doc["profile"]["default"] = default

        with open(path, "w", encoding="utf-8") as f:
            f.write(tomlkit.dumps(toml_doc))

        return True
    except Exception as e:
        logger.error(f"Failed to patch foundry.toml: {e}")
        return False

import pandas as pd

def transform_cwe(cwe: str) -> str:
    if not isinstance(cwe, str):
        return cwe

    split = cwe.strip().split(':')
    if len(split) == 1:
        return cwe

    return split[0]

def generate_compact_report(df: pd.DataFrame) -> str:   
    orig_cwe = df['cwe'].copy(deep=True)
    df['cwe'] = df['cwe'].apply(transform_cwe)

    compact_report = '## Overall'

    compact_report += '\n\nStat by serverities:\n'
    compact_report += df['severity'].value_counts().to_json()
    
    compact_report += '\n\nStat by CWE:\n'
    compact_report += df['cwe'].value_counts().to_json()

    compact_report += "\n\n## Report by tool\n"
    visible_columns = ['severity', 'file_path', 'line_number', 'language', 'cwe', 'description']
    it = 0
    
    for tool in df['tool'].unique():
        df_tool = df[df['tool'] == tool].reset_index(drop=True)
        n_total = len(df_tool)
        
        if n_total == 0:
            continue
            
        it += 1
        compact_report += f'{it}. Tool: {tool}\n'
        compact_report += df_tool['severity'].value_counts().to_json()
        compact_report += '\n'

        h5 = df_tool[visible_columns].head(5)
        compact_report += h5[visible_columns[:-1]].reset_index().to_json(orient='records') 

        if n_total > 5:
            compact_report += f'\n (and {n_total - 5} more)\n'
        else:
            compact_report += '\n'

    compact_report += "\n## Report by CWE\n"
    visible_columns = ['tool', 'severity', 'file_path', 'line_number', 'language']

    it = 0
    for cwe in df['cwe'].unique():
        df_cwe = df[df['cwe'] == cwe].reset_index(drop=True)
        n_total = len(df_cwe)
        
        if n_total == 0:
            continue

        it += 1
        compact_report += f'{it}. CWE: {cwe}\n'
        compact_report += df_cwe['severity'].value_counts().to_json()
        compact_report += '\n\n'

        h5 = df_cwe[visible_columns].head(5)
        compact_report += h5.to_json(orient='records')

        if n_total > 5:
            compact_report += f'\n (and {n_total - 5} more)\n'
        else:
            compact_report += '\n'

        compact_report += '\n'

    compact_report += f'\n\n## CWE note\n{orig_cwe.unique()}'
    return compact_report.strip()


def deduplicate_reports(reports: list[Report]) -> list[Report]:
    # TODO: write this
    return reports

def merge_reports(reports: list[Report | ErrorReport]) -> str:
    """Merge reports into a single string."""
    valid_reports: list[Report] = [
        report for report in reports if 
        not isinstance(report, ErrorReport)
        and report.severity != SeverityLevel.ERROR 
        and report.description != "" 
        and report.description != "n/a" 
        and report.file_path != ""
        and report.line_number != ""
        and report.description is not None
    ]

    if len(valid_reports) == 0:
        return "No security issues found!"

    valid_reports = deduplicate_reports(valid_reports)

    report_list = [{
        "tool": report.tool,
        "severity": report.severity,
        "description": report.description,
        "file_path": report.file_path,
        "line_number": report.line_number,
        "language": report.language,
        "cwe": report.cwe,
        "cve": report.cve
    } for report in valid_reports]

    df = pd.DataFrame(report_list)
    return generate_compact_report(df)
    