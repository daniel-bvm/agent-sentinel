from app.oai_models import (ChatCompletionRequest,
                            ChatCompletionStreamResponse,
                            ChatCompletionAdditionalParameters,
                            ErrorResponse,
                            random_uuid,
                            ChatCompletionMessageParam, OpenAIBaseModel)
from typing import AsyncGenerator, Optional, Any, Callable, Union
import asyncio
from app.oai_streaming import create_streaming_response, ChatCompletionResponseBuilder
from app.utils import AgentResourceManager, convert_mcp_tools_to_openai_format, get_user_messages
import logging
from app.configs import settings
from app.utils import refine_chat_history, wrap_chunk, refine_assistant_message, refine_mcp_response, execute_openai_compatible_toolcall
import os
import json
from mcp.types import TextContent, EmbeddedResource
import re
from src.agent_sentinel.utils import detect_project_languages


logger = logging.getLogger(__name__)

async def wrapstream(
    streaming_iter: AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None], 
    callback: Callable[[ChatCompletionStreamResponse | ErrorResponse], None]
):
    async for chunk in streaming_iter:
        callback(chunk)

        if chunk.choices[0].delta.content:
            yield chunk

async def get_system_prompt(messages: list[ChatCompletionMessageParam] | list[dict[str, Any]]) -> str:
    last_3_messages = get_user_messages(messages, 3)

    base = ''

    if os.path.exists("system_prompt.txt"):
        with open("system_prompt.txt", "r") as f:
            base = f.read()

    github_repo_pattern = re.compile(r'https://github\.com/[^/]+/[^/]+')
    user_message = '\n'.join(last_3_messages)

    found_repo = github_repo_pattern.findall(user_message)
    repo_info_str = ''

    if len(found_repo) > 0:
        repo_info_str = f"Preliminary information about user mentioned repositories:\n"
        
    attach_repo_info = False

    for i, match in enumerate(found_repo):
        try:
            path = clone_repo(match)

            if not path or not os.path.exists(path):
                repo_info_str += f"Repo {match} is invalid or not accessible\n"
                attach_repo_info = True
                continue

            _repo: RepoInfo = RepoInfo(path)

            repo_info_str += f"Repo: {_repo.repo_url}\n"
            repo_info_str += f"Default Branch: {_repo.branch}\n"
            repo_info_str += f"Languages: {detect_project_languages(path)}\n"
            repo_info_str += f"Project structure: {get_directory_tree(path, max_items=5)}\n\n"
    
            attach_repo_info = True
        except Exception as e:
            logger.error(f"Error cloning repository {match}: {e}", exc_info=True)

    if attach_repo_info:
        base += f"\n{repo_info_str}"

    return base

from src.agent_sentinel import mcp as git_action_mcp, audit_mcp as source_code_mcp, main as security_scanners
from src.agent_sentinel.utils import merge_reports, Report, ErrorReport, SeverityLevel
from src.agent_sentinel.git_utils import RepoInfo, clone_repo, get_directory_tree 
from src.agent_sentinel.cwe_utils import get_cwe_by_id
import openai

class FullyHandoff(OpenAIBaseModel): pass

async def list_toolcalls() -> list[dict[str, Any]]: 
    res = [
        *(await git_action_mcp._mcp_list_tools()),
        *(await source_code_mcp._mcp_list_tools())
    ]
    
    return convert_mcp_tools_to_openai_format(res)

fn_mapping = {
    'security_scan': security_scanners.security_scan.fn
}

def fmt_report(report: Report, repo: RepoInfo | None = None) -> str:
    if repo and report.line_start and report.line_end:
        return f"[{report.file_path}:({report.line_start}:{report.line_end})]({repo.get_reference(report.file_path, report.line_start, report.line_end)}) - {report.description} (CWE: {report.cwe or 'N/A'}, CVE: {report.cve or 'N/A'}, Lang: {report.language})"
    else:
        return f"{report.file_path}:{report.line_number} - {report.description} (CWE: {report.cwe or 'N/A'}, CVE: {report.cve or 'N/A'}, Lang: {report.language})"

def normalize_cwe(cwe: str) -> str:
    return cwe.split(':')[0].strip().upper()

VALIDATION_SYSTEM_PROMPT = """
Your task is to confirm a security finding is valid or not, in one step. In case the severity level is not appropriate, change it and explain why.

Found:
{found}

Context:
{context}

References:
{references}

By default, if no action is taken, the security issue finding is valid. In case the secret value found is just dummy, reject it. 
"""

VALIDATION_ACTION = [
    { 
        "type": "function",
        "function": {
            "name": "reject",
            "description": "Reject the security issue finding",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "The reason for rejecting the security issue finding"
                    }
                }
            }
        },
        "type": "function",
        "function": {
            "name": "change_severity_level",
            "description": "Change the severity level of the security issue finding",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "The severity level of the security issue finding if the current severity level is not appropriate",
                        "enum": [
                            "LOW",
                            "MEDIUM",
                            "HIGH",
                            "CRITICAL"
                        ]
                    },
                    "reason": {
                        "type": "string",
                        "description": "The reason for changing the severity level of the security issue finding"
                    }
                }
            }
        }
    }
]

import openai

def change_severity_level(report: Report, severity: str) -> Report:
    severity = severity.upper()

    if severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        logger.warning(f"Invalid severity level: {severity}")
        return report

    report.severity = SeverityLevel(severity)
    return report

def is_match(report_1: Report, report_2: Report) -> bool:
    if report_1.file_path != report_2.file_path:
        return False

    if report_1.line_start != report_2.line_start:
        return False

    if report_1.line_end != report_2.line_end:
        return False
    
    if report_1.cwe != report_2.cwe:
        return False

    return True

import base64

def construct_file_response(file_paths: list[str]) -> str:
    files_xml = ""
    for file_path in file_paths:
        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            encoded_data = base64.b64encode(file_bytes).decode("utf-8")
            filename = os.path.basename(file_path)
            files_xml += (
                f"  <file>\n"
                f"    <filename>{filename}</filename>\n"
                f"    <filedata>{encoded_data}</filedata>\n"
                f"  </file>\n"
            )
        except Exception as e:
            continue

    return f"<files>{files_xml}</files>"

async def confirm_report(report: Report, confirmed_reports: list[Report], deep_mode: bool, repo: RepoInfo | None = None) -> Report | None:
    if any(is_match(report, confirmed_report) for confirmed_report in confirmed_reports):
        logger.info(f"Report is already confirmed: {report}")
        return None

    if report.language == 'dependency':
        logger.info(f"Dependency report is no need to be confirmed again")
        return report 

    context = repo.reveal_content(
        report.file_path, 
        report.line_start, 
        report.line_end, 
        A=2, B=2
    )

    if not context:
        logger.warning(f"Failed to reveal content for {report.file_path}:{report.line_start}:{report.line_end} (file not found or invalid line number)")
        return None
    
    if not deep_mode and report.language != 'code':
        logger.info(f"Dependency report is no need to be confirmed in deep mode")
        return report

    cwe_ids = [
        _id.strip() 
        for _id in report.cwe.split(',')
    ]

    cwes = [
        get_cwe_by_id(cwe_id) 
        for cwe_id in cwe_ids
    ]
    
    cwes = [
        cwe 
        for cwe in cwes 
        if cwe is not None
    ]

    references = ''

    if not cwes:
        references = "No CWE found for this security issue finding"
    
    for i, cwe in enumerate(cwes):
        references += f"{i + 1}. CWE-{cwe.id} - {cwe.name}\n"
        references += f"Description: {cwe.description}\n"
        references += f"Extended Description: {cwe.extended_description}\n"

        if len(cwe.examples) > 0:
            references += f"Examples: \n"

            for example in cwe.examples:
                references += f"```\n{example}\n```\n"

        if len(cwe.consequences) > 0:
            references += f"Consequences: \n"

            for j, consequence in enumerate(cwe.consequences):
                references += f"{j + 1}. {consequence}\n"

        references += "\n"

    client = openai.AsyncClient(
        base_url=settings.llm_base_url, 
        api_key=settings.llm_api_key
    )

    messages = [
        {
            "role": "system",
            "content": VALIDATION_SYSTEM_PROMPT.format(
                found=fmt_report(report, repo),
                context=context,
                references=references
            )
        }
    ]
    
    completion = await client.chat.completions.create(
        model=settings.llm_model_id,
        messages=messages,
        tools=VALIDATION_ACTION,
        tool_choice="auto"
    )

    tools = completion.choices[0].message.tool_calls

    for tool in tools:
        args_json = json.loads(tool.function.arguments)

        if tool.function.name == 'reject':
            logger.warning(f"Rejected security issue finding: {args_json.get('reason', 'Unknown reason')}")
            return None

        elif tool.function.name == 'change_severity_level':
            logger.info(f"Changing severity level of security issue finding: {args_json.get('reason', 'Unknown reason')}")
            report = change_severity_level(report, args_json.get('severity'))
            break

    return report

from pandas import DataFrame
import pandas as pd

REPORT_WRITTING_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "include_table",
            "description": "Respond a table in markdown format to the user. Return a label to reference to.",
            "parameters": {
                "type": "object",
                "properties": {
                    "df_id": {
                        "type": "string",
                        "description": "The id of the dataframe to include in the report",
                        "enum": [
                            "high_severity_df",
                            "medium_severity_df",
                            "other_df"
                        ]
                    },
                    "columns": {
                        "type": "array",
                        "description": "Columns in the dataframe to include in the report",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": ["df_id", "columns"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "include_chart",
            "description": "Respond a chart in markdown format to the user. Return a label to reference to.",
            "parameters": {
                "type": "object",
                "properties": {
                    "df_id": {
                        "type": "string",
                        "description": "The id of the dataframe to include in the report",
                        "enum": [
                            "high_severity_df",
                            "medium_severity_df",
                            "other_df"
                        ]
                    },
                    "chart_type": {
                        "type": "string",
                        "description": "The type of the chart to include in the report",
                        "enum": [
                            "bar",
                            "line",
                            "pie"
                        ]
                    },
                    "x_axis": {
                        "type": "string",
                        "description": "The column to use as the x-axis of the chart"
                    },
                    "y_axis": {
                        "type": "string",
                        "description": "The column to use as the y-axis of the chart"
                    }
                },
                "required": ["df_id", "chart_type", "x_axis", "y_axis"]
            }
        }
    }
]

def generate_table_markdown(df: DataFrame, columns: list[str]) -> str:
    if not columns:
        return df.to_markdown(index=False)

    return df[columns].to_markdown(index=False)

def generate_chart_markdown(df: DataFrame, chart_type: str, x_axis: str, y_axis: str) -> str:
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        import io
        import base64

        # Set style
        plt.style.use('default')
        sns.set_palette("husl")
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if chart_type == "bar":
            if x_axis in df.columns and y_axis in df.columns:
                df.plot(kind='bar', x=x_axis, y=y_axis, ax=ax)
            else:
                # Handle case where columns might not exist
                value_counts = df[x_axis].value_counts() if x_axis in df.columns else df.iloc[:, 0].value_counts()
                value_counts.plot(kind='bar', ax=ax)
                ax.set_ylabel('Count')
        elif chart_type == "pie":
            if x_axis in df.columns:
                df[x_axis].value_counts().plot(kind='pie', ax=ax, autopct='%1.1f%%')
            else:
                df.iloc[:, 0].value_counts().plot(kind='pie', ax=ax, autopct='%1.1f%%')
        elif chart_type == "line":
            if x_axis in df.columns and y_axis in df.columns:
                df.plot(kind='line', x=x_axis, y=y_axis, ax=ax)
            else:
                df.plot(kind='line', ax=ax)
        
        plt.tight_layout()
        buffer = io.BytesIO()
        plt.savefig(buffer, format='jpeg', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()

        return f"<img src='data:image/jpeg;base64,{image_base64}'/>"
        
    except Exception as e:
        logger.error(f"Error generating chart: {e}", exc_info=True)
        return f"Error generating chart: {str(e)}"

async def generate_enhanced_report_with_tools(
    df: DataFrame,
    repo: RepoInfo | None,
    section_name: str,
    severity_filter: list[str],
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate enhanced report section with LLM tools for tables and charts."""
    
    filtered_df = df[df['severity'].isin(severity_filter)] if severity_filter else df
    
    if len(filtered_df) == 0:
        yield wrap_chunk(random_uuid(), f"\n## {section_name}\n\n✅ **No issues found in this category.**\n\n", "assistant")
        return
    
    yield wrap_chunk(random_uuid(), f"\n## {section_name} ({len(filtered_df)} found)\n\n", "assistant")
    
    # Prepare context and dataframes for LLM tools
    context = {
        "total_issues": len(filtered_df),
        "severity_breakdown": filtered_df['severity'].value_counts().to_dict(),
        "tool_breakdown": filtered_df['tool'].value_counts().to_dict(),
        "cwe_breakdown": filtered_df['cwe'].value_counts().to_dict(),
        "language_breakdown": filtered_df['language'].value_counts().to_dict()
    }
    
    # Store dataframes for tool access (in a real implementation, this would be handled differently)
    global temp_dfs
    temp_dfs = {
        "filtered_df": filtered_df,
        "context": context
    }
    
    # Create system prompt for LLM with tool access
    system_prompt = f"""You are a cybersecurity expert creating a detailed security report section.

Section: {section_name}
Context: {json.dumps(context, indent=2)}

Available tools:
- include_table: Generate markdown tables from the data
- include_chart: Generate charts (bar, pie, line) from the data

You have access to a dataframe called "filtered_df" with columns: {list(filtered_df.columns)}

Create a comprehensive analysis that includes:
1. Overview of the issues in this severity category
2. Key patterns and trends (use charts/tables to illustrate)
3. Risk assessment and prioritization
4. Specific recommendations

Use the tools to create informative visualizations. Reference tables and charts with their returned IDs.
"""

    tools = REPORT_WRITTING_TOOLS

    client = openai.AsyncClient(
        base_url=settings.llm_base_url, 
        api_key=settings.llm_api_key
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Generate a comprehensive analysis for the {section_name} section."}
    ]
    
    try:
        completion = await client.chat.completions.create(
            model=settings.llm_model_id,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            stream=True
        )
        
        async for chunk in completion:
            if event.is_set():
                break
            if chunk.choices[0].delta.content:
                yield wrap_chunk(random_uuid(), chunk.choices[0].delta.content, "assistant")
            elif chunk.choices[0].delta.tool_calls:
                # Handle tool calls
                for tool_call in chunk.choices[0].delta.tool_calls:
                    if tool_call.function.name == "include_table":
                        args = json.loads(tool_call.function.arguments)
                        df_id = args.get("df_id", "filtered_df")
                        columns = args.get("columns", [])
                        
                        # Generate table
                        table_md = generate_table_markdown(filtered_df, columns)
                        table_id = f"table_{random_uuid()[-8:]}"
                        
                        yield wrap_chunk(random_uuid(), f"\n**Table {table_id}:**\n{table_md}\n\n", "assistant")
                        
                    elif tool_call.function.name == "include_chart":
                        args = json.loads(tool_call.function.arguments)
                        chart_type = args.get("chart_type", "bar")
                        x_axis = args.get("x_axis", "severity")
                        y_axis = args.get("y_axis", "count")
                        
                        # Generate chart
                        chart_md = generate_chart_markdown(filtered_df, chart_type, x_axis, y_axis)
                        chart_id = f"chart_{random_uuid()[-8:]}"
                        
                        yield wrap_chunk(random_uuid(), f"\n**Chart {chart_id}:**\n{chart_md}\n\n", "assistant")
                
    except Exception as e:
        logger.error(f"Error generating enhanced report: {e}")
        # Fallback to basic analysis
        yield wrap_chunk(random_uuid(), f"Analysis of {len(filtered_df)} issues in {section_name}.\n\n", "assistant")

async def generate_headline(df: DataFrame, repo: RepoInfo | None, event: asyncio.Event) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate executive summary and overview of the security scan results."""
    
    total_issues = len(df)
    if total_issues == 0:
        yield wrap_chunk(random_uuid(), "# Security Report\n\n✅ **No security issues found!** The repository appears to be well-secured.\n\n", "assistant")
        return
    
    # Generate statistics
    severity_stats = df['severity'].value_counts().to_dict()
    tool_stats = df['tool'].value_counts().to_dict()
    language_stats = df['language'].value_counts().to_dict()
    cwe_stats = df['cwe'].value_counts().to_dict()
    
    # Create context for LLM
    context = {
        "total_issues": total_issues,
        "severity_breakdown": severity_stats,
        "tools_used": list(tool_stats.keys()),
        "languages_scanned": list(language_stats.keys()),
        "top_cwes": list(cwe_stats.keys())[:5],
        "repo_url": repo.repo_url if repo else "Unknown"
    }
    
    system_prompt = f"""You are a cybersecurity expert creating an executive summary for a security scan report.

    Scan Results Context:
    - Total Issues Found: {context['total_issues']}
    - Severity Distribution: {context['severity_breakdown']}
    - Tools Used: {', '.join(context['tools_used'])}
    - Languages Scanned: {', '.join(context['languages_scanned'])}
    - Top CWEs: {', '.join(context['top_cwes'])}
    - Repository: {context['repo_url']}

    Create a professional executive summary that:
    1. Starts with a clear headline and security status
    2. Provides key findings and risk assessment
    3. Highlights the most critical issues that need immediate attention
    4. Is concise but informative (2-3 paragraphs)
    5. Uses appropriate security terminology
    """
    
    client = openai.AsyncClient(
        base_url=settings.llm_base_url, 
        api_key=settings.llm_api_key
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Generate the executive summary for this security scan report."}
    ]
    
    try:
        completion = await client.chat.completions.create(
            model=settings.llm_model_id,
            messages=messages,
            stream=True
        )
        
        async for chunk in completion:
            if chunk.choices[0].delta.content:
                yield wrap_chunk(random_uuid(), chunk.choices[0].delta.content, "assistant")
                
    except Exception as e:
        logger.error(f"Error generating headline: {e}")
        yield wrap_chunk(random_uuid(), f"# Security Report\n\n🔍 **{total_issues} security issues found** across {len(tool_stats)} tools.\n\n", "assistant")

async def generate_high_severity_report(
    df: DataFrame,
    repo: RepoInfo | None,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate detailed report for CRITICAL and HIGH severity issues."""
    
    # Include both CRITICAL and HIGH severity
    critical_high_df = df[df['severity'].isin(['CRITICAL', 'HIGH'])]
    
    if len(critical_high_df) == 0:
        yield wrap_chunk(random_uuid(), "\n## 🟢 Critical & High Severity Issues\n\n✅ **No critical or high severity issues found.**\n\n", "assistant")
        return
    
    yield wrap_chunk(random_uuid(), f"\n## 🔴 Critical & High Severity Issues ({len(critical_high_df)} found)\n\n", "assistant")
    
    # Group by CWE for better organization
    grouped_by_cwe = critical_high_df.groupby('cwe')
    
    for cwe_id, group in grouped_by_cwe:
        if event.is_set():
            break
            
        async for chunk in _generate_cwe_detailed_analysis(cwe_id, group, repo, event, is_critical=True):
            yield chunk

async def generate_medium_severity_report(
    df: DataFrame,
    repo: RepoInfo | None,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate detailed report for MEDIUM severity issues."""
    
    medium_df = df[df['severity'] == 'MEDIUM']
    
    if len(medium_df) == 0:
        yield wrap_chunk(random_uuid(), "\n## 🟡 Medium Severity Issues\n\n✅ **No medium severity issues found.**\n\n", "assistant")
        return
    
    yield wrap_chunk(random_uuid(), f"\n## 🟡 Medium Severity Issues ({len(medium_df)} found)\n\n", "assistant")
    
    # Group by CWE for better organization
    grouped_by_cwe = medium_df.groupby('cwe')
    
    for cwe_id, group in grouped_by_cwe:
        if event.is_set():
            break
            
        async for chunk in _generate_cwe_detailed_analysis(cwe_id, group, repo, event, is_critical=False):
            yield chunk
    
async def generate_other_severity_report(
    df: DataFrame,
    repo: RepoInfo | None,
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate summary report for LOW severity and other issues."""
    
    other_df = df[~df['severity'].isin(['CRITICAL', 'HIGH', 'MEDIUM'])]
    
    if len(other_df) == 0:
        yield wrap_chunk(random_uuid(), "\n## 🟢 Low Severity & Other Issues\n\n✅ **No low severity issues found.**\n\n", "assistant")
        return
    
    yield wrap_chunk(random_uuid(), f"\n## 🟢 Low Severity & Other Issues ({len(other_df)} found)\n\n", "assistant")
    
    # For low severity, provide a summary grouped by CWE rather than individual analysis
    cwe_summary = other_df.groupby('cwe').agg({
        'tool': 'count',
        'file_path': lambda x: list(set(x)),
        'description': lambda x: list(x)[:3]  # First 3 examples
    }).rename(columns={'tool': 'count'})
    
    for cwe_id, row in cwe_summary.iterrows():
        if event.is_set():
            break
            
        count = row['count']
        files = row['file_path']
        examples = row['description']
        
        # Get CWE information
        cwe_info = get_cwe_by_id(cwe_id)
        cwe_name = f"CWE-{cwe_info.id}: {cwe_info.name}" if cwe_info else cwe_id
        
        yield wrap_chunk(random_uuid(), f"### {cwe_name}\n\n", "assistant")
        yield wrap_chunk(random_uuid(), f"**{count} occurrence(s)** across {len(files)} file(s)\n\n", "assistant")
        
        if cwe_info and cwe_info.description:
            yield wrap_chunk(random_uuid(), f"**Description:** {cwe_info.description}\n\n", "assistant")
        
        # Show affected files
        yield wrap_chunk(random_uuid(), "**Affected files:**\n", "assistant")
        for file in files[:5]:  # Limit to 5 files
            yield wrap_chunk(random_uuid(), f"- `{file}`\n", "assistant")
        
        if len(files) > 5:
            yield wrap_chunk(random_uuid(), f"- ... and {len(files) - 5} more files\n", "assistant")
        
        yield wrap_chunk(random_uuid(), "\n", "assistant")

async def _generate_cwe_detailed_analysis(
    cwe_id: str, 
    group: DataFrame, 
    repo: RepoInfo | None, 
    event: asyncio.Event,
    is_critical: bool = False
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Generate detailed analysis for a specific CWE group."""
    
    # Get CWE information
    cwe_info = get_cwe_by_id(cwe_id)
    cwe_name = f"CWE-{cwe_info.id}: {cwe_info.name}" if cwe_info else cwe_id
    
    # Header
    icon = "🔥" if is_critical else "⚠️"
    yield wrap_chunk(random_uuid(), f"### {icon} {cwe_name}\n\n", "assistant")
    
    # CWE description
    if cwe_info:
        yield wrap_chunk(random_uuid(), f"**Description:** {cwe_info.description}\n\n", "assistant")
        
        if cwe_info.consequences:
            yield wrap_chunk(random_uuid(), f"**Potential Impact:** {', '.join(cwe_info.consequences[:3])}\n\n", "assistant")
    
    # Show each issue in detail
    for idx, (_, report) in enumerate(group.iterrows()):
        if event.is_set():
            break
            
        if idx >= 5 and not is_critical:  # Limit non-critical issues
            remaining = len(group) - idx
            yield wrap_chunk(random_uuid(), f"*... and {remaining} more similar issues*\n\n", "assistant")
            break
        
        # Issue details
        yield wrap_chunk(random_uuid(), f"**Issue {idx + 1}:** `{report['file_path']}:{report['line_number']}`\n", "assistant")
        yield wrap_chunk(random_uuid(), f"- **Tool:** {report['tool']}\n", "assistant")
        yield wrap_chunk(random_uuid(), f"- **Severity:** {report['severity']}\n", "assistant")
        yield wrap_chunk(random_uuid(), f"- **Description:** {report['description']}\n", "assistant")
        
        # Show source code context if available
        if repo and report['file_path'] and report['line_number']:
            try:
                line_start = int(str(report['line_number']).split('-')[0]) if report['line_number'] else None
                line_end = int(str(report['line_number']).split('-')[-1]) if report['line_number'] else line_start
                
                if line_start:
                    context = repo.reveal_content(report['file_path'], line_start, line_end, A=3, B=3)
                    if context:
                        yield wrap_chunk(random_uuid(), f"\n**Source Code Context:**\n```{report['language']}\n{context}\n```\n", "assistant")
                        
                    # GitHub link
                    github_link = repo.get_reference(report['file_path'], line_start, line_end)
                    yield wrap_chunk(random_uuid(), f"\n[📄 View on GitHub]({github_link})\n", "assistant")
                    
            except Exception as e:
                logger.warning(f"Failed to get source context: {e}")
        
        yield wrap_chunk(random_uuid(), "\n", "assistant")
    
    # Generate LLM analysis for exploitation examples and fixes
    async for chunk in _generate_cwe_analysis_with_llm(cwe_info, group, repo, event, is_critical):
        yield chunk

async def _generate_cwe_analysis_with_llm(
    cwe_info, 
    group: DataFrame, 
    repo: RepoInfo | None, 
    event: asyncio.Event,
    is_critical: bool = False
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    """Use LLM to generate exploitation examples and remediation advice."""
    
    if event.is_set():
        return
    
    # Prepare context for LLM
    issues_context = []
    for _, report in group.iterrows():
        context = {
            "file": report['file_path'],
            "line": report['line_number'],
            "tool": report['tool'],
            "description": report['description'],
            "language": report['language']
        }
        issues_context.append(context)
    
    system_prompt = f"""You are a cybersecurity expert analyzing security vulnerabilities. 

CWE Information:
- ID: {cwe_info.id if cwe_info else 'Unknown'}
- Name: {cwe_info.name if cwe_info else 'Unknown'}
- Description: {cwe_info.description if cwe_info else 'No description available'}

Issues Found:
{json.dumps(issues_context, indent=2)}

Please provide:
1. **Real-world Exploitation Example**: A concrete example of how this vulnerability could be exploited by an attacker
2. **Remediation Steps**: Specific, actionable steps to fix this vulnerability type
3. **Prevention Tips**: Best practices to prevent this issue in the future

Keep your response focused, practical, and include code examples where relevant. Use markdown formatting.
"""
    
    client = openai.AsyncClient(
        base_url=settings.llm_base_url, 
        api_key=settings.llm_api_key
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Generate the exploitation example and remediation advice for these security findings."}
    ]
    
    try:
        completion = await client.chat.completions.create(
            model=settings.llm_model_id,
            messages=messages,
            stream=True
        )
        
        async for chunk in completion:
            if event.is_set():
                break
            if chunk.choices[0].delta.content:
                yield wrap_chunk(random_uuid(), chunk.choices[0].delta.content, "assistant")
                
        yield wrap_chunk(random_uuid(), "\n---\n\n", "assistant")
        
    except Exception as e:
        logger.error(f"Error generating CWE analysis: {e}")
        
        # Fallback content
        yield wrap_chunk(random_uuid(), "**Remediation:** Please review the identified issues and consult security best practices for your technology stack.\n\n", "assistant")

async def generate_security_deep_report(
    confirmed_reports: list[Report], 
    event: asyncio.Event,
    repo: RepoInfo | None = None
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    # Repo object is now passed as parameter
    
    report_list = [
        {
            "tool": report.tool,
            "severity": str(report.severity),  # Convert enum to string
            "description": report.description,
            "file_path": report.file_path,
            "line_number": report.line_number,
            "language": report.language,
            "cwe": report.cwe,
            "cve": report.cve
        } 
        for report in confirmed_reports
    ]

    df = pd.DataFrame(report_list)
    df['cwe'] = df['cwe'].apply(normalize_cwe)

    # Fix the filtering logic
    high_severity_df = df[df['severity'].isin(['CRITICAL', 'HIGH'])]
    medium_severity_df = df[df['severity'] == 'MEDIUM']
    other_df = df[~df['severity'].isin(['CRITICAL', 'HIGH', 'MEDIUM'])]
    
    async for chunk in generate_headline(df, repo, event):
        yield chunk

    async for chunk in generate_high_severity_report(high_severity_df, repo, event):
        yield chunk

    async for chunk in generate_medium_severity_report(medium_severity_df, repo, event):
        yield chunk
        
    async for chunk in generate_other_severity_report(other_df, repo, event):
        yield chunk

async def generate_security_report(
    confirmed_reports: list[Report], 
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    yield wrap_chunk(random_uuid(), merge_reports(confirmed_reports), "assistant")

async def handoff(
    tool_name: str, 
    tool_args: dict[str, Any], 
    event: asyncio.Event
) -> AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse | FullyHandoff, None]:
    
    if tool_name not in fn_mapping:
        yield wrap_chunk(random_uuid(), f"{tool_name} not found", "assistant")
        return

    fn = fn_mapping[tool_name]
    confirmed_reports = []
    deep_mode = tool_args.get('deep', True)
    repo_url = tool_args.get('repo_url', None)

    repo = None

    if repo_url is not None: 
        repo = RepoInfo(clone_repo(repo_url, tool_args.get('branch', None)))

    if not repo:
        yield wrap_chunk(random_uuid(), f"Repository is invalid or not accessible. No security scan is performed.", "assistant")
        return

    async for report in fn(**tool_args):
        if event.is_set():
            logger.info(f"[toolcall] Event signal received, stopping...")
            return

        report: Report | ErrorReport

        if isinstance(report, ErrorReport):
            logger.warning(f"Error report: {report}")

        else:
            report = await confirm_report(report, confirmed_reports, deep_mode, repo)

            if report is None:
                logger.warning(f"Report is rejected...")
                continue

            confirmed_reports.append(report)

            yield wrap_chunk(
                random_uuid(), 
                f"\n<details>\n<summary>{report.tool} found an issue - {report.severity} - {report.cwe or 'Unknown CWE'}</summary>\n```plain\n{fmt_report(report, repo)}\n```\n</details>\n", 
                "assistant"
            )

    if not confirmed_reports:
        yield wrap_chunk(random_uuid(), f"Repository is well-secured, no issues found!", "assistant")
        return

    if deep_mode:
        yield FullyHandoff()

        async for chunk in generate_security_deep_report(confirmed_reports, event, repo):
            yield chunk

    else:
        async for chunk in generate_security_report(confirmed_reports, event):
            yield chunk

async def execute_toolcall_request(
    tool_name: str, 
    tool_args: dict[str, Any],
    event: asyncio.Event
) -> list[Union[TextContent, EmbeddedResource]] | AsyncGenerator[ChatCompletionStreamResponse | ErrorResponse, None]:
    for tool in await source_code_mcp._mcp_list_tools():
        if tool.name == tool_name:
            return handoff(tool_name, tool_args, event) # async generator, no need to await

    return await execute_openai_compatible_toolcall(tool_name, tool_args, git_action_mcp)

async def handle_request(
    request: ChatCompletionRequest, 
    event: asyncio.Event,
    additional_parameters: Optional[ChatCompletionAdditionalParameters] = None
) -> AsyncGenerator[ChatCompletionStreamResponse, None]:
    messages = request.messages
    assert len(request.messages) > 0, "No messages in the request"

    arm = AgentResourceManager()

    system_prompt = await get_system_prompt(messages)
    logger.info(f"[main] System prompt: {system_prompt}")
    
    messages: list[dict[str, Any]] = refine_chat_history(messages, system_prompt, arm)

    oai_tools = await list_toolcalls()
    
    finished = False
    n_calls, max_calls = 0, 25

    while not finished and not event.is_set():
        completion_builder = ChatCompletionResponseBuilder()
        requires_toolcall = n_calls < max_calls
        toolcalls = oai_tools

        payload = dict(
            messages=messages,
            tools=toolcalls,
            tool_choice="auto",
            model=settings.llm_model_id
        )

        if not requires_toolcall:
            payload.pop("tools")
            payload.pop("tool_choice")

        streaming_iter = create_streaming_response(
            settings.llm_base_url,
            settings.llm_api_key,
            **payload
        )

        # need to reveal resource
        async for chunk in arm.handle_streaming_response(wrapstream(streaming_iter, completion_builder.add_chunk)):
            if event.is_set():
                logger.info(f"[main] Event signal received, stopping the request")
                break

            yield chunk

        completion = await completion_builder.build()
        messages.append(refine_assistant_message(completion.choices[0].message))
        
        toolcalls_requested = (completion.choices[0].message.tool_calls or [])

        for call_idx, call in enumerate(toolcalls_requested):
            if event.is_set():
                logger.info(f"[toolcall] Event signal received, stopping the request")
                break

            n_calls += 1

            _id, _name, _args = call.id, call.function.name, call.function.arguments
            _args: dict = json.loads(_args)
            _result = ""

            yield wrap_chunk(random_uuid(), f"<action>Running {_name}...</action>", "assistant")
            result = await execute_toolcall_request(_name, _args, event)
            
            if isinstance(result, AsyncGenerator):
                try:
                    fully_handoff = False

                    async for chunk in result:
                        if isinstance(chunk, ErrorResponse):
                            raise Exception(chunk.message)

                        chunk_content = chunk.choices[0].delta.content or ""
                        striped_chunk_content = chunk_content.strip()

                        if fully_handoff or (
                            striped_chunk_content.startswith('<details>') 
                            and striped_chunk_content.endswith('</details>')
                        ):
                            yield chunk

                        _result += chunk_content

                    if fully_handoff:
                        return

                except Exception as e:
                    logger.error(f"Error executing toolcall: {e}", exc_info=True)
                    _result = f"Error executing toolcall: {e}"

                _result = refine_mcp_response(_result, arm)
            else:
                _result = refine_mcp_response(result, arm)
                yield wrap_chunk(random_uuid(), f'<details><summary>Tool call result</summary>\n```json\n{_result}\n```\n</details>\n', "assistant")

            if not isinstance(_result, str):
                try:
                    _result = json.dumps(_result)
                except:
                    _result = str(_result)

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": _id,
                    "content": _result
                }
            )

        finished = len(toolcalls_requested) == 0

    os.makedirs("logs", exist_ok=True)
    with open(f"logs/messages-{request.request_id}.json", "w") as f:
        json.dump(messages, f, indent=2)

    yield completion