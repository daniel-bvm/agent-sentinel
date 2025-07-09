"""General utility functions for the agent sentinel."""

import os
import subprocess
import tempfile
import logging
import tomlkit
from typing import Any

logger = logging.getLogger(__name__)


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