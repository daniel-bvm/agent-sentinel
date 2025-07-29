"""GitHub repository security analysis and vulnerability detection tools."""

from fastmcp import FastMCP
import logging
from dotenv import load_dotenv
from typing import Any, AsyncGenerator

from . import git_utils
from . import security_scanners
from . import github_utils
from . import diff_utils
from .security_scanners import Report, ErrorReport, SeverityLevel

logger = logging.getLogger(__name__)

mcp = FastMCP("Sentinel - Security Analysis Agent", dependencies=["gitpython"])
audit_mcp = FastMCP("Sentinel - Audit Agent", dependencies=["gitpython"])
diff_mcp = FastMCP("Sentinel - Diff Analysis Agent", dependencies=["gitpython"])

load_dotenv()

@mcp.tool()
def validate_and_set_github_token(token: str | None = None) -> str:
    """
    Validates a GitHub personal access token and sets it as an environment variable.
    """
    return github_utils.validate_and_set_github_token(token)

@audit_mcp.tool()
async def security_scan(repo_url: str, target_path: str = "", branch_name: str = None, deep: bool = True) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Perform a comprehensive security scan of a GitHub repository and get the report.
    Can scan a specific subfolder or individual file within the repository.

    Args:
        - repo_url: The URL of the GitHub repository to scan
        - target_path: The path to the specific subfolder or file within the repository to scan
        - branch_name: The name of the branch to scan
        - deep: Whether to perform a deep scan of the repository

    """
    logger.info(f"Scanning repository {repo_url} with target path {target_path} and branch name {branch_name} and deep mode {deep}")
    async for report in security_scanners.comprehensive_security_scan_concurrent(repo_url, target_path, branch_name, deep):
        yield report


@diff_mcp.tool()
def scan_git_diff(
    local_repo_path: str,
    target_path: str = None,
    mode: str = "working"
) -> dict[str, Any]:
    """
    Scan git working tree for current development changes - only analyzes files that have actually changed.

    This tool is designed for live development workflow where users mount their local git
    repository into a Docker container and want to efficiently analyze their current working changes.
    It only scans files that have modifications, not the entire repository.

    Args:
        local_repo_path: Local path to the git repository (mounted in Docker container)
        target_path: Path to analyze (file or directory within the repository, None for entire repo)
        mode: Working tree analysis mode:
            - "working": Show all working tree changes vs HEAD (staged + unstaged changes)
            - "staged": Show staged changes ready for commit (git diff --cached)
            - "unstaged": Show unstaged changes in working directory (git diff)
            - "status": Show git status information (modified, added, deleted files)
    """
    logger.info(f"Scanning git working tree for path {target_path} in {local_repo_path} with mode {mode}")
    result = diff_utils.scan_git_diff(local_repo_path, target_path, mode)
    logger.info(f"Scan result: {result}")
    return result
