"""GitHub repository security analysis and vulnerability detection tools."""

from fastmcp import FastMCP
import logging
from dotenv import load_dotenv
from typing import Any, AsyncGenerator

from . import git_utils
from . import security_scanners
from . import github_utils
from .security_scanners import Report, ErrorReport, SeverityLevel

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.WARNING,
)
logger = logging.getLogger(__name__)

mcp = FastMCP("Sentinel - Security Analysis Agent", dependencies=["gitpython"])
audit_mcp = FastMCP("Sentinel - Audit Agent", dependencies=["gitpython"])

load_dotenv()


@mcp.tool()
def git_directory_structure(repo_url: str, subfolder: str = "", max_depth: int = None, branch_name: str = None) -> str:
    """
    Clone a Git repository and return its directory structure in a tree format.

    Args:
        repo_url: The URL of the Git repository
        subfolder: Optional path to a specific subfolder within the repository (e.g., "src", "docs/api")
        max_depth: Optional maximum depth to traverse (useful for large repositories)
        branch_name: Optional branch name to checkout before scanning (defaults to main/master branch)

    Returns:
        A string representation of the repository's directory structure
    """
    return git_utils.git_directory_structure(repo_url, subfolder, max_depth, branch_name)


@mcp.tool()
def validate_and_set_github_token(token: str | None = None) -> str:
    """
    Validates a GitHub personal access token and sets it as an environment variable.
    """
    return github_utils.validate_and_set_github_token(token)


@mcp.tool()
def provide_guide_for_github_access_token() -> str:
    """
    Provide a guide for obtaining a GitHub personal access token.
    """
    return github_utils.provide_guide_for_github_access_token()


@audit_mcp.tool()
async def comprehensive_security_scan(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Perform a comprehensive security scan of a GitHub repository concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning (defaults to main/master branch)

    Yields:
        Report or ErrorReport objects as scans complete
    """
    async for report in security_scanners.comprehensive_security_scan_concurrent(repo_url, subfolder, branch_name):
        yield report


@audit_mcp.tool()
async def scan_for_secrets(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Scan a GitHub repository for exposed secrets and sensitive information concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning (defaults to main/master branch)

    Yields:
        Report or ErrorReport objects containing secret findings
    """
    async for report in security_scanners.scan_for_secrets_concurrent(repo_url, subfolder, branch_name):
        yield report


@audit_mcp.tool()
async def scan_dependencies_vulnerabilities(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Scan a GitHub repository for vulnerable dependencies concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning (defaults to main/master branch)

    Yields:
        Report or ErrorReport objects containing dependency vulnerability findings
    """
    async for report in security_scanners.scan_dependencies_vulnerabilities_concurrent(repo_url, subfolder, branch_name):
        yield report


@audit_mcp.tool()
async def scan_code_quality_security(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Perform static code analysis for security issues and code quality concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning (defaults to main/master branch)

    Yields:
        Report or ErrorReport objects containing code quality and security findings
    """
    async for report in security_scanners.scan_code_quality_security_concurrent(repo_url, subfolder, branch_name):
        yield report

