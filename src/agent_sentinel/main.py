"""GitHub repository security analysis and vulnerability detection tools."""

from fastmcp import FastMCP
import logging
from dotenv import load_dotenv
from typing import Any

from . import git_utils
from . import security_scanners
from . import github_utils
from .security_scanners import Report

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

mcp = FastMCP("Sentinel - Security Analysis Agent", dependencies=["gitpython"])

load_dotenv()


@mcp.tool()
def git_directory_structure(repo_url: str, subfolder: str = "", max_depth: int = None) -> str:
    """
    Clone a Git repository and return its directory structure in a tree format.

    Args:
        repo_url: The URL of the Git repository
        subfolder: Optional path to a specific subfolder within the repository (e.g., "src", "docs/api")
        max_depth: Optional maximum depth to traverse (useful for large repositories)

    Returns:
        A string representation of the repository's directory structure
    """
    return git_utils.git_directory_structure(repo_url, subfolder, max_depth)


@mcp.tool()
def checkout_branch(repo_path: str, branch_name: str) -> str:
    """
    Checkout a specific branch in a Git repository.

    Args:
        repo_path: The path to the local Git repository
        branch_name: The name of the branch to checkout
    Returns:
        A message indicating success or failure
    """
    return git_utils.checkout_branch(repo_path, branch_name)


@mcp.tool()
def git_read_important_files(repo_url: str, file_paths: list[str]) -> dict[str, str]:
    """
    Read the contents of specified files in a given Git repository.
    """
    return git_utils.git_read_important_files(repo_url, file_paths)


@mcp.tool()
def validate_and_set_github_token(token: str | None = None) -> str:
    """
    Validates a GitHub personal access token and sets it as an environment variable.
    """
    return github_utils.validate_and_set_github_token(token)


@mcp.tool()
def git_list_directories(repo_url: str, subfolder: str = "", max_depth: int = 1) -> str:
    """
    List directories in a Git repository at a specified depth for quick exploration.

    Args:
        repo_url: The URL of the Git repository
        subfolder: Optional path to a specific subfolder within the repository
        max_depth: Maximum depth to show (default: 1 for top-level only)

    Returns:
        A list of directories at the specified depth
    """
    return git_utils.git_list_directories(repo_url, subfolder, max_depth)


@mcp.tool()
def provide_guide_for_github_access_token() -> str:
    """
    Provide a guide for obtaining a GitHub personal access token.
    """
    return github_utils.provide_guide_for_github_access_token()


@mcp.tool()
async def comprehensive_security_scan(repo_url: str, subfolder: str = "") -> str:
    """
    Perform a comprehensive security scan of a GitHub repository.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A formatted string with each issue on one line
    """
    return await security_scanners.comprehensive_security_scan(repo_url, subfolder)


@mcp.tool()
def scan_for_secrets(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Scan a GitHub repository for exposed secrets and sensitive information.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing secret findings
    """
    return security_scanners.scan_for_secrets(repo_url, subfolder)


@mcp.tool()
def scan_dependencies_vulnerabilities(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Scan a GitHub repository for vulnerable dependencies.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing dependency vulnerability findings
    """
    return security_scanners.scan_dependencies_vulnerabilities(repo_url, subfolder)


@mcp.tool()
def scan_code_quality_security(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Perform static code analysis for security issues and code quality.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing code quality and security findings
    """
    return security_scanners.scan_code_quality_security(repo_url, subfolder)


@mcp.tool()
async def generate_security_report(repo_url: str) -> str:
    """
    Generate a comprehensive security report for a GitHub repository.

    Args:
        repo_url: The URL of the Git repository to analyze

    Returns:
        A formatted security report with findings and recommendations
    """
    return await security_scanners.generate_security_report(repo_url)
