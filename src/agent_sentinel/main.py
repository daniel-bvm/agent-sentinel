"""GitHub repository security analysis and vulnerability detection tools."""

from fastmcp import FastMCP
import logging
from dotenv import load_dotenv
from typing import Any, AsyncGenerator

from . import git_utils
from . import security_scanners
from . import github_utils
from .security_scanners import Report, ErrorReport, SeverityLevel

logger = logging.getLogger(__name__)

mcp = FastMCP("Sentinel - Security Analysis Agent", dependencies=["gitpython"])
audit_mcp = FastMCP("Sentinel - Audit Agent", dependencies=["gitpython"])

load_dotenv()

@mcp.tool()
def validate_and_set_github_token(token: str | None = None) -> str:
    """
    Validates a GitHub personal access token and sets it as an environment variable.
    """
    return github_utils.validate_and_set_github_token(token)

@audit_mcp.tool()
async def security_scan(repo_url: str, subfolder: str = "", branch_name: str = None, deep: bool = True) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Perform a comprehensive security scan of a GitHub repository and get the report.
    """
    async for report in security_scanners.comprehensive_security_scan_concurrent(repo_url, subfolder, branch_name, deep):
        yield report
