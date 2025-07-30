"""GitHub repository security analysis and vulnerability detection tools."""

from fastmcp import FastMCP
import logging
from typing import AsyncGenerator

from . import security_scanners
from .security_scanners import Report, ErrorReport
from typing import Literal

logger = logging.getLogger(__name__)

mcp = FastMCP("Sentinel - Security Analysis Agent", dependencies=["gitpython"])
audit_mcp = FastMCP("Sentinel - Audit Agent", dependencies=["gitpython"])
diff_mcp = FastMCP("Sentinel - Diff Analysis Agent", dependencies=["gitpython"])

@audit_mcp.tool(
    description="Perform a comprehensive security scan of a GitHub repository and get the report. Can scan a specific subfolder or individual file within the repository.",
    annotations={
        "github_repo": "Github repository to scan.",
        "paths": "Specific paths to scan. By default, all detected files/folders are scanned.",
        "branch_name": "Specify the branch to scan. Use None as default branch.",
        "mode": "The mode to scan the repository in. 'full' mode scans all files/folders, 'working' scans only the working tree changes. For quick scans, use working mode",
        "deep": "Perform extra scans on the repository. Deep mode takes more time to run."
    }
)
async def security_scan(
    github_repo: str, 
    paths: list[str] = [],
    branch_name: str | None = None,
    mode: Literal["working", "full"] = "full",
    deep: bool = True
) -> AsyncGenerator[Report | ErrorReport, None]:

    is_remote_url = github_repo.startswith("http")
    logger.info(f"Scanning repository {github_repo} with target path {paths} and branch name {branch_name} and deep mode {deep}")

    async for report in security_scanners.comprehensive_security_scan_concurrent(
        github_repo, 
        paths,
        branch_name if not is_remote_url else None, 
        mode, 
        deep if not is_remote_url else None
    ):
        yield report