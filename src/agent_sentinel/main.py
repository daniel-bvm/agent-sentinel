"""GitHub repository security analysis and vulnerability detection tools."""

from fastmcp import FastMCP
import logging
from typing import AsyncGenerator

from . import security_scanners
from .security_scanners import Report, ErrorReport, ScanNoti
from typing import Literal
import os

logger = logging.getLogger(__name__)

mcp = FastMCP("Sentinel - Security Analysis Agent", dependencies=["gitpython"])
audit_mcp = FastMCP("Sentinel - Audit Agent", dependencies=["gitpython"])
diff_mcp = FastMCP("Sentinel - Diff Analysis Agent", dependencies=["gitpython"])

@audit_mcp.tool(
    description="Perform a comprehensive security scan of a GitHub repository, and or sub-folders, files in the repository, and get the report. mythril, slither, gitleaks, semgrep, codeql and  trivy are used to boost the result confidence.",
    annotations={
        "github_repo": "Github repository to scan. It can be local path or github url.",
        "paths": "Specific paths to scan. By default, all detected files/folders are scanned.",
        "branch_name": "Specify the branch to scan. Use None as default branch.",
        "mode": "The mode to scan the repository in. 'full' mode scans all files/folders, 'working' scans only the working tree changes. For quick scans, use working mode",
        "deep": "Perform extra scans on the source code. Deep mode takes more time to run."
    }
)
async def security_scan(
    github_repo: str, 
    paths: list[str] = [],
    branch_name: str | None = None,
    mode: Literal["working", "full"] = "full",
    deep: bool = True
) -> AsyncGenerator[Report | ErrorReport | ScanNoti, None]:

    if not github_repo.startswith("http") and not os.path.exists(github_repo):
        github_repo = f"https://github.com/{github_repo}"

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
