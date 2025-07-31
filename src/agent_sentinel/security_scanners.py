"""
Security scanners for the Agent Sentinel.
"""

import os
import json
import logging
import re
import asyncio
import hashlib
import shutil
from pathlib import Path

from typing import Any, AsyncGenerator, Awaitable, Literal
from .utils import run_command, detect_project_languages, patch_foundry_config, sync2async
import json_repair
from collections import defaultdict
from .git_utils import clone_repo
from .codeql_utils import run_codeql_scanner
from .trivy_utils import scan_with_trivy
from .models import cwe_mapping, Report, ErrorReport, SeverityLevel
from .diff_utils import scan_git_diff

logger = logging.getLogger(__name__)

# Mapping of tool identities to their post-processing functions
TOOL_POST_PROCESSORS = {
    "slither": lambda result: _parse_slither_result(result),
    "mythril": lambda result: _parse_mythril_result(result),
    "secrets": lambda result: _convert_secrets_to_reports(result),
    "semgrep": lambda result: _parse_scan_results_to_reports(result),
    "trivy": lambda result: _convert_trivy_results_to_reports(result),
    "bandit": lambda result: _convert_bandit_to_reports(result),
    "safety": lambda result: _convert_safety_to_reports(result),
    "npm_audit": lambda result: _convert_npm_audit_to_reports(result),
}

def _get_codeql_post_processor(language: str):
    """Get CodeQL post-processor for a specific language."""
    return lambda result: _parse_codeql_result(result, language)

def _convert_bandit_to_reports(bandit_result: dict[str, Any]) -> list[Report]:
    """Convert Bandit results to Report objects."""
    reports = []
    if isinstance(bandit_result, dict) and "error" not in bandit_result:
        if "results" in bandit_result:
            for issue in bandit_result["results"]:
                if isinstance(issue, dict):
                    confidence_info = f" (Confidence: {issue.get('issue_confidence', 'N/A')})"
                    # Map Bandit severity to SeverityLevel
                    bandit_severity = issue.get("issue_severity", "MEDIUM").upper()
                    try:
                        severity = SeverityLevel(bandit_severity)
                    except ValueError:
                        severity = SeverityLevel.MEDIUM

                    # Extract CWE from test_id or test_name
                    test_id = issue.get("test_id", "")
                    cwe = "n/a"
                    if test_id:
                        # Bandit test IDs often correspond to CWEs
                        cwe = cwe_mapping.get(test_id, f"Bandit-{test_id}")

                    # Enhanced description with more context
                    description_parts = [issue.get('test_name', 'Unknown Security Test')]
                    if issue.get('issue_text'):
                        description_parts.append(issue.get('issue_text'))
                    if issue.get('more_info'):
                        description_parts.append(f"More info: {issue.get('more_info')}")
                    enhanced_description = ": ".join(description_parts) + confidence_info

                    reports.append(Report(
                        tool="Bandit",
                        severity=severity,
                        description=enhanced_description,
                        file_path=issue.get("filename"),
                        line_number=str(issue.get("line_number", "")),
                        language="python",
                        cwe=cwe,
                        information=test_id,  # Add test ID as information
                        report_type="code"
                    ))
    elif isinstance(bandit_result, dict) and "error" in bandit_result:
        reports.append(ErrorReport(
            tool="Bandit",
            reason="scan_failure"
        ))
    return reports

def _convert_safety_to_reports(safety_result: dict[str, Any]) -> list[Report]:
    """Convert Safety results to Report objects."""
    reports = []
    if isinstance(safety_result, dict) and "error" not in safety_result:
        for req_file, file_results in safety_result.items():
            if isinstance(file_results, dict) and "error" not in file_results:
                for severity in ["high", "medium", "low"]:
                    if severity in file_results and file_results[severity]:
                        for package, vulns in file_results[severity].items():
                            for vuln in vulns:
                                cve_info = f" (CVE: {vuln.get('cve', 'N/A')})" if vuln.get('cve', 'N/A') != 'N/A' else ""
                                # Map severity string to SeverityLevel
                                try:
                                    severity_level = SeverityLevel(severity.upper())
                                except ValueError:
                                    severity_level = SeverityLevel.MEDIUM

                                reports.append(Report(
                                    tool="Safety",
                                    severity=severity_level,
                                    description=f"{package}: {vuln.get('advisory', 'N/A')}{cve_info}",
                                    file_path=req_file,
                                    language="python",
                                    cwe=vuln.get('cwe', 'N/A'),
                                    information=f"{package}:{vuln.get('affected_versions', 'N/A')}",  # Add package information
                                    report_type="dependency"
                                ))
            elif isinstance(file_results, dict) and "error" in file_results:
                reports.append(ErrorReport(
                    tool="Safety",
                    reason="scan_failure"
                ))
    else:
        reports.append(ErrorReport(
            tool="Safety",
            reason="scan_failure"
        ))
    return reports

def _convert_npm_audit_to_reports(npm_result: dict[str, Any]) -> list[Report]:
    """Convert npm audit results to Report objects."""
    reports = []
    if isinstance(npm_result, dict) and "error" not in npm_result:
        for severity in ["high", "medium", "low"]:
            if severity in npm_result and npm_result[severity]:
                for package, vulns in npm_result[severity].items():
                    for vuln in vulns:
                        cve_info = f" (CVE: {vuln.get('cve', 'N/A')})" if vuln.get('cve', 'N/A') != 'N/A' else ""
                        # Map severity string to SeverityLevel
                        try:
                            severity_level = SeverityLevel(severity.upper())
                        except ValueError:
                            severity_level = SeverityLevel.MEDIUM

                        # Enhanced description with package version and dependency path
                        description_parts = [f"Package {package}"]
                        if vuln.get('advisory'):
                            description_parts.append(vuln.get('advisory'))
                        if vuln.get('patched_in'):
                            description_parts.append(f"Fixed in: {vuln.get('patched_in')}")
                        if vuln.get('vulnerable_versions'):
                            description_parts.append(f"Vulnerable versions: {vuln.get('vulnerable_versions')}")
                        enhanced_description = ": ".join(description_parts) + cve_info

                        reports.append(Report(
                            tool="npm audit",
                            severity=severity_level,
                            description=enhanced_description,
                            file_path="package.json",  # npm audit always relates to package.json
                            language="javascript",
                            cwe=vuln.get('cwe', 'n/a'),
                            information=f"{package}:{vuln.get('patched_in', 'N/A')}",  # Add package version information
                            report_type="dependency"
                        ))
    else:
        reports.append(ErrorReport(
            tool="npm audit",
            reason="scan_failure"
        ))
    return reports

def compare_path(path_1: str, path_2: str) -> bool:
    """Compare two paths and return True if they are the same."""
    norm_path1 = os.path.normpath(path_1)
    norm_path2 = os.path.normpath(path_2)
    return norm_path1 == norm_path2

async def comprehensive_security_scan_concurrent(
    repo_url: str, 
    paths: list[str] = [], 
    branch_name: str = None, 
    mode: Literal["full", "working", "staged", "unstaged"] = "full", 
    deep: bool = True
) -> AsyncGenerator[Report | ErrorReport, None]:

    # Clone the repository and checkout branch if specified
    repo_path = await sync2async(clone_repo)(repo_url, branch_name)

    if mode != 'full':
        logger.info(f"Scanning repository {repo_url} with mode {mode}; original paths ({paths}) is skipped")
    
        diff: dict[str, Any] = await sync2async(scan_git_diff)(repo_path, mode=mode)
        diff_file_changes = diff.get("file_changes", [])

        paths = [
            file for file in diff_file_changes
        ]

    elif not paths:
        paths.append(repo_path)

    else:
        paths = [
            os.path.join(repo_path, path) 
            for path in paths
        ]

    repo_path = os.path.normpath(repo_path)
    task_map_identity = {} # map id with the scan path
    tasks = []

    for scan_path in paths:
        is_single_file = os.path.isfile(scan_path)
        if is_single_file:
            scan_dir = os.path.dirname(scan_path)
        else:
            scan_dir = scan_path

        # Detect languages
        languages = await sync2async(detect_project_languages)(scan_path)

        # Run Solidity-specific scans
        if "solidity" in languages:
            if deep:
                # Try Mythril for deep analysis when deep=True, fallback to Slither if not available
                # Check if Mythril is available first
                mythril_check = await sync2async(run_command)(["which", "myth"])
                if mythril_check["success"]:
                    # Mythril can handle individual files
                    tasks.append(a_stupid_wrapper(scan_path, "mythril", sync2async(scan_solidity_mythril)(scan_path)))
                else:
                    logger.warning("Mythril not available for deep analysis, falling back to Slither")
                    # Slither needs directory
                    slither_path = scan_dir if is_single_file else scan_path
                    tasks.append(a_stupid_wrapper(slither_path, "slither", sync2async(scan_solidity_slither)(slither_path)))
            else:
                # Use Slither for faster analysis when deep=False - Slither needs directory
                slither_path = scan_dir if is_single_file else scan_path
                tasks.append(a_stupid_wrapper(slither_path, "slither", sync2async(scan_solidity_slither)(slither_path)))

        # Schedule general security scans (these can handle files directly)
        tasks.append(a_stupid_wrapper(scan_path, "secrets", sync2async(scan_secrets_with_gitleaks)(scan_path)))
        tasks.append(a_stupid_wrapper(scan_path, "semgrep", sync2async(scan_semgrep)(scan_path)))

        # Schedule CodeQL analysis for each language (CodeQL needs directory)
        for language in languages:
            codeql_path = scan_dir if is_single_file else scan_path
            tasks.append(a_stupid_wrapper(codeql_path, f"codeql_{language}", sync2async(run_codeql_scanner)(codeql_path, language)))

        # Schedule Trivy scan (can handle files directly)
        tasks.append(a_stupid_wrapper(scan_path, "trivy", sync2async(scan_with_trivy)(scan_path)))

    # Process completed tasks as they finish
    for task in asyncio.as_completed(tasks):
        sub_path, identity, result = await task

        # Handle CodeQL results (which have language suffix)
        if identity.startswith("codeql_"):
            language = identity.replace("codeql_", "")
            post_processor = _get_codeql_post_processor(language)

        else:
            post_processor = TOOL_POST_PROCESSORS.get(identity)

        if post_processor:
            try:
                if isinstance(result, Exception):
                    yield ErrorReport(tool=identity, reason=str(result))
                else:
                    reports = post_processor(result)

                    for report in reports:
                        report.file_path = os.path.relpath(os.path.join(sub_path, report.file_path), repo_path)
                        logger.info(f"Report file path: {report.file_path}")
                        yield report

            except Exception as e:
                logger.error(f"Error processing {identity} results: {e}")
                yield ErrorReport(tool=identity, reason=f"post_processing_error: {str(e)}")
        else:
            logger.warning(f"No post-processor found for {identity}")
            yield ErrorReport(tool=identity, reason="no_post_processor")


def clean_file_path(file_path: str, repo_path: str) -> str:
    """
    Clean file path by removing the base repository path pattern.

    Args:
        file_path: The full file path to clean
        repo_path: The repository path to remove from the file path

    Returns:
        Cleaned relative file path
    """
    if file_path.startswith(repo_path):
        # Remove the repo path and any leading slash
        cleaned = file_path[len(repo_path):].lstrip('/')
        return cleaned if cleaned else file_path
    return file_path



def scan_solidity_slither(scan_path: str) -> dict[str, Any]:
    """Run Slither static analysis on Solidity contracts (with Foundry support)."""
    # 1. Check if Solidity files exist
    found_solidity = any(
        file.endswith(".sol")
        for root, _, files in os.walk(scan_path)
        for file in files
    )
    if not found_solidity:
        return {"error": "No Solidity (.sol) files found"}

    # 2. Detect Foundry project
    foundry_toml = os.path.join(scan_path, "foundry.toml")
    if os.path.isfile(foundry_toml):
        try:
            # Append necessary compiler options to avoid stack-too-deep errors
            if not patch_foundry_config(foundry_toml):
                return {"error": "Failed to patch foundry.toml for optimizer/via_ir"}

            # Build contracts before running Slither
            compile_result = run_command(["forge", "build"], cwd=scan_path)
            if not compile_result["success"]:
                return {"error": f"Forge build failed:\n{compile_result['stderr']}"}
        except Exception as e:
            return {"error": f"Failed to patch and compile Foundry project: {str(e)}"}

    # 3. Run Slither
    slither_output = os.path.join(scan_path, "slither-output.json")
    if os.path.exists(slither_output):
        os.remove(slither_output)
    result = run_command(["slither", ".", "--json", slither_output], cwd=scan_path)

    if not os.path.exists(slither_output):
        return {"error": f"Slither did not generate output file.\nSTDERR:\n{result['stderr']}"}

    # 4. Return raw Slither JSON data for post-processing
    try:
        with open(slither_output, "r") as f:
            slither_data = json_repair.load(f)

        # Clean up the output file
        os.remove(slither_output)

        # Return the raw results with scan_path for file path cleaning
        return {
            "raw_results": slither_data,
            "scan_path": scan_path
        }

    except Exception as e:
        return {"error": f"Failed to process Slither output: {str(e)}"}



def scan_secrets_with_gitleaks(scan_path: str) -> dict[str, Any]:
    """Run Gitleaks for secret detection in a given path (repo, subfolder, or file)."""
    # Determine working directory and output path
    if os.path.isfile(scan_path):
        work_dir = os.path.dirname(scan_path)
        output_path = os.path.join(work_dir, "gitleaks_report.json")
    else:
        work_dir = scan_path
        output_path = os.path.join(scan_path, "gitleaks_report.json")

    if os.path.exists(output_path):
        os.remove(output_path)
    cmd = [
        "gitleaks",
        "detect",
        "--source",
        scan_path,
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        output_path,
    ]
    run_command(cmd, cwd=work_dir)

    if not os.path.exists(output_path):
        return {"error": "Gitleaks did not generate output file."}

    try:
        with open(output_path, "r") as f:
            json_data = json_repair.load(f)

        # Clean up output file
        os.remove(output_path)

        # Return raw results with scan_path for file path cleaning
        return {
            "raw_results": json_data,
            "scan_path": scan_path
        }
    except Exception as e:
        return {"error": f"Failed to parse Gitleaks output: {str(e)}"}


def scan_semgrep(scan_path: str) -> dict[str, Any]:
    """Run Semgrep for multi-language security analysis in a given path (repo, subfolder, or file)."""
    cmd = ["semgrep", "--config=auto", "--json", scan_path]
    # Determine working directory
    work_dir = os.path.dirname(scan_path) if os.path.isfile(scan_path) else scan_path
    result = run_command(cmd, cwd=work_dir)

    if result["success"]:
        try:
            json_result = json_repair.loads(result["stdout"])
            # Return raw results with scan_path for file path cleaning
            return {
                "raw_results": json_result,
                "scan_path": scan_path
            }
        except json.JSONDecodeError:
            return {"error": "Failed to parse Semgrep output"}
    else:
        return {"error": result["stderr"]}

async def a_stupid_wrapper(sub_path: str, identity: str, awaitable_task: Awaitable) -> tuple[str, Any | Exception]:
    try:
        result = await awaitable_task
        return sub_path, identity, result
    except Exception as e:
        return sub_path, identity, e

def _parse_slither_result(slither_result: dict[str, Any]) -> list[Report]:
    """Parse raw Slither JSON results and convert to Report objects."""
    all_reports = []

    if "error" in slither_result:
        all_reports.append(ErrorReport(
            tool="Slither",
            reason=slither_result["error"]
        ))
        return all_reports

    if "raw_results" not in slither_result:
        all_reports.append(ErrorReport(
            tool="Slither",
            reason="No raw results found in Slither output"
        ))
        return all_reports

    raw_data = slither_result["raw_results"]
    scan_path = slither_result.get("scan_path", "")

    # Map Slither impact levels to CWE categories and severity
    impact_to_cwe_severity = {
        "High": {"cwe": "CWE-664", "severity": SeverityLevel.HIGH},      # Improper Control of a Resource
        "Medium": {"cwe": "CWE-703", "severity": SeverityLevel.MEDIUM},  # Improper Check or Handling of Exceptional Conditions
        "Low": {"cwe": "CWE-1061", "severity": SeverityLevel.LOW},       # Insufficient Encapsulation
        "Informational": {"cwe": "CWE-1078", "severity": SeverityLevel.LOW}, # Inappropriate Source Code Style or Formatting
        "Optimization": {"cwe": "CWE-1041", "severity": SeverityLevel.LOW}   # Use of Redundant Code
    }

    # Process detector results
    detectors = raw_data.get("results", {}).get("detectors", [])
    for detector in detectors:
        if not isinstance(detector, dict):
            continue

        # Extract basic information
        check_name = detector.get("check", "Unknown")
        impact = detector.get("impact", "Medium")
        confidence = detector.get("confidence", "Unknown")
        description = detector.get("description", "No description available")

        # Map impact to CWE and severity
        cwe_info = impact_to_cwe_severity.get(impact, {"cwe": "CWE-664", "severity": SeverityLevel.MEDIUM})

        # Extract file and line information from elements
        elements = detector.get("elements", [])
        file_path = None
        line_number = None

        # Find the primary source location
        for element in elements:
            if isinstance(element, dict) and element.get("type") in ["contract", "function", "variable"]:
                source_mapping = element.get("source_mapping", {})
                if source_mapping:
                    filename = source_mapping.get("filename_absolute", "")
                    if filename:
                        file_path = clean_file_path(filename, scan_path)
                    lines = source_mapping.get("lines", [])
                    if lines:
                        if len(lines) == 1:
                            line_number = str(lines[0])
                        else:
                            line_number = f"{lines[0]}-{lines[-1]}"
                    break

        # Enhanced description with confidence and check type
        enhanced_description = f"{check_name}: {description}"
        if confidence != "Unknown":
            enhanced_description += f" (Confidence: {confidence})"

        all_reports.append(Report(
            tool="Slither",
            severity=cwe_info["severity"],
            description=enhanced_description,
            file_path=file_path,
            line_number=line_number,
            language="solidity",
            cwe=cwe_info["cwe"],
            information=check_name,  # Add check name as information
            report_type="code"
        ))

    # Process compilation warnings/errors if present
    compilation_errors = raw_data.get("results", {}).get("compilation_errors", [])
    for error in compilation_errors:
        if isinstance(error, dict):
            error_type = error.get("type", "compilation_error")
            message = error.get("message", "Unknown compilation error")

            all_reports.append(Report(
                tool="Slither",
                severity=SeverityLevel.WARNING,
                description=f"Compilation {error_type}: {message}",
                language="solidity",
                cwe="CWE-1100",  # Insufficient Isolation or Compartmentalization
                information=error_type,  # Add error type as information
                report_type="code"
            ))

    return all_reports

def scan_solidity_mythril(scan_path: str) -> dict[str, Any]:
    """
    Run Mythril security analysis on Solidity contracts using enhanced flattening approach.

    Mythril is a security analysis tool for Ethereum smart contracts that detects a range of
    security issues including integer underflows, owner-overwrite-to-Ether-withdrawal, and others.

    Documentation: https://mythril-classic.readthedocs.io/_/downloads/en/master/pdf/
    """
    # 1. Check if Mythril is available
    mythril_check = run_command(["which", "myth"])
    if not mythril_check["success"]:
        return {"error": "Mythril is not installed or not available in PATH. Install with: pip install mythril"}

    # 2. Check if Solidity files exist
    scan_path_obj = Path(scan_path)
    sol_files = list(scan_path_obj.rglob("*.sol"))

    if not sol_files:
        return {"error": "No Solidity (.sol) files found"}

    logger.info(f"🧾 Found {len(sol_files)} Solidity files to analyze with Mythril.")

    # 3. Create temporary flattened directory
    flattened_dir = scan_path_obj / ".tmp_mythril_flattened"
    flattened_dir.mkdir(exist_ok=True)

    try:
        all_results = []
        solc_version = "0.8.30"  # Default Solidity version

        for sol_file in sol_files:
            parent_dir = sol_file.parent
            parent_hash = hashlib.md5(str(parent_dir).encode()).hexdigest()[:8]

            flat_filename = f"{sol_file.stem}_{parent_hash}.flat.sol"
            flat_path = flattened_dir / flat_filename

            logger.info(f"🔃 Flattening: {sol_file}")
            try:
                # Flatten the contract using forge flatten
                with open(flat_path, "w") as f:
                    flatten_result = run_command(["forge", "flatten", str(sol_file)], cwd=scan_path)
                    if not flatten_result["success"]:
                        logger.warning(f"❌ Failed to flatten {sol_file}: {flatten_result['stderr']}")
                        all_results.append({
                            "success": False,
                            "error": f"Failed to flatten: {flatten_result['stderr']}",
                            "issues": [],
                            "source_path": str(sol_file.relative_to(scan_path_obj))
                        })
                        continue

                    f.write(flatten_result["stdout"])

            except Exception as e:
                logger.warning(f"❌ Failed to flatten {sol_file}: {str(e)}")
                all_results.append({
                    "success": False,
                    "error": f"Failed to flatten: {str(e)}",
                    "issues": [],
                    "source_path": str(sol_file.relative_to(scan_path_obj))
                })
                continue

            logger.info(f"🔍 Analyzing with Mythril: {flat_path}")
            try:
                # Run Mythril on the flattened file
                mythril_result = run_command([
                    "myth", "analyze", str(flat_path),
                    "--solv", solc_version,
                    "--execution-timeout", "60",
                    "-o", "json"
                ])

                if mythril_result["success"]:
                    try:
                        myth_json = json.loads(mythril_result["stdout"])
                        myth_json["source_path"] = str(sol_file.relative_to(scan_path_obj))
                        all_results.append(myth_json)
                    except json.JSONDecodeError as e:
                        logger.warning(f"⚠️ Failed to parse Mythril JSON output for {flat_path}: {str(e)}")
                        all_results.append({
                            "success": False,
                            "error": f"Failed to parse Mythril JSON: {str(e)}",
                            "issues": [],
                            "source_path": str(sol_file.relative_to(scan_path_obj))
                        })
                else:
                    logger.warning(f"⚠️ Mythril analysis failed on: {flat_path}")
                    all_results.append({
                        "success": False,
                        "error": mythril_result["stderr"] or "Mythril analysis failed",
                        "issues": [],
                        "source_path": str(sol_file.relative_to(scan_path_obj))
                    })

            except Exception as e:
                logger.warning(f"⚠️ Mythril analysis exception on {flat_path}: {str(e)}")
                all_results.append({
                    "success": False,
                    "error": f"Mythril analysis exception: {str(e)}",
                    "issues": [],
                    "source_path": str(sol_file.relative_to(scan_path_obj))
                })

        # Return the results in the expected format
        return {
            "raw_results": all_results,
            "scan_path": scan_path
        }

    finally:
        # 4. Clean up the flattened directory
        try:
            if flattened_dir.exists():
                shutil.rmtree(flattened_dir)
                logger.info(f"🧹 Cleaned up flattened directory: {flattened_dir}")
        except Exception as e:
            logger.warning(f"Failed to clean up flattened directory {flattened_dir}: {str(e)}")


def _parse_mythril_result(mythril_result: dict[str, Any]) -> list[Report]:
    """
    Parse raw Mythril JSON results and convert to Report objects.

    Mythril documentation: https://mythril-classic.readthedocs.io/_/downloads/en/master/pdf/

    Expected issue schema:
    {
        "address": 731,
        "code": "assert(i == 0)",
        "contract": "Exceptions",
        "description": "detailed description",
        "filename": "solidity_examples/exceptions.sol",
        "function": "assert1()",
        "lineno": 7,
        "max_gas_used": 492,
        "min_gas_used": 207,
        "severity": "Medium",
        "sourceMap": ":::i",
        "swc-id": "110",
        "title": "Exception State",
        "tx_sequence": {...}
    }
    """
    all_reports = []

    if "error" in mythril_result:
        logger.error(f"Mythril parsing error: {mythril_result['error']}")
        all_reports.append(ErrorReport(
            tool="Mythril",
            reason=mythril_result["error"]
        ))
        return all_reports

    if "raw_results" not in mythril_result:
        logger.error("No raw results found in Mythril output")
        all_reports.append(ErrorReport(
            tool="Mythril",
            reason="No raw results found in Mythril output"
        ))
        return all_reports

    raw_data = mythril_result["raw_results"]
    scan_path = mythril_result.get("scan_path", "")

    logger.info(f"Parsing Mythril results from scan path: {scan_path}")
    logger.info(f"Processing {len(raw_data)} Mythril result files")

    # Map Mythril severity to SeverityLevel
    severity_mapping = {
        "High": SeverityLevel.HIGH,
        "Medium": SeverityLevel.MEDIUM,
        "Low": SeverityLevel.LOW,
    }

    # Map SWC to CWE (SWC is Smart Contract Weakness Classification)
    swc_to_cwe = {
        "SWC-101": "CWE-862",  # Integer Overflow -> Improper Authorization
        "SWC-103": "CWE-1284", # Floating Pragma -> Improper Validation
        "SWC-104": "CWE-252",  # Unchecked Call Return Value -> Unchecked Return Value
        "SWC-105": "CWE-670",  # Unprotected Ether Withdrawal -> Always-Incorrect Control Flow
        "SWC-106": "CWE-691",  # Unprotected SELFDESTRUCT -> Insufficient Control Flow Management
        "SWC-107": "CWE-664",  # Reentrancy -> Improper Control of a Resource
        "SWC-108": "CWE-440",  # State Variable Default Visibility -> Direct Request
        "SWC-109": "CWE-665",  # Uninitialized Storage Pointer -> Improper Initialization
        "SWC-110": "CWE-617",  # Assert Violation -> Reachable Assertion
        "SWC-111": "CWE-834",  # Use of Deprecated Solidity Functions -> Excessive Iteration
        "SWC-112": "CWE-477",  # Delegatecall to Untrusted Callee -> Use of Obsolete Function
        "SWC-113": "CWE-362",  # DoS with Failed Call -> Concurrent Execution
        "SWC-114": "CWE-829",  # Transaction Order Dependence -> Inclusion of Functionality from Untrusted Source
        "SWC-115": "CWE-707",  # Authorization through tx.origin -> Improper Neutralization
        "SWC-116": "CWE-672",  # Block values as a proxy for time -> Operation on a Resource after Expiration
        "SWC-118": "CWE-190",  # Incorrect Constructor Name -> Integer Overflow
        "SWC-119": "CWE-703",  # Shadowing State Variables -> Improper Check or Handling of Exceptional Conditions
        "SWC-120": "CWE-667",  # Weak Sources of Randomness -> Improper Locking
        "SWC-123": "CWE-20",   # Requirement Violation -> Improper Input Validation
        "SWC-124": "CWE-681",  # Write to Arbitrary Storage Location -> Incorrect Conversion between Numeric Types
        "SWC-125": "CWE-561",  # Incorrect Inheritance Order -> Dead Code
        "SWC-127": "CWE-705",  # Arbitrary Jump with Function Type Variable -> Incorrect Control Flow Scoping
        "SWC-128": "CWE-710",  # DoS With Block Gas Limit -> Improper Adherence to Coding Standards
        "110": "CWE-617",      # Assert Violation -> Reachable Assertion (fallback for numeric IDs)
    }

    # Process each file result
    for file_result in raw_data:
        if not isinstance(file_result, dict):
            continue

        source_path = file_result.get("source_path", "unknown")

        # Handle failed analysis
        if not file_result.get("success", True) or file_result.get("error"):
            error_msg = file_result.get("error", "Unknown Mythril error")
            logger.warning(f"Mythril analysis failed for {source_path}: {error_msg}")
            all_reports.append(ErrorReport(
                tool="Mythril",
                reason=f"Analysis failed for {source_path}: {error_msg}"
            ))
            continue

        # Process issues for this file
        issues = file_result.get("issues", [])
        logger.info(f"Processing {len(issues)} issues from {source_path}")

        for issue in issues:
            if not isinstance(issue, dict):
                continue

                        # Extract basic information from Mythril issue (new schema)
            title = issue.get("title", "Unknown vulnerability")
            description = issue.get("description", "No description available")
            severity = issue.get("severity", "Medium")
            swc_id = issue.get("swc-id", "")

            # Extract file and line information (new schema)
            filename = issue.get("filename", source_path)
            line_number = None

            # Handle different line number formats
            if "lineno" in issue:
                line_number = str(issue["lineno"])
            elif "line" in issue:
                line_number = str(issue["line"])

            # Clean file path relative to scan path
            if filename:
                file_path = clean_file_path(filename, scan_path)
                if file_path == filename:  # If cleaning didn't change it, use source_path
                    file_path = source_path
            else:
                file_path = source_path

            # Map SWC to CWE
            cwe = swc_to_cwe.get(swc_id, "CWE-664")  # Default CWE

            # Map severity
            severity_level = severity_mapping.get(severity, SeverityLevel.MEDIUM)

            # Enhanced description with additional context
            enhanced_description = f"{title}: {description}"
            if swc_id:
                enhanced_description += f" (SWC-ID: {swc_id})"

            # Add function information if available
            if issue.get("function"):
                enhanced_description += f" in function {issue.get('function')}"

            # Add contract information if available
            if issue.get("contract"):
                enhanced_description += f" [Contract: {issue.get('contract')}]"

            # Add code snippet if available
            if issue.get("code"):
                enhanced_description += f" | Code: {issue.get('code')}"

            # Add gas usage information if available
            if issue.get("max_gas_used") and issue.get("min_gas_used"):
                enhanced_description += f" | Gas: {issue.get('min_gas_used')}-{issue.get('max_gas_used')}"

            all_reports.append(Report(
                tool="Mythril",
                severity=severity_level,
                description=enhanced_description,
                file_path=file_path,
                line_number=line_number,
                language="solidity",
                cwe=cwe,
                information=swc_id,  # Add SWC ID as information
                report_type="code"
            ))

    logger.info(f"Mythril parsing completed: generated {len(all_reports)} reports")
    if all_reports:
        severity_counts = {}
        for report in all_reports:
            if hasattr(report, 'severity'):
                severity = report.severity.value if hasattr(report.severity, 'value') else str(report.severity)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        logger.info(f"Mythril report severity breakdown: {severity_counts}")

    return all_reports

def _parse_codeql_result(codeql_result: str | list[Report], language: str) -> list[Report]:
    """Parse CodeQL results and convert to Report objects."""
    all_reports = []

    # Handle new format - already a list of Report objects
    if isinstance(codeql_result, list):
        # Update language for all reports if needed
        for report in codeql_result:
            if hasattr(report, 'language') and report.language == "code":
                report.language = language
        return codeql_result

    # Handle legacy string format
    if not isinstance(codeql_result, str) or not codeql_result.strip():
        return all_reports

    # Check for common error patterns
    if "No CodeQL" in codeql_result or "Failed to" in codeql_result or "Error" in codeql_result:
        all_reports.append(ErrorReport(
            tool="CodeQL",
            reason=codeql_result.strip()
        ))
        return all_reports

    # Map CodeQL rule levels to severity and CWE
    level_to_severity_cwe = {
        "error": {"severity": SeverityLevel.HIGH, "cwe": "CWE-754"},      # Improper Check for Unusual or Exceptional Conditions
        "warning": {"severity": SeverityLevel.MEDIUM, "cwe": "CWE-703"}, # Improper Check or Handling of Exceptional Conditions
        "note": {"severity": SeverityLevel.LOW, "cwe": "CWE-1078"},      # Inappropriate Source Code Style or Formatting
        "info": {"severity": SeverityLevel.LOW, "cwe": "CWE-1078"},
    }

    # Parse the formatted string output
    lines = codeql_result.strip().split('\n')
    current_issue = None
    current_description = ""

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("Issue:"):
            # Save previous issue if exists
            if current_issue:
                all_reports.append(current_issue)

            # Start new issue
            current_description = line.replace("Issue:", "").strip()
            current_issue = None

        elif line.startswith("- File:"):
            if current_description:
                file_path = line.replace("- File:", "").strip()
                # Initialize report with current information
                current_issue = Report(
                    tool="CodeQL",
                    severity=SeverityLevel.MEDIUM,  # Default, will be updated if level found
                    description=current_description,
                    file_path=file_path,
                    language=language,
                    cwe="CWE-703",  # Default CWE
                    information=current_description,  # Add description as information for code issues
                    report_type="code"
                )

        elif line.startswith("Level:") and current_issue:
            level = line.replace("Level:", "").strip().lower()
            level_info = level_to_severity_cwe.get(level, {"severity": SeverityLevel.MEDIUM, "cwe": "CWE-703"})
            current_issue.severity = level_info["severity"]
            current_issue.cwe = level_info["cwe"]

        elif line.startswith("- Line:") and current_issue:
            line_num = line.replace("- Line:", "").strip()
            current_issue.line_number = line_num

        elif line.startswith("- From line") and current_issue:
            # Extract line range like "From line 10 to line 20"
            import re
            match = re.search(r'From line (\d+) to line (\d+)', line)
            if match:
                start_line, end_line = match.groups()
                current_issue.line_number = f"{start_line}-{end_line}"

    # Don't forget the last issue
    if current_issue:
        all_reports.append(current_issue)

    return all_reports

def _convert_trivy_results_to_reports(trivy_result: tuple[str, Any]) -> list[Report]:
    """Parse Trivy tuple results and convert to Report objects."""
    all_reports = []

    # Handle new format - already a list of Report objects
    if isinstance(trivy_result, list):
        return trivy_result

    # Handle legacy tuple format
    if not isinstance(trivy_result, tuple) or len(trivy_result) != 2:
        all_reports.append(ErrorReport(
            tool="Trivy",
            reason="Invalid Trivy result format"
        ))
        return all_reports

    vuln_count, trivy_output = trivy_result

    if isinstance(trivy_output, str) and "Error" in trivy_output:
        all_reports.append(ErrorReport(
            tool="Trivy",
            reason=trivy_output.strip()
        ))
        return all_reports

    if not isinstance(trivy_output, str) or not trivy_output.strip():
        return all_reports

    # Map Trivy severity to SeverityLevel
    severity_mapping = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
        "UNKNOWN": SeverityLevel.LOW
    }

    lines = trivy_output.strip().split('\n')
    current_file = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Total number of"):
            continue

        # Try to extract structured vulnerability information
        # Trivy format typically includes: Package, Version, Vulnerability ID, Severity, etc.

        # Look for vulnerability patterns in the line
        if any(keyword in line.lower() for keyword in ['cve-', 'vulnerability', 'package:', 'severity:']):
            # Enhanced parsing for vulnerability details
            parts = line.split()
            severity = SeverityLevel.MEDIUM  # Default
            cwe = "CWE-1104"  # Use of Unmaintained Third Party Components (default for dependency vulns)

            # Extract severity if present
            for severity_key in severity_mapping.keys():
                if severity_key in line.upper():
                    severity = severity_mapping[severity_key]
                    break

            # Extract CVE and map to CWE if possible
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', line, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0)
                # Common CVE to CWE mappings for dependencies
                cve_to_cwe = {
                    "injection": "CWE-74",     # Improper Neutralization of Special Elements
                    "xss": "CWE-79",           # Cross-site Scripting
                    "sql": "CWE-89",           # SQL Injection
                    "csrf": "CWE-352",         # Cross-Site Request Forgery
                    "auth": "CWE-287",         # Improper Authentication
                    "crypto": "CWE-327",       # Use of a Broken or Risky Cryptographic Algorithm
                    "deserial": "CWE-502",     # Deserialization of Untrusted Data
                    "path": "CWE-22",          # Path Traversal
                    "memory": "CWE-119",       # Improper Restriction of Operations within Bounds
                    "buffer": "CWE-120",       # Buffer Copy without Checking Size of Input
                }

                # Try to determine CWE from description
                line_lower = line.lower()
                for vuln_type, mapped_cwe in cve_to_cwe.items():
                    if vuln_type in line_lower:
                        cwe = mapped_cwe
                        break

                # Include CVE in description
                description = f"{cve_id}: {line}"
            else:
                description = line

            # Try to extract package name and version
            package_match = re.search(r'(\w+(?:[-_]\w+)*)\s+(\d+(?:\.\d+)*)', line)
            if package_match:
                package_name, version = package_match.groups()
                description = f"Package {package_name} v{version}: {description}"

            # Try to extract file information from context
            file_path = current_file if current_file else None

            all_reports.append(Report(
                tool="Trivy",
                severity=severity,
                description=description,
                file_path=file_path,
                cwe=cwe,
                information=f"{package_name}:{version}" if package_match else None,  # Add package information
                report_type="dependency" if package_match else "code"
            ))

        # Track current file context
        elif "Target:" in line or line.startswith("File name: ") or line.endswith(('.json', '.txt', '.yml', '.yaml', '.toml', '.lock')):
            current_file = line.replace("Target:", "").strip() if "Target:" in line else line.replace("File name: ", "").strip()

    return all_reports


def _parse_scan_results_to_reports(scan_results: dict[str, Any]) -> list[Report]:
    """
    Parse raw Semgrep JSON results and convert to Report objects.

    Args:
        scan_results: Dictionary containing raw Semgrep results

    Returns:
        List of Report objects
    """
    reports = []

    if "error" in scan_results:
        reports.append(ErrorReport(
            tool="Semgrep",
            reason=scan_results["error"]
        ))
        return reports

    if "raw_results" not in scan_results:
        reports.append(ErrorReport(
            tool="Semgrep",
            reason="No raw results found in Semgrep output"
        ))
        return reports

    raw_data = scan_results["raw_results"]
    scan_path = scan_results.get("scan_path", "")

    # Map Semgrep severity to SeverityLevel
    severity_mapping = {
        "ERROR": SeverityLevel.HIGH,
        "WARNING": SeverityLevel.MEDIUM,
        "INFO": SeverityLevel.LOW
    }

    results = raw_data.get("results", [])
    for result in results:
        if not isinstance(result, dict):
            continue

        # Extract basic information
        file_path = clean_file_path(result.get("path", ""), scan_path)

        # Extract line information
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", 0)
        if start_line == end_line:
            line_number = str(start_line) if start_line else None
        else:
            line_number = f"{start_line}-{end_line}" if start_line and end_line else None

        # Extract metadata
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Get CWE information
        cwe_list = metadata.get("cwe", [])
        if isinstance(cwe_list, list) and cwe_list:
            cwe = ", ".join(cwe_list)
        elif isinstance(cwe_list, str):
            cwe = cwe_list
        else:
            cwe = "n/a"

        # Get severity
        severity_str = extra.get("severity", "WARNING").upper()
        severity = severity_mapping.get(severity_str, SeverityLevel.MEDIUM)

        # Get confidence and other metadata
        confidence = metadata.get("confidence", "UNKNOWN")
        owasp_tags = metadata.get("owasp", [])
        category = metadata.get("category", "")

        # Enhanced description
        message = extra.get("message", result.get("message", "Unknown security issue"))
        description_parts = [message]

        if confidence != "UNKNOWN":
            description_parts.append(f"Confidence: {confidence}")
        if category:
            description_parts.append(f"Category: {category}")
        if owasp_tags:
            if isinstance(owasp_tags, list):
                description_parts.append(f"OWASP: {', '.join(owasp_tags)}")
            else:
                description_parts.append(f"OWASP: {owasp_tags}")

        enhanced_description = " | ".join(description_parts)

        # Determine language from file extension
        language = "code"
        if file_path:
            ext = file_path.split('.')[-1].lower()
            lang_mapping = {
                'py': 'python',
                'js': 'javascript',
                'ts': 'typescript',
                'java': 'java',
                'cpp': 'cpp',
                'c': 'c',
                'go': 'go',
                'rb': 'ruby',
                'php': 'php',
                'sol': 'solidity'
            }
            language = lang_mapping.get(ext, 'code')

        # Get rule ID
        rule_id = metadata.get("rule_id", "unknown_rule")

        reports.append(Report(
            tool="Semgrep",
            severity=severity,
            description=enhanced_description,
            file_path=file_path,
            line_number=line_number,
            language=language,
            cwe=cwe,
            information=rule_id,  # Add rule ID as information
            report_type="code"
        ))

    return reports

def _convert_secrets_to_reports(secrets_result) -> list[Report]:
    """
    Convert secrets scan results to Report objects.

    Args:
        secrets_result: Result from scan_secrets_with_gitleaks

    Returns:
        List of Report objects for secrets findings
    """
    reports = []

    if isinstance(secrets_result, dict) and "error" in secrets_result:
        reports.append(ErrorReport(
            tool="Secret Scanner",
            reason=secrets_result["error"]
        ))
        return reports

    if "raw_results" not in secrets_result:
        reports.append(ErrorReport(
            tool="Secret Scanner",
            reason="No raw results found in secret scanner output"
        ))
        return reports

    raw_data = secrets_result["raw_results"]
    scan_path = secrets_result.get("scan_path", "")

    # Map secret types to CWE identifiers
    secret_type_to_cwe = {
        "aws": "CWE-798",        # Use of Hard-coded Credentials
        "azure": "CWE-798",
        "gcp": "CWE-798",
        "github": "CWE-798",
        "gitlab": "CWE-798",
        "jwt": "CWE-798",
        "api": "CWE-798",
        "token": "CWE-798",
        "key": "CWE-798",
        "password": "CWE-259",   # Use of Hard-coded Password
        "secret": "CWE-798",
        "credential": "CWE-798",
        "cert": "CWE-321",       # Use of Hard-coded Cryptographic Key
        "private": "CWE-321",
        "rsa": "CWE-321",
        "ssh": "CWE-321",
    }

    if not isinstance(raw_data, list):
        return reports

    for item in raw_data:
        if not isinstance(item, dict):
            continue

        # Skip .env files unless they are templates or examples
        file_path = item.get("File", "")
        if ".env" in file_path and not any(x in file_path for x in [".env.template", ".env.example", ".env.sample"]):
            continue

        # Clean file path
        cleaned_file_path = clean_file_path(file_path, scan_path)

        # Extract line information
        start_line = item.get("StartLine", 0)
        end_line = item.get("EndLine", 0)
        if start_line == end_line:
            line_number = str(start_line) if start_line else None
        else:
            line_number = f"{start_line}-{end_line}" if start_line and end_line else None

        # Extract secret information
        description = item.get("Description", "Unknown secret type")
        secret_type = item.get("Secret", None) or None

        # Determine CWE based on secret type
        cwe = "CWE-798"  # Default: Use of Hard-coded Credentials
        for secret_keyword, mapped_cwe in secret_type_to_cwe.items():
            if secret_keyword.lower() in description.lower() or secret_keyword.lower() in secret_type.lower():
                cwe = mapped_cwe
                break

        # Enhanced description with context
        description_parts = [description]
        if secret_type is not None:
            description_parts.append(f"Value: {secret_type}")

        enhanced_description = ", ".join(description_parts)

        # Determine severity based on secret type
        high_severity_types = ["aws", "azure", "gcp", "github", "gitlab", "private", "rsa", "ssh"]
        severity = SeverityLevel.CRITICAL if any(hst in description.lower() or hst in secret_type.lower() for hst in high_severity_types) else SeverityLevel.HIGH

        reports.append(Report(
            tool="Secret Scanner",
            severity=severity,
            description=enhanced_description,
            file_path=cleaned_file_path,
            line_number=line_number,
            cwe=cwe,
            information=secret_type,  # Add secret type as information
            report_type="secret"
        ))

    return reports

