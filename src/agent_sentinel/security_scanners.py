"""
Security scanners for the Agent Sentinel.
"""

import os
import json
import logging
import re
import asyncio
from enum import StrEnum

from typing import Any, AsyncGenerator, Awaitable
from .utils import run_command, detect_project_languages, patch_foundry_config, sync2async
import json_repair
from collections import defaultdict
from .git_utils import clone_repo
from .codeql_utils import run_codeql_scanner
from .trivy_utils import scan_with_trivy
from .models import cwe_mapping, Report, ErrorReport, SeverityLevel

logger = logging.getLogger(__name__)

# Mapping of tool identities to their post-processing functions
TOOL_POST_PROCESSORS = {
    "slither": lambda result: _parse_slither_result(result),
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
                        cwe=cwe
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
                                    cwe=vuln.get('cwe', 'N/A')
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
                            cwe=vuln.get('cwe', 'n/a')
                        ))
    else:
        reports.append(ErrorReport(
            tool="npm audit",
            reason="scan_failure"
        ))
    return reports

async def comprehensive_security_scan_concurrent(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Perform a comprehensive security scan of a GitHub repository concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning

    Yields:
        Report or ErrorReport objects as scans complete
    """
    # Clone the repository and checkout branch if specified
    repo_path = await sync2async(clone_repo)(repo_url, branch_name)
    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path

    # Detect languages
    languages = await sync2async(detect_project_languages)(scan_path)

    # Prepare concurrent tasks
    tasks = []

    # Run Solidity-specific scans
    if "solidity" in languages:
        tasks.append(a_stupid_wrapper("slither", sync2async(scan_solidity_slither)(scan_path)))

    # Schedule general security scans
    tasks.append(a_stupid_wrapper("secrets", sync2async(scan_secrets_with_gitleaks)(scan_path)))
    tasks.append(a_stupid_wrapper("semgrep", sync2async(scan_semgrep)(scan_path)))

    # Schedule CodeQL analysis for each language
    for language in languages:
        tasks.append(a_stupid_wrapper(f"codeql_{language}", sync2async(run_codeql_scanner)(scan_path, language)))

    # Schedule Trivy scan
    tasks.append(a_stupid_wrapper("trivy", sync2async(scan_with_trivy)(scan_path)))

    # Process completed tasks as they finish
    for task in asyncio.as_completed(tasks):
        identity, result = await task

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
                        yield report
            except Exception as e:
                logger.error(f"Error processing {identity} results: {e}")
                yield ErrorReport(tool=identity, reason=f"post_processing_error: {str(e)}")
        else:
            logger.warning(f"No post-processor found for {identity}")
            yield ErrorReport(tool=identity, reason="no_post_processor")

async def scan_for_secrets_concurrent(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Scan a GitHub repository for exposed secrets and sensitive information concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning

    Yields:
        Report or ErrorReport objects containing secret findings
    """
    repo_path = await sync2async(clone_repo)(repo_url, branch_name)
    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path

    # Create single task for secrets scanning
    task = a_stupid_wrapper("secrets", sync2async(scan_secrets_with_gitleaks)(scan_path))

    identity, result = await task

    post_processor = TOOL_POST_PROCESSORS.get(identity)
    if post_processor:
        try:
            if isinstance(result, Exception):
                yield ErrorReport(tool=identity, reason=str(result))
            else:
                reports = post_processor(result)
                for report in reports:
                    yield report
        except Exception as e:
            logger.error(f"Error processing {identity} results: {e}")
            yield ErrorReport(tool=identity, reason=f"post_processing_error: {str(e)}")
    else:
        yield ErrorReport(tool=identity, reason="no_post_processor")

async def scan_dependencies_vulnerabilities_concurrent(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Scan a GitHub repository for vulnerable dependencies concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning

    Yields:
        Report or ErrorReport objects containing dependency vulnerability findings
    """
    repo_path = await sync2async(clone_repo)(repo_url, branch_name)

    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path

    languages = await sync2async(detect_project_languages)(scan_path)

    # Prepare concurrent tasks
    tasks = []

    # Python dependencies
    if "python" in languages:
        tasks.append(a_stupid_wrapper("safety", sync2async(scan_dependencies_safety)(scan_path)))

    if "javascript" in languages:
        tasks.append(a_stupid_wrapper("npm_audit", sync2async(scan_npm_audit)(scan_path)))

    if "solidity" in languages:
        tasks.append(a_stupid_wrapper("slither", sync2async(scan_solidity_slither)(scan_path)))

    # Process completed tasks as they finish
    for task in asyncio.as_completed(tasks):
        identity, result = await task

        post_processor = TOOL_POST_PROCESSORS.get(identity)
        if post_processor:
            try:
                if isinstance(result, Exception):
                    yield ErrorReport(tool=identity, reason=str(result))
                else:
                    reports = post_processor(result)
                    for report in reports:
                        yield report
            except Exception as e:
                logger.error(f"Error processing {identity} results: {e}")
                yield ErrorReport(tool=identity, reason=f"post_processing_error: {str(e)}")
        else:
            logger.warning(f"No post-processor found for {identity}")
            yield ErrorReport(tool=identity, reason="no_post_processor")

async def scan_code_quality_security_concurrent(repo_url: str, subfolder: str = "", branch_name: str = None) -> AsyncGenerator[Report | ErrorReport, None]:
    """
    Perform static code analysis for security issues and code quality concurrently.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository
        branch_name: Optional branch name to checkout before scanning

    Yields:
        Report or ErrorReport objects containing code quality and security findings
    """

    repo_path = await sync2async(clone_repo)(repo_url, branch_name)

    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path

    languages = await sync2async(detect_project_languages)(scan_path)

    # Prepare concurrent tasks
    tasks = []

    # Python code analysis
    if 'python' in languages:
        tasks.append(a_stupid_wrapper("bandit", sync2async(scan_python_bandit)(scan_path)))

    # Multi-language analysis
    tasks.append(a_stupid_wrapper("semgrep", sync2async(scan_semgrep)(scan_path)))

    # CodeQL analysis for each language
    for language in languages:
        tasks.append(a_stupid_wrapper(f"codeql_{language}", sync2async(run_codeql_scanner)(scan_path, language)))

    # Process completed tasks as they finish
    for task in asyncio.as_completed(tasks):
        identity, result = await task

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


def analyze_dependency_report(json_path: str) -> dict:
    """
    Analyze a Safety CLI JSON report and return a dictionary of vulnerabilities
    grouped by priority level ("high", "medium", "low") and package.

    Args:
        json_path (str): Path to the Safety report JSON file.

    Returns:
        dict: Dictionary with priority levels as keys, each containing
            a dict of {package: [vulnerabilities]}.
    """

    def classify_priority(advisory: str, cve: str | None) -> str:
        advisory = advisory.lower() if advisory else ""
        if any(
            kw in advisory
            for kw in [
                "rce",
                "remote code execution",
                "credential",
                "authentication",
                "proxy",
                "data leak",
                "response splitting",
            ]
        ):
            return "High"
        elif any(
            kw in advisory
            for kw in [
                "denial of service",
                "dos",
                "log injection",
                "race condition",
                "crlf",
            ]
        ):
            return "Medium"
        else:
            return "Low"

    # Load and parse the JSON file
    with open(json_path, "r") as f:
        data = json_repair.load(f)

    ignored_vulns = data.get("ignored_vulnerabilities", [])

    grouped = {
        "High": defaultdict(list),
        "Medium": defaultdict(list),
        "Low": defaultdict(list)
    }

    # Classify and group
    for vuln in ignored_vulns:
        package = vuln.get("package_name")
        cve = vuln.get("CVE")
        advisory = vuln.get("advisory")
        url = vuln.get("more_info_url")
        severity = classify_priority(advisory, cve)

        grouped[severity][package].append({
            "cve": cve,
            "advisory": advisory,
            "url": url
        })

    # Convert to returnable format with lowercase keys
    return {
        "high": dict(grouped["High"]),
        "medium": dict(grouped["Medium"]),
        "low": dict(grouped["Low"])
    }


def scan_python_bandit(scan_path: str) -> dict[str, Any]:
    """Run Bandit security scanner for Python code in a given path (repo or subfolder)."""
    cmd = ["bandit", "-r", scan_path, "-f", "json", "-ll"]
    result = run_command(cmd, cwd=scan_path)

    if result["success"]:
        try:
            bandit_result = json_repair.loads(result["stdout"])
            # Clean file paths in the bandit results
            if isinstance(bandit_result, dict) and "results" in bandit_result:
                for issue in bandit_result["results"]:
                    if isinstance(issue, dict) and "filename" in issue:
                        issue["filename"] = clean_file_path(issue["filename"], scan_path)
            return bandit_result
        except json.JSONDecodeError:
            return {"error": "Failed to parse Bandit output"}
    else:
        return {"error": result["stderr"]}


def scan_npm_audit(scan_path: str) -> dict[str, Any]:
    """Run npm audit and format output to be compatible with analyze_dependency_report()."""
    package_json_path = None
    for root, dirs, files in os.walk(scan_path):
        for file in files:
            if file == "package.json":
                package_json_path = os.path.join(root, file)
                break
    if not package_json_path:
        return {"error": "No package.json found"}

    scan_path = os.path.dirname(package_json_path)

    install_result = run_command(["npm", "install", "--ignore-scripts"], cwd=scan_path)
    if not install_result["success"]:
        return {"error": f"npm install failed: {install_result['stderr']}"}

    audit_result = run_command(["npm", "audit", "--json"], cwd=scan_path)
    if not audit_result["success"]:
        return {"error": audit_result["stderr"]}

    try:
        audit_data = json_repair.loads(audit_result["stdout"])
        advisories = audit_data.get("advisories", {})

        # Convert to Safety-like structure
        converted = {
            "ignored_vulnerabilities": []
        }

        for advisory in advisories.values():
            converted["ignored_vulnerabilities"].append({
                "package_name": advisory.get("module_name"),
                "CVE": advisory.get("cves", ["N/A"])[0],
                "advisory": advisory.get("title"),
                "more_info_url": advisory.get("url", "N/A")
            })

        # Write to temp file
        temp_path = os.path.join(scan_path, "npm_safety_format.json")
        with open(temp_path, "w") as f:
            json.dump(converted, f, indent=4)

        # Reuse analyze_dependency_report
        analyzed = analyze_dependency_report(temp_path)

        # Clean up
        os.remove(temp_path)
        return analyzed

    except json.JSONDecodeError:
        return {"error": "Failed to parse npm audit output"}


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


def scan_dependencies_safety(scan_path: str) -> dict[str, Any]:
    """Run Safety scanner for Python dependencies in a given path (repo or subfolder)."""
    req_files = []
    for root, dirs, files in os.walk(scan_path):
        for file in files:
            if (
                file in ['requirements.txt', 'Pipfile', 'pyproject.toml']
                or re.match(r'requirements-.*\.txt', file)
                or re.match(r'requirements_.*\.txt', file)
            ):
                req_files.append(os.path.join(root, file))

    if not req_files:
        return {"error": "No Python dependency files found"}

    results = {}
    for req_file in req_files:
        if req_file.endswith('.txt'):
            cmd = ["safety", "check", "-r", req_file, "--json"]
        else:
            cmd = ["safety", "check", "--json"]

        result = run_command(cmd, cwd=os.path.dirname(req_file))
        try:
            cleaned_req_file = clean_file_path(req_file, scan_path)
            results[cleaned_req_file] = json_repair.loads(result["stdout"]) if result["success"] else {"error": result["stderr"]}
            with open(os.path.join(scan_path, "safety_output.json"), "w") as f:
                json.dump(results[cleaned_req_file], f, indent=4)
            results[cleaned_req_file] = analyze_dependency_report(os.path.join(scan_path, "safety_output.json"))
            os.remove(os.path.join(scan_path, "safety_output.json"))
        except FileNotFoundError:
            cleaned_req_file = clean_file_path(req_file, scan_path)
            results[cleaned_req_file] = {"error": "Safety output file not found"}
        except json.JSONDecodeError:
            cleaned_req_file = clean_file_path(req_file, scan_path)
            results[cleaned_req_file] = {"error": "Failed to parse Safety output"}
            return results

    return results


# TODO: Integrate this function
# TruffleHog is good, but it requires the scan_path to be a valid repository
# and it takes a long time to run.
def scan_secrets_trufflehog(scan_path: str) -> dict[str, Any]:
    """Run TruffleHog for secret detection in a given path (repo or subfolder)."""
    cmd = ["trufflehog", "filesystem", "--json", scan_path]
    result = run_command(cmd, cwd=scan_path)

    if result["success"]:
        secrets = []
        for line in result["stdout"].split('\n'):
            if line.strip():
                try:
                    secret = json_repair.loads(line)
                    # Clean file paths in the secret data
                    if isinstance(secret, dict) and "SourceMetadata" in secret:
                        source_meta = secret["SourceMetadata"]
                        if isinstance(source_meta, dict) and "Data" in source_meta:
                            data = source_meta["Data"]
                            if isinstance(data, dict) and "Filesystem" in data:
                                filesystem = data["Filesystem"]
                                if isinstance(filesystem, dict) and "file" in filesystem:
                                    filesystem["file"] = clean_file_path(filesystem["file"], scan_path)
                    secrets.append(secret)
                except json.JSONDecodeError:
                    continue
        return {"secrets": secrets}
    else:
        return {"error": result["stderr"]}


def scan_secrets_with_gitleaks(scan_path: str) -> dict[str, Any]:
    """Run Gitleaks for secret detection in a given path (repo or subfolder)."""
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
    run_command(cmd, cwd=scan_path)

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
    """Run Semgrep for multi-language security analysis in a given path (repo or subfolder)."""
    cmd = ["semgrep", "--config=auto", "--json", scan_path]
    result = run_command(cmd, cwd=scan_path)

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

async def a_stupid_wrapper(identity: str, awaitable_task: Awaitable) -> tuple[str, Any | Exception]:
    try:
        result = await awaitable_task
        return identity, result
    except Exception as e:
        return identity, e

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
            cwe=cwe_info["cwe"]
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
                cwe="CWE-1100"  # Insufficient Isolation or Compartmentalization
            ))

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
                    cwe="CWE-703"  # Default CWE
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
                cwe=cwe
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

        reports.append(Report(
            tool="Semgrep",
            severity=severity,
            description=enhanced_description,
            file_path=file_path,
            line_number=line_number,
            language=language,
            cwe=cwe
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
        secret_type = item.get("Secret", "unknown")
        match_text = item.get("Match", "")

        # Determine CWE based on secret type
        cwe = "CWE-798"  # Default: Use of Hard-coded Credentials
        for secret_keyword, mapped_cwe in secret_type_to_cwe.items():
            if secret_keyword.lower() in description.lower() or secret_keyword.lower() in secret_type.lower():
                cwe = mapped_cwe
                break

        # Enhanced description with context
        description_parts = [description]
        if secret_type and secret_type != "unknown":
            description_parts.append(f"Type: {secret_type}")
        if match_text and len(match_text) > 10:  # Only include if meaningful
            # Mask most of the secret for security
            masked_match = match_text[:4] + "*" * (len(match_text) - 8) + match_text[-4:] if len(match_text) > 8 else "*" * len(match_text)
            description_parts.append(f"Pattern: {masked_match}")

        enhanced_description = " | ".join(description_parts)

        # Determine severity based on secret type
        high_severity_types = ["aws", "azure", "gcp", "github", "gitlab", "private", "rsa", "ssh"]
        severity = SeverityLevel.CRITICAL if any(hst in description.lower() or hst in secret_type.lower() for hst in high_severity_types) else SeverityLevel.HIGH

        reports.append(Report(
            tool="Secret Scanner",
            severity=severity,
            description=enhanced_description,
            file_path=cleaned_file_path,
            line_number=line_number,
            cwe=cwe
        ))

    return reports

