"""
Security scanners for the Agent Sentinel.
"""

import os
import json
import logging
import re
import asyncio

from typing import Any, AsyncGenerator
from .utils import run_command, detect_project_languages, patch_foundry_config, sync2async
import json_repair
from collections import defaultdict
from .git_utils import clone_repo
from .codeql_utils import run_codeql_scanner
from .trivy_utils import scan_with_trivy

logger = logging.getLogger(__name__)


class Report:
    """
    Represents a security finding from various security scanning tools.
    """

    def __init__(
        self,
        tool: str,
        severity: str,
        description: str,
        file_path: str | None = None,
        line_number: str | None = None,
        language: str = "code",
        cwe: str = "n/a"
    ):
        """
        Initialize a security report.

        Args:
            tool: The security tool that found the issue (e.g., 'Slither', 'Semgrep', 'CodeQL')
            severity: The severity level (e.g., 'HIGH', 'MEDIUM', 'LOW', 'CRITICAL')
            description: Description of the security issue
            file_path: Optional path to the file where the issue was found
            line_number: Optional line number(s) where the issue was found
            language: Programming language (default: "code")
            cwe: Common Weakness Enumeration identifier (default: "n/a")
        """
        self.tool = tool
        self.severity = severity.upper() if severity else "UNKNOWN"
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.language = language
        self.cwe = cwe

    def __str__(self) -> str:
        """String representation of the report."""
        parts = [f"{self.tool} [{self.severity}]"]

        if self.file_path:
            parts.append(f"in {self.file_path}")

        if self.line_number:
            parts.append(f"line {self.line_number}")

        parts.append(f": {self.description}")

        return " ".join(parts)

    def __repr__(self) -> str:
        """Detailed representation of the report."""
        return f"Report(tool='{self.tool}', severity='{self.severity}', description='{self.description}', file_path='{self.file_path}', line_number='{self.line_number}', language='{self.language}', cwe='{self.cwe}')"

    def to_dict(self) -> dict[str, Any]:
        """Convert the report to a dictionary."""
        return {
            "tool": self.tool,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "language": self.language,
            "cwe": self.cwe
        }


class ErrorReport(Report):
    """
    Represents an error that occurred during security scanning.
    """

    def __init__(
        self,
        tool: str,
        reason: str
    ):
        """
        Initialize an error report.

        Args:
            tool: The security tool that encountered the error
            reason: Specific reason for the error
        """
        super().__init__(
            tool=tool,
            severity="ERROR",
            description=f"{tool} error: {reason}",
            file_path=None,
            line_number=None,
            language="code",
            cwe="n/a"
        )
        self.reason = reason

    def __repr__(self) -> str:
        """Detailed representation of the error report."""
        return f"ErrorReport(tool='{self.tool}', severity='{self.severity}', description='{self.description}', reason='{self.reason}', file_path='{self.file_path}', line_number='{self.line_number}', language='{self.language}', cwe='{self.cwe}')"

    def to_dict(self) -> dict[str, Any]:
        """Convert the error report to a dictionary."""
        result = super().to_dict()
        result["reason"] = self.reason
        return result


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

    logger.info(f"package.json found at: {package_json_path}")
    scan_path = os.path.dirname(package_json_path)
    logger.info(f"scan_path: {scan_path}")

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

    # 4. Convert to Safety-style JSON and analyze
    try:
        with open(slither_output, "r") as f:
            slither_data = json_repair.load(f)

        detectors = slither_data.get("results", {}).get("detectors", [])
        fake_safety_data = {
            "ignored_vulnerabilities": []
        }

        for item in detectors:
            contract = item.get("elements", [{}])[0].get("name", "UnknownContract")
            advisory = item.get("description", "No description")
            impact = item.get("impact", "No impact info")
            confidence = item.get("confidence", "Unknown confidence")

            fake_safety_data["ignored_vulnerabilities"].append({
                "package_name": contract,
                "CVE": "N/A",
                "advisory": advisory,
                "more_info_url": f"impact: {impact}, confidence: {confidence}"
            })

        # Save to temp file and analyze
        tmp_json_path = os.path.join(scan_path, "slither_safety_format.json")
        with open(tmp_json_path, "w") as f:
            json.dump(fake_safety_data, f, indent=2)

        analyzed = analyze_dependency_report(tmp_json_path)
        os.remove(tmp_json_path)

        return analyzed

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


# TODO: Remove this function because GitLeaks does not check the Git history
def scan_secrets_with_gitleaks(scan_path: str) -> str:
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

    data = defaultdict(list)
    with open(output_path, "r") as f:
        json_data = json_repair.load(f)
    for item in json_data:
        # Skip .env files
        if (
            ".env" in item["File"]
            and (
                not ".env.template" in item["File"]
                or not ".env.example" in item["File"]
            )
        ):
            continue
        data[clean_file_path(item["File"], scan_path)].append({
            "description": item["Description"],
            "line": f"{item['StartLine']} - {item['EndLine']}",
            "match": item["Match"],
            "secret": item["Secret"],
        })

    string_result = ""
    for file, issues in data.items():
        string_result += f"\nFile: {file}\n"
        for issue in issues:
            string_result += f"Line: {issue['line']}\n"
            string_result += f"Secret: {issue['secret']}\n"
            string_result += f"Description: {issue['description']}\n"
            # string_result += f"Match: {issue['match']}\n"
            string_result += f"\n"

    return string_result


def cwe_priority(item):
    severity_order = {"ERROR": 0, "WARNING": 2}
    confidence_order = {"HIGH": 1, "MEDIUM": 3, "LOW": 4}
    severity = item[1]["severity"]
    confidence = item[1]["confidence"]
    return (
        severity_order.get(severity, 99),
        confidence_order.get(confidence, 99)
    )


def scan_semgrep(scan_path: str) -> str:
    """Run Semgrep for multi-language security analysis in a given path (repo or subfolder)."""
    cmd = ["semgrep", "--config=auto", "--json", scan_path]
    result = run_command(cmd, cwd=scan_path)

    if result["success"]:
        try:
            json_result = json_repair.loads(result["stdout"])
            compact_results = [
                {
                    "path": clean_file_path(individual_result["path"], scan_path),
                    "cwe": individual_result.get("extra", {}).get("metadata", {}).get("cwe", "UNKNOWN"),
                    "message": individual_result.get("extra", {}).get("message", "UNKNOWN"),
                    "owasp": individual_result.get("extra", {}).get("metadata", {}).get("owasp", "UNKNOWN"),
                    "confidence": individual_result.get("extra", {}).get("metadata", {}).get("confidence", "UNKNOWN"),
                    "severity": individual_result.get("extra", {}).get("severity", "UNKNOWN"),
                    "start": individual_result.get("start", "No line number"),
                    "end": individual_result.get("end", "No line number"),
                }
                for individual_result in json_result["results"]
            ]
            grouped_results = defaultdict(list)
            for result in compact_results:
                grouped_results[result["path"]].append(result)

            summary = {}
            for filepath, issues in grouped_results.items():
                file_summary = defaultdict(
                    lambda: {
                        "severity": None,
                        "confidence": None,
                        "owasp_tags": set(),
                        "occurrences": [],
                    },
                )

                for issue in issues:
                    for cwe in issue.get("cwe", ["UNKNOWN"]):
                        data = file_summary[cwe]
                        data["severity"] = issue["severity"]
                        data["confidence"] = issue["confidence"]
                        data["owasp_tags"].update(issue.get("owasp", []))
                        data["occurrences"].append(
                            {
                                "line": f'{issue["start"]["line"]} - {issue["end"]["line"]}' if str(issue["start"]["line"]) != str(issue["end"]["line"]) else str(issue["start"]["line"]),
                                "message": issue["message"],
                            },
                    )

                for cwe in file_summary:
                    file_summary[cwe]["owasp_tags"] = list(file_summary[cwe]["owasp_tags"])
                summary[filepath] = dict(sorted(file_summary.items(), key=cwe_priority))

            summary_str = ""
            for filepath, cwe_dict in summary.items():
                summary_str += f"\n📄 File: {filepath}\n"
                for cwe, data in cwe_dict.items():
                    summary_str += f"  🔐 CWE: {cwe}\n"
                    summary_str += f"     • Severity: {data['severity']}\n"
                    summary_str += f"     • Confidence: {data['confidence']}\n"
                    summary_str += f"     • OWASP Tags: {', '.join(sorted(data['owasp_tags']))}\n"
                    summary_str += f"     • Occurrences:\n"
                    for occ in sorted(data["occurrences"], key=lambda x: x["line"]):
                        summary_str += f"         - Line {occ['line']}: {occ['message']}\n"

            return summary_str


        except json.JSONDecodeError:
            return {"error": "Failed to parse Semgrep output"}
    else:
        return {"error": result["stderr"]}

async def a_stupid_wrapper(identity: str, awaitable_task: asyncio.Awaitable) -> tuple[str, Any | Exception]:
    try:
        result = await awaitable_task
        return identity, result
    except Exception as e:
        return identity, e
    
def _parse_slither_result(slither_result: dict[str, Any]) -> list[Report]:
    all_reports = []
    
    if "error" not in slither_result:
        for severity in ["high", "medium", "low"]:
            if severity in slither_result and slither_result[severity]:
                for contract, vulns in slither_result[severity].items():
                    for vuln in vulns:
                        all_reports.append(Report(
                            tool="Slither",
                            severity=severity.upper(),
                            description=f"Contract {contract}: {vuln.get('advisory', 'N/A')}",
                            language="solidity"
                        ))
    elif slither_result.get("error"):
        all_reports.append(ErrorReport(
            tool="Slither",
            reason="scan_failure"
        ))
    
    return all_reports

def _parse_codeql_result(codeql_result: str, language: str) -> list[Report]:
    all_reports = []

    if isinstance(codeql_result, str) and codeql_result.strip():
        # Parse CodeQL results to extract individual issues
        lines = codeql_result.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith("Issue:"):
                all_reports.append(Report(
                    tool="CodeQL",
                    severity="MEDIUM",
                    description=line.replace("Issue:", "").strip(),
                    language=language
                ))
                
    return all_reports

def _convert_dependency_results_to_reports(trivy_result: tuple[str, Any]) -> list[Report]:
    all_reports = []
    
    if len(trivy_result) == 2 and isinstance(trivy_result[1], str):
        trivy_output = trivy_result[1].strip()

        if trivy_output:
            lines = trivy_output.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith("Total number of"):
                    all_reports.append(Report(
                        tool="Trivy",
                        severity="MEDIUM",
                        description=line
                    ))

    return all_reports

async def comprehensive_security_scan(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Perform a comprehensive security scan of a GitHub repository.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing security findings
    """
    # Clone the repository
    repo_path = await sync2async(clone_repo)(repo_url)
    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path

    # Detect languages
    languages = await sync2async(detect_project_languages)(scan_path)

    # Initialize results list to collect all issues
    all_reports = []

    # Run Solidity-specific scans
    if "solidity" in languages:
        logger.info("Running Solidity scans...")
        slither_result = await sync2async(scan_solidity_slither)(scan_path)
        all_reports.extend(_parse_slither_result(slither_result))

    # Run general security scans
    logger.info("Running general security scans (secrets, semgrep)...")

    # Secrets scan
    secrets_result = await sync2async(scan_secrets_with_gitleaks)(scan_path)
    all_reports.extend(_convert_secrets_to_reports(secrets_result))

    # Semgrep scan
    semgrep_result = await sync2async(scan_semgrep)(scan_path)
    all_reports.extend(_parse_scan_results_to_reports(semgrep_result))

    logger.info("Finish running general security scans (secrets, semgrep)")

    # CodeQL Analysis
    logger.info("Running CodeQL Analysis...")
    for language in languages:
        codeql_result = await sync2async(run_codeql_scanner)(scan_path, language)
        logger.info(f"CodeQL analysis completed for {language}")
        all_reports.extend(_parse_codeql_result(codeql_result, language))

    logger.info("Finish running CodeQL Analysis")

    # Trivy scan
    logger.info("Running Trivy scan...")
    trivy_result = await sync2async(scan_with_trivy)(scan_path)
    all_reports.extend(_convert_dependency_results_to_reports(trivy_result))

    logger.info("Finish running Trivy scan")
    return all_reports


def _parse_scan_results_to_reports(scan_results: str) -> list[Report]:
    """
    Parse the scan results string and convert to Report objects.

    Args:
        scan_results: String containing all scan results

    Returns:
        List of Report objects
    """
    reports = []

    if not scan_results or not scan_results.strip():
        return reports

    lines = scan_results.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        report = _parse_single_line_to_report(line)
        if report:
            reports.append(report)

    return reports


def _parse_single_line_to_report(line: str) -> Report | None:
    """
    Parse a single line from scan results into a Report object.

    Args:
        line: A single line from the scan results

    Returns:
        Report object or None if line couldn't be parsed
    """
    # Pattern: Slither [SEVERITY] ContractName: Description
    slither_match = re.match(r'^Slither \[(\w+)\] ([^:]+): (.+)$', line)
    if slither_match:
        severity, contract, description = slither_match.groups()
        return Report(
            tool="Slither",
            severity=severity,
            description=f"Contract {contract}: {description}",
            language="solidity"
        )

    # Pattern: Secret in file.py: Description - secret
    secret_match = re.match(r'^Secret in ([^:]+): ([^-]+) - (.+)$', line)
    if secret_match:
        file_path, description, secret = secret_match.groups()
        return Report(
            tool="Secret Scanner",
            severity="HIGH",  # Secrets are typically high severity
            description=f"{description.strip()} (Type: {secret.strip()})",
            file_path=file_path.strip()
        )

    # Pattern: Secret Scanner [HIGH] in filepath: Description
    secret_scanner_match = re.match(r'^Secret Scanner \[(\w+)\] in ([^:]+): (.+)$', line)
    if secret_scanner_match:
        severity, file_path, description = secret_scanner_match.groups()
        return Report(
            tool="Secret Scanner",
            severity=severity,
            description=description.strip(),
            file_path=file_path.strip()
        )

    # Pattern: Semgrep file.py Line 10: Message (CWE: CWE-123)
    # Pattern: Semgrep file.py Line 10-15: Message (CWE: CWE-123)
    semgrep_match = re.match(r'^Semgrep ([^\s]+) Line ([^:]+): ([^(]+) \(CWE: ([^)]+)\)$', line)
    if semgrep_match:
        file_path, line_num, message, cwe = semgrep_match.groups()
        return Report(
            tool="Semgrep",
            severity="MEDIUM",  # Default severity for Semgrep
            description=message.strip(),
            file_path=file_path.strip(),
            line_number=line_num.strip(),
            cwe=cwe.strip()
        )

    # Pattern: Semgrep [MEDIUM] in filepath line X: Description (CWE: Y)
    semgrep_new_match = re.match(r'^Semgrep \[(\w+)\] in ([^\s]+) line ([^:]+): ([^(]+) \(CWE: ([^)]+)\)$', line)
    if semgrep_new_match:
        severity, file_path, line_num, message, cwe = semgrep_new_match.groups()
        return Report(
            tool="Semgrep",
            severity=severity,
            description=message.strip(),
            file_path=file_path.strip(),
            line_number=line_num.strip(),
            cwe=cwe.strip()
        )

    # Pattern: CodeQL [language] Issue: Description
    codeql_match = re.match(r'^CodeQL \[([^\]]+)\] Issue: (.+)$', line)
    if codeql_match:
        language, description = codeql_match.groups()
        return Report(
            tool="CodeQL",
            severity="MEDIUM",  # Default severity for CodeQL
            description=description.strip(),
            language=language.strip()
        )

    # Pattern: CodeQL [MEDIUM]: Description
    codeql_new_match = re.match(r'^CodeQL \[(\w+)\]: (.+)$', line)
    if codeql_new_match:
        severity, description = codeql_new_match.groups()
        return Report(
            tool="CodeQL",
            severity=severity,
            description=description.strip()
        )

    # Pattern: Trivy: Description
    trivy_match = re.match(r'^Trivy: (.+)$', line)
    if trivy_match:
        description = trivy_match.group(1)
        return Report(
            tool="Trivy",
            severity="MEDIUM",  # Default severity for Trivy
            description=description.strip()
        )

    # Pattern: Trivy [MEDIUM]: Description
    trivy_new_match = re.match(r'^Trivy \[(\w+)\]: (.+)$', line)
    if trivy_new_match:
        severity, description = trivy_new_match.groups()
        return Report(
            tool="Trivy",
            severity=severity,
            description=description.strip()
        )

    # Generic pattern for any unmatched lines that might contain security info
    if any(keyword in line.lower() for keyword in ['vulnerability', 'security', 'error', 'warning', 'critical']):
        return Report(
            tool="Unknown",
            severity="UNKNOWN",
            description=line
        )

    # Return None for lines that don't match any security-related patterns
    return None


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
            reason="scan_failure"
        ))
        return reports

    if isinstance(secrets_result, str) and secrets_result.strip():
        # Parse the string result to extract individual issues
        lines = secrets_result.strip().split('\n')
        current_file = ""
        secret = ""
        for line in lines:
            line = line.strip()
            if line.startswith("File:"):
                current_file = line.replace("File:", "").strip()
            elif line.startswith("Secret:"):
                secret = line.replace("Secret:", "").strip()
            elif line.startswith("Description:"):
                description = line.replace("Description:", "").strip()
                reports.append(Report(
                    tool="Secret Scanner",
                    severity="HIGH",
                    description=f"{description} (Type: {secret})",
                    file_path=current_file
                ))

    return reports


def _convert_dependency_results_to_reports(dep_results: dict[str, Any]) -> list[Report]:
    """
    Convert dependency vulnerability scan results to Report objects.

    Args:
        dep_results: Results from dependency scanning

    Returns:
        List of Report objects for dependency findings
    """
    reports = []

    if "error" in dep_results:
        reports.append(ErrorReport(
            tool="Dependency Scanner",
            reason="scan_failure"
        ))
        return reports

    # Process results by language
    for language, results in dep_results.items():
        if isinstance(results, dict) and "error" in results:
            reports.append(ErrorReport(
                tool="Dependency Scanner",
                reason="scan_failure"
            ))
            continue

        # Handle different result formats
        if language in ["python", "javascript"]:
            # Handle safety/npm audit results
            if isinstance(results, dict):
                for req_file, file_results in results.items():
                    if isinstance(file_results, dict) and "error" not in file_results:
                        for severity in ["high", "medium", "low"]:
                            if severity in file_results and file_results[severity]:
                                for package, vulns in file_results[severity].items():
                                    for vuln in vulns:
                                        cve_info = f" (CVE: {vuln.get('cve', 'N/A')})" if vuln.get('cve', 'N/A') != 'N/A' else ""
                                        reports.append(Report(
                                            tool="Dependency Scanner",
                                            severity=severity.upper(),
                                            description=f"{package}: {vuln.get('advisory', 'N/A')}{cve_info}",
                                            file_path=req_file,
                                            language=language,
                                            cwe=vuln.get('cwe', 'N/A')
                                        ))
                    elif isinstance(file_results, dict) and "error" in file_results:
                        reports.append(ErrorReport(
                            tool="Dependency Scanner",
                            reason="scan_failure"
                        ))

        elif language == "solidity":
            # Handle slither results
            if isinstance(results, dict) and "error" not in results:
                for severity in ["high", "medium", "low"]:
                    if severity in results and results[severity]:
                        for contract, vulns in results[severity].items():
                            for vuln in vulns:
                                impact_info = f" (Impact: {vuln.get('url', 'N/A')})" if vuln.get('url', 'N/A') != 'N/A' else ""
                                reports.append(Report(
                                    tool="Slither",
                                    severity=severity.upper(),
                                    description=f"Contract {contract}: {vuln.get('advisory', 'N/A')}{impact_info}",
                                    language=language
                                ))
            elif isinstance(results, dict) and "error" in results:
                reports.append(ErrorReport(
                    tool="Slither",
                    reason="scan_failure"
                ))

    return reports


def _convert_code_quality_results_to_reports(code_results: dict[str, Any]) -> list[Report]:
    """
    Convert code quality scan results to Report objects.

    Args:
        code_results: Results from code quality scanning

    Returns:
        List of Report objects for code quality findings
    """
    reports = []

    if "error" in code_results:
        reports.append(ErrorReport(
            tool="Code Quality Scanner",
            reason="scan_failure"
        ))
        return reports

    # Process Bandit results
    if "bandit" in code_results:
        bandit_results = code_results["bandit"]
        if isinstance(bandit_results, dict) and "error" not in bandit_results:
            if "results" in bandit_results:
                for issue in bandit_results["results"]:
                    if isinstance(issue, dict):
                        confidence_info = f" (Confidence: {issue.get('issue_confidence', 'N/A')})"
                        reports.append(Report(
                            tool="Bandit",
                            severity=issue.get("issue_severity", "MEDIUM").upper(),
                            description=f"{issue.get('test_name', 'Unknown')}: {issue.get('issue_text', 'N/A')}{confidence_info}",
                            file_path=issue.get("filename"),
                            line_number=str(issue.get("line_number", "")),
                            language="python"
                        ))
        elif isinstance(bandit_results, dict) and "error" in bandit_results:
            reports.append(ErrorReport(
                tool="Bandit",
                reason="scan_failure"
            ))

    # Process Semgrep results
    if "semgrep" in code_results:
        semgrep_results = code_results["semgrep"]
        if isinstance(semgrep_results, str) and semgrep_results.strip():
            # Parse the string result to extract individual issues
            lines = semgrep_results.strip().split('\n')
            current_file = ""
            cwe = ""
            for line in lines:
                line = line.strip()
                if line.startswith('📄 File:'):
                    current_file = line.replace('📄 File:', '').strip()
                elif line.startswith('🔐 CWE:'):
                    cwe = line.replace('🔐 CWE:', '').strip()
                elif 'Line ' in line and ':' in line:
                    # Extract line info and message
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        line_info = parts[0].strip().replace('- ', '')
                        message = parts[1].strip()
                        reports.append(Report(
                            tool="Semgrep",
                            severity="MEDIUM",
                            description=message,
                            file_path=current_file,
                            line_number=line_info.replace('Line ', ''),
                            cwe=cwe if cwe else "n/a"
                        ))
        elif isinstance(semgrep_results, dict) and "error" in semgrep_results:
            reports.append(ErrorReport(
                tool="Semgrep",
                reason="scan_failure"
            ))

    # Process CodeQL results
    if "codeql" in code_results:
        codeql_results = code_results["codeql"]
        if isinstance(codeql_results, dict):
            for language, results in codeql_results.items():
                if isinstance(results, str) and results.strip():
                    lines = results.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if line.startswith("Issue:"):
                            reports.append(Report(
                                tool="CodeQL",
                                severity="MEDIUM",
                                description=line.replace("Issue:", "").strip(),
                                language=language
                            ))
                elif isinstance(results, dict) and "error" in results:
                    reports.append(ErrorReport(
                        tool="CodeQL",
                        reason="scan_failure"
                    ))

    return reports


async def scan_for_secrets(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Scan a GitHub repository for exposed secrets and sensitive information.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing secret findings
    """
    repo_path = await sync2async(clone_repo)(repo_url)
    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path
    secrets_result = await sync2async(scan_secrets_with_gitleaks)(scan_path)
    return _convert_secrets_to_reports(secrets_result)

async def scan_dependencies_vulnerabilities(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Scan a GitHub repository for vulnerable dependencies.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing dependency vulnerability findings
    """

    logger.info(f"Cloning repository: {repo_url}")
    repo_path = await sync2async(clone_repo)(repo_url)

    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path
    logger.info(f"Scanning path: {scan_path}")

    languages = await sync2async(detect_project_languages)(scan_path)
    logger.info(f"Detected languages: {languages}")

    results = {}

    # Python dependencies
    if "python" in languages:
        results["python"] = await sync2async(scan_dependencies_safety)(scan_path)
        logger.info("Python dependencies scanned with Safety")
    
    if "javascript" in languages:
        results["javascript"] = await sync2async(scan_npm_audit)(scan_path)
        logger.info("JavaScript dependencies scanned with npm audit")
    
    if "solidity" in languages:
        results["solidity"] = await sync2async(scan_solidity_slither)(scan_path)
        logger.info("Solidity dependencies scanned with Slither")

    return _convert_dependency_results_to_reports(results)


async def scan_code_quality_security(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Perform static code analysis for security issues and code quality.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing code quality and security findings
    """

    logger.info(f"Cloning repository: {repo_url}")

    repo_path = await sync2async(clone_repo)(repo_url)
    logger.info(f"Cloned repository: {repo_path}")

    scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path
    logger.info(f"Scanning path: {scan_path}")

    languages = await sync2async(detect_project_languages)(scan_path)
    logger.info(f"Detected languages: {languages}")
    
    async_scan_python_bandit = sync2async(scan_python_bandit)
    async_scan_semgrep = sync2async(scan_semgrep)
    async_run_codeql_scanner = sync2async(run_codeql_scanner)

    results = {}

    # Python code analysis
    if 'python' in languages:
        results["bandit"] = await async_scan_python_bandit(scan_path)
        logger.info("Python code analysis completed")

    # Multi-language analysis
    results["semgrep"] = await async_scan_semgrep(scan_path)
    logger.info("Semgrep analysis completed")
    logger.info("Running CodeQL Analysis...")
    results["codeql"] = {}

    for language in languages:
        results["codeql"][language] = await async_run_codeql_scanner(scan_path, language)
        logger.info(f"CodeQL analysis completed for {language}")

    logger.info("Finish running CodeQL Analysis")
    logger.info("CodeQL Analysis completed")

    return _convert_code_quality_results_to_reports(results)