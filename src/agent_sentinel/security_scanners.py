"""
Security scanners for the Agent Sentinel.
"""

import os
import json
import logging
import re
import asyncio

from typing import Any
from .utils import run_command, detect_project_languages, patch_foundry_config
import json_repair
from collections import defaultdict
from .git_utils import clone_repo
from .codeql_utils import run_codeql_scanner
from .trivy_utils import scan_with_trivy
from openai import AsyncOpenAI

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
        additional_info: dict[str, Any] | None = None
    ):
        """
        Initialize a security report.

        Args:
            tool: The security tool that found the issue (e.g., 'Slither', 'Semgrep', 'CodeQL')
            severity: The severity level (e.g., 'HIGH', 'MEDIUM', 'LOW', 'CRITICAL')
            description: Description of the security issue
            file_path: Optional path to the file where the issue was found
            line_number: Optional line number(s) where the issue was found
            additional_info: Optional dictionary containing additional metadata
        """
        self.tool = tool
        self.severity = severity.upper() if severity else "UNKNOWN"
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.additional_info = additional_info or {}

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
        return f"Report(tool='{self.tool}', severity='{self.severity}', description='{self.description}', file_path='{self.file_path}', line_number='{self.line_number}')"

    def to_dict(self) -> dict[str, Any]:
        """Convert the report to a dictionary."""
        return {
            "tool": self.tool,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "additional_info": self.additional_info
        }


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


async def summarize_with_llm(content: str) -> str:
    """
    Summarize content using LLM.

    Args:
        content: The content to summarize

    Returns:
        Summarized content
    """
    try:
        client = AsyncOpenAI(
            base_url=os.getenv("LLM_BASE_URL"),
            api_key=os.getenv("LLM_API_KEY")
        )

        response = await client.chat.completions.create(
            model=os.getenv("LLM_MODEL_ID", "gpt-3.5-turbo"),
            messages=[
                {
                    "role": "system",
                    "content": """You are a security analyst. Summarize the security scan results, keeping the most critical findings and their details.

IMPORTANT: You must maintain the exact format for each line:
- For Slither: "Slither [SEVERITY] ContractName: Description"
- For Secret Scanner: "Secret Scanner [HIGH] in filepath: Description"
- For Semgrep: "Semgrep [MEDIUM] in filepath line X: Description (CWE: Y)"
- For CodeQL: "CodeQL [MEDIUM]: Description"
- For Trivy: "Trivy [MEDIUM]: Description"

Group similar issues and keep only the most critical ones. Do not change the line format structure."""
                },
                {
                    "role": "user",
                    "content": f"Summarize these security scan results:\n\n{content}"
                }
            ],
            max_tokens=2000,
            temperature=0.1
        )
        # Remove the section between <think> and </think>
        result = re.sub(r'<think>.*?</think>', '', response.choices[0].message.content, flags=re.DOTALL)
        return result

    except Exception as e:
        logger.error(f"Failed to summarize with LLM: {str(e)}")
        return content  # Return original content if summarization fails


async def comprehensive_security_scan(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Perform a comprehensive security scan of a GitHub repository.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing security findings
    """
    try:
        # Clone the repository
        repo_path = clone_repo(repo_url)
        scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path

        # Detect languages
        languages = detect_project_languages(scan_path)

        # Initialize results list to collect all issues
        all_reports = []

        # Run Solidity-specific scans
        if "solidity" in languages:
            logger.info("Running Solidity scans...")
            slither_result = scan_solidity_slither(scan_path)
            if "error" not in slither_result:
                for severity in ["high", "medium", "low"]:
                    if severity in slither_result and slither_result[severity]:
                        for contract, vulns in slither_result[severity].items():
                            for vuln in vulns:
                                all_reports.append(Report(
                                    tool="Slither",
                                    severity=severity.upper(),
                                    description=vuln.get('advisory', 'N/A'),
                                    additional_info={"contract": contract}
                                ))
            elif slither_result.get("error"):
                all_reports.append(Report(
                    tool="Slither",
                    severity="ERROR",
                    description=f"Slither scan error: {slither_result['error']}",
                    additional_info={"error_type": "scan_failure"}
                ))

        # Run general security scans
        logger.info("Running general security scans (secrets, semgrep)...")

        # Secrets scan
        secrets_result = scan_secrets_with_gitleaks(scan_path)
        all_reports.extend(_convert_secrets_to_reports(secrets_result))

        # Semgrep scan
        semgrep_result = scan_semgrep(scan_path)
        all_reports.extend(_parse_scan_results_to_reports(semgrep_result))

        logger.info("Finish running general security scans (secrets, semgrep)")

        # CodeQL Analysis
        logger.info("Running CodeQL Analysis...")
        for language in languages:
            codeql_result = run_codeql_scanner(scan_path, language)
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
                            additional_info={"language": language}
                        ))
            logger.info(f"CodeQL analysis completed for {language}")
        logger.info("Finish running CodeQL Analysis")

        # Trivy scan
        logger.info("Running Trivy scan...")
        trivy_result = scan_with_trivy(scan_path)
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
        logger.info("Finish running Trivy scan")

        # # Check if result is too long and needs summarization
        # result_string = '\n'.join(str(report) for report in all_reports)

        # while len(result_string) > 40000:
        #     logger.info(f"Result string length ({len(result_string)}) exceeds 40000, summarizing with LLM...")

        #     # Split reports into chunks of 100
        #     chunks = []
        #     for i in range(0, len(all_reports), 100):
        #         chunk_reports = all_reports[i:i+100]
        #         chunk_string = '\n'.join(str(report) for report in chunk_reports)
        #         chunks.append(chunk_string)

        #     # Summarize each chunk
        #     summarized_chunks = []
        #     for i, chunk in enumerate(chunks):
        #         logger.info(f"Summarizing chunk {i+1}/{len(chunks)}...")
        #         summarized = await summarize_with_llm(chunk)
        #         summarized_chunks.append(summarized)

        #     # Parse summarized chunks back into Report objects
        #     all_reports = []
        #     for summarized_chunk in summarized_chunks:
        #         chunk_reports = _parse_scan_results_to_reports(summarized_chunk)
        #         all_reports.extend(chunk_reports)

        #     # Recalculate string length for next iteration
        #     result_string = '\n'.join(str(report) for report in all_reports)
        #     logger.info(f"Summarization complete. New length: {len(result_string)}")

        logger.info(f"Security scan completed with {len(all_reports)} findings")
        return all_reports

    except Exception as e:
        error_msg = f"Failed to perform security scan: {str(e)}"
        logger.error(error_msg)
        return [Report(
            tool="System",
            severity="ERROR",
            description=error_msg,
            additional_info={"error_type": "scan_failure"}
        )]


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
            description=description,
            additional_info={"contract": contract}
        )

    # Pattern: Secret in file.py: Description - secret
    secret_match = re.match(r'^Secret in ([^:]+): ([^-]+) - (.+)$', line)
    if secret_match:
        file_path, description, secret = secret_match.groups()
        return Report(
            tool="Secret Scanner",
            severity="HIGH",  # Secrets are typically high severity
            description=description.strip(),
            file_path=file_path.strip(),
            additional_info={"secret_type": secret.strip()}
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
            additional_info={"cwe": cwe.strip()}
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
            additional_info={"cwe": cwe.strip()}
        )

    # Pattern: CodeQL [language] Issue: Description
    codeql_match = re.match(r'^CodeQL \[([^\]]+)\] Issue: (.+)$', line)
    if codeql_match:
        language, description = codeql_match.groups()
        return Report(
            tool="CodeQL",
            severity="MEDIUM",  # Default severity for CodeQL
            description=description.strip(),
            additional_info={"language": language.strip()}
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
            description=line,
            additional_info={"raw_line": line}
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
        reports.append(Report(
            tool="Secret Scanner",
            severity="ERROR",
            description=f"Secret scan error: {secrets_result['error']}",
            additional_info={"error_type": "scan_failure"}
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
                    description=description,
                    file_path=current_file,
                    additional_info={"secret_type": secret}
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
        reports.append(Report(
            tool="Dependency Scanner",
            severity="ERROR",
            description=f"Dependency scan error: {dep_results['error']}",
            additional_info={"error_type": "scan_failure"}
        ))
        return reports

    # Process results by language
    for language, results in dep_results.items():
        if isinstance(results, dict) and "error" in results:
            reports.append(Report(
                tool="Dependency Scanner",
                severity="ERROR",
                description=f"{language} dependency scan error: {results['error']}",
                additional_info={"language": language, "error_type": "scan_failure"}
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
                                        reports.append(Report(
                                            tool="Dependency Scanner",
                                            severity=severity.upper(),
                                            description=f"{package}: {vuln.get('advisory', 'N/A')}",
                                            file_path=req_file,
                                            additional_info={
                                                "language": language,
                                                "package": package,
                                                "cve": vuln.get('cve', 'N/A'),
                                                "url": vuln.get('url', 'N/A')
                                            }
                                        ))
                    elif isinstance(file_results, dict) and "error" in file_results:
                        reports.append(Report(
                            tool="Dependency Scanner",
                            severity="ERROR",
                            description=f"Error scanning {req_file}: {file_results['error']}",
                            file_path=req_file,
                            additional_info={"language": language, "error_type": "scan_failure"}
                        ))

        elif language == "solidity":
            # Handle slither results
            if isinstance(results, dict) and "error" not in results:
                for severity in ["high", "medium", "low"]:
                    if severity in results and results[severity]:
                        for contract, vulns in results[severity].items():
                            for vuln in vulns:
                                reports.append(Report(
                                    tool="Slither",
                                    severity=severity.upper(),
                                    description=vuln.get('advisory', 'N/A'),
                                    additional_info={
                                        "language": language,
                                        "contract": contract,
                                        "impact": vuln.get('url', 'N/A')
                                    }
                                ))
            elif isinstance(results, dict) and "error" in results:
                reports.append(Report(
                    tool="Slither",
                    severity="ERROR",
                    description=f"Slither scan error: {results['error']}",
                    additional_info={"language": language, "error_type": "scan_failure"}
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
        reports.append(Report(
            tool="Code Quality Scanner",
            severity="ERROR",
            description=f"Code quality scan error: {code_results['error']}",
            additional_info={"error_type": "scan_failure"}
        ))
        return reports

    # Process Bandit results
    if "bandit" in code_results:
        bandit_results = code_results["bandit"]
        if isinstance(bandit_results, dict) and "error" not in bandit_results:
            if "results" in bandit_results:
                for issue in bandit_results["results"]:
                    if isinstance(issue, dict):
                        reports.append(Report(
                            tool="Bandit",
                            severity=issue.get("issue_severity", "MEDIUM").upper(),
                            description=f"{issue.get('test_name', 'Unknown')}: {issue.get('issue_text', 'N/A')}",
                            file_path=issue.get("filename"),
                            line_number=str(issue.get("line_number", "")),
                            additional_info={
                                "confidence": issue.get("issue_confidence", "N/A"),
                                "test_id": issue.get("test_id", "N/A")
                            }
                        ))
        elif isinstance(bandit_results, dict) and "error" in bandit_results:
            reports.append(Report(
                tool="Bandit",
                severity="ERROR",
                description=f"Bandit scan error: {bandit_results['error']}",
                additional_info={"error_type": "scan_failure"}
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
                            additional_info={"cwe": cwe}
                        ))
        elif isinstance(semgrep_results, dict) and "error" in semgrep_results:
            reports.append(Report(
                tool="Semgrep",
                severity="ERROR",
                description=f"Semgrep scan error: {semgrep_results['error']}",
                additional_info={"error_type": "scan_failure"}
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
                                additional_info={"language": language}
                            ))
                elif isinstance(results, dict) and "error" in results:
                    reports.append(Report(
                        tool="CodeQL",
                        severity="ERROR",
                        description=f"CodeQL scan error for {language}: {results['error']}",
                        additional_info={"language": language, "error_type": "scan_failure"}
                    ))

    return reports


def scan_for_secrets(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Scan a GitHub repository for exposed secrets and sensitive information.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing secret findings
    """
    try:
        repo_path = clone_repo(repo_url)
        scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path
        secrets_result = scan_secrets_with_gitleaks(scan_path)
        return _convert_secrets_to_reports(secrets_result)
    except Exception as e:
        return [Report(
            tool="Secret Scanner",
            severity="ERROR",
            description=f"Failed to scan for secrets: {str(e)}",
            additional_info={"error_type": "scan_failure"}
        )]


def scan_dependencies_vulnerabilities(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Scan a GitHub repository for vulnerable dependencies.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing dependency vulnerability findings
    """
    try:
        logger.info(f"Cloning repository: {repo_url}")
        repo_path = clone_repo(repo_url)
        scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path
        logger.info(f"Scanning path: {scan_path}")
        languages = detect_project_languages(scan_path)
        logger.info(f"Detected languages: {languages}")

        results = {}

        # Python dependencies
        if "python" in languages:
            results["python"] = scan_dependencies_safety(scan_path)
            logger.info("Python dependencies scanned with Safety")
        if "javascript" in languages:
            results["javascript"] = scan_npm_audit(scan_path)
            logger.info("JavaScript dependencies scanned with npm audit")
        if "solidity" in languages:
            results["solidity"] = scan_solidity_slither(scan_path)
            logger.info("Solidity dependencies scanned with Slither")

        return _convert_dependency_results_to_reports(results)

    except Exception as e:
        return [Report(
            tool="Dependency Scanner",
            severity="ERROR",
            description=f"Failed to scan dependencies: {str(e)}",
            additional_info={"error_type": "scan_failure"}
        )]


def scan_code_quality_security(repo_url: str, subfolder: str = "") -> list[Report]:
    """
    Perform static code analysis for security issues and code quality.

    Args:
        repo_url: The URL of the Git repository to scan
        subfolder: Optional path to a specific subfolder within the repository

    Returns:
        A list of Report objects containing code quality and security findings
    """
    try:
        logger.info(f"Cloning repository: {repo_url}")
        repo_path = clone_repo(repo_url)
        logger.info(f"Cloned repository: {repo_path}")
        scan_path = os.path.join(repo_path, subfolder) if subfolder else repo_path
        logger.info(f"Scanning path: {scan_path}")
        languages = detect_project_languages(scan_path)
        logger.info(f"Detected languages: {languages}")
        results = {}

        # Python code analysis
        if 'python' in languages:
            results["bandit"] = scan_python_bandit(scan_path)
            logger.info("Python code analysis completed")
        # Multi-language analysis
        results["semgrep"] = scan_semgrep(scan_path)
        logger.info("Semgrep analysis completed")
        logger.info("Running CodeQL Analysis...")
        results["codeql"] = {}
        for language in languages:
            results["codeql"][language] = run_codeql_scanner(scan_path, language)
            logger.info(f"CodeQL analysis completed for {language}")
        logger.info("Finish running CodeQL Analysis")
        logger.info("CodeQL Analysis completed")

        return _convert_code_quality_results_to_reports(results)

    except Exception as e:
        return [Report(
            tool="Code Quality Scanner",
            severity="ERROR",
            description=f"Failed to perform code analysis: {str(e)}",
            additional_info={"error_type": "scan_failure"}
        )]


async def generate_security_report(repo_url: str) -> str:
    """
    Generate a comprehensive security report for a GitHub repository.

    Args:
        repo_url: The URL of the Git repository to analyze

    Returns:
        A formatted security report with findings and recommendations
    """
    try:
        # Get comprehensive scan results (list of Report objects)
        scan_results = await comprehensive_security_scan(repo_url)

        # Check if we have error reports
        if len(scan_results) == 1 and scan_results[0].tool == "System" and scan_results[0].severity == "ERROR":
            return f"Error generating report: {scan_results[0].description}"

        # Convert reports to formatted string
        findings_text = ""
        for report in scan_results:
            findings_text += f"{report}\n"

        # Add header and recommendations to the scan results
        report = f"""# Security Analysis Report

{findings_text}

## Recommendations
1. Address all critical and high-severity issues immediately
2. Implement secret scanning in CI/CD pipeline
3. Enable dependency vulnerability scanning
4. Regular security audits and code reviews
5. Follow security best practices for detected languages
"""

        return report

    except Exception as e:
        return f"Error generating security report: {str(e)}"
