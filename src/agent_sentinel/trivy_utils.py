import json_repair
import json
import logging
from collections import defaultdict
import subprocess
import os

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _get_vulnerability_severity_order(severity: str) -> int:
    """Get the order of the vulnerability severity."""
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }
    return severity_order.get(severity.upper(), 4)


def _convert_vulnerability_to_str(vulnerability: dict) -> str:
    """Convert vulnerability to string."""
    return (
        f"File name: {vulnerability['file_name']}\n"
        f"Package name: {vulnerability.get('PkgName', '')}\n"
        f"Description: {vulnerability.get('Title', '')}\n"
        f"Installed version: {vulnerability.get('InstalledVersion', '')}\n"
        f"Fixed version: {vulnerability.get('FixedVersion', '')}\n"
        f"CWE: {', '.join(vulnerability.get('CweIDs', []))}\n"
    )


def _run_trivy_scan(scan_path: str) -> str | None:
    """Run Trivy scan and return the report."""
    result_path = f"{scan_path}/trivy-report.json"
    command = f"trivy fs --format json -o {result_path} {scan_path}"
    logger.debug(f"Running Trivy scan with command: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    logger.debug(f"Trivy scan result: {result.stdout}")
    if not os.path.exists(result_path):
        raise FileNotFoundError("Error running Trivy scan")
    return result_path


def _parse_trivy_report(report_path: str) -> tuple[int, str]:
    """Parse Trivy report and return a string with the vulnerabilities and secrets."""
    with open(report_path) as f:
        data = json_repair.load(f)

    vulnerabilities_by_severity = defaultdict(list)

    str_result = ""
    for result in data["Results"]:
        file_name = result["Target"]
        for vulnerability in result.get("Vulnerabilities", []):
            vulnerability["file_name"] = file_name
            vulnerabilities_by_severity[vulnerability.get("Severity", "UNKNOWN")].append(vulnerability)

    sorted_severities = sorted(vulnerabilities_by_severity.keys(), key=lambda x: _get_vulnerability_severity_order(x))
    vulnerabilities_num = 0
    high_severity_vulnerabilities_num = 0
    critical_severity_vulnerabilities_num = 0
    medium_severity_vulnerabilities_num = 0
    low_severity_vulnerabilities_num = 0
    unknown_severity_vulnerabilities_num = 0

    for severity in sorted_severities:
        vulnerabilities_num += len(vulnerabilities_by_severity[severity])
        if severity == "HIGH":
            high_severity_vulnerabilities_num += len(vulnerabilities_by_severity[severity])
        elif severity == "CRITICAL":
            critical_severity_vulnerabilities_num += len(vulnerabilities_by_severity[severity])
        elif severity == "MEDIUM":
            medium_severity_vulnerabilities_num += len(vulnerabilities_by_severity[severity])
        elif severity == "LOW":
            low_severity_vulnerabilities_num += len(vulnerabilities_by_severity[severity])
        else:
            unknown_severity_vulnerabilities_num += len(vulnerabilities_by_severity[severity])

    str_result += f"Total number of vulnerabilities: {vulnerabilities_num}\n"
    str_result += f"Total number of critical severity vulnerabilities: {critical_severity_vulnerabilities_num}\n"
    str_result += f"Total number of high severity vulnerabilities: {high_severity_vulnerabilities_num}\n"
    str_result += f"Total number of medium severity vulnerabilities: {medium_severity_vulnerabilities_num}\n"
    str_result += f"Total number of low severity vulnerabilities: {low_severity_vulnerabilities_num}\n"
    for severity in sorted_severities:
        vulnerabilities = vulnerabilities_by_severity[severity]
        for vulnerability in vulnerabilities:
            str_result += _convert_vulnerability_to_str(vulnerability)
            str_result += "\n"
    return vulnerabilities_num, str_result


def scan_with_trivy(scan_path: str) -> tuple[int, str]:
    """Scan the path with Trivy and return the report."""
    result_path = _run_trivy_scan(scan_path)
    if result_path is None:
        return 0, "Error while running Trivy scan. Skipping Trivy scan."
    return _parse_trivy_report(result_path)


# if __name__ == "__main__":
#     str_result = scan_with_trivy("/Users/macbookpro/Projects/eternal-ai")
#     with open("/Users/macbookpro/Projects/agent-sentinel/.tmp/trivy-report.txt", "w") as f:
#         f.write(str_result)
