import json_repair
import json
import logging
import subprocess
import os

from .models import Report, SeverityLevel, ErrorReport
import tempfile

logger = logging.getLogger(__name__)

# Mapping Trivy severity to SeverityLevel enum
SEVERITY_MAPPING = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "UNKNOWN": SeverityLevel.LOW
}

def _extract_dependency_information(vulnerability: dict) -> str | None:
    """
    Extract package:version information from vulnerability data.

    Args:
        vulnerability: Vulnerability dictionary from Trivy results

    Returns:
        Package:version string or None if not extractable
    """
    pkg_name = vulnerability.get("PkgName", "")
    installed_version = vulnerability.get("InstalledVersion", "")

    if pkg_name and installed_version:
        return f"{pkg_name}:{installed_version}"
    elif pkg_name:
        return pkg_name

    return None


def _run_trivy_scan(scan_path: str) -> str | None:
    """Run Trivy scan and return the report."""
    # Determine output path based on whether scan_path is a file or directory
    if os.path.isfile(scan_path):
        result_path = f"{os.path.dirname(scan_path)}/trivy-report.json"
    else:
        result_path = f"{scan_path}/trivy-report.json"
    command = f"trivy fs --format json -o {result_path} {scan_path}"
    logger.info(f"Running Trivy scan with command: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    logger.info(f"Trivy scan result: {result.stdout}")
    if not os.path.exists(result_path):
        raise FileNotFoundError("Error running Trivy scan")
    return result_path


def _parse_trivy_report(report_path: str) -> list[Report]:
    """Parse Trivy report and return a list of Report objects."""
    with open(report_path) as f:
        data = json_repair.load(f)

    reports = []

    for result in data.get("Results", []):
        file_name = result["Target"]

        # Process vulnerabilities
        for vulnerability in result.get("Vulnerabilities", []):
            # Get severity
            severity_str = vulnerability.get("Severity", "UNKNOWN").upper()
            severity = SEVERITY_MAPPING.get(severity_str, SeverityLevel.MEDIUM)

            # Get CWE mapping
            cwe = "CWE-1104"  # Use of Unmaintained Third Party Components (default for dependency vulns)

            # Try to determine CWE from vulnerability details
            vuln_title = vulnerability.get("Title", "").lower()
            vuln_description = vulnerability.get("Description", "").lower()
            combined_text = f"{vuln_title} {vuln_description}"

            # Enhanced description with context
            description_parts = []

            # Add vulnerability details
            vuln_id = vulnerability.get("VulnerabilityID", "")
            if vuln_id:
                description_parts.append(f"ID: {vuln_id}")

            # Add package information
            pkg_name = vulnerability.get("PkgName", "")
            if pkg_name:
                description_parts.append(f"Package: {pkg_name}")

            installed_version = vulnerability.get("InstalledVersion", "")
            if installed_version:
                description_parts.append(f"Installed version: {installed_version}")

            fixed_version = vulnerability.get("FixedVersion", "")
            if fixed_version:
                description_parts.append(f"Fixed in: {fixed_version}")


            title = vulnerability.get("Title", "")
            if title:
                description_parts.append(f"Title: {title}")

            # Add CWE information if available
            cwe_ids = vulnerability.get("CweIDs", [])
            if cwe_ids:
                cwe = ", ".join(cwe_ids)
                # description_parts.append(f"CWE: {cwe}")

            # Combine all parts
            if description_parts:
                description = ", ".join(description_parts)
            else:
                description = ""

            # Determine language from file extension
            language = "code"
            if file_name:
                if file_name.endswith(('.json', '.yml', '.yaml', '.toml')):
                    language = "config"
                elif file_name.endswith(('.lock', '.txt')):
                    language = "dependency"
                else:
                    ext = file_name.split('.')[-1].lower() if '.' in file_name else ""
                    lang_mapping = {
                        'py': 'python',
                        'js': 'javascript',
                        'ts': 'typescript',
                        'java': 'java',
                        'go': 'go',
                        'rb': 'ruby',
                        'php': 'php'
                    }
                    language = lang_mapping.get(ext, 'dependency')

            report = Report(
                tool="Trivy",
                severity=severity,
                description=description,
                file_path=file_name if file_name else None,
                line_number=None,  # Trivy typically doesn't provide line numbers
                language=language,
                cwe=cwe,
                cve=vuln_id,
                information=_extract_dependency_information(vuln),  # Add dependency information
                report_type="dependency" if language == "dependency" else "code"
            )

            reports.append(report)

        # Process secrets if present
        for secret in result.get("Secrets", []):
            severity = SeverityLevel.HIGH  # Secrets are typically high severity
            cwe = "CWE-798"  # Use of Hard-coded Credentials

            description_parts = []

            secret_title = secret.get("Title", "")
            if secret_title:
                description_parts.append(f"Secret: {secret_title}")

            rule_id = secret.get("RuleID", "")
            if rule_id:
                description_parts.append(f"Rule: {rule_id}")

            # Extract secret value for information field (masked appropriately)
            secret_value = None
            match = secret.get("Match", "")
            if match:
                # Mask the secret for security but keep it in information field
                if len(match) > 8:
                    secret_value = match[:4] + "*" * (len(match) - 8) + match[-4:]
                    masked_match = secret_value  # Use the same masked version for description
                else:
                    secret_value = "*" * len(match)
                    masked_match = secret_value
                description_parts.append(f"Pattern: {masked_match}")

            # Get line information
            start_line = secret.get("StartLine", 0)
            end_line = secret.get("EndLine", 0)

            line_number = None
            if start_line > 0:
                if start_line == end_line:
                    line_number = str(start_line)
                else:
                    line_number = f"{start_line}-{end_line}"

            description = " | ".join(description_parts) if description_parts else "Unknown secret"

            report = Report(
                tool="Trivy",
                severity=severity,
                description=description,
                file_path=file_name if file_name else None,
                line_number=line_number,
                language="code",
                cwe=cwe,
                information=secret_value,  # Add secret information
                report_type="secret"
            )

            reports.append(report)

    return reports


def scan_with_trivy(scan_path: str) -> list[Report]:
    """Scan the path with Trivy and return a list of Report objects."""
    try:
        result_path = _run_trivy_scan(scan_path)
        if result_path is None:
            return [ErrorReport(
                tool="Trivy",
                reason="Error while running Trivy scan"
            )]
        return _parse_trivy_report(result_path)
    except FileNotFoundError:
        return [ErrorReport(
            tool="Trivy",
            reason="Trivy scan failed - output file not found"
        )]
    except Exception as e:
        return [ErrorReport(
            tool="Trivy",
            reason=f"Trivy scan failed: {str(e)}"
        )]
