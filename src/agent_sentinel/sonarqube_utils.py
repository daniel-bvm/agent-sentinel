import subprocess
import time
import requests
import re
import uuid
import os
import json
import json_repair
import logging
from pathlib import Path

from .models import Report, SeverityLevel, ErrorReport
logger = logging.getLogger(__name__)

SONARQUBE_SHELL_SCRIPT = "/opt/sonarqube/bin/linux-x86-64/sonar.sh"
SONAR_SCANNER_CONFIG_FILE = "/opt/sonar-scanner/conf/sonar-scanner.properties"
SONARQUBE_URL = "http://localhost:9000"
SONARQUBE_USER = "admin"
SONARQUBE_PASSWORD = "admin"
SONAR_SCANNER_OUTPUT_DIR = "/tmp/sonar-scanner-output"

# Mapping SonarQube severity to SeverityLevel enum
SONARQUBE_SEVERITY_MAPPING = {
    "BLOCKER": SeverityLevel.CRITICAL,
    "CRITICAL": SeverityLevel.HIGH,
    "MAJOR": SeverityLevel.MEDIUM,
    "MINOR": SeverityLevel.LOW,
    "INFO": SeverityLevel.LOW
}


def _run_with_live_output(cmd):
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1,
    )

    # Print output line-by-line as it becomes available
    for line in process.stdout:
        logger.info(line)

    process.stdout.close()
    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, cmd)


def _write_sonar_scanner_config(
    config_file: str = SONAR_SCANNER_CONFIG_FILE,
) -> None:
    """Write the SonarQube config file."""
    with open(config_file, "w") as f:
        # f.write(f"sonar.host.url={SONARQUBE_URL}\n")
        f.write(f"sonar.login={SONARQUBE_USER}\n")
        f.write(f"sonar.password={SONARQUBE_PASSWORD}\n")


def start_sonarqube():
    # Run sh SONARQUBE_SHELL_SCRIPT start
    command = f"sh {SONARQUBE_SHELL_SCRIPT} start"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def stop_sonarqube():
    # Run sh SONARQUBE_SHELL_SCRIPT stop
    command = f"sh {SONARQUBE_SHELL_SCRIPT} stop"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def _wait_for_sonarqube_to_start():
    # Wait for 10 seconds
    time.sleep(10)
    # Check if the sonarqube is running
    try:
        response = requests.get(f"{SONARQUBE_URL}/api/system/status")
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "UP":
                return True
    except Exception as e:
        logger.error(f"Error waiting for SonarQube to start: {e}")
        return False
    return False


def _get_sonarqube_token(
    user: str = SONARQUBE_USER,
    password: str = SONARQUBE_PASSWORD,
) -> str:
    """Get the token for SonarQube API.

    curl -u admin:12345678 -X POST "http://localhost:9000/api/user_tokens/generate" -d "name=token-<uuid>"
    Save the token as an environment variable: SONARQUBE_TOKEN
    """
    # Generate a random token name
    token_name = f"token-{uuid.uuid4()}"
    try:
        response = requests.post(
            f"{SONARQUBE_URL}/api/user_tokens/generate",
            data={"name": token_name},
            auth=(user, password),
        )
        if response.status_code == 200:
            token = response.json()["token"]
            os.environ["SONARQUBE_TOKEN"] = token
            return token
    except Exception as e:
        logger.error(f"Error getting SonarQube token: {e}")
    return ""


def _get_sonar_scanner_result(project_key: str) -> dict:
    """Get the result of the Sonar Scanner.

    curl -u <token>: \
    "http://localhost:9000/api/issues/search?componentKeys=<project_key>&pageSize=500"
    """
    token = os.getenv("SONARQUBE_TOKEN") or _get_sonarqube_token()
    logger.info(f"Token: {token}")
    response = requests.get(
        f"{SONARQUBE_URL}/api/issues/search?componentKeys={project_key}&pageSize=500",
        auth=(token, ""),
    )
    if response.status_code == 200:
        return response.json()
    return None


def _get_sonar_scanner_severity_order(severity: str) -> int:
    """Get the order of the severity."""
    severity_order = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}
    return severity_order.get(severity, 4)


def _is_text_range_different(issue: dict) -> bool:
    """Check if the text range is different from the line."""
    return (
        issue.get("textRange", {}).get("startLine", 0)
        != issue.get("textRange", {}).get("endLine", 0)
    )


def _summarize_sonar_scanner_result(sonar_scanner_result_path: str) -> dict:
    """Summarize the Sonar Scanner result to reduce the number of text."""
    logger.info(f"Summarizing Sonar Scanner result from {sonar_scanner_result_path}...")
    with open(sonar_scanner_result_path, "r") as f:
        try:
            data = json_repair.loads(f.read())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format"}
        except Exception as e:
            return {"error": str(e)}
    logger.info(f"Total issues: {data['total']}, {len(data['issues'])}")
    summary = {"total": data["total"], "issues": []}
    for issue in data["issues"]:
        summary["issues"].append(
            {
                "file": (
                    issue
                    .get("component", "")
                    .replace(f"{issue.get('project', '')}:", "")
                ),
                "message": issue.get("message", ""),
                "severity": issue.get("severity", ""),
                "line": (
                    f"From {issue.get('textRange', {}).get('startLine', 0)} to "
                    f"{issue.get('textRange', {}).get('endLine', 0)}"
                    if _is_text_range_different(issue)
                    else issue.get("line", 0)
                ),
            },
        )

    # Sort the issues by severity
    summary["issues"].sort(
        key=lambda x: _get_sonar_scanner_severity_order(x["severity"])
    )

    return summary


def _convert_sonarqube_summary_to_reports(summary: dict) -> list[Report]:
    """Convert SonarQube summary to list of Report objects."""
    reports = []

    # Handle error case
    if "error" in summary:
        reports.append(ErrorReport(
            tool="SonarQube",
            reason=summary["error"]
        ))
        return reports

    # Process issues
    issues = summary.get("issues", [])
    for issue in issues:
        # Get severity and map to SeverityLevel
        severity_str = issue.get("severity", "MAJOR").upper()
        severity = SONARQUBE_SEVERITY_MAPPING.get(severity_str, SeverityLevel.MEDIUM)

        # Get file path
        file_path = issue.get("file", "")

        # Get line information
        line_info = issue.get("line", "")
        line_number = None
        if isinstance(line_info, str) and line_info.strip():
            if line_info.startswith("From ") and " to " in line_info:
                # Extract range like "From 10 to 20"
                match = re.search(r'From (\d+) to (\d+)', line_info)
                if match:
                    start_line, end_line = match.groups()
                    line_number = f"{start_line}-{end_line}"
                else:
                    line_number = line_info
            else:
                line_number = str(line_info)
        elif isinstance(line_info, (int, float)) and line_info > 0:
            line_number = str(int(line_info))

        # Get message/description
        description = issue.get("message", "Unknown SonarQube issue")

        # Map severity to CWE (common SonarQube patterns)
        severity_to_cwe = {
            SeverityLevel.CRITICAL: "CWE-119",   # Improper Restriction of Operations
            SeverityLevel.HIGH: "CWE-703",       # Improper Check or Handling of Exceptional Conditions
            SeverityLevel.MEDIUM: "CWE-1078",    # Inappropriate Source Code Style or Formatting
            SeverityLevel.LOW: "CWE-1078",       # Inappropriate Source Code Style or Formatting
        }
        cwe = severity_to_cwe.get(severity, "CWE-703")

        # Determine language from file extension
        language = "code"
        if file_path:
            ext = file_path.split('.')[-1].lower() if '.' in file_path else ""
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
                'cs': 'csharp',
                'css': 'css',
                'html': 'html',
                'xml': 'xml'
            }
            language = lang_mapping.get(ext, 'code')

        # Create Report object
        report = Report(
            tool="SonarQube",
            severity=severity,
            description=description,
            file_path=file_path if file_path else None,
            line_number=line_number,
            language=language,
            cwe=cwe,
            report_type="code"
        )

        reports.append(report)

    return reports


def scan_project_with_sonar_scanner(project_path: str) -> list[Report]:
    """Scan the project with Sonar Scanner."""
    _write_sonar_scanner_config()
    if not _wait_for_sonarqube_to_start():
        logger.info("SonarQube is not running, starting it...")
        start_sonarqube()

        # Wait for 30 seconds
        time.sleep(30)
        retries = 0
        while not _wait_for_sonarqube_to_start():
            retries += 1
            logger.info(f"Waiting for SonarQube to start... ({retries}/30)")
            time.sleep(5)
            if retries >= 30:
                logger.error("SonarQube is not running, exiting...")
                return [ErrorReport(
                    tool="SonarQube",
                    reason="SonarQube takes too long to start"
                )]

    logger.info("SonarQube is running, scanning project...")
    project_key = uuid.uuid4()
    # Run sonar-scanner
    command = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={project_path}",
    ]
    try:
        _run_with_live_output(command)
    except subprocess.CalledProcessError as e:
        logger.error(f"Sonar Scanner failed: {e}")
        return [ErrorReport(
            tool="SonarQube",
            reason=f"Sonar Scanner failed: {e}"
        )]
    logger.info("Finish running Sonar Scanner")

    logger.info("Getting Sonar Scanner result...")
    result = _get_sonar_scanner_result(project_key)
    logger.info(f"Result: {result}")
    if not result:
        logger.error("Sonar Scanner failed, exiting...")
        return [ErrorReport(
            tool="SonarQube",
            reason="Sonar Scanner failed"
        )]
    Path(SONAR_SCANNER_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    json_path = Path(SONAR_SCANNER_OUTPUT_DIR) / f"{project_key}.json"

    try:
        with open(json_path, "w") as f:
            json.dump(result, f)

        summary = _summarize_sonar_scanner_result(json_path)

        # TODO: Check why the stop scanner command takes too long?
        # stop_sonarqube()

        # Convert summary to list of Report objects
        reports = _convert_sonarqube_summary_to_reports(summary)

        # Clean up the JSON result file after processing
        if json_path.exists():
            try:
                json_path.unlink()
                logger.info(f"Cleaned up SonarQube result file: {json_path}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up SonarQube result file {json_path}: {cleanup_error}")

        return reports

    except Exception as e:
        logger.error(f"Error processing SonarQube results: {e}")
        # Clean up on error
        if json_path.exists():
            try:
                json_path.unlink()
                logger.info(f"Cleaned up SonarQube result file after error: {json_path}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up SonarQube result file {json_path}: {cleanup_error}")

        return [ErrorReport(
            tool="SonarQube",
            reason=f"Error processing results: {str(e)}"
        )]
