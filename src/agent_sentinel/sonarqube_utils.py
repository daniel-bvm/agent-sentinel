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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SONARQUBE_SHELL_SCRIPT = "/opt/sonarqube/bin/linux-x86-64/sonar.sh"
SONAR_SCANNER_CONFIG_FILE = "/opt/sonar-scanner/conf/sonar-scanner.properties"
SONARQUBE_URL = "http://localhost:9000"
SONARQUBE_USER = "admin"
SONARQUBE_PASSWORD = "admin"
# SONARQUBE_PASSWORD = "12345678"
SONAR_SCANNER_OUTPUT_DIR = "/tmp/sonar-scanner-output"

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


def _parse_url_result_from_sonar_scanner(sonar_scanner_output: str) -> str:
    """Parse the URL result from the Sonar Scanner output.

    URL will have the form:
    http://localhost:9000/api/ce/task?id=<task_id>
    """
    # Extract the task_id from the URL
    match = re.search(r"/api/ce/task\?id=([^&\s]+)", sonar_scanner_output)
    return f"{SONARQUBE_URL}/api/ce/task?id={match.group(1)}" if match else ""


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
                    f"From {issue.get('textRange', {}).get('startLine', 0)} to {issue.get('textRange', {}).get('endLine', 0)}"
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


def scan_project_with_sonar_scanner(project_path: str) -> dict:
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
                return {"error": "SonarQube takes too long to start"}

    logger.info("SonarQube is running, scanning project...")
    project_key = uuid.uuid4()
    # Run sonar-scanner
    command = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={project_path}",
    ]
    _run_with_live_output(command)

    # result = subprocess.run(command, shell=True, capture_output=True, text=True)
    try:
        _run_with_live_output(command)
    except subprocess.CalledProcessError as e:
        logger.error(f"Sonar Scanner failed: {e}")
        return {"error": "Sonar Scanner failed"}
    # if result.returncode != 0:
    #     logger.error(f"Sonar Scanner failed: {result.stderr}")
    #     return {"error": "Sonar Scanner failed"}
    logger.info(f"Finish running Sonar Scanner")

    logger.info(f"Getting Sonar Scanner result...")
    result = _get_sonar_scanner_result(project_key)
    logger.info(f"Result: {result}")
    if not result:
        logger.error("Sonar Scanner failed, exiting...")
        return {"error": "Sonar Scanner failed"}
    Path(SONAR_SCANNER_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    json_path = Path(SONAR_SCANNER_OUTPUT_DIR) / f"{project_key}.json"
    with open(json_path, "w") as f:
        json.dump(result, f)

    summary = _summarize_sonar_scanner_result(json_path)

    # TODO: Check why the stop scanner command takes too long?
    # stop_sonarqube()

    return summary


if __name__ == "__main__":
    # txt_path = "/Users/macbookpro/Projects/agent-sentinel/.tmp/scanner_output.txt"
    # with open(txt_path, "r") as f:
    #     sonar_scanner_output = f.read()
    # # print(sonar_scanner_output)
    # print(_parse_url_result_from_sonar_scanner(sonar_scanner_output))
    # print(_get_sonarqube_token())
    # print(os.environ["SONARQUBE_TOKEN"])
    # data = _get_sonar_scanner_result("myproject-hehe")
    # with open("./.tmp/sonar_scanner_result.json", "w") as f:
    #     json.dump(data, f)
    # summary = _summarize_sonar_scanner_result("./.tmp/sonar_scanner_result.json")
    # print(summary)
    # print(f"Total issues: {summary['total']}, {len(summary['issues'])}")
    _write_sonar_scanner_config()
