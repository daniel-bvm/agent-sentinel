import subprocess
import time
import requests

SONARQUBE_SHELL_SCRIPT = "/opt/sonarqube/bin/linux-x86-64/sonar.sh"
SONARQUBE_URL = "http://localhost:9000"


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


# TODO: Check the implementation of ElasticSearch without root user
# {"id":"147B411E-AZf5H3Nfh00p6GNlGmc4","version":"10.4.1.88267","status":"UP"}
# {"id":"147B411E-AZf5H3Nfh00p6GNlGmc4","version":"10.4.1.88267","status":"STARTING"}
def _wait_for_sonarqube_to_start():
    # Wait for 10 seconds
    time.sleep(10)
    # Check if the sonarqube is running

    response = requests.get(f"{SONARQUBE_URL}/api/system/status")
    if response.status_code == 200:
        data = response.json()
        if data["status"] == "UP":
            return True
    return False





