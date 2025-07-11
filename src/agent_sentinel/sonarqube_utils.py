import subprocess
import time

SONARQUBE_SHELL_SCRIPT = "/opt/sonarqube/bin/linux-x86-64/sonar.sh"


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
    command = f"sh {SONARQUBE_SHELL_SCRIPT} status"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout



