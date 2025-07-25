import json
import json_repair
import logging
from collections import defaultdict
import subprocess
import os
from threading import Lock

from .models import Report, SeverityLevel

single_call_lock = Lock()
logger = logging.getLogger(__name__)

CODEQL_SUPPORTED_LANGUAGES = [
    # "cpp",
    # "csharp",
    "go",
    "java",
    "javascript",
    "python",
    "ruby",
    "swift",
]

# Mapping CodeQL severity levels to SeverityLevel enum
SEVERITY_MAPPING = {
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note": SeverityLevel.LOW,
    "recommendation": SeverityLevel.LOW,
}

# Mapping rule levels to CWE identifiers (common CodeQL patterns)
RULE_CWE_MAPPING = {
    "error": "CWE-703",  # Improper Check or Handling of Exceptional Conditions
    "warning": "CWE-703",
    "note": "CWE-703",
    "recommendation": "CWE-703",
}


def _get_rule_level(rule_id: str, run_data: dict, rule_index: int) -> str:
    """Get rule level with the rule ID from the run data."""
    rules = run_data.get("tool", {}).get("driver", {}).get("rules", [])
    if rule_index < len(rules):
        return (
            rules[rule_index]
            .get("defaultConfiguration", {})
            .get("level", "error")
        )
    for rule in rules:
        if rule.get("id") == rule_id:
            return rule.get("defaultConfiguration", {}).get("level", "error")
    return "error"


def parse_codeql_results(
    sarif_file_path: str,
    save_to_path: str | None = None,
) -> list[Report]:
    """Parse CodeQL results to a list of Report objects."""
    with open(sarif_file_path) as f:
        data = json_repair.loads(f.read())
    if save_to_path:
        with open(save_to_path, "w") as f:
            json.dump(data, f, indent=4)
    runs = data["runs"]
    if len(runs) == 0:
        return []
    run_data = runs[0]
    results = run_data["results"]
    logger.info(f"Total results: {len(results)}")
    if len(results) == 0:
        return []

    reports = []

    for result in results:
        physical_location = result.get("locations", ["no-file-information"])[0].get("physicalLocation", {})
        file_name = physical_location.get("artifactLocation", {}).get("uri", "no-file-information")

        # Get line information
        region = physical_location.get("region", {})
        start_line = region.get("startLine", 0)
        end_line = region.get("endLine", 0)

        # Format line number
        if start_line == 0 and end_line == 0:
            line_number = None
        elif start_line == end_line:
            line_number = str(start_line)
        else:
            line_number = f"{start_line}-{end_line}"

        rule_info = result.get("rule", {})
        rule_id = result.get("ruleId", rule_info.get("id", "no-rule-information"))
        rule_level = _get_rule_level(
            rule_id=rule_id,
            run_data=run_data,
            rule_index=result.get("ruleIndex", rule_info.get("index", 0)),
        )

        # Map rule level to severity
        severity = SEVERITY_MAPPING.get(rule_level.lower(), SeverityLevel.MEDIUM)

        # Get CWE mapping
        cwe = RULE_CWE_MAPPING.get(rule_level.lower(), "CWE-703")

        # Get description
        description = result["message"]["text"]

        # Create Report object
        report = Report(
            tool="CodeQL",
            severity=severity,
            description=description,
            file_path=file_name if file_name != "no-file-information" else None,
            line_number=line_number,
            language="code",  # Will be set by caller based on language scanned
            cwe=cwe
        )

        reports.append(report)

    return reports


def download_codeql_pack(language: str) -> None:
    """Download the CodeQL pack for a given language."""

    if language not in CODEQL_SUPPORTED_LANGUAGES:
        logger.info(f"Language {language} is not supported by CodeQL. Skipping CodeQL pack download.")
        raise RuntimeError(f"Language {language} is not supported by CodeQL.")
    
    # if the file is already downloaded, skip the download
    if os.path.exists(f"codeql/{language}-queries"):
        logger.info(f"CodeQL pack for {language} already downloaded. Skipping download.")
        return

    logger.info(f"Downloading CodeQL pack for {language}...")
    command = f"codeql pack download codeql/{language}-queries"
    logger.debug(f"Running command: {command}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        logger.error(f"Failed to download CodeQL pack for {language}.")
        raise RuntimeError(f"Failed to download CodeQL pack for {language}.")

    logger.info(f"CodeQL pack for {language} downloaded successfully.")


def create_codeql_database(scan_path: str, language: str) -> str:
    """Create a CodeQL database for a given path with a given language."""
    logger.info(f"Creating CodeQL database for {scan_path} with {language}...")
    
    if language not in CODEQL_SUPPORTED_LANGUAGES:
        logger.info(f"Language {language} is not supported by CodeQL. Skipping CodeQL database creation.")
        raise RuntimeError(f"Language {language} is not supported by CodeQL.")

    # if the database is already created, skip the creation
    if os.path.exists(f"{scan_path}/codeql-db-{language}"):
        logger.info(f"CodeQL database for {scan_path} with {language} already created. Skipping creation.")
        return f"{scan_path}/codeql-db-{language}"

    database_path = f"{scan_path}/codeql-db-{language}"
    command = f"codeql database create {database_path} --language={language} --build-mode=none >/dev/null 2>&1"
    logger.debug(f"Running command: {command}")
    # Run the command in the scan path
    result = subprocess.run(command, shell=True, cwd=scan_path)
    if result.returncode != 0:
        logger.error(f"Failed to create CodeQL database for {scan_path} with {language}.")
        raise RuntimeError(f"Failed to create CodeQL database for {scan_path} with {language}.")

    logger.info(f"CodeQL database for {scan_path} with {language} created successfully.")
    return database_path

def get_system_ram() -> int:
    """Get the system RAM in MB."""
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // 1024 // 1024


def analyze_codeql_database(
    scan_path: str,
    language: str,
    database_path: str,
) -> str:
    """Analyze a CodeQL database for a given path with a given language."""
    logger.info(f"Analyzing CodeQL database for {scan_path} with {language}...")
    result_output_path = f"{scan_path}/results-{language}.sarif"
    ram = get_system_ram()
    command = f"codeql database analyze -q {database_path} codeql/{language}-queries --format=sarifv2.1.0 --output={result_output_path} --ram={int(ram * 0.85)}"
    logger.debug(f"Running command: {command}")
    result = subprocess.run(command, shell=True, cwd=scan_path)
    if result.returncode != 0:
        logger.error(f"Failed to analyze CodeQL database for {scan_path} with {language}.")
        raise RuntimeError(f"Failed to analyze CodeQL database for {scan_path} with {language}.")
    logger.info(f"CodeQL database for {scan_path} with {language} analyzed successfully.")
    return result_output_path

def run_codeql_scanner(scan_path: str, language: str) -> list[Report]:
    """Run CodeQL on a given path with a given language."""
    from .models import ErrorReport

    if language not in CODEQL_SUPPORTED_LANGUAGES:
        return [ErrorReport(
            tool="CodeQL",
            reason=f"Language {language} is not supported by CodeQL"
        )]

    logger.info("Running CodeQL scanner...")
    try:
        download_codeql_pack(language)
    except RuntimeError:
        logger.error(f"Failed to download CodeQL pack for {language}.")
        return [ErrorReport(
            tool="CodeQL",
            reason=f"Failed to download CodeQL pack for {language}"
        )]
    try:
        database_path = create_codeql_database(scan_path, language)
    except RuntimeError:
        logger.error(f"Failed to create CodeQL database for {scan_path} with {language}.")
        return [ErrorReport(
            tool="CodeQL",
            reason=f"Failed to create CodeQL database for {scan_path} with {language}"
        )]
    try:
        with single_call_lock:
            result_output_path = analyze_codeql_database(scan_path, language, database_path)
    except RuntimeError:
        logger.error(f"Failed to analyze CodeQL database for {scan_path} with {language}.")
        return [ErrorReport(
            tool="CodeQL",
            reason=f"Failed to analyze CodeQL database for {scan_path} with {language}"
        )]

    reports = parse_codeql_results(sarif_file_path=result_output_path)

    # Set the correct language for all reports
    for report in reports:
        report.language = language

    return reports


def main():
    logger.info("Starting CodeQL analysis...")
    path = "/Users/macbookpro/Projects/eternal-ai"

    language = "python"
    reports = run_codeql_scanner(path, language)
    logger.info(f"\nPython reports: {len(reports)} found")
    for report in reports:
        logger.info(f"  {report}")

    language = "javascript"
    reports = run_codeql_scanner(path, language)
    logger.info(f"\nJavaScript reports: {len(reports)} found")
    for report in reports:
        logger.info(f"  {report}")


if __name__ == "__main__":
    main()
