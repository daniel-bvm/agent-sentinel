import subprocess
import os

import json


def scan_codeql(scan_path: str, language: str = "python") -> dict:
    """Run CodeQL static analysis on a given codebase."""
    db_path = os.path.join(scan_path, "codeql-db")
    sarif_path = os.path.join(scan_path, "results.sarif")

    # Step 1: Create database
    create_cmd = [
        "codeql", "database", "create", db_path,
        "--language", language,
        "--source-root", scan_path
    ]
    subprocess.run(create_cmd, check=True)

    # Step 2: Analyze
    analyze_cmd = [
        "codeql", "database", "analyze", db_path,
        f"codeql/{language}-queries.qls",
        "--format=sarifv2.1.0",
        "--output", sarif_path
    ]
    subprocess.run(analyze_cmd, check=True)

    # Step 3: Load SARIF output
    with open(sarif_path) as f:
        return json.load(f)


if __name__ == "__main__":
    path = "/Users/macbookpro/Projects/eternal-ai/ai-architectures/knowledge-base"
    results = scan_codeql(path)
    with open("codeql_results.json", "w") as f:
        json.dump(results, f, indent=2)
