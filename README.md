# Agent Sentinel - Security Analysis Agent

Agent Sentinel is a comprehensive security analysis tool designed to identify vulnerabilities and security issues in GitHub repositories. It provides multiple scanning capabilities to ensure thorough security assessment.

## Features

### 🔍 Comprehensive Security Scanning
- **Multi-language static analysis** using Semgrep
- **Python security scanning** with Bandit
- **Secret detection** using TruffleHog
- **Dependency vulnerability scanning** with Safety
- **Infrastructure security analysis** for Docker and CI/CD
- **Automated security reporting**

### 🛡️ Security Tools Integrated
- **Bandit** - Python security linter
- **Safety** - Python dependency vulnerability scanner
- **Semgrep** - Multi-language static analysis
- **TruffleHog** - Secret detection in code and git history
- **Custom analyzers** for Docker and GitHub Actions

### 📊 Analysis Capabilities
- Language detection and appropriate tool selection
- Severity classification (Critical, High, Medium, Low)
- Comprehensive security reports
- Actionable remediation recommendations

## Installation

```bash
pip install -e .
```

## Configuration

### Environment Variables
- `GITHUB_ACCESS_TOKEN` - Required GitHub personal access token

### MCP Configuration
```json
{
    "mcpServers": {
        "agent-sentinel": {
            "command": "agent-sentinel",
            "args": [],
            "env": {
                "GITHUB_ACCESS_TOKEN": "your-github-token"
            }
        }
    }
}
```

## Usage

### Available Tools

1. **comprehensive_security_scan(repo_url)** - Complete security analysis
2. **scan_for_secrets(repo_url)** - Secret detection only
3. **scan_dependencies_vulnerabilities(repo_url)** - Dependency vulnerability scan
4. **scan_code_quality_security(repo_url)** - Static code analysis
5. **scan_infrastructure_security(repo_url)** - Infrastructure security scan
6. **generate_security_report(repo_url)** - Formatted security report

### Example Usage

```python
# Comprehensive security scan
result = comprehensive_security_scan("https://github.com/user/repo")

# Generate security report
report = generate_security_report("https://github.com/user/repo")
```

## Security Checks Performed

### Code Security
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Cryptographic issues
- Authentication/authorization flaws

### Infrastructure Security
- Docker security best practices
- Container privilege escalation
- GitHub Actions security
- CI/CD pipeline vulnerabilities

### Dependency Security
- Known CVEs in dependencies
- Outdated packages
- Security advisories
- License compliance

### Secret Detection
- Hardcoded credentials
- API keys and tokens
- Database connection strings
- SSH keys
- Certificate files

## Supported Languages

- **Python** - Bandit, Safety, pip-audit
- **JavaScript/TypeScript** - Semgrep
- **Java** - Semgrep
- **C/C++** - Semgrep
- **Go** - Semgrep
- **Multi-language** - Semgrep, TruffleHog

## Security Report Output

The agent generates comprehensive security reports including:
- Executive summary with issue counts
- Detailed findings by category
- Severity classifications
- Remediation recommendations
- Best practice guidelines

## Dependencies

- Python 3.8+
- Git
- Security scanning tools (installed automatically)

## GitHub Token Setup

To obtain a GitHub Personal Access Token:
1. Go to GitHub Settings > Developer settings > Personal access tokens
2. Generate new token (classic)
3. Select 'repo' scope for full repository access
4. Copy the token and set it as `GITHUB_ACCESS_TOKEN` environment variable

## License

MIT License

Let me break down how this code technically works:

1. Purpose:
The `mcp-git-ingest` is a Model Context Protocol (MCP) server designed to help read GitHub repository structures and important files. It provides two main tools:
- `github_directory_structure`: Returns a tree-like representation of a repository's directory structure
- `github_read_important_files`: Reads and returns the contents of specified files in a repository

2. Technical Implementation:

a. Dependencies:
- Uses `fastmcp` for creating an MCP server
- Uses `gitpython` for Git repository operations
- Requires Python 3.8+

b. Key Functions:

`clone_repo(repo_url: str) -> str`:
- Creates a deterministic temporary directory based on the repository URL's hash
- Checks if the repository is already cloned
- If not, clones the repository
- Handles error cases and cleanup
- Returns the path to the cloned repository

`get_directory_tree(path: str, prefix: str = "") -> str`:
- Recursively generates a tree-like directory structure
- Skips `.git` directories
- Uses Unicode box-drawing characters to create a visual tree representation
- Handles sorting of entries

`github_directory_structure(repo_url: str) -> str`:
- Clones the repository
- Generates directory tree
- Cleans up the temporary repository after processing
- Returns the tree structure or an error message

`github_read_important_files(repo_url: str, file_paths: List[str]) -> dict[str, str]`:
- Clones the repository
- Reads specified files
- Returns a dictionary mapping file paths to their contents
- Handles file reading errors
- Cleans up the temporary repository

3. Error Handling:
- Uses try-except blocks to handle repository cloning, file reading errors
- Ensures temporary directories are always cleaned up using `finally` blocks
- Returns descriptive error messages

4. Performance Optimizations:
- Uses a hash-based temporary directory naming to potentially reuse cloned repositories
- Checks for existing repositories before cloning
- Implements cleanup to prevent accumulation of temporary files

5. Unique Features:
- Deterministic temporary directory creation
- Unicode tree representation
- Flexible file reading with error handling

6. Execution:
- Can be run as a CLI tool via `mcp-git-ingest`
- Configured through `pyproject.toml`
- Depends on `fastmcp` for MCP server functionality

The code is a robust, flexible tool for programmatically exploring and reading GitHub repositories, with a focus on error handling and clean implementation.

Would you like me to elaborate on any specific aspect of the implementation?
```

