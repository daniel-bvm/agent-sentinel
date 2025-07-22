# Agent Sentinel - Security Analysis Agent

Agent Sentinel is a comprehensive security analysis tool designed to identify vulnerabilities and security issues in GitHub repositories. Built as a Model Context Protocol (MCP) server with FastAPI integration, it provides both programmatic access and streaming security analysis capabilities.

## Architecture

### MCP Servers
- **Sentinel - Security Analysis Agent** (`mcp`): Git repository operations and file analysis
- **Sentinel - Audit Agent** (`audit_mcp`): Security scanning and vulnerability detection

### FastAPI Server
- RESTful API endpoints for chat-based interactions
- Streaming responses for real-time security analysis
- OpenAI-compatible tool integration

## Features

### 🔍 Git Repository Analysis
- **Repository structure visualization** in tree format
- **File content reading** from specific paths
- **Directory exploration** at configurable depths
- **Branch checkout** capabilities
- **GitHub token management** and validation

### 🛡️ Security Scanning Tools
- **GitLeaks** - Secret detection in code and git history
- **Bandit** - Python security linter
- **Safety** - Python dependency vulnerability scanner
- **Semgrep** - Multi-language static analysis
- **Slither** - Solidity smart contract security analysis
- **CodeQL** - Advanced static analysis for multiple languages
- **Trivy** - Container and dependency vulnerability scanning
- **npm audit** - JavaScript/Node.js dependency scanning

### 📊 Analysis Capabilities
- **Concurrent scanning** for improved performance
- **Language detection** and appropriate tool selection
- **Severity classification** (Critical, High, Medium, Low, Warning, Error)
- **CWE mapping** for vulnerability categorization
- **Streaming results** as scans complete
- **Error handling** and reporting

## Installation

```bash
pip install -e .
```

## Configuration

### Environment Variables
- `GITHUB_ACCESS_TOKEN` - Required GitHub personal access token for private repositories
- `LLM_API_KEY` - OpenAI API key for chat functionality
- `LLM_BASE_URL` - LLM API endpoint (default: https://api.openai.com/v1)
- `LLM_MODEL_ID` - Model identifier (default: gpt-4o-mini)
- `HOST` - Server host (default: 0.0.0.0)
- `PORT` - Server port (default: 80)

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

### MCP Tools

#### Git Repository Tools
```python
# Get repository directory structure
git_directory_structure("https://github.com/user/repo", subfolder="src", max_depth=3)

# Read specific files
git_read_important_files("https://github.com/user/repo", ["README.md", "package.json"])

# List directories at specific depth
git_list_directories("https://github.com/user/repo", subfolder="src", max_depth=2)

# Checkout a specific branch
checkout_branch("/path/to/repo", "feature-branch")

# Validate and set GitHub token
validate_and_set_github_token("your-token-here")

# Get token setup guide
provide_guide_for_github_access_token()
```

#### Security Scanning Tools
```python
# Comprehensive security scan (all tools)
async for report in comprehensive_security_scan("https://github.com/user/repo"):
    print(report)

# Secret detection only
async for report in scan_for_secrets("https://github.com/user/repo"):
    print(report)

# Dependency vulnerability scan
async for report in scan_dependencies_vulnerabilities("https://github.com/user/repo"):
    print(report)

# Static code analysis
async for report in scan_code_quality_security("https://github.com/user/repo"):
    print(report)
```

### FastAPI Server

Start the server:
```bash
python server.py
```

The server provides:
- `/prompt` - Chat completion endpoint with tool calling
- `/health` - Health check endpoint
- OpenAI-compatible streaming responses

## Security Checks Performed

### Code Security
- **Python**: Bandit security linter, Safety dependency scanner
- **JavaScript/TypeScript**: Semgrep analysis, npm audit
- **Solidity**: Slither smart contract analysis
- **Multi-language**: Semgrep rules, CodeQL analysis

### Vulnerability Types Detected
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Cryptographic issues
- Authentication/authorization flaws
- Hardcoded credentials and secrets
- Insecure dependencies
- Code quality issues

### Secret Detection
- API keys and tokens
- Database connection strings
- SSH keys and certificates
- Hardcoded passwords
- Cloud service credentials (AWS, Azure, GCP)
- GitHub tokens and similar

## Supported Languages

- **Python** - Bandit, Safety, pip-audit, Semgrep, CodeQL
- **JavaScript/TypeScript** - npm audit, Semgrep, CodeQL
- **Solidity** - Slither, Semgrep
- **Java, C/C++, Go, C#** - Semgrep, CodeQL
- **Multi-language** - GitLeaks secret detection

## Report Structure

Security reports include:
- **Tool identification** - Which scanner found the issue
- **Severity level** - Critical, High, Medium, Low classification
- **File location** - Exact file path and line numbers
- **CWE mapping** - Common Weakness Enumeration identifiers
- **Detailed descriptions** - Issue explanation and context
- **Language detection** - Programming language context

## Dependencies

### Core Dependencies
- Python 3.8+
- FastMCP 2.9.2
- GitPython 3.0.6
- FastAPI
- Uvicorn

### Security Tools
- bandit[toml]==1.8.6
- safety==3.4.0
- semgrep==1.86.0
- detect-secrets==1.5.0
- pip-audit==2.9.0
- slither-analyzer==0.11.3

### Additional Tools
- GitLeaks (external binary)
- CodeQL (external binary)
- Trivy (external binary)

## GitHub Token Setup

To obtain a GitHub Personal Access Token:
1. Go to GitHub Settings > Developer settings > Personal access tokens
2. Generate new token (classic)
3. Select 'repo' scope for full repository access
4. Copy the token and set it as `GITHUB_ACCESS_TOKEN` environment variable

Use the `provide_guide_for_github_access_token()` tool for detailed instructions.

## Error Handling

The system includes comprehensive error handling:
- **ErrorReport objects** for scan failures
- **Tool-specific error codes** for debugging
- **Graceful degradation** when tools are unavailable
- **Detailed error messages** with remediation suggestions

## License

MIT License
```

