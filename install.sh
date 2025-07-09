#!/bin/bash
# Agent Sentinel Installation Script

echo "🛡️  Installing Agent Sentinel - Security Analysis Agent"
echo "=================================================="

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>/dev/null | cut -d' ' -f2)
if [ -z "$python_version" ]; then
    echo "❌ Python 3.8+ is required but not found. Please install Python first."
    exit 1
fi

echo "✅ Python $python_version found"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -e .

# Install security scanning tools
echo "🔧 Installing security scanning tools..."
pip install bandit safety semgrep truffleHog detect-secrets pip-audit

# Check if GitHub token is set
if [ -z "$GITHUB_ACCESS_TOKEN" ]; then
    echo "⚠️  Warning: GITHUB_ACCESS_TOKEN environment variable is not set"
    echo "   Please set it with: export GITHUB_ACCESS_TOKEN='your-token'"
    echo "   See README.md for instructions on creating a GitHub token"
else
    echo "✅ GitHub token is configured"
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "To use Agent Sentinel:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run: agent-sentinel"
echo "3. Make sure GITHUB_ACCESS_TOKEN is set in your environment"
echo ""
echo "For more information, see README.md"
