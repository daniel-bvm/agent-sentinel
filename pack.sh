#!/bin/bash

# Exit immediately on error
set -e

find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

rm -rf sentinel.zip
zip -r sentinel.zip src config.json Dockerfile pyproject.toml system_prompt.txt app server.py install_trivy.sh greeting.txt
