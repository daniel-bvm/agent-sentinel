FROM nikolasigmoid/py-mcp-proxy:latest

# Install basic packages
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gnupg \
    unzip
# RUN apt-get update && apt-get install -y gcc libc-dev

# # Install solc manually (v0.8.20 as example)
# RUN curl -L -o /usr/bin/solc https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux && \
#     chmod +x /usr/bin/solc && \
#     solc --version

# --- Install Node.js + npm ---
RUN apt-get update && \
    apt-get install -y curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Verify install
RUN node -v && npm -v

# # --- Install Foundry (forge CLI) ---
# RUN curl -L https://foundry.paradigm.xyz | bash && \
#     ~/.foundry/bin/foundryup

# Add forge to PATH
ENV PATH="/root/.foundry/bin:$PATH"

COPY pyproject.toml pyproject.toml
COPY src src
COPY config.json config.json
COPY system_prompt.txt system_prompt.txt

RUN pip install . && rm -rf pyproject.toml
