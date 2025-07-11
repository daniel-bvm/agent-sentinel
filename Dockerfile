FROM nikolasigmoid/py-mcp-proxy:latest

# Install essential packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gnupg \
    unzip \
    ca-certificates \
    tar \
    wget \
    python3-pip \
    nodejs \
    npm && \
    rm -rf /var/lib/apt/lists/*

# --- Install Node.js 20 ---
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    node -v && npm -v

# --- Install Gitleaks (latest release) ---
RUN export GITLEAKS_VERSION=$(curl -s "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" \
    | grep -Po '"tag_name": "v\K[0-9.]+') && \
    wget -qO gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm gitleaks.tar.gz

# --- Install Foundry ---
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:$PATH"

# --- Install Slither ---
RUN pip install slither-analyzer

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml pyproject.toml
COPY src src
COPY config.json config.json
COPY system_prompt.txt system_prompt.txt

# Install Python package
RUN pip install . && rm -f pyproject.toml
