FROM nikolasigmoid/py-mcp-proxy:latest

# --- Install dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gnupg \
    unzip \
    ca-certificates \
    tar \
    wget \
    python3-pip \
    openjdk-17-jdk \
    nodejs \
    npm \
    jq \
    procps \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- Java config ---
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="$JAVA_HOME/bin:$PATH"

# --- Install SonarScanner CLI ---
RUN curl -sL https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip -o scanner.zip && \
    unzip scanner.zip && \
    mv sonar-scanner-5.0.1.3006-linux /opt/sonar-scanner && \
    ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner && \
    rm scanner.zip

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
RUN pip install slither-analyzer requests

# --- Install SonarQube ---
ENV SONAR_VERSION=10.4.1.88267
RUN curl -LO https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${SONAR_VERSION}.zip && \
    unzip sonarqube-${SONAR_VERSION}.zip && \
    mv sonarqube-${SONAR_VERSION} /opt/sonarqube && \
    rm sonarqube-${SONAR_VERSION}.zip

# --- Install CodeQL CLI ---
ENV CODEQL_VERSION="2.15.5"
RUN curl -L -o codeql.tar.gz https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.tar.gz && \
    tar -xzf codeql.tar.gz && \
    mv codeql /opt/codeql && \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql && \
    rm codeql.tar.gz

WORKDIR /app

COPY pyproject.toml pyproject.toml
COPY src src
COPY config.json config.json
COPY system_prompt.txt system_prompt.txt

RUN pip install . && rm -f pyproject.toml
