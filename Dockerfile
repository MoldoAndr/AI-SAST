FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \ 
    wget \
    unzip \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && \
    apt-get install -y nodejs && \
    node --version && \
    npm --version

RUN git clone --depth 1 https://github.com/github/codeql.git /opt/codeql-repo

RUN mkdir -p /opt/codeql && \
    wget -q https://github.com/github/codeql-cli-binaries/releases/download/v2.15.1/codeql-linux64.zip -O codeql.zip && \
    unzip codeql.zip -d /opt/codeql && \
    rm codeql.zip && \
    chmod +x /opt/codeql/codeql/codeql && \
    ln -sf /opt/codeql/codeql/codeql /usr/local/bin/codeql && \
    chmod 755 /usr/local/bin/codeql

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /project/input /project/output && \
    chmod -R 777 /project

COPY src/ /app/src/
COPY entrypoint.sh /app/

RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:5000/ || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
