FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install general dependencies and Node.js
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \ 
    wget \
    unzip \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 16 (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && \
    apt-get install -y nodejs && \
    node --version && \
    npm --version

# Clone CodeQL repository for queries
RUN git clone --depth 1 https://github.com/github/codeql.git /opt/codeql-repo

# Install CodeQL 
RUN mkdir -p /opt/codeql && \
    wget -q https://github.com/github/codeql-cli-binaries/releases/download/v2.15.1/codeql-linux64.zip -O codeql.zip && \
    unzip codeql.zip -d /opt/codeql && \
    rm codeql.zip && \
    chmod +x /opt/codeql/codeql/codeql && \
    ln -sf /opt/codeql/codeql/codeql /usr/local/bin/codeql && \
    chmod 755 /usr/local/bin/codeql

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create project directory structure
RUN mkdir -p /project/input /project/output && \
    chmod -R 777 /project

# Copy source code and entrypoint
COPY src/ /app/src/
COPY entrypoint.sh /app/

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port for Flask app
EXPOSE 5000

# Healthcheck for web app
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:5000/ || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
