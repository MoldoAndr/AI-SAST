FROM python:3.11-slim

# Set working directory
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \ 
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/codeql && \
    wget -q https://github.com/github/codeql-cli-binaries/releases/download/v2.15.1/codeql-linux64.zip -O codeql.zip && \
    unzip codeql.zip -d /opt/codeql && \
    rm codeql.zip && \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql

RUN git clone --depth 1 https://github.com/github/codeql.git /opt/codeql-repo

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and entrypoint
COPY src/ /app/src/
COPY src/web/templates/ /app/templates/
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
