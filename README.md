# AI_SAST: AI-Powered Static Application Security Testing Tool

AI_SAST is a Docker-based tool that uses OpenAI's language models to perform advanced static code analysis for frontend applications, identifying potential security vulnerabilities through AI-powered analysis.

## Features

- 🔍 **Smart File Discovery**: Recursively scans directories and intelligently filters security-relevant files
- 🔄 **File Relationship Analysis**: Identifies dependencies between files for contextual vulnerability detection
- 🧠 **AI-Powered Analysis**: Leverages OpenAI's language models to detect sophisticated security vulnerabilities
- 📊 **Comprehensive Reporting**: Generates detailed JSON reports with vulnerability information and remediation advice
- 🌐 **Web Interface**: Easy-to-use web dashboard to view scan results and launch new scans
- 🐳 **Docker Integration**: Runs as a containerized application for easy deployment and isolation

## Quick Start

### Prerequisites

- Docker installed on your system
- An OpenAI API key

### Running with Docker

```bash
docker run -d \
  -p 5000:5000 \
  -e OPENAI_API_KEY="your_openai_api_key" \
  -v /path/to/your/code:/project \
  -v /path/to/output:/logs \
  andreimoldovan2/ai_sast
```

Then access the web interface at http://localhost:5000

### Command Line Usage

You can also run AI_SAST directly from the command line inside the container:

```bash
docker run \
  -e OPENAI_API_KEY="your_openai_api_key" \
  -v /path/to/your/code:/project \
  -v /path/to/output:/logs \
  andreimoldovan2/ai_sast python /app/src/main.py
```

## Environment Variables

- `OPENAI_API_KEY` or `OPENAI_KEY`: Your OpenAI API key (required)
- `SRC_DIR`: Source directory to scan (default: `/project`)
- `OUTPUT_DIR`: Directory to store logs and reports (default: `/logs`)
- `PROJECT_NAME`: Custom project name to use in reports (optional)
- `OPENAI_MODEL`: OpenAI model to use (default: `gpt-4-turbo`)
- `MAX_TOKENS`: Maximum tokens for OpenAI responses (default: `8192`)
- `TEMPERATURE`: Temperature parameter for OpenAI (default: `0.2`)
- `LOG_LEVEL`: Logging level (default: `INFO`)
- `BATCH_SIZE`: Number of files to process in parallel (default: `10`)
- `MAX_RETRIES`: Maximum number of retries for API calls (default: `3`)
- `RETRY_DELAY`: Delay between retries in seconds (default: `5`)

## Web Interface

AI_SAST provides a web interface that allows you to:

1. View all previous scan results
2. Start new scans by selecting directories within the mounted volume
3. View detailed vulnerability reports with severity levels and remediation advice
4. Track scan job progress in real-time

The web interface is accessible at http://localhost:5000 when running the Docker container.

## Example Output

The tool generates vulnerability reports in JSON format:

```
logs/
│
├── my_project_logs/
│   ├── cross_site_scripting_xss.json
│   ├── insecure_authentication.json
│   └── path_traversal.json
```

Each JSON file contains details about the vulnerabilities including:
- Vulnerability type
- Description
- File location (file, line, column)
- Severity level (critical, high, medium, low)
- Recommended remediation

## Vulnerability Types Detected

The tool can detect a wide range of vulnerabilities including:

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Authentication
- Insecure Data Storage
- Insecure API Endpoints
- Information Leakage
- Improper Access Control
- Insecure Dependencies
- Prototype Pollution
- Path Traversal
- Server-Side Request Forgery (SSRF)
- SQL/NoSQL Injection
- DOM-based vulnerabilities
- Sensitive Data Exposure

## Project Architecture

```
AI_SAST/
├── src/
│   ├── scanner/                        # Core scanning functionality
│   │   ├── __init__.py
│   │   ├── config.py                   # Configuration management
│   │   ├── file_analyzer.py            # Analyzes file relationships
│   │   ├── file_discovery.py           # Smart file discovery
│   │   ├── logger.py                   # Logging setup
│   │   ├── openai_client.py            # OpenAI API client
│   │   └── vulnerability_detector.py   # Vulnerability detection
│   ├── web/                            # Web interface
│   │   ├── app.py                      # Flask web application
│   │   ├── static/                     # Static assets
│   │   └── templates/                  # HTML templates
│   └── main.py                         # Command-line entrypoint
├── Dockerfile                          # Docker configuration
├── entrypoint.sh                       # Container entrypoint script
├── requirements.txt                    # Python dependencies
└── README.md                           # Documentation
```

## Building the Docker Image

To build the Docker image yourself:

```bash
git clone https://github.com/MoldoAndr/AI_SAST.git
cd AI_SAST
docker build -t yourusername/ai_sast .
```
