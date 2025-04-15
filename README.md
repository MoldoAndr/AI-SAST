# AI_SAST: AI-Powered Static Application Security Testing Tool

AI_SAST is a Docker-based tool that uses OpenAI's language models to perform advanced static code analysis for frontend files, identifying potential security vulnerabilities.

## Features

- 🔍 **Smart File Discovery**: Recursively scans frontend directories and intelligently filters relevant files.
- 🔄 **File Relationship Analysis**: Identifies dependencies between files for more accurate vulnerability detection.
- 🧠 **AI-Powered Analysis**: Leverages OpenAI's language models to detect potential security vulnerabilities.
- 📊 **Comprehensive Reporting**: Generates detailed JSON reports with vulnerability information.
- 🐳 **Docker Integration**: Run as a Docker container against any frontend project.

## Quick Start

### Prerequisites

- Docker installed on your system
- An OpenAI API key

### Usage

```bash
docker run -e OPENAI_KEY="your_openai_api_key" -e OUTPUT_DIR=/logs -v /path/to/your/frontend:/app/src -v /path/to/output:/logs username/AI_SAST
```

## Environment Variables

- `OPENAI_KEY` or `OPENAI_API_KEY`: Your OpenAI API key (required)
- `SRC_DIR`: Source directory to scan (default: `/app/src`)
- `OUTPUT_DIR`: Directory to store logs and reports (default: `/logs`)
- `OPENAI_MODEL`: OpenAI model to use (default: `gpt-4-turbo`)
- `TEMPERATURE`: Temperature parameter for OpenAI (default: `0.2`)
- `MAX_TOKENS`: Maximum tokens for OpenAI responses (default: `8192`)
- `LOG_LEVEL`: Logging level (default: `INFO`)
- `BATCH_SIZE`: Number of files to process in parallel (default: `10`)

## Building the Docker Image

To build the Docker image yourself:

```bash
git clone https://github.com/yourusername/AI_SAST.git
cd AI_SAST
docker build -t yourusername/AI_SAST .
```

## Example Output

The tool generates vulnerability reports in JSON format:

```
logs/
│
├── MY_WEBSITE_logs/
│   ├── cross_site_scripting_xss.json
│   ├── sql_injection.json
│   └── insecure_authentication.json
```

Each JSON file contains details about the vulnerabilities including:
- Vulnerability type
- Description
- File location (file, line, column)
- Severity level
- Recommended fix

## Vulnerability Types Detected

The tool can detect a wide range of frontend vulnerabilities including:

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Authentication
- SQL Injection
- NoSQL Injection
- DOM-based vulnerabilities
- Prototype Pollution
- Insecure Data Storage
- Path Traversal
- And many more...

## Architecture

1. **File Discovery**: The tool scans the frontend directory and identifies relevant files for security analysis.
2. **File Relationship Analysis**: Analyzes imports and dependencies between files.
3. **AI-Powered Analysis**: Uses OpenAI to analyze each file and detect potential vulnerabilities.
4. **Reporting**: Generates detailed vulnerability reports.

## Development

### Project Structure

```
AI_SAST/
├── src/
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── file_analyzer.py
│   │   ├── file_discovery.py
│   │   ├── logger.py
│   │   ├── openai_client.py
│   │   └── vulnerability_detector.py
│   └── main.py
├── Dockerfile
├── entrypoint.sh
├── requirements.txt
└── README.md
```

### Running Tests

```bash
cd AI_SAST
python -m unittest discover tests
```