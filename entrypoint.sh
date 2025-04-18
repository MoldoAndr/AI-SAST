#!/bin/bash

export SRC_DIR="${SRC_DIR:-/project}"
export OUTPUT_DIR="${OUTPUT_DIR:-/logs}"
export PROJECT_NAME="${PROJECT_NAME:-src}"
export OPENAI_MODEL="${OPENAI_MODEL:-gpt-4-turbo}"
export ENABLE_CODEQL="${ENABLE_CODEQL:-true}"
export CODEQL_LANGUAGE="${CODEQL_LANGUAGE:-javascript}"

echo "Starting AI_SAST web interface on port 5000..."
exec python /app/src/web/app.py