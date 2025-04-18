#!/bin/bash

# Set default environment variables if not provided
export SRC_DIR="${SRC_DIR:-/project}"
export OUTPUT_DIR="${OUTPUT_DIR:-/logs}"
export PROJECT_NAME="${PROJECT_NAME:-src}"
export OPENAI_MODEL="${OPENAI_MODEL:-gpt-4-turbo}"

# Start the Flask web app
echo "Starting AI_SAST web interface on port 5000..."
exec python /app/src/web/app.py
