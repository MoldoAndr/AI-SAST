#!/bin/bash

# Check for required environment variables
if [ -z "$OPENAI_KEY" ]; then
    echo "Error: OPENAI_KEY environment variable is required"
    exit 1
fi

if [ ! -d "/app/src" ]; then
    echo "Error: Source directory not mounted. Please use -v /path/to/frontend:/app/src"
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Output directory not specified or does not exist. Please use -OUTPUT_DIR:/path/to/logs"
    exit 1
fi

# Export OpenAI API key
export OPENAI_API_KEY=$OPENAI_KEY

# Run the scanner
echo "Starting AI_SAST scanner..."
python /app/src/main.py

echo "Scan complete! Check results in the output directory."