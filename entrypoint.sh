#!/bin/bash

# Check for required environment variables
if [ -z "$OPENAI_KEY" ]; then
    echo "Error: OPENAI_KEY environment variable is required"
    exit 1
fi

if [ -z "$SRC_DIR" ]; then
    echo "Error: SRC_DIR environment variable is required"
    exit 1
fi

if [ ! -d "$SRC_DIR" ]; then
    echo "Error: Source directory $SRC_DIR does not exist"
    exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
    echo "Error: OUTPUT_DIR environment variable is required"
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Output directory $OUTPUT_DIR does not exist"
    exit 1
fi

# Export OpenAI API key
export OPENAI_API_KEY=$OPENAI_KEY

# Run the scanner
echo "Starting AI_SAST scanner..."
python /app/src/main.py

echo "Scan complete! Check results in the output directory."
