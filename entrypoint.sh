#!/bin/bash

# Create input and output directories if they don't exist
mkdir -p /project/input
mkdir -p /project/output

echo "Starting AI_SAST web interface on port 5000..."
exec python /app/src/web/app.py
