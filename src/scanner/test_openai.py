#!/usr/bin/env python3
"""
Test script to verify OpenAI API connection.
Place this in the src directory and run it to test your API key and connection.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("openai_test")

# Add the parent directory to the path so we can import the openai_client module
sys.path.append(str(Path(__file__).parent.parent))

try:
    from scanner.openai_client import get_openai_client, call_openai_with_retry
    
    def test_openai_connection():
        """Test the OpenAI connection with a simple prompt."""
        logger.info("Starting OpenAI connection test...")
        
        # Check environment variable
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY environment variable is not set")
            return False
        
        logger.info(f"API key found with length: {len(api_key)}")
        logger.info(f"API key starts with: {api_key[:4]}...")
        
        try:
            # Get the client
            client = get_openai_client()
            logger.info("OpenAI client created successfully")
            
            # Make a simple test call
            test_message = "Hello, this is a test message from AI_SAST. Please reply with 'Connection successful'."
            response = call_openai_with_retry(
                client=client,
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": test_message}
                ],
                temperature=0.2,
                max_tokens=50
            )
            
            # Check if we got a response
            if response and hasattr(response, 'choices') and len(response.choices) > 0:
                content = response.choices[0].message.content
                logger.info(f"Response received: {content}")
                
                # Print token usage
                if hasattr(response, 'usage'):
                    logger.info(f"Token usage - Input: {response.usage.prompt_tokens}, Output: {response.usage.completion_tokens}")
                
                return True
            else:
                logger.error("No valid response received")
                return False
                
        except Exception as e:
            logger.error(f"Error testing OpenAI connection: {str(e)}", exc_info=True)
            return False
    
    if __name__ == "__main__":
        success = test_openai_connection()
        if success:
            logger.info("Test completed successfully! OpenAI connection is working.")
            sys.exit(0)
        else:
            logger.error("Test failed! OpenAI connection is not working properly.")
            sys.exit(1)
            
except ImportError as e:
    logger.error(f"Import error: {str(e)}")
    logger.error("Make sure you're running this from the src directory")
    sys.exit(1)
