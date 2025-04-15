"""
OpenAI client module for AI_SAST.

Handles creation and configuration of the OpenAI client.
"""

import os
import time
import logging
from openai import OpenAI

logger = logging.getLogger("ai_sast")


def get_openai_client() -> OpenAI:
    """
    Get an OpenAI client instance with the API key from environment variables.
    
    Returns:
        OpenAI: OpenAI client instance
    """
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is not set")
    
    return OpenAI(api_key=api_key)


def call_openai_with_retry(client, model, messages, temperature=0.2, max_tokens=4000, 
                          max_retries=3, retry_delay=5):
    """
    Call OpenAI API with retry logic for handling rate limits and temporary errors.
    
    Args:
        client: OpenAI client
        model: Model to use
        messages: Messages to send
        temperature: Temperature parameter
        max_tokens: Maximum tokens to generate
        max_retries: Maximum number of retries
        retry_delay: Delay between retries in seconds
        
    Returns:
        Response from OpenAI API
        
    Raises:
        Exception: If the API call fails after all retries
    """
    retries = 0
    while retries <= max_retries:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response
        except Exception as e:
            error_msg = str(e).lower()
            
            # Rate limit or server errors that should trigger a retry
            if any(msg in error_msg for msg in ["rate limit", "timeout", "server", "overloaded", "capacity"]):
                retries += 1
                wait_time = retry_delay * (2 ** retries)  # Exponential backoff
                
                if retries <= max_retries:
                    logger.warning(f"OpenAI API error: {str(e)}. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"OpenAI API error after {max_retries} retries: {str(e)}")
                    raise
            else:
                # Other errors that shouldn't trigger a retry
                logger.error(f"OpenAI API error: {str(e)}")
                raise