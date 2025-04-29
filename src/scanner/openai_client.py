"""
OpenAI client module for AI_SAST.

Handles creation and configuration of the OpenAI client with enhanced debugging.
"""

import os
import time
import logging
import json
import traceback
from pathlib import Path
from openai import OpenAI, APIError, APIConnectionError, RateLimitError

logger = logging.getLogger("ai_sast")

# Create debug directory
debug_dir = Path("debug_logs")
debug_dir.mkdir(exist_ok=True, parents=True)

def validate_api_key(api_key):
    """
    Validate the format of the API key.
    
    Args:
        api_key: The API key to validate
        
    Returns:
        tuple: (is_valid, message)
    """
    if not api_key:
        return False, "API key is empty"
    
    if not api_key.startswith("sk-"):
        return False, f"API key has incorrect format, should start with 'sk-' but starts with '{api_key[:3]}'"
    
    if len(api_key) < 20:
        return False, f"API key is too short ({len(api_key)} chars), expected at least 20 chars"
        
    return True, "API key format is valid"

def get_openai_client() -> OpenAI:
    """
    Get an OpenAI client instance with the API key from environment variables.
    Includes enhanced validation and debugging.
    
    Returns:
        OpenAI: OpenAI client instance
    """
    # Try multiple environment variable names
    for env_var in ["OPENAI_API_KEY", "OPENAI_KEY", "OPEN_API_KEY", "API_KEY"]:
        api_key = os.getenv(env_var)
        if api_key:
            logger.info(f"Found API key in environment variable {env_var}")
            break
    
    if not api_key:
        error_msg = "OpenAI API key not found in any environment variable"
        logger.error(error_msg)
        
        # Log all environment variables (masked) to help debugging
        env_vars = {k: ("***" if "key" in k.lower() or "token" in k.lower() or "secret" in k.lower() else v[:10]+"..." if isinstance(v, str) and len(v) > 10 else v) 
                    for k, v in os.environ.items()}
        logger.debug(f"Available environment variables: {json.dumps(env_vars, indent=2)}")
        
        # Save error to debug file
        with open(debug_dir / "api_key_error.log", "w") as f:
            f.write(f"Error: {error_msg}\n")
            f.write(f"Environment variables (keys only): {list(os.environ.keys())}")
        
        raise ValueError(error_msg)
    
    # Validate API key format
    is_valid, message = validate_api_key(api_key)
    
    # Log a masked version of the API key for debugging
    masked_key = f"sk-...{api_key[-4:]}" if api_key.startswith("sk-") else f"{api_key[:3]}...{api_key[-3:]}"
    
    if is_valid:
        logger.info(f"Using API key: {masked_key} (Length: {len(api_key)})")
    else:
        logger.warning(f"API key validation issue: {message}")
        logger.warning(f"Using potentially invalid API key: {masked_key} (Length: {len(api_key)})")
    
    # Create debug file with API key info (masked)
    with open(debug_dir / "api_key_info.log", "w") as f:
        f.write(f"API key format valid: {is_valid}\n")
        f.write(f"Message: {message}\n")
        f.write(f"Masked key: {masked_key}\n")
        f.write(f"Key length: {len(api_key)}")
    
    # Create the client with debugging
    try:
        client = OpenAI(api_key=api_key)
        logger.info("OpenAI client created successfully")
        return client
    except Exception as e:
        logger.error(f"Error creating OpenAI client: {str(e)}")
        with open(debug_dir / "client_creation_error.log", "w") as f:
            f.write(f"Error creating OpenAI client: {str(e)}\n")
            f.write(traceback.format_exc())
        raise


def call_openai_with_retry(client, model="gpt-4o", messages=None, temperature=0.0, max_tokens=4000, 
                          max_retries=3, retry_delay=5):
    """
    Call OpenAI API with retry logic for handling rate limits and temporary errors.
    With enhanced debugging to track request and response details.
    
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
    if messages is None:
        messages = []
    
    # Generate a unique filename for this request
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    request_id = f"{timestamp}_{hash(str(messages))}"
    debug_file = debug_dir / f"openai_request_{request_id}.json"
    
    # Log request details
    request_info = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages_count": len(messages),
        "messages_preview": [
            {
                "role": msg["role"],
                "content_preview": msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
            } for msg in messages
        ]
    }
    
    logger.info(f"Making OpenAI API call with model: {model}")
    logger.debug(f"Request details: {json.dumps(request_info)}")
    
    # Ensure the system prompt strongly enforces JSON output
    if messages and len(messages) > 0 and messages[0]["role"] == "system":
        if "json" not in messages[0]["content"].lower():
            # Add JSON instruction to system prompt if not already present
            messages[0]["content"] += " You must respond with valid JSON only, no additional text or explanations. If no results are found, return an empty array []."
            logger.debug("Added JSON instruction to system prompt")
    
    # Save full request to file for debugging
    try:
        with open(debug_file, 'w') as f:
            json.dump({
                "request": {
                    "model": model,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "messages": messages
                },
                "timestamp": timestamp,
                "request_id": request_id
            }, f, indent=2)
        
        logger.debug(f"Full request details saved to {debug_file}")
    except Exception as e:
        logger.warning(f"Failed to save request details to file: {str(e)}")
    
    retries = 0
    while retries <= max_retries:
        try:
            attempt_log = f"Attempt {retries + 1}/{max_retries + 1} to call OpenAI API"
            logger.info(attempt_log)
            
            # Update debug file with attempt info
            try:
                with open(debug_file, 'r') as f:
                    debug_data = json.load(f)
                
                debug_data.setdefault("attempts", []).append({
                    "attempt": retries + 1,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
                with open(debug_file, 'w') as f:
                    json.dump(debug_data, f, indent=2)
            except Exception:
                pass
            
            start_time = time.time()
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"}  # Force JSON response
            )
            end_time = time.time()
            
            # Log response time
            elapsed_time = end_time - start_time
            logger.info(f"OpenAI API call completed in {elapsed_time:.2f} seconds")
            
            # Log token usage
            if hasattr(response, 'usage'):
                usage_log = f"Token usage - Input: {response.usage.prompt_tokens}, Output: {response.usage.completion_tokens}, Total: {response.usage.total_tokens}"
                logger.info(usage_log)
                
                # Append response to the debug file
                try:
                    with open(debug_file, 'r') as f:
                        debug_data = json.load(f)
                    
                    debug_data["response"] = {
                        "elapsed_time": elapsed_time,
                        "token_usage": {
                            "prompt_tokens": response.usage.prompt_tokens,
                            "completion_tokens": response.usage.completion_tokens,
                            "total_tokens": response.usage.total_tokens
                        },
                        "response_preview": response.choices[0].message.content[:100] + "..." 
                        if len(response.choices[0].message.content) > 100 
                        else response.choices[0].message.content,
                        "status": "success"
                    }
                    
                    with open(debug_file, 'w') as f:
                        json.dump(debug_data, f, indent=2)
                        
                    logger.debug(f"Response details appended to {debug_file}")
                except Exception as e:
                    logger.warning(f"Could not save response details to debug file: {str(e)}")
            
            # Also save full response to a separate file
            response_file = debug_dir / f"openai_response_{request_id}.txt"
            try:
                with open(response_file, 'w') as f:
                    f.write(response.choices[0].message.content)
                logger.debug(f"Full response content saved to {response_file}")
            except Exception as e:
                logger.warning(f"Could not save full response: {str(e)}")
            
            # Validate JSON response
            try:
                response_content = response.choices[0].message.content.strip()
                json.loads(response_content)  # Test if response is valid JSON
                logger.debug("Response is valid JSON")
            except json.JSONDecodeError as e:
                logger.warning(f"Response is not valid JSON: {str(e)}")
                # Save the invalid JSON to a separate file for inspection
                invalid_json_file = debug_dir / f"invalid_json_{request_id}.txt"
                with open(invalid_json_file, 'w') as f:
                    f.write(response_content)
                logger.debug(f"Invalid JSON saved to {invalid_json_file}")
            
            return response
            
        except RateLimitError as e:
            error_msg = f"OpenAI API rate limit error: {str(e)}"
            logger.warning(error_msg)
            
            # Append error to the debug file
            try:
                with open(debug_file, 'r') as f:
                    debug_data = json.load(f)
                
                debug_data.setdefault("errors", []).append({
                    "attempt": retries + 1,
                    "error": str(e),
                    "error_type": "RateLimitError",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "retry": retries < max_retries
                })
                
                with open(debug_file, 'w') as f:
                    json.dump(debug_data, f, indent=2)
            except Exception:
                pass
            
            # Always retry on rate limit errors with exponential backoff
            retries += 1
            wait_time = retry_delay * (2 ** retries)  # Exponential backoff
            
            if retries <= max_retries:
                logger.warning(f"Rate limit error. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"OpenAI API rate limit error after {max_retries} retries: {str(e)}")
                raise
                
        except APIConnectionError as e:
            error_msg = f"OpenAI API connection error: {str(e)}"
            logger.warning(error_msg)
            
            # Append error to the debug file
            try:
                with open(debug_file, 'r') as f:
                    debug_data = json.load(f)
                
                debug_data.setdefault("errors", []).append({
                    "attempt": retries + 1,
                    "error": str(e),
                    "error_type": "APIConnectionError",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "retry": retries < max_retries
                })
                
                with open(debug_file, 'w') as f:
                    json.dump(debug_data, f, indent=2)
            except Exception:
                pass
            
            # Retry connection errors (network issues)
            retries += 1
            wait_time = retry_delay * (1.5 ** retries)  # Less aggressive backoff for connection issues
            
            if retries <= max_retries:
                logger.warning(f"Connection error. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"OpenAI API connection error after {max_retries} retries: {str(e)}")
                # Additional debug info for connection errors
                logger.error("If this is a network issue, check your internet connection and firewall settings")
                raise
                
        except APIError as e:
            error_msg = f"OpenAI API error: {str(e)}"
            logger.warning(error_msg)
            
            # Append error to the debug file
            try:
                with open(debug_file, 'r') as f:
                    debug_data = json.load(f)
                
                debug_data.setdefault("errors", []).append({
                    "attempt": retries + 1,
                    "error": str(e),
                    "error_type": "APIError",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "retry": retries < max_retries
                })
                
                with open(debug_file, 'w') as f:
                    json.dump(debug_data, f, indent=2)
            except Exception:
                pass
            
            # Only retry server errors (5xx), not client errors (4xx)
            if "5" in str(e) or "server_error" in str(e).lower() or "timeout" in str(e).lower():
                retries += 1
                wait_time = retry_delay * (2 ** retries)
                
                if retries <= max_retries:
                    logger.warning(f"Server error. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"OpenAI API server error after {max_retries} retries: {str(e)}")
                    raise
            else:
                # Client errors should not be retried
                logger.error(f"OpenAI API client error (not retrying): {str(e)}")
                raise
                
        except Exception as e:
            error_msg = f"Unexpected error calling OpenAI API: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            
            # Append error to the debug file
            try:
                with open(debug_file, 'r') as f:
                    debug_data = json.load(f)
                
                debug_data.setdefault("errors", []).append({
                    "attempt": retries + 1,
                    "error": str(e),
                    "error_type": "UnexpectedError",
                    "traceback": traceback.format_exc(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "retry": False
                })
                
                with open(debug_file, 'w') as f:
                    json.dump(debug_data, f, indent=2)
            except Exception:
                pass
            
            # Don't retry unexpected errors
            raise


def clean_response_for_json_parsing(response_text: str) -> str:
    """
    Clean the response text to ensure it's valid JSON.
    
    Args:
        response_text: The raw response text from OpenAI
        
    Returns:
        str: Cleaned response ready for JSON parsing
    """
    # Log the original response
    logger.debug(f"Cleaning response for JSON parsing, original length: {len(response_text)}")
    
    # Trim whitespace
    cleaned = response_text.strip()
    
    # Remove markdown JSON code blocks if present
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
        
    # Trim again after removing code blocks
    cleaned = cleaned.strip()
    
    # If empty or just whitespace, return valid empty JSON array
    if not cleaned:
        logger.warning("Response was empty after cleaning, returning empty array")
        return "[]"
    
    # Check if it's already a valid JSON
    try:
        json.loads(cleaned)
        logger.debug("Response is valid JSON after cleaning")
        return cleaned
    except json.JSONDecodeError:
        # If it's not valid JSON, try to extract just the JSON part
        logger.warning("Response is not valid JSON after initial cleaning, attempting to extract JSON")
        
        # Try to find JSON array or object
        import re
        # Look for array
        array_match = re.search(r'\[\s*\{.+\}\s*\]', cleaned, re.DOTALL)
        if array_match:
            logger.debug("Found JSON array pattern in response")
            return array_match.group(0)
        
        # Look for object 
        object_match = re.search(r'\{\s*".+\}\s*', cleaned, re.DOTALL)
        if object_match:
            logger.debug("Found JSON object pattern in response")
            return object_match.group(0)
        
        logger.warning("Could not extract valid JSON, returning empty array")
        return "[]"


def test_api_connection():
    """
    Test the OpenAI API connection and log the results.
    Returns True if successful, False otherwise.
    """
    logger.info("Testing OpenAI API connection...")
    
    try:
        client = get_openai_client()
        
        test_msg = "This is a test message to verify API connectivity. Please respond with 'Connection successful' in a JSON format: {\"status\": \"success\", \"message\": \"Connection successful\"}"
        response = call_openai_with_retry(
            client=client,
            model="gpt-4o",  # You can change this to gpt-3.5-turbo if needed
            messages=[
                {"role": "system", "content": "You are a helpful assistant. Respond with JSON only."},
                {"role": "user", "content": test_msg}
            ],
            temperature=0.0,
            max_tokens=50
        )
        
        if response and hasattr(response, 'choices') and len(response.choices) > 0:
            content = response.choices[0].message.content
            logger.info(f"Test successful! Response received: {content}")
            
            # Validate response is JSON
            try:
                json_response = json.loads(content)
                logger.info(f"Response is valid JSON: {json.dumps(json_response)}")
                return True
            except json.JSONDecodeError:
                logger.warning(f"Response is not valid JSON: {content}")
                return False
        else:
            logger.error("Test failed: No valid response received")
            return False
            
    except Exception as e:
        logger.error(f"Test failed with error: {str(e)}")
        logger.error(traceback.format_exc())
        return False