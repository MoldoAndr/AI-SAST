"""
Pricing tracker module for AI_SAST.

Tracks token usage and calculates pricing for OpenAI API calls.
"""

import os
import threading
import json
from pathlib import Path
from typing import Dict, Any

# Global pricing constants for GPT-4o
INPUT_TOKEN_PRICE = 3.750 / 1_000_000  # $3.750 per 1M tokens
OUTPUT_TOKEN_PRICE = 15.000 / 1_000_000  # $15.000 per 1M tokens

# Global state for tracking total usage across all projects
GLOBAL_PRICING = {
    "input_tokens": 0,
    "output_tokens": 0,
    "cost": 0.0
}

# Thread lock for thread-safe updates
PRICING_LOCK = threading.Lock()

def update_global_pricing(usage: Dict[str, Any]) -> None:
    """
    Update the global pricing tracker with usage from a project.
    
    Args:
        usage: Usage dictionary with input_tokens, output_tokens, and cost
    """
    with PRICING_LOCK:
        GLOBAL_PRICING["input_tokens"] += usage.get("input_tokens", 0)
        GLOBAL_PRICING["output_tokens"] += usage.get("output_tokens", 0)
        GLOBAL_PRICING["cost"] += usage.get("cost", 0.0)
        
        # Save to a persistent file for the web interface to access
        try:
            pricing_file = Path("pricing_data.json")
            with open(pricing_file, 'w') as f:
                json.dump(GLOBAL_PRICING, f)
        except Exception:
            pass  # Silently fail if we can't write to the file

def get_global_pricing() -> Dict[str, Any]:
    """
    Get the current global pricing data.
    
    Returns:
        Dict[str, Any]: Dictionary with input_tokens, output_tokens, and cost
    """
    with PRICING_LOCK:
        return GLOBAL_PRICING.copy()

def calculate_cost(input_tokens: int, output_tokens: int) -> float:
    """
    Calculate the cost based on token usage.
    
    Args:
        input_tokens: Number of input tokens
        output_tokens: Number of output tokens
        
    Returns:
        float: Cost in USD
    """
    input_cost = input_tokens * INPUT_TOKEN_PRICE
    output_cost = output_tokens * OUTPUT_TOKEN_PRICE
    return input_cost + output_cost

class PricingTracker:
    """
    Tracker for token usage and pricing per project.
    """
    
    def __init__(self):
        """Initialize the pricing tracker."""
        self.project_usage = {}
        self.lock = threading.Lock()
    
    def track_usage(self, project_name: str, input_tokens: int, output_tokens: int) -> None:
        """
        Track token usage for a project.
        
        Args:
            project_name: Name of the project
            input_tokens: Number of input tokens used
            output_tokens: Number of output tokens generated
        """
        cost = calculate_cost(input_tokens, output_tokens)
        
        with self.lock:
            if project_name not in self.project_usage:
                self.project_usage[project_name] = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost": 0.0
                }
            
            self.project_usage[project_name]["input_tokens"] += input_tokens
            self.project_usage[project_name]["output_tokens"] += output_tokens
            self.project_usage[project_name]["cost"] += cost
    
    def get_project_usage(self, project_name: str) -> Dict[str, Any]:
        """
        Get token usage for a specific project.
        
        Args:
            project_name: Name of the project
            
        Returns:
            Dict[str, Any]: Token usage and cost information
        """
        with self.lock:
            if project_name not in self.project_usage:
                return {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost": 0.0
                }
            
            return self.project_usage[project_name].copy()
    
    def get_total_usage(self) -> Dict[str, Any]:
        """
        Get the total token usage across all projects.
        
        Returns:
            Dict[str, Any]: Total token usage and cost information
        """
        total_input = 0
        total_output = 0
        total_cost = 0.0
        
        with self.lock:
            for usage in self.project_usage.values():
                total_input += usage["input_tokens"]
                total_output += usage["output_tokens"]
                total_cost += usage["cost"]
        
        return {
            "input_tokens": total_input,
            "output_tokens": total_output,
            "cost": total_cost
        }
