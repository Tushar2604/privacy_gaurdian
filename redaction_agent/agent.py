import os
import logging
import json
import re
from typing import Dict, List, Any, Optional
from google.adk.agents import Agent
from google.cloud import dlp_v2
from google.cloud.dlp_v2 import types

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def simple_redact_content(content: str, pii_types: List[str]) -> str:
    """
    Simple redaction using regex patterns (fallback when DLP is not available).
    """
    redacted_content = content
    
    # Define regex patterns for different PII types
    patterns = {
        "EMAIL_ADDRESS": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "PHONE_NUMBER": r'\+?1?\s*\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}',
        "CREDIT_CARD_NUMBER": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        "US_SSN": r'\b\d{3}-\d{2}-\d{4}\b',
        "PERSON_NAME": r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'
    }
    
    for pii_type in pii_types:
        if pii_type in patterns:
            pattern = patterns[pii_type]
            redacted_content = re.sub(pattern, '█' * 10, redacted_content)
    
    return redacted_content

def redact_sensitive_data(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact PII from file contents based on consent status.
    
    Args:
        event: Dictionary containing:
            - file_path: str - Path to the file to process
            - file_contents: str (optional) - Contents of the file
            - pii_findings: List[str] - List of PII types found
            - consent_results: Dict[str, bool] - Consent status for each PII type
    
    Returns:
        Dictionary with redaction results
    """
    try:
        file_path = event.get('file_path')
        file_contents = event.get('file_contents')
        pii_findings = event.get('pii_findings', [])
        consent_results = event.get('consent_results', {})
        
        # Validate inputs
        if not file_path:
            return {"error": "Missing required field: file_path"}
            
        if not file_contents and not os.path.exists(file_path):
            return {"error": "File not found and no contents provided"}
            
        # Read file if contents not provided
        if not file_contents:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_contents = f.read()
        
        # Determine which PII types to redact (no consent)
        pii_to_redact = [
            pii_type for pii_type in pii_findings 
            if not consent_results.get(pii_type, False)
        ]
        
        if not pii_to_redact:
            return {
                "redacted_file_path": file_path,
                "redacted_pii_types": [],
                "status": "success",
                "message": "No PII to redact (all have consent)"
            }
        
        # Try Google Cloud DLP first, fallback to simple redaction
        try:
            # Check if Google Cloud project is configured
            project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
            if not project_id:
                raise Exception("GOOGLE_CLOUD_PROJECT not set")
            
            # Initialize DLP client
            dlp_client = dlp_v2.DlpServiceClient()
            
            # Prepare DLP request
            parent = f"projects/{project_id}"
            
            # Convert PII types to DLP info types
            info_types = [{"name": pii_type} for pii_type in pii_to_redact]
            
            # Configure redaction
            inspect_config = {
                "info_types": info_types,
                "min_likelihood": "POSSIBLE"
            }
            
            # Prepare the item to be inspected
            item = {"value": file_contents}
            
            # Configure redaction
            deidentify_config = {
                "info_type_transformations": {
                    "transformations": [{
                        "primitive_transformation": {
                            "character_mask_config": {
                                "masking_character": "█"
                            }
                        }
                    }]
                }
            }
            
            # Call the API
            response = dlp_client.deidentify_content(
                request={
                    "parent": parent,
                    "deidentify_config": deidentify_config,
                    "inspect_config": inspect_config,
                    "item": item,
                }
            )
            
            redacted_content = response.item.value
            logger.info("Used Google Cloud DLP for redaction")
            
        except Exception as e:
            logger.warning(f"DLP API error: {str(e)}, using simple redaction fallback")
            # Use simple redaction fallback
            redacted_content = simple_redact_content(file_contents, pii_to_redact)
        
        # Save redacted content
        redacted_path = f"{os.path.splitext(file_path)[0]}_redacted{os.path.splitext(file_path)[1]}"
        
        with open(redacted_path, 'w', encoding='utf-8') as f:
            f.write(redacted_content)
        
        return {
            "redacted_file_path": redacted_path,
            "redacted_pii_types": pii_to_redact,
            "status": "success"
        }
        
    except Exception as e:
        logger.error(f"Error in redaction: {str(e)}")
        return {
            "error": str(e),
            "status": "error"
        }

# Create the redaction agent
root_agent = Agent(
    name="redaction_agent",
    model="gemini-2.0-flash",
    description="Redacts PII from files based on consent status",
    instruction="""
    You are a privacy-focused redaction agent. Your job is to:
    1. Identify PII that lacks consent
    2. Redact that PII from files
    3. Save the redacted version
    4. Report what was redacted
    
    The agent will try Google Cloud DLP API first, then fall back to simple regex-based redaction.
    """,
    tools=[redact_sensitive_data]
)