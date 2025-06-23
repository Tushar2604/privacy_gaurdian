import os
import logging
from datetime import datetime, timedelta
from google.adk.agents import Agent
from google.cloud import firestore
from typing import Dict, Any, List

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Local consent database for hackathon (fallback when Firestore is not available)
LOCAL_CONSENT_DB = {
    "user123": {
        "EMAIL_ADDRESS": {"granted": True, "valid_until": None},
        "PHONE_NUMBER": {"granted": False, "valid_until": None},
        "CREDIT_CARD_NUMBER": {"granted": False, "valid_until": None},
        "PERSON_NAME": {"granted": True, "valid_until": None},
        "US_SSN": {"granted": False, "valid_until": None},
        "US_DRIVER_LICENSE": {"granted": False, "valid_until": None},
        "US_PASSPORT": {"granted": False, "valid_until": None}
    }
}

def verify_consent_for_pii_types(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify consent for multiple PII types for a user.
    
    Args:
        event: Dictionary containing:
            - user_id: str - Unique user identifier
            - pii_findings: List[str] - List of PII types to check
    
    Returns:
        Dictionary with consent results for each PII type
    """
    try:
        user_id = event.get('user_id', '')
        pii_findings = event.get('pii_findings', [])
        
        if not user_id or not pii_findings:
            return {"error": "Missing required fields: user_id and pii_findings"}
        
        consent_results = {}
        
        # Try Firestore first, fallback to local dict
        try:
            # Initialize Firestore client
            db = firestore.Client()
            consent_collection = os.getenv('FIRESTORE_CONSENT_COLLECTION', 'user_consents')
            
            # Get user's consent document
            doc_ref = db.collection(consent_collection).document(user_id)
            doc = doc_ref.get()
            
            if doc.exists:
                consent_data = doc.to_dict()
                # Check each PII type
                for pii_type in pii_findings:
                    consent = consent_data.get(pii_type, {})
                    has_consent = consent.get('granted', False)
                    
                    # Check expiration if valid_until exists
                    valid_until = consent.get('valid_until')
                    if valid_until and datetime.utcnow() > valid_until:
                        has_consent = False
                    
                    consent_results[pii_type] = has_consent
            else:
                # No Firestore record, use local fallback
                logger.info(f"No Firestore record for user {user_id}, using local fallback")
                for pii_type in pii_findings:
                    consent_results[pii_type] = LOCAL_CONSENT_DB.get(user_id, {}).get(pii_type, {}).get('granted', False)
                    
        except Exception as e:
            logger.warning(f"Firestore error: {str(e)}, using local fallback")
            # Use local fallback
            for pii_type in pii_findings:
                consent_results[pii_type] = LOCAL_CONSENT_DB.get(user_id, {}).get(pii_type, {}).get('granted', False)
        
        return {
            "consent_results": consent_results,
            "status": "verified"
        }

    except Exception as e:
        logger.error(f"Error in verify_consent_for_pii_types: {str(e)}")
        return {
            "error": str(e),
            "consent_results": {}
        }

def verify_consent(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify if user has valid consent for a single data type (legacy function).
    
    Args:
        event: Dictionary containing:
            - user_id: str - Unique user identifier
            - data_type: str - Type of data processing
    
    Returns:
        Dictionary with consent status and details
    """
    try:
        user_id = event.get('user_id', '')
        data_type = event.get('data_type', '')
        
        if not user_id or not data_type:
            return {"error": "Missing required fields: user_id and data_type"}
        
        # Try Firestore first, fallback to local dict
        try:
            db = firestore.Client()
            consent_collection = os.getenv('FIRESTORE_CONSENT_COLLECTION', 'user_consents')
            
            doc_ref = db.collection(consent_collection).document(user_id)
            doc = doc_ref.get()
            
            if doc.exists:
                consent_data = doc.to_dict()
                consent = consent_data.get(data_type, {})
                has_consent = consent.get('granted', False)
                
                valid_until = consent.get('valid_until')
                if valid_until and datetime.utcnow() > valid_until:
                    has_consent = False
                
                return {
                    "has_consent": has_consent,
                    "message": "Valid consent found" if has_consent else "Consent not granted",
                    "user_id": user_id,
                    "data_type": data_type
                }
            else:
                # Use local fallback
                has_consent = LOCAL_CONSENT_DB.get(user_id, {}).get(data_type, {}).get('granted', False)
                return {
                    "has_consent": has_consent,
                    "message": "Using local fallback",
                    "user_id": user_id,
                    "data_type": data_type
                }
                
        except Exception as e:
            logger.warning(f"Firestore error: {str(e)}, using local fallback")
            has_consent = LOCAL_CONSENT_DB.get(user_id, {}).get(data_type, {}).get('granted', False)
            return {
                "has_consent": has_consent,
                "message": "Using local fallback due to Firestore error",
                "user_id": user_id,
                "data_type": data_type
            }

    except Exception as e:
        logger.error(f"Error in verify_consent: {str(e)}")
        return {
            "error": str(e),
            "has_consent": False
        }

# Create the root agent
root_agent = Agent(
    name="consent_agent",
    model="gemini-2.0-flash",
    description="Verifies user consents for data processing",
    instruction="""
    You are a consent verification agent. Your job is to check if users have given
    valid consent for specific types of data processing.
    
    Use verify_consent_for_pii_types to check multiple PII types at once.
    Use verify_consent for single data type verification.
    
    Return consent results in the format: {"consent_results": {"PII_TYPE": true/false}}
    """,
    tools=[verify_consent_for_pii_types, verify_consent]
)
