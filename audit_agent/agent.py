import os
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from google.adk.agents import Agent
from google.cloud import bigquery
import csv

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Local audit storage for hackathon (fallback when BigQuery is not available)
AUDIT_LOG_FILE = "audit_log.jsonl"
COMPLIANCE_REPORT_FILE = "compliance_report.json"

class AuditLogger:
    """Handles audit logging to both BigQuery and local files."""
    
    def __init__(self):
        self.audit_entries = []
        self.bigquery_client = None
        self.use_bigquery = False
        
        # Try to initialize BigQuery
        try:
            project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
            if project_id:
                self.bigquery_client = bigquery.Client(project=project_id)
                self.use_bigquery = True
                logger.info("BigQuery client initialized successfully")
            else:
                logger.info("No GOOGLE_CLOUD_PROJECT set, using local file logging")
        except Exception as e:
            logger.warning(f"BigQuery initialization failed: {str(e)}, using local file logging")
    
    def log_audit_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Log an audit event to BigQuery or local file.
        
        Args:
            event_data: Dictionary containing audit event data
        
        Returns:
            True if logging was successful
        """
        try:
            # Add timestamp if not present
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.now().isoformat()
            
            # Try BigQuery first
            if self.use_bigquery and self.bigquery_client:
                return self._log_to_bigquery(event_data)
            else:
                return self._log_to_local_file(event_data)
                
        except Exception as e:
            logger.error(f"Error logging audit event: {str(e)}")
            return False
    
    def _log_to_bigquery(self, event_data: Dict[str, Any]) -> bool:
        """Log audit event to BigQuery."""
        try:
            dataset_id = os.getenv('BIGQUERY_DATASET', 'privacy_audit')
            table_id = os.getenv('BIGQUERY_TABLE', 'audit_events')
            
            table_ref = self.bigquery_client.dataset(dataset_id).table(table_id)
            
            # Insert the row
            errors = self.bigquery_client.insert_rows_json(table_ref, [event_data])
            
            if errors:
                logger.error(f"BigQuery insert errors: {errors}")
                return False
            
            logger.info("Audit event logged to BigQuery successfully")
            return True
            
        except Exception as e:
            logger.error(f"BigQuery logging error: {str(e)}")
            return False
    
    def _log_to_local_file(self, event_data: Dict[str, Any]) -> bool:
        """Log audit event to local JSONL file."""
        try:
            with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event_data) + '\n')
            
            logger.info(f"Audit event logged to local file: {AUDIT_LOG_FILE}")
            return True
            
        except Exception as e:
            logger.error(f"Local file logging error: {str(e)}")
            return False

# Global audit logger instance
audit_logger = AuditLogger()

def log_file_processing_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Log a file processing event with all pipeline details.
    
    Args:
        event: Dictionary containing:
            - file_path: str - Path to the original file
            - user_id: str - User ID
            - pii_findings: List[str] - PII types found
            - consent_results: Dict[str, bool] - Consent status
            - redaction_result: Dict[str, Any] - Redaction results
    
    Returns:
        Dictionary with logging status
    """
    try:
        file_path = event.get('file_path')
        user_id = event.get('user_id')
        pii_findings = event.get('pii_findings', [])
        consent_results = event.get('consent_results', {})
        redaction_result = event.get('redaction_result', {})
        
        # Create comprehensive audit entry
        audit_entry = {
            "event_type": "file_processing_completed",
            "timestamp": datetime.now().isoformat(),
            "file_path": file_path,
            "user_id": user_id,
            "pii_types_detected": pii_findings,
            "consent_status": consent_results,
            "redacted_pii_types": redaction_result.get('redacted_pii_types', []),
            "redacted_file_path": redaction_result.get('redacted_file_path'),
            "processing_status": redaction_result.get('status', 'unknown'),
            "compliance_status": "compliant" if redaction_result.get('status') == 'success' else "non_compliant"
        }
        
        # Log the event
        success = audit_logger.log_audit_event(audit_entry)
        
        return {
            "audit_logged": success,
            "audit_entry": audit_entry,
            "message": "File processing event logged successfully" if success else "Failed to log audit event"
        }
        
    except Exception as e:
        logger.error(f"Error in log_file_processing_event: {str(e)}")
        return {
            "audit_logged": False,
            "error": str(e)
        }

def generate_compliance_report(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive compliance report.
    
    Args:
        event: Dictionary containing:
            - report_period: str (optional) - Time period for report
            - user_id: str (optional) - Specific user to report on
    
    Returns:
        Dictionary with compliance report
    """
    try:
        report_period = event.get('report_period', 'all')
        user_id = event.get('user_id')
        
        # Read audit log entries
        audit_entries = []
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        audit_entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        
        # Filter entries based on criteria
        if user_id:
            audit_entries = [entry for entry in audit_entries if entry.get('user_id') == user_id]
        
        # Generate report statistics
        total_files_processed = len(audit_entries)
        compliant_files = len([entry for entry in audit_entries if entry.get('compliance_status') == 'compliant'])
        non_compliant_files = total_files_processed - compliant_files
        
        # PII statistics
        all_pii_types = set()
        all_redacted_pii = set()
        
        for entry in audit_entries:
            all_pii_types.update(entry.get('pii_types_detected', []))
            all_redacted_pii.update(entry.get('redacted_pii_types', []))
        
        # Create compliance report
        compliance_report = {
            "report_generated_at": datetime.now().isoformat(),
            "report_period": report_period,
            "user_id_filter": user_id,
            "summary": {
                "total_files_processed": total_files_processed,
                "compliant_files": compliant_files,
                "non_compliant_files": non_compliant_files,
                "compliance_rate": round((compliant_files / total_files_processed * 100) if total_files_processed > 0 else 0, 2)
            },
            "pii_statistics": {
                "total_pii_types_detected": len(all_pii_types),
                "total_pii_types_redacted": len(all_redacted_pii),
                "pii_types_detected": list(all_pii_types),
                "pii_types_redacted": list(all_redacted_pii)
            },
            "recent_processing_events": audit_entries[-10:] if audit_entries else [],  # Last 10 events
            "compliance_status": "compliant" if non_compliant_files == 0 else "requires_attention"
        }
        
        # Save report to file
        with open(COMPLIANCE_REPORT_FILE, 'w', encoding='utf-8') as f:
            json.dump(compliance_report, f, indent=2)
        
        return {
            "report_generated": True,
            "report_file": COMPLIANCE_REPORT_FILE,
            "compliance_report": compliance_report
        }
        
    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}")
        return {
            "report_generated": False,
            "error": str(e)
        }

def export_audit_to_csv(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Export audit log to CSV format for analysis.
    
    Args:
        event: Dictionary containing:
            - output_file: str (optional) - Output CSV filename
    
    Returns:
        Dictionary with export status
    """
    try:
        output_file = event.get('output_file', 'audit_export.csv')
        
        if not os.path.exists(AUDIT_LOG_FILE):
            return {
                "exported": False,
                "error": "No audit log file found"
            }
        
        # Read audit entries
        audit_entries = []
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    audit_entries.append(entry)
                except json.JSONDecodeError:
                    continue
        
        if not audit_entries:
            return {
                "exported": False,
                "error": "No audit entries found"
            }
        
        # Write to CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'timestamp', 'event_type', 'file_path', 'user_id', 
                'pii_types_detected', 'consent_status', 'redacted_pii_types',
                'redacted_file_path', 'processing_status', 'compliance_status'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for entry in audit_entries:
                # Flatten nested structures for CSV
                row = {
                    'timestamp': entry.get('timestamp'),
                    'event_type': entry.get('event_type'),
                    'file_path': entry.get('file_path'),
                    'user_id': entry.get('user_id'),
                    'pii_types_detected': ', '.join(entry.get('pii_types_detected', [])),
                    'consent_status': json.dumps(entry.get('consent_status', {})),
                    'redacted_pii_types': ', '.join(entry.get('redacted_pii_types', [])),
                    'redacted_file_path': entry.get('redacted_file_path'),
                    'processing_status': entry.get('processing_status'),
                    'compliance_status': entry.get('compliance_status')
                }
                writer.writerow(row)
        
        return {
            "exported": True,
            "output_file": output_file,
            "entries_exported": len(audit_entries)
        }
        
    except Exception as e:
        logger.error(f"Error exporting audit to CSV: {str(e)}")
        return {
            "exported": False,
            "error": str(e)
        }

# Create the audit agent
root_agent = Agent(
    name="audit_agent",
    model="gemini-2.0-flash",
    description="Logs all privacy compliance actions and generates audit reports",
    instruction="""
    You are the Audit Commander Agent responsible for:
    1. Logging all file processing events with PII detection and redaction details
    2. Generating compliance reports showing processing statistics
    3. Exporting audit data for analysis
    
    Use the appropriate function based on the task:
    - log_file_processing_event: Log a completed file processing event
    - generate_compliance_report: Create comprehensive compliance report
    - export_audit_to_csv: Export audit data to CSV format
    
    The agent supports both BigQuery (production) and local file (hackathon) logging.
    """,
    tools=[log_file_processing_event, generate_compliance_report, export_audit_to_csv]
) 