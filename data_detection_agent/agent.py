from google.adk.agents import Agent
from presidio_analyzer import AnalyzerEngine
import logging

def detect_data(event: dict) -> dict:
    """
    Receives event payload from watchdog_agent, scans the file for sensitive data using Presidio.
    """
    file_path = event.get("file_path")
    logging.info(f"[data_detective_agent] Received file for analysis: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    analyzer = AnalyzerEngine()
    results = analyzer.analyze(
        text=content,
        entities=[
            "PERSON_NAME",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD_NUMBER",
            "US_SSN",
            "US_DRIVER_LICENSE",
            "US_PASSPORT"
        ],
        language="en"
    )

    # Extract unique PII types found
    pii_types = list(set([result.entity_type for result in results]))

    return {
        "pii_findings": pii_types,
        "status": "scanned"
    }

root_agent = Agent(
    name="data_detection_agent",
    model="gemini-2.0-flash",
    description="Agent that analyzes ingested data for compliance-relevant features.",
    instruction="Receive file event payloads and scan for sensitive data. Return only the PII types found in a simple format.",
    tools=[detect_data],
)