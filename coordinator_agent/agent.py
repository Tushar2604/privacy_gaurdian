from google.adk.agents import Agent
# Import your existing agents
from watchdog_agent.agent import root_agent as watchdog_agent
from data_detection_agent.agent import root_agent as data_detection_agent
from consent_agent.agent import root_agent as consent_agent
from redaction_agent.agent import root_agent as redaction_agent
from audit_agent.agent import root_agent as audit_agent

# Define the coordinator agent
coordinator = Agent(
    name="coordinator_agent",
    model="gemini-2.0-flash",
    description="Coordinates file ingestion and data detection pipeline.",
    instruction="You are responsible for orchestrating the privacy compliance pipeline. When a file is ingested, trigger the watchdog agent, then pass its output to the data detection agent, and report the results.",
    sub_agents=[
        watchdog_agent,
        data_detection_agent,
        consent_agent, 
        redaction_agent,
        audit_agent
    ]
)

# Expose as root_agent
root_agent = coordinator