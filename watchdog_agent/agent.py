from google.adk.agents import Agent
from datetime import datetime
import os
import base64
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import time

class FileIngestionHandler(FileSystemEventHandler):
    """Handler for file system events in the watched directory."""
    
    def __init__(self):
        self.latest_event = None
    
    def on_created(self, event):
        if not event.is_directory:
            self.latest_event = {
                "event_type": "file_created",
                "file_path": event.src_path,
                "timestamp": datetime.now().isoformat()
            }
    
    def on_modified(self, event):
        if not event.is_directory:
            self.latest_event = {
                "event_type": "file_modified", 
                "file_path": event.src_path,
                "timestamp": datetime.now().isoformat()
            }

# Global handler instance
file_handler = FileIngestionHandler()
observer = None

def start_file_monitoring() -> dict:
    """
    Start monitoring the watched directory for new files.
    Returns:
        Status of monitoring start.
    """
    global observer
    WATCHED_DIR = "watched_dir"
    os.makedirs(WATCHED_DIR, exist_ok=True)
    
    if observer is None:
        observer = Observer()
        observer.schedule(file_handler, WATCHED_DIR, recursive=False)
        observer.start()
        
        return {
            "status": "monitoring_started",
            "watched_directory": WATCHED_DIR,
            "message": "File monitoring is now active"
        }
    else:
        return {
            "status": "already_monitoring",
            "message": "File monitoring is already active"
        }

def stop_file_monitoring() -> dict:
    """
    Stop monitoring the watched directory.
    Returns:
        Status of monitoring stop.
    """
    global observer
    if observer:
        observer.stop()
        observer.join()
        observer = None
        return {
            "status": "monitoring_stopped",
            "message": "File monitoring has been stopped"
        }
    else:
        return {
            "status": "not_monitoring",
            "message": "File monitoring was not active"
        }

def upload_file(source_path: str, user_id: str = "user123") -> dict:
    """
    Copy a local file from the given source_path to watched_dir and generate an event payload.
    Args:
        source_path: The path to the file to copy.
        user_id: The user ID for the file owner.
    Returns:
        An event payload for the next agent.
    """
    WATCHED_DIR = "watched_dir"
    os.makedirs(WATCHED_DIR, exist_ok=True)
    filename = os.path.basename(source_path)
    dest_path = os.path.join(WATCHED_DIR, filename)
    shutil.copy2(source_path, dest_path)
    
    payload = {
        "event_type": "new_file_ingested",
        "file_path": dest_path,
        "user_id": user_id,
        "timestamp": datetime.now().isoformat()
    }
    return payload

def monitor_watched_directory() -> dict:
    """
    Monitor the watched directory for new files and process them.
    Returns:
        Event payload for any new files found.
    """
    WATCHED_DIR = "watched_dir"
    if not os.path.exists(WATCHED_DIR):
        return {"error": "Watched directory does not exist"}
    
    # Check if there's a recent file system event
    if file_handler.latest_event:
        event = file_handler.latest_event
        file_path = event["file_path"]
        
        payload = {
            "event_type": "new_file_ingested",
            "file_path": file_path,
            "user_id": "user123",  # Default user ID
            "timestamp": event["timestamp"]
        }
        
        # Clear the latest event
        file_handler.latest_event = None
        return payload
    
    # Fallback: process the most recent file
    files = os.listdir(WATCHED_DIR)
    if not files:
        return {"message": "No files found in watched directory"}
    
    # Process the most recent file
    latest_file = max(files, key=lambda f: os.path.getctime(os.path.join(WATCHED_DIR, f)))
    file_path = os.path.join(WATCHED_DIR, latest_file)
    
    payload = {
        "event_type": "new_file_ingested",
        "file_path": file_path,
        "user_id": "user123",  # Default user ID
        "timestamp": datetime.now().isoformat()
    }
    return payload

root_agent = Agent(
    name="watchdog_agent",
    model="gemini-2.0-flash",
    description="Agent that detects new data ingestion events and starts the privacy compliance pipeline",
    instruction="You are responsible for monitoring new file ingestion events. When a new file arrives, generate an event payload containing the file path, user ID, and timestamp for downstream agents.",
    tools=[upload_file, monitor_watched_directory, start_file_monitoring, stop_file_monitoring],
)