"""
File Integrity Monitor
Monitors critical system directories for unauthorized changes.
"""
import os
import hashlib
import threading
import time
from datetime import datetime
from typing import Callable, Dict
from pathlib import Path

from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class FileIntegrityMonitor:
    """Monitors file integrity in critical system directories."""
    
    def __init__(self, event_callback: Callable = None):
        """
        Initialize File Integrity Monitor.
        
        Args:
            event_callback: Callback function to handle detected events
        """
        self.event_callback = event_callback
        self.running = False
        self.thread = None
        
        # Store file hashes
        self.file_hashes: Dict[str, str] = {}
        self.file_modified_times: Dict[str, float] = {}
        
        # Track changes for ransomware detection
        self.recent_changes = []
    
    def start(self):
        """Start monitoring file integrity."""
        self.running = True
        
        # Initialize baseline
        logger.info("Initializing file integrity baseline...")
        self._initialize_baseline()
        
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("File Integrity Monitor started")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)  # Reduced timeout for faster shutdown
        logger.info("File Integrity Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._check_files()
                
                # Clean up old changes (older than time window)
                current_time = time.time()
                self.recent_changes = [
                    (t, path) for t, path in self.recent_changes
                    if current_time - t < Settings.RAPID_FILE_CHANGE_TIME_WINDOW
                ]
                
                # Check for ransomware patterns
                if len(self.recent_changes) > Settings.RAPID_FILE_CHANGE_THRESHOLD:
                    self._trigger_ransomware_alert()
                
                time.sleep(Settings.FILE_INTEGRITY_INTERVAL)
            
            except Exception as e:
                logger.error(f"Error in file integrity monitoring: {e}")
                time.sleep(Settings.FILE_INTEGRITY_INTERVAL)
    
    def _initialize_baseline(self):
        """Initialize baseline file hashes."""
        # Monitor critical files first
        for file_path in Settings.CRITICAL_FILES:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                try:
                    mtime = os.path.getmtime(file_path)
                    self.file_modified_times[file_path] = mtime
                    logger.info(f"Added critical file to baseline: {file_path}")
                except (PermissionError, OSError) as e:
                    logger.warning(f"Cannot access critical file {file_path}: {e}")
        
        # Monitor top-level files in directories
        for monitored_path in Settings.MONITORED_PATHS:
            if not os.path.exists(monitored_path):
                logger.warning(f"Monitored path does not exist: {monitored_path}")
                continue
            
            try:
                # Only monitor top-level files in critical directories
                # (Full recursive scan would be too resource-intensive)
                for item in os.listdir(monitored_path)[:50]:  # Limit to first 50 items
                    file_path = os.path.join(monitored_path, item)
                    
                    if os.path.isfile(file_path):
                        try:
                            # Store modification time instead of hash for performance
                            mtime = os.path.getmtime(file_path)
                            self.file_modified_times[file_path] = mtime
                        except (PermissionError, OSError):
                            pass  # Skip files we can't access
            
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot access {monitored_path}: {e}")
        
        logger.info(f"Initialized baseline for {len(self.file_modified_times)} files")
    
    def _check_files(self):
        """Check monitored files for changes."""
        for file_path, baseline_mtime in list(self.file_modified_times.items()):
            try:
                if not os.path.exists(file_path):
                    # File was deleted
                    self._trigger_event(
                        event_type="File Deleted",
                        severity="Warning",
                        description=f"Monitored file deleted: {file_path}",
                        threat_score=40,
                        raw_data={'file_path': file_path}
                    )
                    del self.file_modified_times[file_path]
                    continue
                
                current_mtime = os.path.getmtime(file_path)
                
                if current_mtime != baseline_mtime:
                    # File was modified - determine severity based on file type
                    is_critical = file_path in Settings.CRITICAL_FILES
                    severity = "Critical" if is_critical else "Warning"
                    threat_score = 70 if is_critical else 50
                    
                    self._trigger_event(
                        event_type="File Modified",
                        severity=severity,
                        description=f"{'Critical system file' if is_critical else 'Monitored file'} modified: {file_path}",
                        threat_score=threat_score,
                        raw_data={'file_path': file_path, 'is_critical': is_critical}
                    )
                    
                    # Update baseline
                    self.file_modified_times[file_path] = current_mtime
                    
                    # Track for ransomware detection
                    self.recent_changes.append((time.time(), file_path))
            
            except (PermissionError, OSError, FileNotFoundError):
                pass  # Skip files we can't access
        
        # Check for new files in monitored directories
        for monitored_path in Settings.MONITORED_PATHS:
            if not os.path.exists(monitored_path):
                continue
            
            try:
                for item in os.listdir(monitored_path)[:50]:
                    file_path = os.path.join(monitored_path, item)
                    
                    if os.path.isfile(file_path) and file_path not in self.file_modified_times:
                        # New file detected
                        self._trigger_event(
                            event_type="New File Created",
                            severity="Info",
                            description=f"New file in monitored directory: {file_path}",
                            threat_score=20,
                            raw_data={'file_path': file_path}
                        )
                        
                        # Add to baseline
                        try:
                            mtime = os.path.getmtime(file_path)
                            self.file_modified_times[file_path] = mtime
                        except (PermissionError, OSError):
                            pass
            
            except (PermissionError, OSError):
                pass
    
    def _trigger_ransomware_alert(self):
        """Trigger alert for possible ransomware activity."""
        self._trigger_event(
            event_type="Possible Ransomware Activity",
            severity="Critical",
            description=f"Rapid file changes detected: {len(self.recent_changes)} files changed in {Settings.RAPID_FILE_CHANGE_TIME_WINDOW}s",
            threat_score=90,
            raw_data={
                'change_count': len(self.recent_changes),
                'time_window': Settings.RAPID_FILE_CHANGE_TIME_WINDOW
            }
        )
        
        # Reset counter after alert
        self.recent_changes = []
    
    def _trigger_event(self, event_type: str, severity: str, description: str,
                       threat_score: int, raw_data: dict = None):
        """Trigger a security event."""
        if self.event_callback:
            event = {
                'event_type': event_type,
                'severity': severity,
                'source': 'File Integrity Monitor',
                'description': description,
                'event_id': None,
                'raw_data': raw_data,
                'threat_score': threat_score
            }
            self.event_callback(event)
    
    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
