"""
Windows Event Log Monitor
Monitors Windows Event Logs for security-related events.
"""
import threading
import time
from datetime import datetime
from typing import Callable, Optional

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("Warning: pywin32 not available. Windows Event Log monitoring disabled.")

from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class WindowsEventMonitor:
    """Monitors Windows Event Logs for security events."""
    
    def __init__(self, event_callback: Callable = None):
        """
        Initialize Windows Event Monitor.
        
        Args:
            event_callback: Callback function to handle detected events
        """
        self.event_callback = event_callback
        self.running = False
        self.thread = None
        self.last_record_numbers = {}
        
        if not WIN32_AVAILABLE:
            logger.warning("win32evtlog not available. Event monitoring will be limited.")
    
    def start(self):
        """Start monitoring Windows Event Logs."""
        if not WIN32_AVAILABLE:
            logger.error("Cannot start event monitoring: pywin32 not installed")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Windows Event Monitor started")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)  # Reduced timeout for faster shutdown
        logger.info("Windows Event Monitor stopped")
    
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        # Initialize last record numbers for each log
        for log_name in Settings.WINDOWS_EVENT_LOGS:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                self.last_record_numbers[log_name] = total
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                logger.error(f"Error initializing {log_name} log: {e}")
        
        while self.running:
            try:
                for log_name in Settings.WINDOWS_EVENT_LOGS:
                    self._check_log(log_name)
                
                time.sleep(Settings.WINDOWS_EVENT_POLL_INTERVAL)
            
            except Exception as e:
                logger.error(f"Error in event monitoring loop: {e}")
                time.sleep(Settings.WINDOWS_EVENT_POLL_INTERVAL)
    
    def _check_log(self, log_name: str):
        """Check a specific event log for new events."""
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            # Track the highest record number we've seen
            new_events_processed = []
            
            for event in events:
                # Get the record number for this event
                record_number = event.RecordNumber
                
                # Skip if we've already processed this event
                if log_name in self.last_record_numbers:
                    if record_number <= self.last_record_numbers[log_name]:
                        continue
                
                # Check if this is a security event we care about
                event_id = event.EventID & 0xFFFF  # Get the actual event ID
                
                if log_name == "Security" and event_id in Settings.SECURITY_EVENT_IDS:
                    self._process_security_event(event, event_id, log_name)
                    new_events_processed.append(record_number)
                elif log_name == "System" and event_id in [7045, 7040]:  # Service events
                    self._process_system_event(event, event_id, log_name)
                    new_events_processed.append(record_number)
            
            # Update the last record number we've seen for this log
            if new_events_processed:
                self.last_record_numbers[log_name] = max(new_events_processed)
            
            win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            logger.error(f"Error checking {log_name} log: {e}")
    
    
    
    def _process_security_event(self, event, event_id: int, log_name: str):
        """Process a security event."""
        try:
            # Determine severity based on event type
            severity = self._get_severity(event_id)
            
            # Get event description
            event_desc = Settings.SECURITY_EVENT_IDS.get(event_id, "Unknown Event")
            
            # Extract additional data
            try:
                event_data = {
                    'computer': event.ComputerName,
                    'time_generated': event.TimeGenerated.isoformat() if event.TimeGenerated else None,
                    'source': event.SourceName,
                    'event_category': event.EventCategory,
                    'strings': event.StringInserts if hasattr(event, 'StringInserts') else []
                }
            except:
                event_data = {}
            
            # Build description
            description = f"{event_desc}"
            if event_data.get('strings'):
                # Add relevant string data (like username for login events)
                if event_id in [4624, 4625]:  # Logon events
                    if len(event_data['strings']) > 5:
                        username = event_data['strings'][5]
                        description += f" - User: {username}"
                
                # Add process info for process creation events
                elif event_id == 4688:  # Process created
                    if len(event_data['strings']) > 5:
                        process_name = event_data['strings'][5] if len(event_data['strings']) > 5 else ''
                        if process_name:
                            description += f" - Process: {process_name}"
                        # Command line is usually in index 8 (if command line auditing is enabled)
                        if len(event_data['strings']) > 8:
                            cmdline = event_data['strings'][8]
                            if cmdline and cmdline.strip():
                                description += f" - Command: {cmdline}"
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(event_id, event_data)
            
            event_info = {
                'event_type': event_desc,
                'severity': severity,
                'source': f"Windows Event Log - {log_name}",
                'description': description,
                'event_id': event_id,
                'raw_data': event_data,
                'threat_score': threat_score
            }
            
            if self.event_callback:
                self.event_callback(event_info)
            
        except Exception as e:
            logger.error(f"Error processing security event {event_id}: {e}")
    
    def _process_system_event(self, event, event_id: int, log_name: str):
        """Process a system event."""
        try:
            event_data = {
                'computer': event.ComputerName,
                'time_generated': event.TimeGenerated.isoformat() if event.TimeGenerated else None,
                'source': event.SourceName,
                'strings': event.StringInserts if hasattr(event, 'StringInserts') else []
            }
            
            description = "Service Installed"
            if event_data.get('strings') and len(event_data['strings']) > 0:
                service_name = event_data['strings'][0]
                description += f" - Service: {service_name}"
            
            event_info = {
                'event_type': 'Service Installation',
                'severity': 'Warning',
                'source': f"Windows Event Log - {log_name}",
                'description': description,
                'event_id': event_id,
                'raw_data': event_data,
                'threat_score': 30
            }
            
            if self.event_callback:
                self.event_callback(event_info)
        
        except Exception as e:
            logger.error(f"Error processing system event {event_id}: {e}")
    
    def _get_severity(self, event_id: int) -> str:
        """Determine severity based on event ID."""
        # Critical events
        if event_id in [4625, 4720, 4732, 4719, 4697, 7045]:
            return "Critical"
        
        # Warning events
        elif event_id in [4723, 4724, 4672, 4688]:
            return "Warning"
        
        # Info events
        else:
            return "Info"
    
    def _calculate_threat_score(self, event_id: int, event_data: dict) -> int:
        """Calculate threat score for an event."""
        score = 0
        
        # Base scores by event type
        threat_scores = {
            4625: 60,  # Failed logon - potential brute force
            4720: 50,  # Account created
            4732: 50,  # User added to group
            4719: 70,  # Audit policy changed
            4697: 60,  # Service installed
            7045: 60,  # Service installed (system log)
            4672: 40,  # Special privileges assigned
            4688: 20,  # Process created
            4624: 10,  # Successful logon
        }
        
        score = threat_scores.get(event_id, 10)
        
        return min(score, 100)
