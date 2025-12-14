"""
Network Activity Monitor
Monitors network connections and detects suspicious activity.
"""
import threading
import time
import psutil
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, Set

from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class NetworkMonitor:
    """Monitors network activity for suspicious patterns."""
    
    def __init__(self, event_callback: Callable = None):
        """
        Initialize Network Monitor.
        
        Args:
            event_callback: Callback function to handle detected events
        """
        self.event_callback = event_callback
        self.running = False
        self.thread = None
        
        # Track connections
        self.known_connections: Set[tuple] = set()
        self.connection_attempts: Dict[str, list] = defaultdict(list)
    
    def start(self):
        """Start monitoring network activity."""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Network Monitor started")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)  # Reduced timeout for faster shutdown
        logger.info("Network Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._check_connections()
                time.sleep(Settings.NETWORK_MONITOR_INTERVAL)
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                time.sleep(Settings.NETWORK_MONITOR_INTERVAL)
    
    def _check_connections(self):
        """Check current network connections."""
        try:
            connections = psutil.net_connections(kind='inet')
            current_connections = set()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port
                    
                    conn_tuple = (remote_ip, remote_port, local_port)
                    current_connections.add(conn_tuple)
                    
                    # Check if this is a new connection
                    if conn_tuple not in self.known_connections:
                        self._process_new_connection(remote_ip, remote_port, local_port)
            
            # Update known connections
            self.known_connections = current_connections
        
        except (psutil.AccessDenied, PermissionError):
            # Need admin privileges for full connection info
            logger.debug("Access denied for network connections (may need admin privileges)")
        except Exception as e:
            logger.error(f"Error checking connections: {e}")
    
    def _process_new_connection(self, remote_ip: str, remote_port: int, local_port: int):
        """Process a new network connection."""
        try:
            # Check for suspicious ports
            if remote_port in Settings.SUSPICIOUS_PORTS:
                self._trigger_event(
                    event_type="Suspicious Port Connection",
                    severity="Warning",
                    description=f"Connection to suspicious port {remote_port} at {remote_ip}",
                    threat_score=50,
                    raw_data={
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'local_port': local_port
                    }
                )
            
            # Track connection attempts to same IP
            now = datetime.now()
            self.connection_attempts[remote_ip].append(now)
            
            # Clean up old attempts (older than 5 minutes)
            cutoff = now - timedelta(minutes=5)
            self.connection_attempts[remote_ip] = [
                t for t in self.connection_attempts[remote_ip] if t > cutoff
            ]
            
            # Check for port scanning (multiple connections to same IP)
            if len(self.connection_attempts[remote_ip]) > 10:
                self._trigger_event(
                    event_type="Possible Port Scan",
                    severity="Critical",
                    description=f"Multiple connection attempts to {remote_ip} detected",
                    threat_score=70,
                    raw_data={
                        'remote_ip': remote_ip,
                        'attempt_count': len(self.connection_attempts[remote_ip])
                    }
                )
        
        except Exception as e:
            logger.error(f"Error processing connection: {e}")
    
    def _trigger_event(self, event_type: str, severity: str, description: str, 
                       threat_score: int, raw_data: dict = None):
        """Trigger a security event."""
        if self.event_callback:
            event = {
                'event_type': event_type,
                'severity': severity,
                'source': 'Network Monitor',
                'description': description,
                'event_id': None,
                'raw_data': raw_data,
                'threat_score': threat_score
            }
            self.event_callback(event)
