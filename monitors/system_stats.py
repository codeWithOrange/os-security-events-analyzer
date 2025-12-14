"""
System Statistics Monitor
Monitors CPU, memory, disk, and process information.
"""

import threading
import time
import psutil
from datetime import datetime
from typing import Callable

from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class SystemStatsMonitor:
    """Monitors system resource usage and statistics."""

    def __init__(
        self, event_callback: Callable = None, stats_callback: Callable = None
    ):
        """
        Initialize System Statistics Monitor.

        Args:
            event_callback: Callback for security events
            stats_callback: Callback for system statistics
        """
        self.event_callback = event_callback
        self.stats_callback = stats_callback
        self.running = False
        self.thread = None

        # Baselines for anomaly detection
        self.cpu_baseline = 0
        self.memory_baseline = 0
        self.readings_count = 0

    def start(self):
        """Start monitoring system statistics."""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("System Stats Monitor started")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)  # Reduced timeout for faster shutdown
        logger.info("System Stats Monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Collect statistics
                stats = self._collect_stats()

                # Send stats to callback
                if self.stats_callback:
                    self.stats_callback(stats)

                # Check for anomalies
                self._check_anomalies(stats)

                # Update baselines
                self._update_baselines(stats)

                time.sleep(Settings.SYSTEM_STATS_INTERVAL)

            except Exception as e:
                logger.error(f"Error in system stats monitoring: {e}")
                time.sleep(Settings.SYSTEM_STATS_INTERVAL)

    def _collect_stats(self) -> dict:
        """Collect current system statistics."""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory
            memory = psutil.virtual_memory()

            # Disk
            disk = psutil.disk_usage("/")

            # Network
            net_io = psutil.net_io_counters()

            # Connections
            try:
                connections = len(psutil.net_connections())
            except:
                connections = 0

            # Process count
            process_count = len(psutil.pids())

            stats = {
                "timestamp": datetime.now().isoformat(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_mb": memory.used / (1024 * 1024),
                "memory_total_mb": memory.total / (1024 * 1024),
                "disk_usage_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 * 1024 * 1024),
                "network_bytes_sent": net_io.bytes_sent,
                "network_bytes_recv": net_io.bytes_recv,
                "active_connections": connections,
                "process_count": process_count,
            }

            return stats

        except Exception as e:
            logger.error(f"Error collecting system stats: {e}")
            return {}

    def _check_anomalies(self, stats: dict):
        """Check for system anomalies that might indicate security issues."""
        if self.readings_count < 5:  # Need baseline first
            return

        # Check for CPU spike
        if stats["cpu_percent"] > 90 and self.cpu_baseline < 50:
            self._trigger_event(
                event_type="CPU Spike",
                severity="Warning",
                description=f"CPU usage spike detected: {stats['cpu_percent']:.1f}% (baseline: {self.cpu_baseline:.1f}%)",
                threat_score=30,
            )

        # Check for memory spike
        if stats["memory_percent"] > 90 and self.memory_baseline < 70:
            self._trigger_event(
                event_type="Memory Spike",
                severity="Warning",
                description=f"Memory usage spike detected: {stats['memory_percent']:.1f}% (baseline: {self.memory_baseline:.1f}%)",
                threat_score=30,
            )

        # Check for excessive connections
        if stats["active_connections"] > 500:
            self._trigger_event(
                event_type="Excessive Network Connections",
                severity="Critical",
                description=f"Unusual number of network connections: {stats['active_connections']}",
                threat_score=60,
            )

    def _update_baselines(self, stats: dict):
        """Update baseline values for anomaly detection."""
        self.readings_count += 1

        # Simple moving average
        alpha = 0.1  # Weight for new reading
        self.cpu_baseline = (alpha * stats["cpu_percent"]) + (
            (1 - alpha) * self.cpu_baseline
        )
        self.memory_baseline = (alpha * stats["memory_percent"]) + (
            (1 - alpha) * self.memory_baseline
        )

    def _trigger_event(
        self, event_type: str, severity: str, description: str, threat_score: int
    ):
        """Trigger a security event."""
        if self.event_callback:
            event = {
                "event_type": event_type,
                "severity": severity,
                "source": "System Stats Monitor",
                "description": description,
                "event_id": None,
                "raw_data": None,
                "threat_score": threat_score,
            }
            self.event_callback(event)

    def get_current_stats(self) -> dict:
        """Get current system statistics (blocking call)."""
        return self._collect_stats()
