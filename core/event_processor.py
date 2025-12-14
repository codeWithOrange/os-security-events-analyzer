"""
Event Processor
Central processing pipeline for all security events.
"""

import queue
import threading
from typing import Callable, Optional

from core.database import DatabaseManager
from core.threat_analyzer import ThreatAnalyzer
from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class EventProcessor:
    """Processes and routes security events."""

    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize event processor.

        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.threat_analyzer = ThreatAnalyzer()

        # Event queue for async processing
        self.event_queue = queue.Queue()

        # Processing thread
        self.running = False
        self.processing_thread = None

        # Callbacks for UI updates
        self.event_callbacks = []
        self.alert_callbacks = []

    def start(self):
        """Start event processing."""
        self.running = True
        self.processing_thread = threading.Thread(
            target=self._processing_loop, daemon=True
        )
        self.processing_thread.start()
        logger.info("Event Processor started")

    def stop(self):
        """Stop event processing."""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(
                timeout=1
            )  # Reduced timeout for faster shutdown
        logger.info("Event Processor stopped")

    def register_event_callback(self, callback: Callable):
        """Register a callback for new events."""
        self.event_callbacks.append(callback)

    def register_alert_callback(self, callback: Callable):
        """Register a callback for new alerts."""
        self.alert_callbacks.append(callback)

    def process_event(self, event: dict):
        """
        Queue an event for processing.

        Args:
            event: Event dictionary from monitor
        """
        self.event_queue.put(event)

    def _processing_loop(self):
        """Main event processing loop."""
        while self.running:
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1)

                # Process the event
                self._handle_event(event)

                self.event_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in event processing loop: {e}")

    def _handle_event(self, event: dict):
        """
        Handle a single event.

        Args:
            event: Event dictionary
        """
        try:
            # Enhance event with threat analysis
            enhanced_event = self.threat_analyzer.analyze_event(event)

            # Store event in database
            event_id = self.db_manager.add_event(
                event_type=enhanced_event.get("event_type", "Unknown"),
                severity=enhanced_event.get("severity", "Info"),
                source=enhanced_event.get("source", "Unknown"),
                description=enhanced_event.get("description", ""),
                event_id=enhanced_event.get("event_id"),
                raw_data=enhanced_event.get("raw_data"),
                threat_score=enhanced_event.get("threat_score", 0),
            )

            enhanced_event["id"] = event_id

            # Check if alert should be triggered
            if self._should_trigger_alert(enhanced_event):
                self._create_alert(event_id, enhanced_event)

            # Notify UI callbacks
            for callback in self.event_callbacks:
                try:
                    callback(enhanced_event)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")

            logger.debug(
                f"Processed event: {enhanced_event.get('event_type')} (Score: {enhanced_event.get('threat_score', 0)})"
            )

        except Exception as e:
            logger.error(f"Error handling event: {e}")

    def _should_trigger_alert(self, event: dict) -> bool:
        """Determine if an alert should be triggered for this event."""
        threat_score = event.get("threat_score", 0)
        severity = event.get("severity", "Info")

        # Trigger alert for high threat scores
        if threat_score >= Settings.CRITICAL_THREAT_SCORE:
            return True

        # Trigger alert for critical severity
        if severity == "Critical":
            return True

        # Trigger alert for specific threat patterns
        if event.get("threat_pattern"):
            return True

        return False

    def _create_alert(self, event_id: int, event: dict):
        """Create an alert for a critical event."""
        try:
            # Get recommendations
            recommendations = self.threat_analyzer.get_recommendations(event)

            # Build alert message
            threat_pattern = event.get("threat_pattern", "")
            threat_score = event.get("threat_score", 0)

            if threat_pattern:
                message = f"{threat_pattern} detected (Threat Score: {threat_score})"
            else:
                message = f"{event.get('severity')} event: {event.get('event_type')} (Score: {threat_score})"

            # Store alert in database
            alert_id = self.db_manager.add_alert(
                event_id=event_id,
                alert_type=threat_pattern or event.get("event_type", "Security Alert"),
                message=message,
                recommendations="\n".join(recommendations) if recommendations else None,
            )

            alert = {
                "id": alert_id,
                "event_id": event_id,
                "alert_type": threat_pattern
                or event.get("event_type", "Security Alert"),
                "message": message,
                "recommendations": recommendations,
                "severity": event.get("severity"),
                "triggered_at": event.get("timestamp"),
            }

            # Notify alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")

            logger.warning(f"Alert triggered: {message}")

        except Exception as e:
            logger.error(f"Error creating alert: {e}")

    def get_event_statistics(self) -> dict:
        """Get current event statistics."""
        try:
            total_events = self.db_manager.get_total_event_count()
            critical_events = self.db_manager.get_critical_event_count()
            severity_counts = self.db_manager.get_event_counts_by_severity()

            return {
                "total_events": total_events,
                "critical_events": critical_events,
                "severity_counts": severity_counts,
            }
        except Exception as e:
            logger.error(f"Error getting event statistics: {e}")
            return {}
