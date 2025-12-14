"""
Threat Analyzer
Advanced threat detection and event correlation engine.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class ThreatAnalyzer:
    """Analyzes security events and detects threat patterns."""

    def __init__(self):
        """Initialize threat analyzer."""
        # Track failed login attempts by user
        self.failed_logins: Dict[str, List[datetime]] = defaultdict(list)

        # Track privilege escalation attempts
        self.privilege_events: List[tuple] = []

        # Track service installations
        self.service_installations: List[tuple] = []

    def analyze_event(self, event: dict) -> dict:
        """
        Analyze a security event and enhance it with threat intelligence.

        Args:
            event: Event dictionary

        Returns:
            Enhanced event with additional threat information
        """
        event_type = event.get("event_type", "")
        event_id = event.get("event_id")

        # Brute force detection
        if "Failed Logon" in event_type or event_id == 4625:
            result = self._analyze_brute_force(event)
            if result:
                event["threat_score"] = max(
                    event.get("threat_score", 0), result["threat_score"]
                )
                event["threat_pattern"] = result["pattern"]

        # Privilege escalation detection
        elif event_id in [4672, 4673, 4732]:
            result = self._analyze_privilege_escalation(event)
            if result:
                event["threat_score"] = max(
                    event.get("threat_score", 0), result["threat_score"]
                )
                event["threat_pattern"] = result["pattern"]

        # Service installation detection
        elif event_id in [4697, 7045]:
            result = self._analyze_service_installation(event)
            if result:
                event["threat_score"] = max(
                    event.get("threat_score", 0), result["threat_score"]
                )
                event["threat_pattern"] = result["pattern"]

        # Ransomware pattern
        elif "Ransomware" in event_type:
            event["threat_score"] = 95
            event["threat_pattern"] = "Ransomware Activity"

        return event

    def _analyze_brute_force(self, event: dict) -> dict:
        """Detect brute force login attempts."""
        try:
            # Extract username from event
            raw_data = event.get("raw_data", {})
            strings = raw_data.get("strings", [])

            username = "unknown"
            if len(strings) > 5:
                username = strings[5]

            # Track failed login
            now = datetime.now()
            self.failed_logins[username].append(now)

            # Clean up old attempts
            cutoff = now - timedelta(seconds=Settings.BRUTE_FORCE_TIME_WINDOW)
            self.failed_logins[username] = [
                t for t in self.failed_logins[username] if t > cutoff
            ]

            # Check if threshold exceeded
            attempt_count = len(self.failed_logins[username])
            if attempt_count >= Settings.BRUTE_FORCE_THRESHOLD:
                logger.warning(
                    f"Brute force detected: {attempt_count} failed logins for {username}"
                )
                return {
                    "threat_score": min(70 + (attempt_count * 5), 100),
                    "pattern": f"Brute Force Attack ({attempt_count} attempts)",
                    "username": username,
                    "attempt_count": attempt_count,
                }

        except Exception as e:
            logger.error(f"Error analyzing brute force: {e}")

        return None

    def _analyze_privilege_escalation(self, event: dict) -> dict:
        """Detect privilege escalation patterns."""
        try:
            now = datetime.now()
            self.privilege_events.append((now, event))

            # Clean up old events
            cutoff = now - timedelta(minutes=10)
            self.privilege_events = [
                (t, e) for t, e in self.privilege_events if t > cutoff
            ]

            # Check for multiple privilege events in short time
            if len(self.privilege_events) >= 3:
                logger.warning(
                    f"Privilege escalation pattern detected: {len(self.privilege_events)} events"
                )
                return {
                    "threat_score": 75,
                    "pattern": f"Privilege Escalation Pattern ({len(self.privilege_events)} events)",
                }

        except Exception as e:
            logger.error(f"Error analyzing privilege escalation: {e}")

        return None

    def _analyze_service_installation(self, event: dict) -> dict:
        """Analyze service installation events."""
        try:
            now = datetime.now()
            self.service_installations.append((now, event))

            # Clean up old events
            cutoff = now - timedelta(minutes=30)
            self.service_installations = [
                (t, e) for t, e in self.service_installations if t > cutoff
            ]

            # Multiple service installations can indicate malware
            if len(self.service_installations) >= 3:
                logger.warning(
                    f"Multiple service installations detected: {len(self.service_installations)}"
                )
                return {
                    "threat_score": 65,
                    "pattern": f"Suspicious Service Activity ({len(self.service_installations)} installations)",
                }

        except Exception as e:
            logger.error(f"Error analyzing service installation: {e}")

        return None

    def get_recommendations(self, event: dict) -> List[str]:
        """
        Get security recommendations based on event.

        Args:
            event: Event dictionary

        Returns:
            List of recommended actions
        """
        recommendations = []

        event_type = event.get("event_type", "")
        threat_score = event.get("threat_score", 0)
        threat_pattern = event.get("threat_pattern", "")

        # Brute force recommendations
        if "Brute Force" in threat_pattern:
            recommendations.extend(
                [
                    "🔒 Lock the affected user account temporarily",
                    "🛡️ Implement account lockout policy",
                    "📧 Notify the user about suspicious login attempts",
                    "🔍 Review access logs for the source IP address",
                    "⚙️ Consider implementing multi-factor authentication",
                ]
            )

        # Privilege escalation
        elif "Privilege Escalation" in threat_pattern:
            recommendations.extend(
                [
                    "🔍 Investigate the user account and recent activities",
                    "🛡️ Review privilege assignments",
                    "📋 Check for unauthorized group memberships",
                    "🔒 Implement principle of least privilege",
                    "📊 Audit system administrator accounts",
                ]
            )

        # Ransomware
        elif "Ransomware" in event_type or "Ransomware" in threat_pattern:
            recommendations.extend(
                [
                    "🚨 IMMEDIATE: Isolate affected systems from network",
                    "💾 Check backup integrity",
                    "🔍 Identify patient zero and attack vector",
                    "🛡️ Run full antivirus scan",
                    "📞 Consider contacting incident response team",
                ]
            )

        # Service installation
        elif "Service" in event_type:
            recommendations.extend(
                [
                    "🔍 Verify the service is legitimate",
                    "🛡️ Check service executable signature",
                    "📋 Review service permissions and account",
                    "🔒 Disable service if suspicious",
                    "📊 Monitor service activity",
                ]
            )

        # Network threats
        elif "Network" in event.get("source", "") or "Port" in event_type:
            recommendations.extend(
                [
                    "🔍 Investigate the remote IP address",
                    "🛡️ Check firewall rules",
                    "📋 Review connection logs",
                    "🔒 Block suspicious IPs if confirmed malicious",
                    "📊 Monitor for continued activity",
                ]
            )

        # File integrity
        elif "File" in event_type:
            recommendations.extend(
                [
                    "🔍 Verify file changes are authorized",
                    "📋 Review file permissions",
                    "🛡️ Check file signature if critical system file",
                    "💾 Restore from backup if unauthorized",
                    "📊 Monitor for additional changes",
                ]
            )

        # Generic high-threat recommendations
        if threat_score >= Settings.CRITICAL_THREAT_SCORE and not recommendations:
            recommendations.extend(
                [
                    "🚨 Investigate immediately",
                    "📋 Document all findings",
                    "🔍 Check system logs for related events",
                    "🛡️ Consider quarantining affected system",
                    "📞 Escalate to security team",
                ]
            )

        return recommendations
