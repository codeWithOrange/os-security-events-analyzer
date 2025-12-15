"""
Application Configuration Settings
Centralized configuration management for the security logger.
"""

import os


class Settings:
    """Application configuration settings."""

    # Database Configuration
    DATABASE_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "security_events.db"
    )

    # Monitoring Intervals (in seconds)
    WINDOWS_EVENT_POLL_INTERVAL = 6
    SYSTEM_STATS_INTERVAL = 10
    NETWORK_MONITOR_INTERVAL = 15
    FILE_INTEGRITY_INTERVAL = 30

    # Event Log Sources to Monitor
    WINDOWS_EVENT_LOGS = ["Security", "System", "Application"]

    # Security Event IDs to Monitor
    SECURITY_EVENT_IDS = {
        # Logon/Logoff Events
        4624: "Successful Logon",
        4625: "Failed Logon",
        4634: "Logoff",
        4647: "User Initiated Logoff",
        # Account Management
        4720: "User Account Created",
        4722: "User Account Enabled",
        4723: "Password Change Attempted",
        4724: "Password Reset Attempted",
        4726: "User Account Deleted",
        4732: "Member Added to Security-Enabled Local Group",
        4733: "Member Removed from Security-Enabled Local Group",
        # Privilege Use
        4672: "Special Privileges Assigned to New Logon",
        4673: "Privileged Service Called",
        # Process Tracking
        4688: "New Process Created",
        4689: "Process Terminated",
        # Policy Changes
        4719: "System Audit Policy Changed",
        # System Events
        4697: "Service Installed",
        7045: "Service Installed (System Log)",
        # Object Access
        4663: "Object Access Attempted",
        4656: "Handle to Object Requested",
    }

    # Threat Detection Thresholds
    BRUTE_FORCE_THRESHOLD = 5  # Failed logins within time window
    BRUTE_FORCE_TIME_WINDOW = 300  # 5 minutes in seconds

    RAPID_FILE_CHANGE_THRESHOLD = 50  # File changes within time window
    RAPID_FILE_CHANGE_TIME_WINDOW = 60  # 1 minute in seconds

    # Alert Thresholds
    CRITICAL_THREAT_SCORE = 80
    WARNING_THREAT_SCORE = 50

    # GUI Configuration
    THEME_MODE = "dark"  # "dark", "light", "system"
    ACCENT_COLOR = "#1f6aa5"  # Blue

    DASHBOARD_REFRESH_INTERVAL = 5000  # milliseconds

    # Data Retention
    EVENT_RETENTION_DAYS = 30  # Keep events for 30 days

    # File Integrity Monitoring Paths
    MONITORED_PATHS = [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    ]

    # Critical Files to Monitor (specific files, including those in subdirectories)
    CRITICAL_FILES = [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",  # DNS resolution mapping
        "C:\\Windows\\System32\\drivers\\etc\\networks",  # Network names
        "C:\\Windows\\win.ini",  # Windows configuration
        "C:\\Windows\\system.ini",  # System configuration
    ]

    # Network Monitoring
    SUSPICIOUS_PORTS = [
        22,  # SSH
        23,  # Telnet
        3389,  # RDP
        4444,  # Metasploit default
        5900,  # VNC
        6666,  # IRC
    ]

    # Export Settings
    EXPORT_FORMATS = ["csv", "json"]
