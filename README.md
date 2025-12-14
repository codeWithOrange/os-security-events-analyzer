# Security Event Logger

A professional real-time OS security event monitoring application for Windows. This desktop application monitors and records OS-level security events, providing insights into potential vulnerabilities through an advanced dashboard interface.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

## 🌟 Features

### Monitoring Capabilities

- **Windows Event Logs**: Real-time monitoring of Security, System, and Application logs
- **System Statistics**: CPU, memory, disk, and process monitoring with anomaly detection
- **Network Activity**: Connection tracking, suspicious port detection, and port scan identification
- **File Integrity**: Monitor critical system directories for unauthorized changes

### Advanced Security Features

- **Threat Detection Engine**:
  - Brute force attack detection
  - Privilege escalation pattern recognition
  - Ransomware activity detection
  - Service installation monitoring
- **Threat Scoring**: Automatic risk assessment (0-100) for each event
- **Event Correlation**: Link related events to identify attack chains
- **Intelligent Recommendations**: Actionable security recommendations for each threat

### Professional Dashboard

- **Real-time Statistics Cards**: Total events, critical events, threat scores, active monitors
- **Interactive Charts**:
  - Events timeline (last 24 hours)
  - Events by severity (donut chart)
  - Top event types (bar chart)
- **Auto-refresh**: Configurable automatic data updates
- **Dark/Light Mode**: Modern theme support

### Data Management

- **SQLite Database**: Persistent event storage with indexing
- **Advanced Filtering**: Search events by keyword, severity, type, and date range
- **Export Functionality**: Export events to CSV or JSON
- **Data Retention**: Automatic cleanup of old events (configurable)

### User Interface

- **Event Log Viewer**: Searchable, sortable table with color-coded severity
- **Alert Management**: View and acknowledge security alerts
- **Event Details**: Detailed popup view for each event with recommendations
- **Responsive Design**: Professional CustomTkinter-based GUI

## 📋 Requirements

- **Operating System**: Windows 10/11 (requires Administrator privileges)
- **Python**: 3.8 or higher
- **Dependencies**:
  - customtkinter >= 5.2.1
  - matplotlib >= 3.8.2
  - psutil >= 5.9.6
  - pywin32 >= 306
  - pillow >= 10.1.0

## 🚀 Installation

1. **Clone or download the repository**:

   ```bash
   git clone <repository-url>
   cd security_logger
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python --version  # Should be 3.8+
   ```

## 💻 Usage

### Running the Application

**IMPORTANT**: This application requires Administrator privileges to access Windows Event Logs and monitor system-level activities.

1. **Open PowerShell or Command Prompt as Administrator**:

   - Right-click on PowerShell/CMD
   - Select "Run as Administrator"

2. **Navigate to the application directory**:

   ```bash
   cd e:\OSProjects\security_logger
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

### Using the Dashboard

1. **Dashboard View**:

   - View real-time statistics and charts
   - Monitor overall system threat level
   - Track events over time

2. **Event Log View**:

   - Browse all recorded security events
   - Filter by severity (Critical, Warning, Info)
   - Search events by keyword
   - Double-click any event to view detailed information
   - Export events to CSV

3. **Alerts View**:
   - View active security alerts
   - Read recommended actions for each alert
   - Acknowledge alerts after investigation
   - View associated events

### Understanding Threat Scores

- **0-29**: Low Risk (green) - Normal system activity
- **30-49**: Medium Risk (yellow) - Potentially suspicious activity
- **50-79**: High Risk (orange) - Suspicious activity requiring attention
- **80-100**: Critical Risk (red) - Immediate investigation required

### Common Security Events

- **Event 4625**: Failed login attempts (potential brute force)
- **Event 4720**: User account created (unauthorized access)
- **Event 4732**: User added to security group (privilege escalation)
- **Event 4697/7045**: Service installed (potential malware)
- **File Changes**: Rapid file modifications (possible ransomware)
- **Network Anomalies**: Suspicious port connections

## ⚙️ Configuration

Edit `config/settings.py` to customize:

- **Monitoring Intervals**: How often each monitor checks for events
- **Threat Thresholds**: Brute force detection sensitivity
- **Monitored Paths**: Directories for file integrity monitoring
- **Event Retention**: How long to keep historical data
- **Dashboard Refresh**: Auto-refresh interval for GUI

Example configuration:

```python
# Monitoring Intervals (in seconds)
WINDOWS_EVENT_POLL_INTERVAL = 5
SYSTEM_STATS_INTERVAL = 10
NETWORK_MONITOR_INTERVAL = 15
FILE_INTEGRITY_INTERVAL = 30

# Threat Detection Thresholds
BRUTE_FORCE_THRESHOLD = 5  # Failed logins
BRUTE_FORCE_TIME_WINDOW = 300  # 5 minutes

# Data Retention
EVENT_RETENTION_DAYS = 30
```

## 📊 Database Schema

The application uses SQLite with the following tables:

- **events**: Security events with timestamp, type, severity, description, threat score
- **alerts**: Security alerts linked to events with recommendations
- **system_stats**: System resource usage statistics over time

## 🛡️ Security Considerations

- **Administrator Privileges**: Required for full monitoring capabilities
- **Data Privacy**: All data is stored locally in SQLite database
- **Log Files**: Application logs stored in `logs/` directory
- **Resource Usage**: Monitors use minimal system resources
- **Network Monitoring**: Requires admin rights for connection details

## 🔧 Troubleshooting

### Application won't start

- Ensure running with Administrator privileges
- Check Python version (3.8+)
- Verify all dependencies are installed

### No events appearing

- Confirm Administrator privileges
- Check Windows Event Log service is running
- Review logs in `logs/` directory

### High CPU usage

- Increase monitoring intervals in settings
- Reduce number of monitored paths for file integrity
- Check for excessive security events

### Import errors

- Reinstall dependencies: `pip install -r requirements.txt`
- Ensure pywin32 is properly installed: `python -m pywin32_postinstall`

## 📁 Project Structure

```
security_logger/
├── main.py                      # Application entry point
├── requirements.txt             # Dependencies
├── config/
│   └── settings.py             # Configuration
├── core/
│   ├── database.py             # Database manager
│   ├── event_processor.py      # Event processing pipeline
│   └── threat_analyzer.py      # Threat detection engine
├── monitors/
│   ├── windows_events.py       # Windows Event Log monitor
│   ├── system_stats.py         # System statistics monitor
│   ├── network_monitor.py      # Network activity monitor
│   └── file_integrity.py       # File integrity monitor
├── gui/
│   ├── app.py                  # Main application window
│   ├── dashboard.py            # Dashboard view
│   ├── event_log_view.py       # Event log view
│   ├── alerts_view.py          # Alerts view
│   └── components/             # Reusable GUI components
└── utils/
    ├── admin_check.py          # Admin privilege verification
    └── logger.py               # Logging configuration
```

## 🎯 Use Cases

1. **Security Monitoring**: Track security events across your system in real-time
2. **Intrusion Detection**: Identify brute force attacks, privilege escalation, and suspicious activity
3. **Compliance**: Maintain audit logs of security events
4. **Incident Response**: Investigate security incidents with detailed event logs
5. **System Health**: Monitor system resource usage and network activity

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional threat detection patterns
- Cross-platform support (Linux, macOS)
- Enhanced visualization and reporting
- Machine learning-based anomaly detection
- Integration with SIEM systems

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is for legitimate security monitoring purposes only. Users are responsible for complying with applicable laws and regulations regarding system monitoring and logging.

## 🙏 Acknowledgments

- CustomTkinter for the modern GUI framework
- Matplotlib for chart visualization
- PSUtil for system monitoring
- PyWin32 for Windows API access

---

**Built with ❤️ for cybersecurity professionals and system administrators**
