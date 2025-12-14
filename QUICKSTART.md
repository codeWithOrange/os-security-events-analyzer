# Quick Start Guide - Security Event Logger

## 🚀 Get Started in 3 Steps

### Step 1: Open PowerShell as Administrator

**IMPORTANT**: This application requires Administrator privileges!

1. Press `Windows + X`
2. Select "Windows PowerShell (Admin)" or "Terminal (Admin)"
3. Click "Yes" on the UAC prompt

### Step 2: Navigate to the Application

```powershell
cd e:\OSProjects\security_logger
```

### Step 3: Run the Application

```powershell
python main.py
```

---

## 🎯 What to Expect

### On First Launch

1. **Database Creation**: SQLite database will be automatically created
2. **Monitor Startup**: All 4 monitoring services will start:

   - ✅ Windows Event Log Monitor
   - ✅ System Statistics Monitor
   - ✅ Network Activity Monitor
   - ✅ File Integrity Monitor

3. **Initial Dashboard**: You'll see the dashboard with:
   - Statistics cards (initially showing 0)
   - Empty charts (will populate as events occur)
   - Green status indicators for all monitors

### After a Few Minutes

- Windows security events will start appearing
- System statistics will be collected
- Network connections will be tracked
- File integrity baseline will be established
- Dashboard charts will update every 5 seconds

---

## 🔍 Exploring the Application

### Dashboard View (Default)

- View real-time statistics
- See events timeline chart
- Monitor threat score
- Check system status

### Event Log View

- Click "📋 Event Log" in sidebar
- Browse all recorded events
- Search for specific events
- Filter by severity
- Double-click any event for details
- Export to CSV

### Alerts View

- Click "🚨 Alerts" in sidebar
- View security alerts
- Read recommendations
- Acknowledge alerts

---

## 💡 Quick Tips

### To Generate Test Events

1. **Failed Login Event**:

   - Try wrong password on lock screen
   - Will trigger brute force detection after 5 attempts

2. **Network Events**:

   - Browse websites
   - Open applications that use network
   - Events will appear automatically

3. **System Events**:
   - Run resource-intensive applications
   - Watch for CPU/Memory alerts

### Customization

Edit `config/settings.py` to adjust:

- Monitoring intervals
- Threat detection thresholds
- File paths to monitor
- Dashboard refresh rate

---

## ⚠️ Troubleshooting

### "Administrator Privileges Required" Error

- **Solution**: Run PowerShell as Administrator (Step 1)

### No Events Appearing

- **Wait**: Events take a few minutes to appear
- **Generate**: Manually trigger system events (see tips above)
- **Check**: Verify all monitors show green status

### Import Errors

```powershell
pip install -r requirements.txt
```

---

## 🎨 Theme Toggle

- Use the "Dark/Light" toggle at bottom of sidebar
- Switch between dark and light modes
- Preference is saved

---

## 📊 Understanding the Dashboard

### Stat Cards

- **Total Events**: All events recorded
- **Critical Events**: High-severity events only
- **Threat Score**: Average threat level (0-100)
  - 0-29: 🟢 Low Risk
  - 30-49: 🟡 Medium Risk
  - 50-79: 🟠 High Risk
  - 80-100: 🔴 Critical Risk
- **Active Monitors**: Number of running monitors (should be 4)

### Charts

1. **Events Over Time**: 24-hour event history
2. **Events by Severity**: Distribution breakdown
3. **Top Event Types**: Most frequent events

---

## 🛡️ Security Best Practices

1. **Regular Monitoring**: Check dashboard daily
2. **Investigate Alerts**: Review all critical alerts
3. **Export Data**: Periodically export event logs
4. **Update Baselines**: Restart to update file integrity baselines
5. **Review Settings**: Adjust thresholds based on your environment

---

## 📝 Notes

- **Database Location**: `e:\OSProjects\security_logger\security_events.db`
- **Logs Location**: `e:\OSProjects\security_logger\logs\`
- **Data Retention**: Events older than 30 days are auto-deleted
- **Auto-Refresh**: Dashboard updates every 5 seconds

---

## 🆘 Need Help?

Refer to `README.md` for:

- Detailed feature documentation
- Configuration options
- Event ID reference
- Troubleshooting guide

---

**You're all set! Enjoy monitoring your system security! 🎉**
