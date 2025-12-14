# Enable Windows Process Auditing

## Why Process Creation Events Aren't Being Logged

By default, Windows **does not log process creation events** (Event ID 4688). You need to enable this in the Windows Audit Policy.

## How to Enable Process Auditing

### Method 1: Local Group Policy Editor (Recommended)

1. **Open Group Policy Editor** (as Administrator):
   ```cmd
   gpedit.msc
   ```

2. Navigate to:
   ```
   Computer Configuration
   └── Windows Settings
       └── Security Settings
           └── Advanced Audit Policy Configuration
               └── Audit Policies
                   └── Detailed Tracking
   ```

3. **Double-click** on `Audit Process Creation`

4. Check both boxes:
   - ✅ Configure the following audit events
   - ✅ Success
   - ✅ Failure (optional)

5. Click **OK**

### Method 2: Command Line (Quick)

Run this command in **Administrator Command Prompt**:

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

### Method 3: PowerShell (Quick)

Run this in **Administrator PowerShell**:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

## Enable Command Line Auditing (Optional but Recommended)

To see the **full command line** of created processes (like your PowerShell command):

### Via Group Policy:

1. In `gpedit.msc`, navigate to:
   ```
   Computer Configuration
   └── Administrative Templates
       └── System
           └── Audit Process Creation
   ```

2. **Double-click** `Include command line in process creation events`

3. Select **Enabled**

4. Click **OK**

### Via Registry (Alternative):

```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

## Verify It's Working

1. **Restart your security logger** after enabling auditing

2. Run a test command:
   ```cmd
   powershell -command "Write-Host 'Test'"
   ```

3. **Within 5 seconds**, you should see in your security logger:
   - Event Type: "New Process Created"
   - Severity: Warning
   - Description: Shows "powershell.exe" and the command (if command line auditing is enabled)

## What You'll See

Once enabled, your security logger will detect:
- ✅ PowerShell executions (including your memory allocation command)
- ✅ CMD executions
- ✅ Executable launches
- ✅ Script executions
- ✅ Suspicious process creation patterns

## Troubleshooting

### Still not seeing events?

1. **Check Event Viewer manually**:
   - Open Event Viewer (`eventvwr.msc`)
   - Go to: Windows Logs → Security
   - Filter for Event ID 4688
   - If you don't see events here, the audit policy isn't applied

2. **Force policy update**:
   ```cmd
   gpupdate /force
   ```

3. **Check current audit settings**:
   ```cmd
   auditpol /get /subcategory:"Process Creation"
   ```

   Should show:
   ```
   Process Creation    Success
   ```

## Security Note

⚠️ **Warning**: Process auditing can generate a **large volume of events** on busy systems. Monitor your disk space and consider:
- Adjusting `EVENT_RETENTION_DAYS` in settings
- Using the cleanup feature regularly
- Monitoring only critical processes (advanced configuration)

