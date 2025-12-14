"""
Administrator Privilege Checker
Verifies if the application is running with administrator privileges.
"""
import ctypes
import sys


def is_admin():
    """
    Check if the current process has administrator privileges.
    
    Returns:
        bool: True if running as administrator, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def require_admin():
    """
    Check for admin privileges and exit with error message if not elevated.
    """
    if not is_admin():
        print("=" * 60)
        print("ERROR: Administrator Privileges Required")
        print("=" * 60)
        print("\nThis application requires administrator privileges to:")
        print("  - Access Windows Event Logs")
        print("  - Monitor system-level security events")
        print("  - Track network connections")
        print("  - Monitor file system changes")
        print("\nPlease run this application as Administrator:")
        print("  1. Right-click on PowerShell or Command Prompt")
        print("  2. Select 'Run as Administrator'")
        print("  3. Navigate to the application directory")
        print("  4. Run: python main.py")
        print("\n" + "=" * 60)
        sys.exit(1)
