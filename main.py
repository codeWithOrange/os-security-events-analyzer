"""
Security Event Logger
Real-time OS security event monitoring and logging application.

This application monitors Windows Event Logs, system statistics, network activity,
and file integrity to detect potential security threats and vulnerabilities.
"""
from utils.admin_check import require_admin
from utils.logger import setup_logger
from gui.app import main

logger = setup_logger(__name__)


if __name__ == "__main__":
    # Check for administrator privileges
    require_admin()
    
    logger.info("=" * 60)
    logger.info("Security Event Logger Starting...")
    logger.info("=" * 60)
    
    # Start application
    main()
