"""
Main Application Window
Security Event Logger GUI application.
"""

import customtkinter as ctk
from typing import Optional

from gui.dashboard import DashboardView
from gui.event_log_view import EventLogView
from gui.alerts_view import AlertsView
from core.database import DatabaseManager
from core.event_processor import EventProcessor
from monitors.windows_events import WindowsEventMonitor
from monitors.system_stats import SystemStatsMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.file_integrity import FileIntegrityMonitor
from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class SecurityLoggerApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        """Initialize the application."""
        super().__init__()

        # Configure window
        self.title("Security Event Logger")
        self.geometry("1400x900")

        # Set theme
        ctk.set_appearance_mode(Settings.THEME_MODE)
        ctk.set_default_color_theme("blue")

        # Initialize components
        self.db_manager = DatabaseManager()
        self.event_processor = EventProcessor(self.db_manager)

        # Monitoring services
        self.monitors = {
            "windows_events": None,
            "system_stats": None,
            "network": None,
            "file_integrity": None,
        }

        # Monitoring state
        self.monitoring_active = False

        # Current view
        self.current_view = None

        # Create GUI
        self._create_widgets()

        # Start monitoring
        self._start_monitoring()

        # Setup auto-refresh
        self._setup_auto_refresh()

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        logger.info("Application started successfully")

    def _create_widgets(self):
        """Create application widgets."""
        # Main container
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        # Logo/Title
        logo_label = ctk.CTkLabel(
            self.sidebar,
            text="🛡️ Security\nLogger",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        # Navigation buttons
        self.dashboard_btn = ctk.CTkButton(
            self.sidebar,
            text="📊 Dashboard",
            command=self.show_dashboard,
            font=ctk.CTkFont(size=14),
            height=40,
            anchor="w",
        )
        self.dashboard_btn.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.events_btn = ctk.CTkButton(
            self.sidebar,
            text="📋 Event Log",
            command=self.show_events,
            font=ctk.CTkFont(size=14),
            height=40,
            anchor="w",
            fg_color="transparent",
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray30"),
        )
        self.events_btn.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.alerts_btn = ctk.CTkButton(
            self.sidebar,
            text="🚨 Alerts",
            command=self.show_alerts,
            font=ctk.CTkFont(size=14),
            height=40,
            anchor="w",
            fg_color="transparent",
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray30"),
        )
        self.alerts_btn.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        # Control buttons section
        control_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        control_frame.grid(row=4, column=0, padx=20, pady=(20, 10), sticky="ew")

        control_title = ctk.CTkLabel(
            control_frame, text="Controls", font=ctk.CTkFont(size=12, weight="bold")
        )
        control_title.pack(anchor="w", pady=(0, 10))

        # Start button
        self.start_btn = ctk.CTkButton(
            control_frame,
            text="▶️ Start Monitoring",
            command=self.start_monitoring,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=35,
            fg_color="#4CAF50",
            hover_color="#45a049",
            state="disabled",  # Disabled by default since monitoring starts automatically
        )
        self.start_btn.pack(fill="x", pady=5)

        # Stop button
        self.stop_btn = ctk.CTkButton(
            control_frame,
            text="⏸️ Stop Monitoring",
            command=self.stop_monitoring,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=35,
            fg_color="green",
            hover_color="#f57c00",
        )
        self.stop_btn.pack(fill="x", pady=5)

        # Exit button
        self.exit_btn = ctk.CTkButton(
            control_frame,
            text="🚪 Exit Application",
            command=self.on_closing,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=35,
            fg_color="#f44336",
            hover_color="#d32f2f",
        )
        self.exit_btn.pack(fill="x", pady=5)

        # Monitoring status
        status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        status_frame.grid(row=7, column=0, padx=20, pady=20, sticky="ew")

        status_title = ctk.CTkLabel(
            status_frame,
            text="Monitor Status",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        status_title.pack(anchor="w", pady=(0, 10))

        self.status_labels = {}
        monitors = [
            ("Windows Events", "windows_events"),
            ("System Stats", "system_stats"),
            ("Network", "network"),
            ("File Integrity", "file_integrity"),
        ]

        for name, key in monitors:
            label = ctk.CTkLabel(
                status_frame,
                text=f"● {name}",
                font=ctk.CTkFont(size=10),
                text_color="#4CAF50",
                anchor="w",
            )
            label.pack(anchor="w", pady=2)
            self.status_labels[key] = label

        # Theme toggle
        theme_label = ctk.CTkLabel(
            self.sidebar, text="Appearance", font=ctk.CTkFont(size=12, weight="bold")
        )
        theme_label.grid(row=8, column=0, padx=20, pady=(20, 5), sticky="w")

        self.theme_switch = ctk.CTkSegmentedButton(
            self.sidebar, values=["Dark", "Light"], command=self.change_theme
        )
        self.theme_switch.set("Dark")
        self.theme_switch.grid(row=9, column=0, padx=20, pady=(0, 20), sticky="ew")

        # Main content area
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew")

        # Create views (but don't pack them yet)
        self.dashboard_view = DashboardView(self.content_frame, self.db_manager)
        self.event_log_view = EventLogView(self.content_frame, self.db_manager)
        self.alerts_view = AlertsView(self.content_frame, self.db_manager)

        # Show dashboard by default
        self.show_dashboard()

    def show_dashboard(self):
        """Show dashboard view."""
        self._switch_view(self.dashboard_view)
        self._set_active_button(self.dashboard_btn)
        self.dashboard_view.refresh()

    def show_events(self):
        """Show event log view."""
        self._switch_view(self.event_log_view)
        self._set_active_button(self.events_btn)
        self.event_log_view.refresh()

    def show_alerts(self):
        """Show alerts view."""
        self._switch_view(self.alerts_view)
        self._set_active_button(self.alerts_btn)
        self.alerts_view.refresh()

    def _switch_view(self, new_view):
        """Switch to a different view."""
        # Hide current view
        if self.current_view:
            self.current_view.pack_forget()

        # Show new view
        new_view.pack(fill="both", expand=True)
        self.current_view = new_view

    def _set_active_button(self, active_btn):
        """Set the active navigation button."""
        buttons = [self.dashboard_btn, self.events_btn, self.alerts_btn]

        for btn in buttons:
            if btn == active_btn:
                btn.configure(fg_color=("#3b8ed0", "#1f6aa5"), text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=("gray10", "gray90"))

    def change_theme(self, value):
        """Change application theme."""
        mode = value.lower()
        ctk.set_appearance_mode(mode)

    def _start_monitoring(self):
        """Start all monitoring services (called on application startup)."""
        try:
            # Start event processor
            self.event_processor.start()

            # Register event log callback for real-time updates
            self.event_processor.register_event_callback(
                self.event_log_view.on_new_event
            )

            # Windows Events Monitor
            self.monitors["windows_events"] = WindowsEventMonitor(
                event_callback=self.event_processor.process_event
            )
            self.monitors["windows_events"].start()

            # System Stats Monitor
            self.monitors["system_stats"] = SystemStatsMonitor(
                event_callback=self.event_processor.process_event,
                stats_callback=self._on_system_stats,
            )
            self.monitors["system_stats"].start()

            # Network Monitor
            self.monitors["network"] = NetworkMonitor(
                event_callback=self.event_processor.process_event
            )
            self.monitors["network"].start()

            # File Integrity Monitor
            self.monitors["file_integrity"] = FileIntegrityMonitor(
                event_callback=self.event_processor.process_event
            )
            self.monitors["file_integrity"].start()

            self.monitoring_active = True
            self._update_monitor_status()
            self._update_control_buttons()

            logger.info("All monitors started successfully")

        except Exception as e:
            logger.error(f"Error starting monitors: {e}")

    def start_monitoring(self):
        """Start monitoring (called by Start button)."""
        if self.monitoring_active:
            return

        logger.info("Starting monitoring services...")
        self._start_monitoring()

    def stop_monitoring(self):
        """Stop all monitoring services."""
        if not self.monitoring_active:
            return

        logger.info("Stopping monitoring services...")

        try:
            # Stop all monitors
            for name, monitor in self.monitors.items():
                if monitor:
                    try:
                        monitor.stop()
                        logger.info(f"Stopped {name} monitor")
                    except Exception as e:
                        logger.error(f"Error stopping {name} monitor: {e}")

            # Stop event processor
            self.event_processor.stop()

            self.monitoring_active = False
            self._update_monitor_status()
            self._update_control_buttons()

            logger.info("All monitors stopped")

        except Exception as e:
            logger.error(f"Error stopping monitors: {e}")

    def _update_monitor_status(self):
        """Update monitor status indicators."""
        if self.monitoring_active:
            color = "#4CAF50"  # Green
            symbol = "●"  # Filled circle
        else:
            color = "#757575"  # Gray
            symbol = "○"  # Empty circle

        for key, label in self.status_labels.items():
            name = label.cget("text").split(" ", 1)[1]  # Get name after symbol
            label.configure(text=f"{symbol} {name}", text_color=color)

    def _update_control_buttons(self):
        """Update control button states."""
        if self.monitoring_active:
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
        else:
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")

    def _on_system_stats(self, stats: dict):
        """Handle system statistics update."""
        try:
            self.db_manager.add_system_stat(
                cpu_percent=stats.get("cpu_percent", 0),
                memory_percent=stats.get("memory_percent", 0),
                memory_used_mb=stats.get("memory_used_mb", 0),
                disk_usage_percent=stats.get("disk_usage_percent", 0),
                network_bytes_sent=stats.get("network_bytes_sent", 0),
                network_bytes_recv=stats.get("network_bytes_recv", 0),
                active_connections=stats.get("active_connections", 0),
            )
        except Exception as e:
            logger.error(f"Error saving system stats: {e}")

    def _setup_auto_refresh(self):
        """Setup automatic refresh of current view."""

        def refresh():
            if self.current_view == self.dashboard_view:
                self.dashboard_view.refresh()

            # Schedule next refresh
            self.after(Settings.DASHBOARD_REFRESH_INTERVAL, refresh)

        # Start refresh loop
        self.after(Settings.DASHBOARD_REFRESH_INTERVAL, refresh)

    def on_closing(self):
        """Handle application close."""
        logger.info("Shutting down application...")

        # Immediately withdraw (hide) the window so user sees instant response
        self.withdraw()

        # Force update to ensure window is hidden
        self.update()

        # Stop all monitors with reduced timeout to prevent hanging
        for name, monitor in self.monitors.items():
            if monitor:
                try:
                    monitor.stop()
                    logger.info(f"Stopped {name} monitor")
                except Exception as e:
                    logger.error(f"Error stopping {name} monitor: {e}")

        # Stop event processor
        try:
            self.event_processor.stop()
        except Exception as e:
            logger.error(f"Error stopping event processor: {e}")

        # Skip cleanup on exit for faster shutdown (cleanup happens on next start anyway)
        # This prevents the delay from database operations

        logger.info("Application shutdown complete")

        # Destroy the window
        self.destroy()


def main():
    """Main entry point."""
    app = SecurityLoggerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
