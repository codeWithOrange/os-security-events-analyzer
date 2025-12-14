"""
Alerts View
Displays active security alerts with acknowledgment capability.
"""

import customtkinter as ctk
from tkinter import ttk
from datetime import datetime
from typing import List, Dict
import threading


class AlertsView(ctk.CTkFrame):
    """Alerts view showing active security alerts."""

    def __init__(self, parent, db_manager, **kwargs):
        """
        Initialize alerts view.

        Args:
            parent: Parent widget
            db_manager: Database manager instance
        """
        super().__init__(parent, **kwargs)

        self.db_manager = db_manager
        self.is_loading = False
        self.alert_cards = {}  # Store references to alert cards

        self.configure(fg_color="transparent")

        self._create_widgets()

    def _create_widgets(self):
        """Create alerts widgets."""
        # Title
        title = ctk.CTkLabel(
            self, text="🚨 Security Alerts", font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Filter frame
        filter_frame = ctk.CTkFrame(self, fg_color=("gray85", "gray20"))
        filter_frame.pack(fill="x", padx=20, pady=(0, 10))

        filter_container = ctk.CTkFrame(filter_frame, fg_color="transparent")
        filter_container.pack(fill="x", padx=15, pady=15)

        # Show acknowledged toggle
        self.show_acknowledged = ctk.CTkSwitch(
            filter_container,
            text="Show Acknowledged Alerts",
            font=ctk.CTkFont(size=12),
            command=self.refresh,
        )
        self.show_acknowledged.pack(side="left")

        # Refresh button
        self.refresh_btn = ctk.CTkButton(
            filter_container,
            text="🔄 Refresh",
            command=self.refresh,
            width=100,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.refresh_btn.pack(side="right")

        # Loading indicator
        self.loading_label = ctk.CTkLabel(
            filter_container,
            text="Loading...",
            font=ctk.CTkFont(size=12),
            text_color="#2196F3",
        )
        # Don't pack yet, only shown during loading

        # Alerts container (scrollable)
        self.alerts_container = ctk.CTkScrollableFrame(self)
        self.alerts_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Info label
        self.info_label = ctk.CTkLabel(
            self,
            text="No alerts",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
        )
        self.info_label.pack(pady=(0, 20))

    def load_alerts(self):
        """Load alerts from database asynchronously."""
        if self.is_loading:
            return  # Prevent multiple simultaneous loads

        self.is_loading = True
        self.refresh_btn.configure(state="disabled")
        self.loading_label.pack(side="right", padx=(10, 10))

        # Run database query in background thread
        def load_in_background():
            try:
                show_ack = self.show_acknowledged.get() == 1
                alerts = self.db_manager.get_alerts(
                    acknowledged=None if show_ack else False,
                    limit=50,  # Limit to prevent too many widgets
                )

                # Update UI on main thread
                self.after(0, lambda: self._display_alerts(alerts))
            except Exception as e:
                print(f"Error loading alerts: {e}")
                self.after(0, self._loading_complete)

        # Start background thread
        thread = threading.Thread(target=load_in_background, daemon=True)
        thread.start()

    def _display_alerts(self, alerts: List[Dict]):
        """Display alerts in the UI (called on main thread)."""
        # Clear existing alerts
        for widget in self.alerts_container.winfo_children():
            widget.destroy()

        self.alert_cards.clear()

        if not alerts:
            self.info_label.configure(text="No alerts found")
            self._loading_complete()
            return

        # Display each alert
        for alert in alerts:
            card = self._create_alert_card(alert)
            if card:
                self.alert_cards[alert["id"]] = card

        self.info_label.configure(text=f"Showing {len(alerts)} alerts")
        self._loading_complete()

    def _loading_complete(self):
        """Complete loading state."""
        self.is_loading = False
        self.refresh_btn.configure(state="normal")
        self.loading_label.pack_forget()

    def _create_alert_card(self, alert: Dict):
        """Create a card for an alert."""
        # Determine color based on severity
        severity = alert.get("severity", "Warning")
        if severity == "Critical":
            border_color = "#f44336"
        elif severity == "Warning":
            border_color = "#ff9800"
        else:
            border_color = "#2196F3"

        # Card frame
        card = ctk.CTkFrame(
            self.alerts_container,
            fg_color=("gray90", "gray15"),
            border_width=3,
            border_color=border_color,
            corner_radius=10,
        )
        card.pack(fill="x", pady=5)

        # Header
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 5))

        # Alert type and severity
        type_label = ctk.CTkLabel(
            header,
            text=f"🚨 {alert.get('alert_type', 'Security Alert')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=border_color,
        )
        type_label.pack(side="left")

        # Severity badge
        severity_badge = ctk.CTkLabel(
            header,
            text=severity,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="white",
            fg_color=border_color,
            corner_radius=5,
            padx=8,
            pady=2,
        )

        severity_badge.pack(side="left", padx=(10, 0))

        # Timestamp
        triggered_at = alert.get("triggered_at", "")
        if triggered_at:
            try:
                dt = datetime.fromisoformat(triggered_at)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                timestamp = triggered_at
        else:
            timestamp = "Unknown"

        time_label = ctk.CTkLabel(
            header,
            text=timestamp,
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
        )
        time_label.pack(side="right")

        # Message
        message_label = ctk.CTkLabel(
            card,
            text=alert.get("message", ""),
            font=ctk.CTkFont(size=12),
            wraplength=800,
            justify="left",
            anchor="w",
        )
        message_label.pack(fill="x", padx=15, pady=(0, 10))

        # Recommendations
        recommendations = alert.get("recommendations", "")
        if recommendations:
            rec_frame = ctk.CTkFrame(
                card, fg_color=("gray80", "gray25"), corner_radius=5
            )
            rec_frame.pack(fill="x", padx=15, pady=(0, 10))

            rec_title = ctk.CTkLabel(
                rec_frame,
                text="Recommended Actions:",
                font=ctk.CTkFont(size=11, weight="bold"),
                anchor="w",
            )
            rec_title.pack(fill="x", padx=10, pady=(10, 5))

            rec_text = ctk.CTkLabel(
                rec_frame,
                text=recommendations,
                font=ctk.CTkFont(size=11),
                wraplength=780,
                justify="left",
                anchor="w",
            )
            rec_text.pack(fill="x", padx=10, pady=(0, 10))

        # Actions
        actions_frame = ctk.CTkFrame(card, fg_color="transparent")
        actions_frame.pack(fill="x", padx=15, pady=(0, 15))

        # View event button
        view_btn = ctk.CTkButton(
            actions_frame,
            text="View Event",
            command=lambda: self._view_event(alert.get("event_id")),
            width=120,
            height=30,
            font=ctk.CTkFont(size=11),
        )
        view_btn.pack(side="left", padx=(0, 5))

        # Acknowledge button (if not acknowledged)
        if not alert.get("acknowledged"):
            ack_btn = ctk.CTkButton(
                actions_frame,
                text="Acknowledge",
                command=lambda aid=alert.get(
                    "id"
                ), af=actions_frame: self._acknowledge_alert(aid, af),
                width=120,
                height=30,
                font=ctk.CTkFont(size=11),
                fg_color="#4CAF50",
                hover_color="#45a049",
            )
            ack_btn.pack(side="left")
        else:
            ack_label = ctk.CTkLabel(
                actions_frame,
                text="✅ Acknowledged",
                font=ctk.CTkFont(size=11),
                text_color="#4CAF50",
            )
            ack_label.pack(side="left")

        return card

    def _view_event(self, event_id: int):
        """View the event associated with an alert."""
        if not event_id:
            return

        try:
            event = self.db_manager.get_event_by_id(event_id)
            if event:
                from gui.components.event_details import EventDetailsDialog

                EventDetailsDialog(self, event)
        except Exception as e:
            print(f"Error viewing event: {e}")

    def _acknowledge_alert(self, alert_id: int, actions_frame):
        """Acknowledge an alert without full refresh."""
        try:
            # Update database
            self.db_manager.acknowledge_alert(alert_id)

            # Update UI without full refresh - just replace button with label
            for widget in actions_frame.winfo_children():
                if (
                    isinstance(widget, ctk.CTkButton)
                    and widget.cget("text") == "Acknowledge"
                ):
                    widget.destroy()
                    break

            # Add acknowledged label
            ack_label = ctk.CTkLabel(
                actions_frame,
                text="✅ Acknowledged",
                font=ctk.CTkFont(size=11),
                text_color="#4CAF50",
            )
            ack_label.pack(side="left")

        except Exception as e:
            print(f"Error acknowledging alert: {e}")

    def refresh(self):
        """Refresh alerts list."""
        self.load_alerts()
