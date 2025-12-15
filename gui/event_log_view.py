"""
Event Log View
Displays security events in a searchable, filterable table.
"""

import customtkinter as ctk
from tkinter import ttk, messagebox
import csv
import json
from datetime import datetime
from typing import List, Dict

from gui.components.event_details import EventDetailsDialog
from utils.logger import setup_logger

logger = setup_logger(__name__)


class EventLogView(ctk.CTkFrame):
    """Event log view with table and filters."""

    def __init__(self, parent, db_manager, **kwargs):
        """
        Initialize event log view.

        Args:
            parent: Parent widget
            db_manager: Database manager instance
        """
        super().__init__(parent, **kwargs)

        self.db_manager = db_manager
        self.current_events = []
        self.auto_refresh_enabled = True
        self.max_displayed_events = 400  # Limit to prevent performance issues

        self.configure(fg_color="transparent")

        self._create_widgets()

    def _create_widgets(self):
        """Create event log widgets."""
        # Title
        title = ctk.CTkLabel(
            self, text="📋 Event Log", font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Filters frame
        filters_frame = ctk.CTkFrame(self, fg_color=("gray85", "gray20"))
        filters_frame.pack(fill="x", padx=20, pady=(0, 10))

        filters_container = ctk.CTkFrame(filters_frame, fg_color="transparent")
        filters_container.pack(fill="x", padx=15, pady=15)

        # Search box
        search_label = ctk.CTkLabel(
            filters_container, text="Search:", font=ctk.CTkFont(size=12, weight="bold")
        )
        search_label.pack(side="left", padx=(0, 5))

        self.search_entry = ctk.CTkEntry(
            filters_container, placeholder_text="Search events...", width=200
        )
        self.search_entry.pack(side="left", padx=5)

        # Severity filter
        severity_label = ctk.CTkLabel(
            filters_container,
            text="Severity:",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        severity_label.pack(side="left", padx=(20, 5))

        self.severity_filter = ctk.CTkOptionMenu(
            filters_container, values=["All", "Critical", "Warning", "Info"], width=120
        )
        self.severity_filter.set("All")
        self.severity_filter.pack(side="left", padx=5)

        # Filter button
        filter_btn = ctk.CTkButton(
            filters_container,
            text="Apply Filters",
            command=self.apply_filters,
            width=120,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        filter_btn.pack(side="left", padx=10)

        # Clear All button
        clear_btn = ctk.CTkButton(
            filters_container,
            text="🗑️ Clear All",
            command=self.clear_all_data,
            width=120,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="blue",
            hover_color="#d32f2f",
        )
        clear_btn.pack(side="left", padx=5)

        # Export CSV button
        export_csv_btn = ctk.CTkButton(
            filters_container,
            text="📤 Export CSV",
            command=self.export_csv,
            width=120,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#4CAF50",
            hover_color="#45a049",
        )
        export_csv_btn.pack(side="right", padx=5)

        # Export JSON button
        export_json_btn = ctk.CTkButton(
            filters_container,
            text="📥 Export JSON",
            command=self.export_json,
            width=120,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#2196F3",
            hover_color="#1976D2",
        )
        export_json_btn.pack(side="right", padx=5)

        # Auto-refresh toggle
        self.auto_refresh_switch = ctk.CTkSwitch(
            filters_container,
            text="🔄 Live Updates",
            font=ctk.CTkFont(size=11),
            command=self._toggle_auto_refresh,
        )
        self.auto_refresh_switch.select()  # On by default
        self.auto_refresh_switch.pack(side="right", padx=10)

        # Table frame with scrollbar
        table_frame = ctk.CTkFrame(self, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Create treeview for events
        style = ttk.Style()
        style.theme_use("default")

        # Configure treeview colors for dark mode
        style.configure(
            "Treeview",
            background="#2b2b2b",
            foreground="white",
            fieldbackground="#2b2b2b",
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#1f6aa5",
            foreground="white",
            borderwidth=0,
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#1f6aa5")])

        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical")
        v_scrollbar.pack(side="right", fill="y")

        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal")
        h_scrollbar.pack(side="bottom", fill="x")

        # Create treeview
        columns = ("ID", "Time", "Type", "Severity", "Source", "Description", "Threat")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            yscrollcommand=v_scrollbar.set,
            xscrollcommand=h_scrollbar.set,
            selectmode="browse",
        )

        v_scrollbar.config(command=self.tree.yview)
        h_scrollbar.config(command=self.tree.xview)

        # Define columns
        self.tree.heading("ID", text="ID")
        self.tree.heading("Time", text="Timestamp")
        self.tree.heading("Type", text="Event Type")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Description", text="Description")
        self.tree.heading("Threat", text="Threat Score")

        # Set column widths
        self.tree.column("ID", width=50, minwidth=50)
        self.tree.column("Time", width=150, minwidth=100)
        self.tree.column("Type", width=150, minwidth=100)
        self.tree.column("Severity", width=80, minwidth=80)
        self.tree.column("Source", width=180, minwidth=100)
        self.tree.column("Description", width=300, minwidth=150)
        self.tree.column("Threat", width=80, minwidth=80)

        self.tree.pack(fill="both", expand=True)

        # Bind double-click to show details
        self.tree.bind("<Double-Button-1>", self._on_row_double_click)

        # Info label
        self.info_label = ctk.CTkLabel(
            self,
            text="No events loaded",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
        )
        self.info_label.pack(pady=(0, 20))

    def load_events(self, events: List[Dict] = None):
        """Load events into the table."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Get events from database if not provided
        if events is None:
            events = self.db_manager.get_events(limit=500)

        self.current_events = events

        # Add events to table
        for event in events:
            timestamp = event.get("timestamp", "")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass

            severity = event.get("severity", "Info")

            # Add row with tag for color coding
            item_id = self.tree.insert(
                "",
                "end",
                values=(
                    event.get("id", ""),
                    timestamp,
                    event.get("event_type", ""),
                    severity,
                    event.get("source", ""),
                    event.get("description", ""),
                    event.get("threat_score", 0),
                ),
                tags=(severity.lower(),),
            )

        # Configure row colors
        self.tree.tag_configure("critical", background="#7a1f1f")
        self.tree.tag_configure("warning", background="#7a5f1f")
        self.tree.tag_configure("info", background="#1f3a7a")

        # Update info label
        self.info_label.configure(text=f"Showing {len(events)} events")

    def apply_filters(self):
        """Apply search and filter criteria."""
        search_text = self.search_entry.get().lower()
        severity = self.severity_filter.get()

        # Get filtered events
        if search_text:
            events = self.db_manager.search_events(search_text, limit=500)
        else:
            events = self.db_manager.get_events(
                severity=severity if severity != "All" else None, limit=500
            )

        self.load_events(events)

    def _on_row_double_click(self, event):
        """Handle double-click on table row."""
        selection = self.tree.selection()
        if not selection:
            return

        # Get event ID from selected row
        item = self.tree.item(selection[0])
        event_id = item["values"][0]

        # Get full event details
        event = self.db_manager.get_event_by_id(event_id)

        if event:
            # Show details dialog
            EventDetailsDialog(self, event)

    def export_csv(self):
        """Export current events to CSV."""
        if not self.current_events:
            # Show error message
            error_label = ctk.CTkLabel(
                self,
                text="❌ No events to export. Please load events first.",
                font=ctk.CTkFont(size=11),
                text_color="#f44336",
            )
            error_label.pack(pady=(0, 10))

            # Remove after 3 seconds
            self.after(3000, error_label.destroy)
            return

        try:
            # Use absolute path in security_logger directory
            import os

            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = f"security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            filepath = os.path.join(base_dir, filename)

            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "id",
                        "timestamp",
                        "event_type",
                        "severity",
                        "source",
                        "description",
                        "event_id",
                        "threat_score",
                    ],
                )
                writer.writeheader()

                for event in self.current_events:
                    # Remove raw_data and created_at for CSV export
                    export_event = {
                        "id": event.get("id", ""),
                        "timestamp": event.get("timestamp", ""),
                        "event_type": event.get("event_type", ""),
                        "severity": event.get("severity", ""),
                        "source": event.get("source", ""),
                        "description": event.get("description", ""),
                        "event_id": event.get("event_id", ""),
                        "threat_score": event.get("threat_score", 0),
                    }
                    writer.writerow(export_event)

            # Show success message
            success_label = ctk.CTkLabel(
                self,
                text=f"✅ Exported {len(self.current_events)} events to:\n{filepath}",
                font=ctk.CTkFont(size=11),
                text_color="#4CAF50",
            )
            success_label.pack(pady=(0, 10))

            # Remove after 5 seconds
            self.after(5000, success_label.destroy)

            print(f"CSV exported successfully to: {filepath}")

        except PermissionError as e:
            # Permission error
            error_label = ctk.CTkLabel(
                self,
                text=f"❌ Permission denied. Cannot write to file.",
                font=ctk.CTkFont(size=11),
                text_color="#f44336",
            )
            error_label.pack(pady=(0, 10))
            self.after(3000, error_label.destroy)
            print(f"Permission error exporting CSV: {e}")

        except Exception as e:
            # General error
            error_label = ctk.CTkLabel(
                self,
                text=f"❌ Export failed: {str(e)}",
                font=ctk.CTkFont(size=11),
                text_color="#f44336",
            )
            error_label.pack(pady=(0, 10))
            self.after(3000, error_label.destroy)
            print(f"Error exporting CSV: {e}")

    def export_json(self):
        """Export current events to JSON."""
        if not self.current_events:
            # Show error message
            error_label = ctk.CTkLabel(
                self,
                text="❌ No events to export. Please load events first.",
                font=ctk.CTkFont(size=11),
                text_color="#f44336",
            )
            error_label.pack(pady=(0, 10))

            # Remove after 3 seconds
            self.after(3000, error_label.destroy)
            return

        try:
            # Use absolute path in security_logger directory
            import os

            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = (
                f"security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            filepath = os.path.join(base_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                # Create export data
                export_data = []
                for event in self.current_events:
                    # Remove raw_data for cleaner export
                    export_event = {
                        "id": event.get("id", ""),
                        "timestamp": event.get("timestamp", ""),
                        "event_type": event.get("event_type", ""),
                        "severity": event.get("severity", ""),
                        "source": event.get("source", ""),
                        "description": event.get("description", ""),
                        "event_id": event.get("event_id", ""),
                        "threat_score": event.get("threat_score", 0),
                    }
                    export_data.append(export_event)

                json.dump(export_data, f, indent=2, ensure_ascii=False)

            # Show success message
            success_label = ctk.CTkLabel(
                self,
                text=f"✅ Exported {len(self.current_events)} events to:\n{filepath}",
                font=ctk.CTkFont(size=11),
                text_color="#4CAF50",
            )
            success_label.pack(pady=(0, 10))

            # Remove after 5 seconds
            self.after(5000, success_label.destroy)

            print(f"JSON exported successfully to: {filepath}")

        except PermissionError as e:
            # Permission error
            error_label = ctk.CTkLabel(
                self,
                text=f"❌ Permission denied. Cannot write to file.",
                font=ctk.CTkFont(size=11),
                text_color="#f44336",
            )
            error_label.pack(pady=(0, 10))
            self.after(3000, error_label.destroy)
            print(f"Permission error exporting JSON: {e}")

        except Exception as e:
            # General error
            error_label = ctk.CTkLabel(
                self,
                text=f"❌ Export failed: {str(e)}",
                font=ctk.CTkFont(size=11),
                text_color="#f44336",
            )
            error_label.pack(pady=(0, 10))
            self.after(3000, error_label.destroy)
            print(f"Error exporting JSON: {e}")

    def on_new_event(self, event: Dict):
        """Called when a new event is logged (real-time update)."""
        if not self.auto_refresh_enabled:
            return

        # Only add if no filters are active
        search_text = self.search_entry.get().lower()
        severity_filter = self.severity_filter.get()

        # Skip if filters don't match
        if search_text or severity_filter != "All":
            return  # Don't add to filtered view

        # Add new event to the top of the table
        self.after(0, lambda: self._add_event_to_table(event))

    def _add_event_to_table(self, event: Dict):
        """Add a single event to the table (called on main thread)."""
        try:
            # Check if we've hit the limit
            if len(self.tree.get_children()) >= self.max_displayed_events:
                # Remove the oldest event (last item)
                children = self.tree.get_children()
                if children:
                    self.tree.delete(children[-1])

            # Format timestamp
            timestamp = event.get("timestamp", "")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass

            severity = event.get("severity", "Info")

            # Insert at the top (index 0)
            self.tree.insert(
                "",
                0,  # Insert at beginning
                values=(
                    event.get("id", ""),
                    timestamp,
                    event.get("event_type", ""),
                    severity,
                    event.get("source", ""),
                    event.get("description", ""),
                    event.get("threat_score", 0),
                ),
                tags=(severity.lower(),),
            )

            # Update info label
            count = len(self.tree.get_children())
            self.info_label.configure(text=f"Showing {count} events (Live)")

        except Exception as e:
            print(f"Error adding event to table: {e}")

    def _toggle_auto_refresh(self):
        """Toggle auto-refresh on/off."""
        self.auto_refresh_enabled = self.auto_refresh_switch.get() == 1
        if self.auto_refresh_enabled:
            # Refresh to get latest events
            self.refresh()

    def refresh(self):
        """Refresh event list."""
        self.load_events()

    def clear_all_data(self):
        """Clear all events from database with confirmation."""
        # Show confirmation dialog
        result = messagebox.askyesno(
            "Clear All Data",
            "This will permanently delete ALL events, alerts, and system statistics from the database.\n\n"
            "Are you sure you want to continue?",
            icon="warning",
        )

        if result:
            try:
                # Clear database
                events, alerts, stats = self.db_manager.clear_all_data()

                # Clear the table view
                for item in self.tree.get_children():
                    self.tree.delete(item)

                # Update info label
                self.info_label.configure(text="All data cleared")

                # Show success message
                success_label = ctk.CTkLabel(
                    self,
                    text=f"✅ Cleared {events} events, {alerts} alerts, {stats} system stats",
                    font=ctk.CTkFont(size=12),
                    text_color="#4CAF50",
                )
                success_label.pack(pady=(0, 10))

                # Remove after 5 seconds
                self.after(5000, success_label.destroy)

                logger.info("All data cleared successfully")

            except Exception as e:
                # Show error
                error_label = ctk.CTkLabel(
                    self,
                    text=f"❌ Error clearing data: {str(e)}",
                    font=ctk.CTkFont(size=12),
                    text_color="#f44336",
                )
                error_label.pack(pady=(0, 10))
                self.after(2000, error_label.destroy)
                print(f"Error clearing data: {e}")
