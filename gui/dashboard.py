"""
Dashboard View
Main dashboard displaying overview statistics and charts.
"""

import customtkinter as ctk
from typing import Dict, List
from datetime import datetime

from gui.components.stat_cards import StatCard, ThreatScoreCard
from gui.components.charts import LineChart, DonutChart, BarChart


class DashboardView(ctk.CTkFrame):
    """Main dashboard view with statistics and charts."""

    def __init__(self, parent, db_manager, **kwargs):
        """
        Initialize dashboard view.

        Args:
            parent: Parent widget
            db_manager: Database manager instance
        """
        super().__init__(parent, **kwargs)

        self.db_manager = db_manager

        self.configure(fg_color="transparent")

        self._create_widgets()

    def _create_widgets(self):
        """Create dashboard widgets."""
        # Title
        title = ctk.CTkLabel(
            self, text="🛡️ Security Dashboard", font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Stat cards row
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(fill="x", padx=20, pady=(0, 20))

        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Create stat cards
        self.total_events_card = StatCard(
            stats_frame, title="Total Events", value="0", icon="📊", color="#2196F3"
        )
        self.total_events_card.grid(row=0, column=0, padx=5, sticky="ew")

        self.critical_events_card = StatCard(
            stats_frame, title="Critical Events", value="0", icon="🚨", color="#f44336"
        )
        self.critical_events_card.grid(row=0, column=1, padx=5, sticky="ew")

        self.threat_score_card = ThreatScoreCard(stats_frame)
        self.threat_score_card.grid(row=0, column=2, padx=5, sticky="ew")

        self.active_monitors_card = StatCard(
            stats_frame, title="Active Monitors", value="4", icon="👁️", color="#4CAF50"
        )
        self.active_monitors_card.grid(row=0, column=3, padx=5, sticky="ew")

        # Charts container
        charts_container = ctk.CTkFrame(self, fg_color="transparent")
        charts_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        charts_container.grid_columnconfigure((0, 1), weight=1)
        charts_container.grid_rowconfigure((0, 1), weight=1)

        # Events timeline chart
        self.timeline_chart = LineChart(
            charts_container, title="Events Over Time (Last 24 Hours)"
        )
        self.timeline_chart.grid(
            row=0, column=0, columnspan=2, padx=5, pady=5, sticky="nsew"
        )

        # Events by severity
        self.severity_chart = DonutChart(charts_container, title="Events by Severity")
        self.severity_chart.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Events by type
        self.type_chart = BarChart(charts_container, title="Top Event Types")
        self.type_chart.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

    def refresh(self):
        """Refresh dashboard data."""
        try:
            # Update stat cards
            total_events = self.db_manager.get_total_event_count()
            self.total_events_card.update_value(str(total_events))

            critical_events = self.db_manager.get_critical_event_count()
            self.critical_events_card.update_value(str(critical_events))

            # Calculate average threat score from recent events
            recent_events = self.db_manager.get_recent_events(minutes=60, limit=100)
            if recent_events:
                avg_threat_score = sum(
                    e.get("threat_score", 0) for e in recent_events
                ) // len(recent_events)
                self.threat_score_card.update_score(avg_threat_score)
            else:
                self.threat_score_card.update_score(0)

            # Update timeline chart
            timeline_data = self.db_manager.get_events_timeline(
                hours=24, interval_minutes=60
            )
            if timeline_data:
                times, counts = zip(*timeline_data)
                self.timeline_chart.update_data(
                    list(times), list(counts), label="Events", color="#2196F3"
                )
            else:
                self.timeline_chart.update_data([], [], label="Events")

            # Update severity chart
            severity_counts = self.db_manager.get_event_counts_by_severity()
            if severity_counts:
                labels = list(severity_counts.keys())
                values = list(severity_counts.values())
                colors = []
                for label in labels:
                    if label == "Critical":
                        colors.append("#f44336")
                    elif label == "Warning":
                        colors.append("#ff9800")
                    else:
                        colors.append("#2196F3")

                self.severity_chart.update_data(labels, values, colors)
            else:
                self.severity_chart.update_data([], [])

            # Update type chart
            type_counts = self.db_manager.get_event_counts_by_type(limit=8)
            if type_counts:
                labels, values = zip(*type_counts)
                self.type_chart.update_data(list(labels), list(values), color="#1f6aa5")
            else:
                self.type_chart.update_data([], [])

        except Exception as e:
            print(f"Error refreshing dashboard: {e}")
