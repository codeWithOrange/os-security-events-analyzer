"""
Event Details Component
Popup window showing detailed event information.
"""
import customtkinter as ctk
import json
from typing import Dict


class EventDetailsDialog(ctk.CTkToplevel):
    """Dialog showing detailed event information."""
    
    def __init__(self, parent, event: Dict):
        """
        Initialize event details dialog.
        
        Args:
            parent: Parent window
            event: Event dictionary
        """
        super().__init__(parent)
        
        self.event = event
        
        # Configure window
        self.title(f"Event Details - {event.get('event_type', 'Unknown')}")
        self.geometry("700x600")
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        self._create_widgets()
        
        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (700 // 2)
        y = (self.winfo_screenheight() // 2) - (600 // 2)
        self.geometry(f"700x600+{x}+{y}")
    
    def _create_widgets(self):
        """Create dialog widgets."""
        # Header
        header = ctk.CTkFrame(self, fg_color=("gray80", "gray25"))
        header.pack(fill="x", padx=0, pady=0)
        
        title = ctk.CTkLabel(
            header,
            text=f"🔍 {self.event.get('event_type', 'Unknown Event')}",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(padx=20, pady=15)
        
        # Scrollable content
        content_frame = ctk.CTkScrollableFrame(self)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Basic Information
        self._add_section(content_frame, "Basic Information")
        
        info_items = [
            ("Event ID", self.event.get('id', 'N/A')),
            ("Timestamp", self.event.get('timestamp', 'N/A')),
            ("Event Type", self.event.get('event_type', 'N/A')),
            ("Severity", self.event.get('severity', 'N/A')),
            ("Source", self.event.get('source', 'N/A')),
            ("Windows Event ID", self.event.get('event_id', 'N/A')),
        ]
        
        for label, value in info_items:
            self._add_info_row(content_frame, label, str(value))
        
        # Threat Analysis
        self._add_section(content_frame, "Threat Analysis")
        
        threat_score = self.event.get('threat_score', 0)
        threat_pattern = self.event.get('threat_pattern', 'None detected')
        
        self._add_info_row(content_frame, "Threat Score", f"{threat_score}/100")
        self._add_info_row(content_frame, "Threat Pattern", threat_pattern)
        
        # Description
        self._add_section(content_frame, "Description")
        
        desc_label = ctk.CTkLabel(
            content_frame,
            text=self.event.get('description', 'No description available'),
            font=ctk.CTkFont(size=12),
            wraplength=600,
            justify="left"
        )
        desc_label.pack(anchor="w", pady=(0, 15))
        
        # Raw Data
        if self.event.get('raw_data'):
            self._add_section(content_frame, "Raw Event Data")
            
            raw_data_text = ctk.CTkTextbox(
                content_frame,
                height=150,
                font=ctk.CTkFont(family="Consolas", size=10)
            )
            raw_data_text.pack(fill="x", pady=(0, 15))
            
            # Format raw data
            try:
                formatted_data = json.dumps(self.event['raw_data'], indent=2)
            except:
                formatted_data = str(self.event['raw_data'])
            
            raw_data_text.insert("1.0", formatted_data)
            raw_data_text.configure(state="disabled")
        
        # Close button
        close_btn = ctk.CTkButton(
            self,
            text="Close",
            command=self.destroy,
            width=120,
            height=35,
            font=ctk.CTkFont(size=13, weight="bold")
        )
        close_btn.pack(pady=(0, 20))
    
    def _add_section(self, parent, title: str):
        """Add a section header."""
        section = ctk.CTkLabel(
            parent,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#1f6aa5")
        )
        section.pack(anchor="w", pady=(15, 10))
    
    def _add_info_row(self, parent, label: str, value: str):
        """Add an information row."""
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=2)
        
        label_widget = ctk.CTkLabel(
            row,
            text=f"{label}:",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=150,
            anchor="w"
        )
        label_widget.pack(side="left")
        
        value_widget = ctk.CTkLabel(
            row,
            text=value,
            font=ctk.CTkFont(size=12),
            anchor="w"
        )
        value_widget.pack(side="left", fill="x", expand=True)
