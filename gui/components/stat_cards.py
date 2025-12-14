"""
Stat Cards Component
Displays key statistics in card format with animations.
"""
import customtkinter as ctk
from typing import Optional


class StatCard(ctk.CTkFrame):
    """A card that displays a statistic with icon and label."""
    
    def __init__(self, parent, title: str, value: str = "0", icon: str = "📊",
                 color: str = "#1f6aa5", **kwargs):
        """
        Initialize stat card.
        
        Args:
            parent: Parent widget
            title: Card title
            value: Value to display
            icon: Emoji icon
            color: Accent color
        """
        super().__init__(parent, **kwargs)
        
        self.title = title
        self.color = color
        
        # Configure frame
        self.configure(fg_color=("gray85", "gray20"), corner_radius=10)
        
        # Create layout
        self._create_widgets(icon, value)
    
    def _create_widgets(self, icon: str, value: str):
        """Create card widgets."""
        # Icon and title row
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=15, pady=(15, 5))
        
        # Icon
        icon_label = ctk.CTkLabel(
            top_frame,
            text=icon,
            font=ctk.CTkFont(size=24)
        )
        icon_label.pack(side="left")
        
        # Title
        title_label = ctk.CTkLabel(
            top_frame,
            text=self.title,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("gray30", "gray70")
        )
        title_label.pack(side="left", padx=(10, 0))
        
        # Value
        self.value_label = ctk.CTkLabel(
            self,
            text=value,
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=self.color
        )
        self.value_label.pack(padx=15, pady=(5, 15))
    
    def update_value(self, new_value: str):
        """Update the displayed value."""
        self.value_label.configure(text=new_value)


class ThreatScoreCard(ctk.CTkFrame):
    """Special card for threat score with color-coded display."""
    
    def __init__(self, parent, **kwargs):
        """Initialize threat score card."""
        super().__init__(parent, **kwargs)
        
        self.configure(fg_color=("gray85", "gray20"), corner_radius=10)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create card widgets."""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(15, 5))
        
        icon_label = ctk.CTkLabel(
            header,
            text="🎯",
            font=ctk.CTkFont(size=24)
        )
        icon_label.pack(side="left")
        
        title_label = ctk.CTkLabel(
            header,
            text="Threat Score",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("gray30", "gray70")
        )
        title_label.pack(side="left", padx=(10, 0))
        
        # Score value
        self.score_label = ctk.CTkLabel(
            self,
            text="0",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#4CAF50"  # Green by default
        )
        self.score_label.pack(padx=15, pady=(5, 5))
        
        # Score description
        self.desc_label = ctk.CTkLabel(
            self,
            text="Low Risk",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60")
        )
        self.desc_label.pack(padx=15, pady=(0, 15))
    
    def update_score(self, score: int):
        """Update threat score with color coding."""
        # Determine color and description
        if score >= 80:
            color = "#f44336"  # Red
            desc = "Critical Risk"
        elif score >= 50:
            color = "#ff9800"  # Orange
            desc = "High Risk"
        elif score >= 30:
            color = "#ffc107"  # Yellow
            desc = "Medium Risk"
        else:
            color = "#4CAF50"  # Green
            desc = "Low Risk"
        
        self.score_label.configure(text=str(score), text_color=color)
        self.desc_label.configure(text=desc)
