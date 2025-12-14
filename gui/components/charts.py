"""
Charts Component
Custom chart widgets using matplotlib embedded in CustomTkinter.
"""
import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from datetime import datetime
from typing import List, Tuple, Dict


class BaseChart(ctk.CTkFrame):
    """Base class for chart widgets."""
    
    def __init__(self, parent, title: str, **kwargs):
        """Initialize base chart."""
        super().__init__(parent, **kwargs)
        
        self.title = title
        self.configure(fg_color=("gray85", "gray20"), corner_radius=10)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(6, 4), dpi=80, facecolor='#2b2b2b')
        self.ax = self.fig.add_subplot(111)
        
        # Style the plot
        self.ax.set_facecolor('#1e1e1e')
        self.ax.tick_params(colors='white', labelsize=8)
        self.ax.spines['bottom'].set_color('white')
        self.ax.spines['left'].set_color('white')
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
    
    def clear(self):
        """Clear the chart."""
        self.ax.clear()
        self.ax.set_facecolor('#1e1e1e')


class LineChart(BaseChart):
    """Line chart for time-series data."""
    
    def __init__(self, parent, title: str, **kwargs):
        """Initialize line chart."""
        super().__init__(parent, title, **kwargs)
    
    def update_data(self, time_data: List[str], values: List[int], 
                    label: str = "Events", color: str = "#1f6aa5"):
        """
        Update chart with new data.
        
        Args:
            time_data: List of timestamp strings
            values: List of values
            label: Line label
            color: Line color
        """
        self.clear()
        
        if not time_data or not values:
            self.ax.text(0.5, 0.5, 'No data available', 
                        ha='center', va='center', color='white',
                        transform=self.ax.transAxes)
            self.canvas.draw()
            return
        
        # Plot line
        self.ax.plot(range(len(values)), values, color=color, linewidth=2, 
                    marker='o', markersize=4, label=label)
        
        # Set labels
        self.ax.set_xlabel('Time', color='white', fontsize=9)
        self.ax.set_ylabel('Count', color='white', fontsize=9)
        self.ax.set_title(self.title, color='white', fontsize=11, fontweight='bold', pad=10)
        
        # Format x-axis with time
        if len(time_data) <= 10:
            self.ax.set_xticks(range(len(time_data)))
            self.ax.set_xticklabels([t.split()[1] if ' ' in t else t for t in time_data], 
                                   rotation=45, ha='right', fontsize=7)
        else:
            # Show fewer labels for many data points
            step = len(time_data) // 5
            ticks = range(0, len(time_data), step)
            self.ax.set_xticks(ticks)
            self.ax.set_xticklabels([time_data[i].split()[1] if ' ' in time_data[i] 
                                    else time_data[i] for i in ticks], 
                                   rotation=45, ha='right', fontsize=7)
        
        # Add grid
        self.ax.grid(True, alpha=0.2, color='white', linestyle='--')
        
        # Legend
        if label:
            self.ax.legend(loc='upper left', fontsize=8)
        
        # Tight layout
        self.fig.tight_layout()
        
        self.canvas.draw()


class DonutChart(BaseChart):
    """Donut chart for categorized data."""
    
    def __init__(self, parent, title: str, **kwargs):
        """Initialize donut chart."""
        super().__init__(parent, title, **kwargs)
    
    def update_data(self, labels: List[str], values: List[int], 
                    colors: List[str] = None):
        """
        Update chart with new data.
        
        Args:
            labels: Category labels
            values: Values for each category
            colors: Optional list of colors
        """
        self.clear()
        
        if not labels or not values or sum(values) == 0:
            self.ax.text(0.5, 0.5, 'No data available', 
                        ha='center', va='center', color='white',
                        transform=self.ax.transAxes)
            self.canvas.draw()
            return
        
        # Default colors
        if not colors:
            colors = ['#f44336', '#ff9800', '#2196F3']  # Red, Orange, Blue
        
        # Create donut chart
        wedges, texts, autotexts = self.ax.pie(
            values,
            labels=labels,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            pctdistance=0.85,
            textprops={'color': 'white', 'fontsize': 9}
        )
        
        # Create donut hole
        centre_circle = plt.Circle((0, 0), 0.70, fc='#1e1e1e')
        self.ax.add_artist(centre_circle)
        
        # Title
        self.ax.set_title(self.title, color='white', fontsize=11, 
                         fontweight='bold', pad=10)
        
        # Equal aspect ratio ensures circular shape
        self.ax.axis('equal')
        
        self.fig.tight_layout()
        self.canvas.draw()


class BarChart(BaseChart):
    """Bar chart for comparing categories."""
    
    def __init__(self, parent, title: str, **kwargs):
        """Initialize bar chart."""
        super().__init__(parent, title, **kwargs)
    
    def update_data(self, labels: List[str], values: List[int], 
                    color: str = "#1f6aa5"):
        """
        Update chart with new data.
        
        Args:
            labels: Category labels
            values: Values for each category
            color: Bar color
        """
        self.clear()
        
        if not labels or not values:
            self.ax.text(0.5, 0.5, 'No data available', 
                        ha='center', va='center', color='white',
                        transform=self.ax.transAxes)
            self.canvas.draw()
            return
        
        # Create horizontal bars
        y_pos = range(len(labels))
        self.ax.barh(y_pos, values, color=color, alpha=0.8)
        
        # Set labels
        self.ax.set_yticks(y_pos)
        self.ax.set_yticklabels(labels, fontsize=8)
        self.ax.set_xlabel('Count', color='white', fontsize=9)
        self.ax.set_title(self.title, color='white', fontsize=11, 
                         fontweight='bold', pad=10)
        
        # Add value labels on bars
        for i, v in enumerate(values):
            self.ax.text(v + max(values) * 0.01, i, str(v), 
                        color='white', va='center', fontsize=8)
        
        # Invert y-axis to have highest at top
        self.ax.invert_yaxis()
        
        # Add grid
        self.ax.grid(True, alpha=0.2, color='white', linestyle='--', axis='x')
        
        self.fig.tight_layout()
        self.canvas.draw()
