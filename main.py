#!/usr/bin/env python3
"""
ShadowIT Detector - Network-based Unauthorized SaaS Detection Tool
==================================================================
A proof-of-concept cybersecurity tool that passively monitors network traffic
to identify unauthorized SaaS application usage via DNS queries and TLS SNI.

Author: Cybersecurity Engineering Team
Version: 1.0.0
"""

import asyncio
import shutil
import sys
import os
import csv
import platform
import ctypes
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, List
from enum import Enum
import threading
from collections import defaultdict

import pyshark
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box


# =============================================================================
# CONFIGURATION & DATA CLASSES
# =============================================================================

class RiskLevel(Enum):
    """Risk severity levels for detected services."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


@dataclass
class ServiceCategory:
    """Defines a service category with its risk score and level."""
    name: str
    risk_score: int
    risk_level: RiskLevel
    description: str


@dataclass
class DetectedEvent:
    """Represents a detected ShadowIT event."""
    timestamp: datetime
    source_ip: str
    domain: str
    service_name: str
    category: ServiceCategory
    detection_method: str  # 'DNS' or 'TLS-SNI'
    
    def __hash__(self):
        return hash((self.source_ip, self.domain, self.detection_method))
    
    def __eq__(self, other):
        if isinstance(other, DetectedEvent):
            return (self.source_ip == other.source_ip and 
                    self.domain == other.domain and 
                    self.detection_method == other.detection_method)
        return False


# =============================================================================
# SERVICE DATABASES
# =============================================================================

# Sanctioned/Approved corporate services
SANCTIONED_SERVICES: Dict[str, str] = {
    # Company infrastructure
    "company-email.com": "Corporate Email",
    "mail.company.com": "Corporate Email",
    "internal-jira.io": "Corporate JIRA",
    "jira.company.com": "Corporate JIRA",
    "confluence.company.com": "Corporate Confluence",
    "sharepoint.company.com": "Corporate SharePoint",
    "teams.company.com": "Corporate Teams",
    "slack.company.com": "Corporate Slack",
    "zoom.company.com": "Corporate Zoom",
    "vpn.company.com": "Corporate VPN",
    "ad.company.com": "Active Directory",
    "ldap.company.com": "LDAP Server",
    "git.company.com": "Corporate Git",
    "gitlab.company.com": "Corporate GitLab",
    "github.company.com": "Corporate GitHub",
    "drive.company.com": "Corporate Drive",
    "docs.company.com": "Corporate Docs",
    "calendar.company.com": "Corporate Calendar",
    "hr.company.com": "HR Portal",
    "finance.company.com": "Finance Portal",
    "sap.company.com": "SAP System",
    "salesforce.company.com": "Corporate Salesforce",
}

# Unauthorized/Shadow IT services with categorization
UNAUTHORIZED_SERVICES: Dict[str, tuple] = {
    # File Sharing - High Risk (Score 9)
    "dropbox.com": ("Dropbox", "File Sharing"),
    "dropboxapi.com": ("Dropbox API", "File Sharing"),
    "mega.nz": ("Mega", "File Sharing"),
    "mega.co.nz": ("Mega", "File Sharing"),
    "wetransfer.com": ("WeTransfer", "File Sharing"),
    "we.tl": ("WeTransfer Short", "File Sharing"),
    "send-anywhere.com": ("Send Anywhere", "File Sharing"),
    "file.io": ("File.io", "File Sharing"),
    "transfer.sh": ("Transfer.sh", "File Sharing"),
    "pcloud.com": ("pCloud", "File Sharing"),
    "mediafire.com": ("MediaFire", "File Sharing"),
    "box.com": ("Box (Personal)", "File Sharing"),
    "sync.com": ("Sync.com", "File Sharing"),
    "icedrive.net": ("Icedrive", "File Sharing"),
    "terabox.com": ("TeraBox", "File Sharing"),
    
    # Unapproved Chat - Medium Risk (Score 6)
    "slack.com": ("Slack (Personal)", "Unapproved Chat"),
    "slack-edge.com": ("Slack Edge", "Unapproved Chat"),
    "discord.com": ("Discord", "Unapproved Chat"),
    "discord.gg": ("Discord CDN", "Unapproved Chat"),
    "discordapp.com": ("Discord App", "Unapproved Chat"),
    "telegram.org": ("Telegram", "Unapproved Chat"),
    "t.me": ("Telegram Web", "Unapproved Chat"),
    "signal.org": ("Signal", "Unapproved Chat"),
    "whats-app.com": ("WhatsApp Web", "Unapproved Chat"),
    "web.whatsapp.com": ("WhatsApp Web", "Unapproved Chat"),
    "wickr.com": ("Wickr", "Unapproved Chat"),
    "threema.ch": ("Threema", "Unapproved Chat"),
    "wire.com": ("Wire", "Unapproved Chat"),
    "element.io": ("Element", "Unapproved Chat"),
    "matrix.org": ("Matrix", "Unapproved Chat"),
    "rocket.chat": ("Rocket.Chat", "Unapproved Chat"),
    
    # Personal Email - Medium Risk (Score 6)
    "gmail.com": ("Gmail", "Personal Email"),
    "mail.google.com": ("Gmail", "Personal Email"),
    "outlook.com": ("Outlook Personal", "Personal Email"),
    "hotmail.com": ("Hotmail", "Personal Email"),
    "yahoo.com": ("Yahoo Mail", "Personal Email"),
    "protonmail.com": ("ProtonMail", "Personal Email"),
    "proton.me": ("Proton Mail", "Personal Email"),
    "tutanota.com": ("Tutanota", "Personal Email"),
    "icloud.com": ("iCloud Mail", "Personal Email"),
    "mail.ru": ("Mail.ru", "Personal Email"),
    "zoho.com": ("Zoho Mail", "Personal Email"),
    
    # Streaming/Social - Low Risk (Score 3)
    "youtube.com": ("YouTube", "Streaming/Social"),
    "googlevideo.com": ("YouTube Video", "Streaming/Social"),
    "youtu.be": ("YouTube Short", "Streaming/Social"),
    "netflix.com": ("Netflix", "Streaming/Social"),
    "hulu.com": ("Hulu", "Streaming/Social"),
    "disneyplus.com": ("Disney+", "Streaming/Social"),
    "primevideo.com": ("Prime Video", "Streaming/Social"),
    "spotify.com": ("Spotify", "Streaming/Social"),
    "twitch.tv": ("Twitch", "Streaming/Social"),
    "tiktok.com": ("TikTok", "Streaming/Social"),
    "instagram.com": ("Instagram", "Streaming/Social"),
    "facebook.com": ("Facebook", "Streaming/Social"),
    "twitter.com": ("Twitter", "Streaming/Social"),
    "x.com": ("X (Twitter)", "Streaming/Social"),
    "linkedin.com": ("LinkedIn", "Streaming/Social"),
    "reddit.com": ("Reddit", "Streaming/Social"),
    "pinterest.com": ("Pinterest", "Streaming/Social"),
    "snapchat.com": ("Snapchat", "Streaming/Social"),
}

# Services to completely ignore (Background noise, OS updates, Telemetry, CDNs)
IGNORED_SERVICES: Set[str] = {
    # Microsoft / Windows
    "microsoft.com", "windows.com", "windowsupdate.com", "azure.com", 
    "office.com", "live.com", "bing.com", "skype.com", "xbox.com", 
    "xboxlive.com", "msn.com", "onenote.com", "sharepoint.com",
    "microsoftonline.com", "azureedge.net", "trafficmanager.net",
    "msedge.net", "s-microsoft.com", "a-msedge.net",
    
    # Google Infrastructure (keep google.com/youtube.com visible, hide backend)
    "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com", 
    "1e100.net", "app-measurement.com", "doubleclick.net", 
    "google-analytics.com", "googlesyndication.com", "googleusercontent.com",
    
    # AWS / Cloud / CDNs
    "amazonaws.com", "cloudfront.net", "akamai.net", "akamaiedge.net",
    "edgekey.net", "fastly.net", "cloudflare.net",
    
    # Security / Updates / Telemetry
    "digicert.com", "sectigo.com", "globalsign.com", "letsencrypt.org",
    "mozilla.org", "firefox.com", "start.page", 
    "pki.goog", "ocsp.pki.goog", "clients1.google.com", "clients2.google.com",
    "dns.google",
    
    # Trackers / Ads / Analytics (Aggressive filter)
    "scorecardresearch.com", "doubleclick.net", "googlesyndication.com",
    "google-analytics.com", "fpjs.io", "fingerprintjs.com",
    "adjust.com", "appsflyer.com", "branch.io", "braze.com",
    "mparticle.com", "segment.io", "sentry.io", "bugsnag.com",
    "hotjar.com", "optimizely.com", "criteo.com", "outbrain.com",
    "taboola.com", "adroll.com", "quantserve.com",
    
    # Extra Microsoft/Bing background
    "msn.cn", "msftstatic.com", "bingapis.com", "c.bing.com",
    "bat.bing.com", "r.bing.com", "browser.events.data.microsoft.com",
    "edge.microsoft.com", "config.edge.skype.com",
    
    # Common CDNs for assets (often not the main site)
    "typography.com", "typekit.net", "fonts.googleapis.com", 
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "code.jquery.com",
    "googletagmanager.com",
    
    # User-requested filters (Background apps/Common noise)
    # "google.com", "www.google.com", 
    # "whatsapp.com", "web.whatsapp.com", "chat.whatsapp.com",
    # "cloudflare.com", "chatgpt.com",
}

# Category risk definitions
CATEGORY_RISKS: Dict[str, ServiceCategory] = {
    "File Sharing": ServiceCategory(
        name="File Sharing",
        risk_score=9,
        risk_level=RiskLevel.CRITICAL,
        description="High data exfiltration risk"
    ),
    "Unapproved Chat": ServiceCategory(
        name="Unapproved Chat",
        risk_score=6,
        risk_level=RiskLevel.HIGH,
        description="Communication risk"
    ),
    "Personal Email": ServiceCategory(
        name="Personal Email",
        risk_score=6,
        risk_level=RiskLevel.HIGH,
        description="Data leakage risk"
    ),
    "Streaming/Social": ServiceCategory(
        name="Streaming/Social",
        risk_score=3,
        risk_level=RiskLevel.LOW,
        description="Productivity risk"
    ),
    "Unknown": ServiceCategory(
        name="Unknown",
        risk_score=5,
        risk_level=RiskLevel.MEDIUM,
        description="Unclassified service"
    ),
    "General Web": ServiceCategory(
        name="General Web",
        risk_score=1,
        risk_level=RiskLevel.LOW,
        description="General web traffic"
    ),
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def normalize_domain(domain: str) -> str:
    """
    Normalize domain name: lowercase, remove trailing dots.
    
    Args:
        domain: Raw domain string
        
    Returns:
        Normalized domain string
    """
    if not domain:
        return ""
    return domain.lower().rstrip(".").strip()


def extract_base_domain(domain: str) -> str:
    """
    Extract the base domain (e.g., 'dropbox.com' from 'www.dropbox.com').
    
    Args:
        domain: Full domain string
        
    Returns:
        Base domain
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def check_tshark_installed() -> bool:
    """
    Verify that TShark is installed on the system.
    On Windows, checks common installation paths and updates PATH if found.
    
    Returns:
        True if TShark is installed, False otherwise
    """
    if shutil.which("tshark"):
        return True
        
    # Check common Windows paths
    if platform.system() == "Windows":
        common_paths = [
            r"C:\Program Files\Wireshark",
            r"C:\Program Files (x86)\Wireshark",
        ]
        
        for path in common_paths:
            tshark_path = os.path.join(path, "tshark.exe")
            if os.path.exists(tshark_path):
                # Add to PATH for this session
                os.environ["PATH"] += os.pathsep + path
                return True
                
    return False


def get_service_info(domain: str) -> tuple:
    """
    Look up service information for a given domain.
    
    Args:
        domain: Normalized domain name
        
    """
    # 1. Check IGNORED_SERVICES first (Priority Filter)
    # We check the base domain and the full domain
    base_domain = extract_base_domain(domain)
    
    if domain in IGNORED_SERVICES or base_domain in IGNORED_SERVICES:
        return (None, None, False)
        
    # Check for subdomains of ignored services
    for ignored in IGNORED_SERVICES:
        if domain.endswith(f".{ignored}"):
            return (None, None, False)

    # 2. Check exact match in sanctioned services
    if domain in SANCTIONED_SERVICES:
        return (SANCTIONED_SERVICES[domain], "Sanctioned", True)
    
    # 3. Check exact match in unauthorized services
    if domain in UNAUTHORIZED_SERVICES:
        service_name, category = UNAUTHORIZED_SERVICES[domain]
        return (service_name, category, False)
    
    # 4. Check base domain matches
    # base_domain is already calculated above
    
    if base_domain in SANCTIONED_SERVICES:
        return (SANCTIONED_SERVICES[base_domain], "Sanctioned", True)
    
    if base_domain in UNAUTHORIZED_SERVICES:
        service_name, category = UNAUTHORIZED_SERVICES[base_domain]
        return (service_name, category, False)
    
    # 5. Check for subdomain matches in unauthorized list
    for svc_domain, (svc_name, category) in UNAUTHORIZED_SERVICES.items():
        if domain.endswith(f".{svc_domain}") or domain == svc_domain:
            return (svc_name, category, False)
    
    # 6. Check for subdomain matches in sanctioned list
    for svc_domain, svc_name in SANCTIONED_SERVICES.items():
        if domain.endswith(f".{svc_domain}") or domain == svc_domain:
            return (svc_name, "Sanctioned", True)
    
    # 7. Catch-all for any other domain -> General Web
    # Use the base domain as the service name
    return (base_domain, "General Web", False)


# =============================================================================
# PACKET PROCESSOR
# =============================================================================

class PacketProcessor:
    """
    Processes captured network packets to extract DNS and TLS information.
    """
    
    def __init__(self, event_queue: asyncio.Queue):
        self.event_queue = event_queue
        self.seen_domains: Set[str] = set()
        self.stats = {
            "dns_packets": 0,
            "tls_packets": 0,
            "unique_domains": 0,
            "shadow_it_detected": 0,
        }
        self.unique_services: Dict[str, DetectedEvent] = {}
        
        # Initialize Logging
        self.log_filename = "shadowit_logs.csv"
        self._init_log_file()

    def _init_log_file(self):
        """Initialize the CSV log file with headers if it doesn't exist."""
        file_exists = os.path.isfile(self.log_filename)
        try:
            with open(self.log_filename, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow([
                        "Timestamp", "Source IP", "Domain/Service", 
                        "Category", "Risk Score", "Detection Method"
                    ])
        except Exception as e:
            print(f"[!] Error initializing log file: {e}")

    def log_event(self, event: DetectedEvent):
        """Log a detected event to the CSV file."""
        try:
            with open(self.log_filename, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    event.source_ip,
                    event.service_name,
                    event.category.name,
                    f"{event.category.risk_score}/10",
                    event.detection_method
                ])
        except Exception:
            pass  # Don't crash on logging error
    
    def process_dns_packet(self, packet) -> Optional[DetectedEvent]:
        """
        Extract DNS query information from a packet.
        
        Args:
            packet: PyShark packet object
            
        Returns:
            DetectedEvent if unauthorized service found, None otherwise
        """
        try:
            if not hasattr(packet, 'dns'):
                return None
            
            dns = packet.dns
            
            # Get query name from DNS
            if hasattr(dns, 'qry_name'):
                domain = normalize_domain(dns.qry_name)
            elif hasattr(dns, 'resp_name'):
                domain = normalize_domain(dns.resp_name)
            else:
                return None
            
            if not domain:
                return None
            
            self.stats["dns_packets"] += 1
            
            # Skip if already seen
            domain_key = f"dns:{domain}"
            if domain_key in self.seen_domains:
                return None
            
            # Get source IP
            src_ip = "Unknown"
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
            
            # Check service info
            service_name, category_name, is_sanctioned = get_service_info(domain)
            
            if is_sanctioned:
                return None  # Ignore sanctioned services
            
            if service_name:
                # FILTER: For "General Web" (unknown sites), ignore DNS matches 
                # to prevent "Hover/Prefetch" noise.
                # [USER REVERT] Re-enabling DNS for everything to show "junk" traffic
                # if category_name == "General Web":
                #    return None

                self.seen_domains.add(domain_key)
                self.stats["shadow_it_detected"] += 1
                
                category = CATEGORY_RISKS.get(category_name, CATEGORY_RISKS["Unknown"])
                
                event = DetectedEvent(
                    timestamp=datetime.now(),
                    source_ip=src_ip,
                    domain=domain,
                    service_name=service_name,
                    category=category,
                    detection_method="DNS"
                )
                
                # Track for summary report (keep latest occurrence)
                self.unique_services[domain] = event
                
                # Log to CSV
                self.log_event(event)
                
                return event
            
            # Unknown domain - optionally track
            # Uncomment to track unknown domains:
            # self.seen_domains.add(domain_key)
            # return DetectedEvent(
            #     timestamp=datetime.now(),
            #     source_ip=src_ip,
            #     domain=domain,
            #     service_name="Unknown",
            #     category=CATEGORY_RISKS["Unknown"],
            #     detection_method="DNS"
            # )
            
            return None
            
        except AttributeError:
            return None
    
    def process_tls_packet(self, packet) -> Optional[DetectedEvent]:
        """
        Extract TLS SNI information from a packet.
        
        Args:
            packet: PyShark packet object
            
        Returns:
            DetectedEvent if unauthorized service found, None otherwise
        """
        try:
            if not hasattr(packet, 'tls') and not hasattr(packet, 'ssl'):
                return None
            
            # Try TLS first, then SSL
            tls_layer = getattr(packet, 'tls', None) or getattr(packet, 'ssl', None)
            
            if not tls_layer:
                return None
            
            # Extract SNI from handshake extensions
            sni = None
            
            # Try various field names for SNI
            if hasattr(tls_layer, 'handshake_extensions_server_name'):
                sni = tls_layer.handshake_extensions_server_name
            elif hasattr(tls_layer, 'ssl_handshake_extensions_server_name'):
                sni = tls_layer.ssl_handshake_extensions_server_name
            
            if not sni:
                return None
            
            domain = normalize_domain(sni)
            if not domain:
                return None
            
            self.stats["tls_packets"] += 1
            
            # Skip if already seen
            domain_key = f"tls:{domain}"
            if domain_key in self.seen_domains:
                return None
            
            # Get source IP
            src_ip = "Unknown"
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
            
            # Check service info
            service_name, category_name, is_sanctioned = get_service_info(domain)
            
            if is_sanctioned:
                return None  # Ignore sanctioned services
            
            if service_name:
                self.seen_domains.add(domain_key)
                self.stats["shadow_it_detected"] += 1
                
                category = CATEGORY_RISKS.get(category_name, CATEGORY_RISKS["Unknown"])
                
                event = DetectedEvent(
                    timestamp=datetime.now(),
                    source_ip=src_ip,
                    domain=domain,
                    service_name=service_name,
                    category=category,
                    detection_method="TLS-SNI"
                )
                
                # Track for summary report (keep latest occurrence)
                self.unique_services[domain] = event
                
                # Log to CSV
                self.log_event(event)
                
                return event
            
            return None
            
        except AttributeError:
            return None


# =============================================================================
# DASHBOARD
# =============================================================================

class Dashboard:
    """
    Real-time terminal dashboard for ShadowIT detection events.
    """
    
    def __init__(self):
        self.console = Console()
        self.events: List[DetectedEvent] = []
        self.max_events = 50
        self.stats = defaultdict(int)
        
    def add_event(self, event: DetectedEvent):
        """Add a new detection event to the dashboard."""
        # Avoid duplicates
        if event not in self.events:
            self.events.insert(0, event)
            self.stats[event.category.name] += 1
            
            # Keep only recent events
            if len(self.events) > self.max_events:
                self.events.pop()
    
    def get_risk_color(self, risk_level: RiskLevel) -> str:
        """Get color code for risk level."""
        colors = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "orange3",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
            RiskLevel.UNKNOWN: "grey",
        }
        return colors.get(risk_level, "white")
    
    def get_score_color(self, score: int) -> str:
        """Get color based on risk score."""
        if score >= 9:
            return "red"
        elif score >= 6:
            return "orange3"
        elif score >= 4:
            return "yellow"
        else:
            return "green"
    
    def create_event_table(self) -> Table:
        """Create the main events table."""
        table = Table(
            title="[bold cyan]🚨 ShadowIT Detection Events[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
        )
        
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("Source IP", style="cyan", width=16)
        table.add_column("Service Detected", style="bright_white", width=22)
        table.add_column("Category", width=18)
        table.add_column("Risk Score", justify="center", width=12)
        table.add_column("Method", style="dim", width=10)
        
        for event in self.events[:20]:  # Show last 20 events
            risk_color = self.get_risk_color(event.category.risk_level)
            score_color = self.get_score_color(event.category.risk_score)
            
            table.add_row(
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.source_ip,
                f"[bold]{event.service_name}[/bold]",
                f"[{risk_color}]{event.category.name}[/{risk_color}]",
                f"[{score_color} bold]{event.category.risk_score}/10[/{score_color} bold]",
                event.detection_method
            )
        
        return table
    
    def create_stats_panel(self) -> Panel:
        """Create statistics panel."""
        total_events = len(self.events)
        
        stats_text = Text()
        stats_text.append(f"Total Detections: ", style="bold")
        stats_text.append(f"{total_events}\n", style="cyan bold")
        
        for category, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            category_obj = CATEGORY_RISKS.get(category)
            if category_obj:
                color = self.get_risk_color(category_obj.risk_level)
                stats_text.append(f"  • {category}: ", style="dim")
                stats_text.append(f"{count}\n", style=f"{color} bold")
        
        return Panel(
            stats_text,
            title="[bold green]📊 Statistics[/bold green]",
            border_style="green",
            box=box.ROUNDED,
        )
    
    def create_risk_legend(self) -> Panel:
        """Create risk score legend panel."""
        legend_text = Text()
        legend_text.append("Risk Scoring Guide:\n\n", style="bold underline")
        legend_text.append("  9-10 ", style="red bold")
        legend_text.append("= Critical (File Sharing)\n", style="dim")
        legend_text.append("  6-8  ", style="orange3 bold")
        legend_text.append("= High (Unapproved Chat/Email)\n", style="dim")
        legend_text.append("  4-5  ", style="yellow bold")
        legend_text.append("= Medium (Unknown)\n", style="dim")
        legend_text.append("  1-3  ", style="green bold")
        legend_text.append("= Low (Streaming/Social/General)", style="dim")
        
        return Panel(
            legend_text,
            title="[bold yellow]⚠️ Risk Legend[/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    
    def create_layout(self) -> Layout:
        """Create the full dashboard layout."""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=12),
        )
        
        layout["main"].split_row(
            Layout(name="events", ratio=3),
            Layout(name="sidebar", ratio=1),
        )
        
        layout["sidebar"].split_column(
            Layout(name="stats"),
            Layout(name="legend"),
        )
        
        # Header
        header_text = Text()
        header_text.append("╔══════════════════════════════════════════════════════════════════╗\n", style="cyan")
        header_text.append("║     ", style="cyan")
        header_text.append("🔒 ShadowIT Detector - Network Security Monitoring", style="bold bright_white")
        header_text.append("               ║\n", style="cyan")
        header_text.append("╚══════════════════════════════════════════════════════════════════╝", style="cyan")
        layout["header"].update(Panel(header_text, box=box.SIMPLE))
        
        # Main content
        layout["events"].update(self.create_event_table())
        layout["stats"].update(self.create_stats_panel())
        layout["legend"].update(self.create_risk_legend())
        
        # Footer
        footer_text = Text()
        footer_text.append("Status: ", style="bold")
        footer_text.append("[ACTIVE] Monitoring DNS & TLS traffic...\n", style="green bold")
        footer_text.append("Press ", style="dim")
        footer_text.append("Ctrl+C", style="bold bright_white")
        footer_text.append(" to stop monitoring", style="dim")
        layout["footer"].update(Panel(footer_text, border_style="blue", box=box.ROUNDED))
        
        return layout
    
    def print_alert(self, event: DetectedEvent):
        """Print an immediate alert for a detected event."""
        risk_color = self.get_risk_color(event.category.risk_level)
        score_color = self.get_score_color(event.category.risk_score)
        
        alert_panel = Panel(
            f"[bold]{event.service_name}[/bold] detected from [cyan]{event.source_ip}[/cyan]\n"
            f"Category: [{risk_color}]{event.category.name}[/{risk_color}] | "
            f"Risk: [{score_color}]{event.category.risk_score}/10[/{score_color}] | "
            f"Method: {event.detection_method}",
            title=f"[bold red]🚨 SHADOW IT ALERT[/bold red]",
            border_style="red",
            box=box.HEAVY,
        )
        self.console.print(alert_panel)


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class ShadowITDetector:
    """
    Main ShadowIT Detector application.
    """
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.processor = PacketProcessor(self.event_queue)
        self.dashboard = Dashboard()
        self.running = False
        self.capture = None
        
    def print_banner(self):
        """Print application startup banner."""
        console = Console()
        banner = r"""
[bold cyan]
   ____  _               _     _____ _______   __     ____       _            _   _
  / ___|| |__   __ _  __| |   |_   _|_   _\ \ / /    |  _ \  ___| |_ ___  ___| |_(_)_ __   __ _
  \___ \| '_ \ / _` |/ _` |_____| |   | |  \ V /_____| | | |/ _ \ __/ _ \/ __| __| | '_ \ / _` |
   ___) | | | | (_| | (_| |_____| |   | |   | |_____| |_| |  __/ ||  __/\__ \ |_| | | | | (_| |
  |____/|_| |_|\__,_|\__,_|     |_|   |_|   |_|     |____/ \___|\__\___||___/\__|_|_| |_|\__, |
                                                                                         |___/
[/bold cyan]
[dim]Network-based Unauthorized SaaS Detection Tool - Proof of Concept[/dim]
[dim]Version 1.0.0 | Cybersecurity Engineering Team[/dim]
        """
        console.print(banner)
    
    def print_startup_info(self):
        """Print startup configuration information."""
        console = Console()
        
        info_table = Table(title="[bold green]Configuration[/bold green]", box=box.ROUNDED)
        info_table.add_column("Setting", style="cyan")
        info_table.add_column("Value", style="bright_white")
        
        info_table.add_row("Network Interface", str(self.interface) if self.interface is not None else "Default")
        info_table.add_row("Capture Filter", "dns or tls")
        info_table.add_row("Sanctioned Services", str(len(SANCTIONED_SERVICES)))
        info_table.add_row("Unauthorized Services", str(len(UNAUTHORIZED_SERVICES)))
        info_table.add_row("Risk Categories", str(len(CATEGORY_RISKS)))
        
        console.print(info_table)
        console.print()
    
    async def packet_callback(self, packet):
        """Callback for each captured packet."""
        # Process DNS packets
        event = self.processor.process_dns_packet(packet)
        if event:
            await self.event_queue.put(event)
            return
        
        # Process TLS packets
        event = self.processor.process_tls_packet(packet)
        if event:
            await self.event_queue.put(event)
    
    async def capture_packets(self):
        """Start packet capture using PyShark in a separate thread to avoid blocking."""
        def _capture_loop():
            # Create a new event loop for this thread as Pyshark requires one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Create capture object
                self.capture = pyshark.LiveCapture(
                    interface=self.interface,
                    bpf_filter="udp port 53 or tcp port 443",
                    display_filter="dns or tls.handshake.type == 1",
                )
                
                # Sniff continuously
                for packet in self.capture.sniff_continuously():
                    if not self.running:
                        break
                    
                    # Process packet in the main loop safely
                    asyncio.run_coroutine_threadsafe(
                        self.packet_callback(packet), 
                        self.loop
                    )
            except Exception as e:
                # We can't use rich console here safely if it's not thread-safe, 
                # but we'll try to print strictly to stderr or just pass
                print(f"Capture error: {e}", file=sys.stderr)

        # Run the capture loop in a separate thread
        self.loop = asyncio.get_running_loop()
        await self.loop.run_in_executor(None, _capture_loop)
    
    async def process_events(self, live: Live):
        """Process events from the queue and update dashboard."""
        while self.running:
            try:
                # Wait for an event
                event = await asyncio.wait_for(self.event_queue.get(), timeout=0.1)
                self.dashboard.add_event(event)
                # Update the live display instead of printing a new alert
                live.update(self.dashboard.create_layout())
            except asyncio.TimeoutError:
                # Refresh display periodically even if no events
                live.update(self.dashboard.create_layout())
                continue

    async def run(self):
        """Main run loop."""
        # Check TShark installation (quietly)
        if not check_tshark_installed():
            print("Error: TShark is not installed or not found in PATH.")
            sys.exit(1)
            
        # No banner, no startup info - just start
        self.running = True
        
        # Start capture task
        capture_task = asyncio.create_task(self.capture_packets())
        
        # Run dashboard in Live context
        with Live(self.dashboard.create_layout(), refresh_per_second=4, screen=True) as live:
            try:
                await self.process_events(live)
            except asyncio.CancelledError:
                pass
            finally:
                self.stop()
                # Cancel capture if still running
                if not capture_task.done():
                    capture_task.cancel()
                    try:
                        await capture_task
                    except asyncio.CancelledError:
                        pass
        
        # Print summary report AFTER Live context exits so it stays visible
        console = Console()
        if self.processor and self.processor.unique_services:
            console.print("\n")
            summary_table = Table(
                title="[bold magenta]📝 Session Summary Report[/bold magenta]",
                box=box.DOUBLE_EDGE,
                show_header=True,
                header_style="bold cyan",
                border_style="magenta",
            )
            
            summary_table.add_column("Service / Domain", style="bright_white", width=30)
            summary_table.add_column("Category", width=20)
            summary_table.add_column("Risk", justify="center", width=10)
            summary_table.add_column("Source IP", style="dim", width=15)
            summary_table.add_column("Method", style="dim", width=10)
            
            # Sort by risk score (descending), then name
            sorted_events = sorted(
                self.processor.unique_services.values(), 
                key=lambda x: (x.category.risk_score, x.service_name), 
                reverse=True
            )
            
            for event in sorted_events:
                risk_color = self.dashboard.get_risk_color(event.category.risk_level)
                score_color = self.dashboard.get_score_color(event.category.risk_score)
                
                summary_table.add_row(
                    f"[bold]{event.service_name}[/bold]",
                    f"[{risk_color}]{event.category.name}[/{risk_color}]",
                    f"[{score_color}]{event.category.risk_score}/10[/{score_color}]",
                    event.source_ip,
                    event.detection_method
                )
            
            console.print(summary_table)
            console.print("\n")

        console.print(f"[dim]Total DNS packets: {self.processor.stats['dns_packets']}[/dim]")
        console.print(f"[dim]Total TLS packets: {self.processor.stats['tls_packets']}[/dim]")
        console.print(f"[dim]ShadowIT events: {self.processor.stats['shadow_it_detected']}[/dim]")
    
    def stop(self):
        """Stop the detector."""
        self.running = False
        if self.capture:
            try:
                self.capture.close()
            except Exception:
                pass


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    """Application entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ShadowIT Detector - Network-based Unauthorized SaaS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py                    # Use default interface
  sudo python main.py -i eth0            # Use specific interface
  sudo python main.py --interface wlan0  # Use WiFi interface

Note: Root/Administrator privileges are required for packet capture.
        """
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (default: auto-detect)",
        default=None
    )
    
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit"
    )
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        console = Console()
        console.print("[bold]Available Network Interfaces:[/bold]\n")
        try:
            from pyshark.tshark.tshark import get_tshark_interfaces
            interfaces = get_tshark_interfaces()
            for idx, iface in enumerate(interfaces):
                console.print(f"  [{idx}] {iface}")
        except Exception as e:
            console.print(f"[red]Could not list interfaces: {e}[/red]")
            console.print("[dim]Try running: tshark -D[/dim]")
        return
    
    # Check for root/admin privileges
    is_admin = False
    try:
        if platform.system() == "Windows":
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except Exception:
        pass

    if not is_admin:
        console = Console()
        console.print("[bold red]⚠ Warning: Administrator/Root privileges required![/bold red]")
        
        if platform.system() == "Windows":
             console.print("[yellow]Please run this command prompt as Administrator.[/yellow]")
        else:
            console.print("[yellow]Please run with sudo:[/yellow]")
            console.print(f"[cyan]  sudo python {sys.argv[0]}[/cyan]\n")
        sys.exit(1)
    
    # Run the detector
    # Pass interface as string to avoid PyShark iteration errors
    detector = ShadowITDetector(interface=args.interface)
    
    try:
        # Suppress stderr to hide annoying asyncio/pyshark closure errors on exit
        null_file = open(os.devnull, 'w')
        original_stderr = sys.stderr
        sys.stderr = null_file
        
        try:
            asyncio.run(detector.run())
        except KeyboardInterrupt:
            pass
        finally:
            # We want to keep stderr suppressed during the final shutdown phase of this script
            # because that's when pyshark's __del__ runs and throws the error
            pass
            
            # If we wanted to restore:
            # sys.stderr = original_stderr
            # null_file.close()
            
    except Exception:
        pass


if __name__ == "__main__":
    main()
