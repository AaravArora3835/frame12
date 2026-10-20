#!/usr/bin/env python3
from scapy.all import sniff, Dot11, Dot11Deauth
from collections import defaultdict, deque
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
import threading
import time

INTERFACE = "wlan0mon"
WINDOW_SECONDS = 10
THRESHOLD = 10

deauth_log = defaultdict(list)
recent_alerts = deque(maxlen=8)
total_frames = 0
total_alerts = 0
alert_active = False

console = Console()

def make_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="status", size=4),
        Layout(name="table"),
        Layout(name="alerts", size=10)
    )
    return layout

def render(layout):
    global alert_active

    if alert_active:
        status_text = "⚠  ALERT — DEAUTH ATTACK DETECTED\nSuspicious disconnect activity on your network. Avoid logging into sensitive accounts right now."
    else:
        status_text = "✓  MONITORING — NO ANOMALY"
    status_style = "bold white on red" if alert_active else "bold white on green"
    layout["status"].update(Panel(status_text, style=status_style))

    table = Table(title="Deauth Frame Rate by Source (last 10s)")
    table.add_column("Source MAC", style="cyan")
    table.add_column("Frames in Window", justify="right")
    table.add_column("Status", justify="center")

    now = datetime.now()
    for source, timestamps in deauth_log.items():
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        count = len([t for t in timestamps if t > cutoff])
        if count > 0:
            status = "[bold red]ALERT[/bold red]" if count >= THRESHOLD else "[green]normal[/green]"
            table.add_row(source, str(count), status)

    layout["table"].update(table)

    alert_text = "\n".join(recent_alerts) if recent_alerts else "No alerts yet."
    layout["alerts"].update(Panel(alert_text, title=f"Recent Alerts (Total: {total_alerts} | Total Frames: {total_frames})"))

def handle_packet(packet):
    global total_frames, total_alerts, alert_active

    if packet.haslayer(Dot11Deauth):
        source = packet[Dot11].addr2
        now = datetime.now()
        total_frames += 1

        deauth_log[source].append(now)
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        deauth_log[source] = [t for t in deauth_log[source] if t > cutoff]

        count = len(deauth_log[source])

        if count >= THRESHOLD:
            alert_active = True
            total_alerts += 1
            timestamp_str = now.strftime("%H:%M:%S")
            recent_alerts.append(f"[{timestamp_str}] ALERT: {source} — {count} frames/10s")

def sniff_thread():
    sniff(iface=INTERFACE, prn=handle_packet, store=False)

if __name__ == "__main__":
    layout = make_layout()
    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()

    with Live(layout, refresh_per_second=4, screen=True) as live:
        while True:
            render(layout)
            time.sleep(0.25)
