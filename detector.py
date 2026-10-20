#!/usr/bin/env python3
from scapy.all import sniff, Dot11, Dot11Deauth
from collections import defaultdict
from datetime import datetime, timedelta
import csv

INTERFACE = "wlan0mon"
WINDOW_SECONDS = 10
THRESHOLD = 10
CSV_FILE = "results.csv"

deauth_log = defaultdict(list)

csv_file = open(CSV_FILE, "a", newline="")
csv_writer = csv.writer(csv_file)
if csv_file.tell() == 0:
    csv_writer.writerow(["timestamp", "source_mac", "count_in_window", "alert"])

def handle_packet(packet):
    if packet.haslayer(Dot11Deauth):
        source = packet[Dot11].addr2
        now = datetime.now()

        deauth_log[source].append(now)
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        deauth_log[source] = [t for t in deauth_log[source] if t > cutoff]

        count = len(deauth_log[source])
        is_alert = count >= THRESHOLD

        timestamp_str = now.strftime("%H:%M:%S.%f")[:-3]

        csv_writer.writerow([timestamp_str, source, count, is_alert])
        csv_file.flush()

        if is_alert:
            print(f"[{timestamp_str}] ALERT: {source} — {count} frames in last {WINDOW_SECONDS}s")
        else:
            print(f"[{timestamp_str}] deauth from {source} — {count}/{THRESHOLD} in window")

print(f"Monitoring {INTERFACE}, logging to {CSV_FILE} (threshold: {THRESHOLD}/{WINDOW_SECONDS}s)...")
sniff(iface=INTERFACE, prn=handle_packet, store=False)
