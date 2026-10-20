# Frame 12

A real-time Wi-Fi deauthentication attack detector. Runs on a laptop with a wireless adapter in monitor mode, watches for deauth frames (802.11 management frame subtype 12, which is where the name comes from), and alerts the second it sees an attack happening.

## Why

Deauth attacks kick devices off Wi-Fi silently. No password needed, no warning, nothing that looks different from a normal dropped connection. Most people who get hit by one just assume their router glitched, because there's no way to tell the difference. That's the actual problem. The attack is invisible by design.

This tool makes it visible.

## How it works

- Sniffs 802.11 management frames with Scapy, in monitor mode
- Tracks deauth frame count per source MAC over a rolling 10 second window
- Alerts when a source sends more than 10 deauth frames in that window. I picked 10 because my baseline testing on normal network traffic never produced more than 0 deauth frames in any 10 second window, so anything above that is already well outside normal
- Logs every event to CSV
- Shows all of it through a live terminal dashboard built with `rich`, a status panel that flips green to red, a live table of current rates per device, and a rolling alert log

## Results

Tested on my own devices, on my own network, three runs:

| Test | Deauth frames sent | Frames flagged as attack | False positives | Time to first alert |
|---|---|---|---|---|
| Baseline, no attack | 0 | 0 | 0 | n/a |
| Targeted attack | 3,035 | 3,017 | 0 | under 1 second |
| Broadcast attack | 4,044 | 4,026 | 0 | under 1 second |

Raw logs are in the repo if you want to check the numbers yourself.

The more interesting result: some of my test devices resisted the attack entirely, which is Protected Management Frames (part of WPA3) doing its job. But it wasn't consistent. The exact same phone was vulnerable on one connection and protected on the next connection to the same network. My best explanation is that my router has PMF set to optional instead of required, so it gets renegotiated every time a device connects instead of being guaranteed session to session. I haven't confirmed this by checking the RSN capability bits in Wireshark yet, so take it as a hypothesis, not a proven result. It's the next thing I want to verify.

## Ethics

All testing in this repo was done against devices and networks I own. Sending deauth frames at a network you don't have permission to test is illegal. This tool is built for detecting and understanding the attack, not for running it against anyone else.

## Requirements

- Linux (I used Ubuntu 24.04)
- A wireless adapter that supports monitor mode, to run the detector (I used an Alfa AWUS036ACM, MediaTek MT7612U chipset)
- The same adapter also needs to support packet injection if you want to reproduce the test attacks yourself, not just run detection
- Python 3, with `scapy` and `rich` installed (`pip install -r requirements.txt`)

## Running it

Put the adapter into monitor mode first. The interface name below is whatever `airmon-ng` renames it to on your system, check with `iwconfig` if you're not sure:

```bash
sudo airmon-ng start <your interface>
```

Then run the dashboard:

```bash
sudo python3 dashboard.py
```

Or the plain logging version without the UI:

```bash
sudo python3 detector.py
```

Both scripts have the interface name set near the top as `INTERFACE = "wlan0mon"`, change that line if yours comes up differently.

## What it doesn't do yet

It detects and alerts. It doesn't block the attack or notify you anywhere outside the dashboard itself. Pushing an alert to a phone is the obvious next step, and eventually prompting a user to turn on required PMF if the tool sees their router isn't enforcing it.

This started because my grandma's tablet kept dropping off her Wi-Fi and she figured it was broken. It probably was, but a deauth attack would have looked exactly the same from where she sat, and she'd have had no way to tell.
