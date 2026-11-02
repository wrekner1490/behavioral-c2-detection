# Behavioral C2 Detection System

A defensive, research-oriented system that detects command-and-control (C2)
**beaconing behaviour** in network traffic by its timing/statistical pattern
rather than by signatures. It ships with a dummy C2 server and beacon so you can
generate labelled test traffic in a closed lab, capture it, and run the analyzer.

## Modules

| Command | Purpose |
|---|---|
| `server`  | Dummy C2 server (lab traffic generator) |
| `beacon`  | Dummy beacon client — `fixed`, `random`, or `evasion` timing modes |
| `capture` | Capture traffic on an interface to a pcap |
| `analyze` | Analyze a pcap and score hosts for beaconing behaviour |
| `demo`    | Print the end-to-end demo instructions |

## Requirements

```
pip install -r requirements.txt
```

`flask`, `requests`, `scapy`, `rich`, `matplotlib`, `numpy`

> Packet capture needs appropriate privileges and a real interface name.
> Intended for use in an **isolated lab** against the bundled dummy beacon only.

## Quick start

```bash
# terminal 1
python main.py server
# terminal 2
python main.py beacon --mode fixed --interval 2
# terminal 3
python main.py capture --interface "Wi-Fi" --duration 30 --output my_traffic.pcap
# then
python main.py analyze --pcap my_traffic.pcap
```

## Layout

- `capture/`   — traffic capture
- `analysis/`  — per-window feature extraction
- `detection/` — scoring / detection engine
- `beacon/`, `server/` — lab traffic generators

## Status

Course project; pipeline (generate → capture → analyze) is complete.
