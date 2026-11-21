#!/usr/bin/env python3
"""Summarize Suricata EVE JSON events into a CSV report (standard library only)."""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

def read_events(path):
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"Skipping malformed JSON at line {line_no}")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eve_json", help="Path to Suricata eve.json")
    parser.add_argument("--output", default="reports/summary.csv")
    args = parser.parse_args()

    alerts = []
    counts = Counter()
    for event in read_events(args.eve_json):
        event_type = event.get("event_type", "unknown")
        counts[event_type] += 1
        if event_type == "alert":
            alert = event.get("alert", {})
            alerts.append({
                "timestamp": event.get("timestamp", ""),
                "signature": alert.get("signature", "Unknown"),
                "severity": alert.get("severity", ""),
                "category": alert.get("category", ""),
                "src_ip": event.get("src_ip", ""),
                "src_port": event.get("src_port", ""),
                "dest_ip": event.get("dest_ip", ""),
                "dest_port": event.get("dest_port", ""),
                "proto": event.get("proto", ""),
            })

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = ["timestamp", "signature", "severity", "category", "src_ip",
              "src_port", "dest_ip", "dest_port", "proto"]
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    print("Event totals:")
    for name, count in sorted(counts.items()):
        print(f"  {name}: {count}")
    print(f"Alert rows: {len(alerts)}")
    print(f"CSV report: {output}")

if __name__ == "__main__":
    main()
