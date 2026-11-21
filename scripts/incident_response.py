#!/usr/bin/env python3
"""Create a human-review incident register from Suricata alert events.

This intentionally does not block hosts, alter firewall rules, or take disruptive action.
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eve_json", help="Path to Suricata eve.json")
    parser.add_argument("--output", default="reports/incidents.json")
    args = parser.parse_args()

    incidents = []
    with Path(args.eve_json).open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert", {})
            incidents.append({
                "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                "event_timestamp": event.get("timestamp"),
                "status": "needs_human_review",
                "severity": alert.get("severity"),
                "signature": alert.get("signature", "Unknown"),
                "category": alert.get("category"),
                "source": {"ip": event.get("src_ip"), "port": event.get("src_port")},
                "destination": {"ip": event.get("dest_ip"), "port": event.get("dest_port")},
                "protocol": event.get("proto"),
                "recommended_review": [
                    "Confirm the alert is relevant to the monitored lab/network.",
                    "Compare the event with expected activity and other logs.",
                    "Document the analyst decision before taking any response action."
                ]
            })

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(incidents, indent=2), encoding="utf-8")
    print(f"Recorded {len(incidents)} alert(s) for human review: {output}")

if __name__ == "__main__":
    main()
