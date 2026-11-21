# Network Intrusion Detection System (NIDS)

A beginner-friendly, defensive NIDS lab using **Suricata**. It monitors traffic on an interface you are authorized to inspect, evaluates local detection rules, writes alerts to `eve.json`, and provides a small Python report tool.

## Features
- Suricata-based network monitoring
- Custom local rules for common suspicious patterns (scan-like connection bursts, ICMP, DNS query visibility)
- JSON alert/event logging
- Python log summarizer (`scripts/analyze_eve.py`)
- Safe response workflow: records an incident report for review; it does **not** automatically block devices or change firewall rules
- Example dashboard data export as CSV

> Use only on your own device/network or in a lab where you have explicit permission. Detection rules are starting examples, not proof that an attack occurred. Tune them to your environment.

## Repository structure
```text
Network_IDS_Project/
├── config/
│   └── suricata-local.yaml
├── rules/
│   └── local.rules
├── scripts/
│   ├── analyze_eve.py
│   └── incident_response.py
├── logs/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
├── .gitignore
├── requirements.txt
└── README.md
```

## 1. Install Suricata (Ubuntu/Debian/Kali Linux)
```bash
sudo apt update
sudo apt install suricata jq -y
suricata --build-info
```
On other systems, follow the official Suricata installation guide.

## 2. Identify the interface
```bash
ip -br link
```
Choose the interface you are authorized to monitor (for example, `eth0` or `wlan0`). Do not assume the interface name.

## 3. Add the local rules
Copy the supplied rules into Suricata's local rules directory:
```bash
sudo cp rules/local.rules /etc/suricata/rules/local.rules
```
Open `/etc/suricata/suricata.yaml` and make sure:
- `HOME_NET` is set to your own lab/home subnet (not `any`)
- `default-rule-path` is `/var/lib/suricata/rules` or the path used by your installation
- `rule-files` includes `local.rules`
- `eve-log` is enabled and includes `alert`, `dns`, `http`, `tls`, and `flow` event types as appropriate

The included `config/suricata-local.yaml` is a reference snippet, not a complete replacement for the distribution's full `suricata.yaml`.

## 4. Validate configuration and rules
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```
Fix any reported path or rule errors before starting monitoring.

## 5. Run in IDS mode
Replace `wlan0` with your authorized interface:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i wlan0
```
Keep the terminal open while monitoring. Stop with `Ctrl+C`. For a service-based setup, consult your distribution's Suricata service documentation and verify the configured interface before enabling it.

## 6. Review alerts
Common log location:
```bash
sudo tail -f /var/log/suricata/eve.json
```
Analyze the log:
```bash
python3 scripts/analyze_eve.py /var/log/suricata/eve.json --output reports/summary.csv
```

Create an incident review record from the latest alert:
```bash
python3 scripts/incident_response.py /var/log/suricata/eve.json --output reports/incidents.json
```
This script only records and summarizes alerts. A human should validate the event and decide what action is appropriate.

## 7. Dashboard / visualization
Open the generated CSV (`reports/summary.csv`) in LibreOffice Calc or Excel. You can also import it into a dashboard tool. No external service or cloud upload is required.

## Rule notes
- The rules are intentionally conservative examples for a controlled lab.
- `SCAN-LIKE` flags a high rate of TCP SYN attempts from one source within a short window; legitimate inventory tools can also trigger it.
- ICMP and DNS rules are visibility alerts and are not necessarily malicious.
- Thresholds should be tuned after observing normal baseline traffic.

## GitHub upload
1. Create a public repository named `Network-Intrusion-Detection-System`.
2. Extract this ZIP.
3. Upload the folder contents (not the ZIP alone), or use:
```bash
git init
git add .
git commit -m "Add Suricata-based Network IDS project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/Network-Intrusion-Detection-System.git
git push -u origin main
```
Replace `YOUR-USERNAME` with your GitHub username.

## Limitations
- This is an educational starter project, not an enterprise IDS.
- Encrypted payloads generally cannot be inspected as readable application content.
- Detection depends on rule coverage, correct interface selection, and log configuration.
- Do not run packet capture on networks without permission.
