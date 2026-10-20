# Network Triage Tool

A Python-based cybersecurity project for analyzing network packet capture files (PCAP/PCAPNG) and identifying potentially suspicious network activity.

## Features

- Upload and analyze PCAP/PCAPNG files
- Summarize network traffic
- Detect possible TCP SYN port-scan activity using heuristics
- Store analysis history in SQLite
- Review and filter alerts
- Investigate IP addresses
- Export analysis reports to CSV and PDF
- View traffic summaries and charts

## Tech Stack

- Python
- Flask
- Scapy
- SQLite
- HTML, CSS, JavaScript
- Chart.js
- ReportLab
- Pytest

## Run Locally

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   python app.py
   ```

5. Open `http://127.0.0.1:5000` in your browser.

## Run Tests

```bash
python -m pytest -v
```

## Disclaimer

This project is intended for educational and defensive cybersecurity analysis. Detection results are heuristic and should be verified before drawing conclusions. Analyze only packet captures you are authorized to access.

## Author

Rahul Singh
