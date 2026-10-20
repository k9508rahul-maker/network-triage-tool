# Network Triage Tool

A Flask-based cybersecurity project for analyzing authorized network packet capture (PCAP) files and identifying traffic patterns that may need further investigation.

## Features

- PCAP and PCAPNG file analysis
- IPv4 and IPv6 traffic inspection
- Protocol distribution dashboard
- Source and destination IP investigation
- Heuristic detection of possible TCP SYN port scans
- Security findings with severity levels
- SQLite database for analysis history
- Search and filtering for security alerts
- Alert status management
- CSV and PDF report export
- Dashboard charts
- Automated tests with pytest

## Technology Stack

- Python
- Flask
- Scapy
- SQLite
- HTML and CSS
- JavaScript and Chart.js
- ReportLab
- Pytest

## Project Structure

```text
network-triage-tool/
├── analyzer/
├── database/
├── static/
├── templates/
├── tests/
├── uploads/
├── reports/
├── app.py
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:

   ```bash
   git clone YOUR_GITHUB_REPOSITORY_URL
   cd network-triage-tool
   ```

2. Create and activate a virtual environment on Windows:

   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

4. Set a development secret key in PowerShell:

   ```powershell
   $env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
   ```

5. Start the application:

   ```powershell
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

## Run Tests

```powershell
python -m pytest tests -v
```

## Security Notice

Use this tool only with packet captures you are authorized to analyze. Detection results are heuristic indicators, not proof of malicious activity. This project is a local development prototype and requires additional security review before production deployment.

## Author

Rahul Singh — BCA Cyber Security student.
