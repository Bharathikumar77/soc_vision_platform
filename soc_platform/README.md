# SOC Alert Investigation Training Platform

A realistic Blue Team training environment modeled after LetsDefend and TryHackMe Blue Team labs.

---

## Project Structure

```
soc_platform/
├── app.py                  # Flask backend - all routes
├── schema.sql              # SQLite database schema
├── requirements.txt        # Python dependencies
├── data/
│   ├── __init__.py
│   └── seed.py             # 50+ realistic SOC scenarios
├── templates/
│   ├── base.html           # Base layout with sidebar
│   ├── login.html          # Login page
│   ├── dashboard.html      # Main dashboard
│   ├── alerts.html         # Alert library
│   ├── investigate.html    # Investigation page
│   ├── logs.html           # Log viewer
│   ├── report.html         # Incident report
│   └── leaderboard.html    # Analyst leaderboard
└── static/
    ├── css/main.css        # Full dark SOC theme
    └── js/main.js          # UI interactions
```

---

## Setup Instructions

### Prerequisites
- Python 3.9 or higher
- pip

### Step 1 — Create a virtual environment

```bash
cd soc_platform
python -m venv venv
```

Activate it:
- **Windows:** `venv\Scripts\activate`
- **Linux/Mac:** `source venv/bin/activate`

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Run the app

```bash
python app.py
```

The database is created and seeded automatically on first run.

Open your browser at: **http://127.0.0.1:5000**

---

## VS Code Run Instructions

### Option A — Terminal
1. Open the `soc_platform` folder in VS Code
2. Open Terminal (`Ctrl+` `)
3. Run:
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
python app.py
```

### Option B — VS Code Launch Config
Create `.vscode/launch.json`:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "SOC Platform",
            "type": "python",
            "request": "launch",
            "program": "app.py",
            "env": { "FLASK_ENV": "development" },
            "jinja": true
        }
    ]
}
```
Then press **F5** to run.

---

## Login Credentials

| Username        | Password     | Role        |
|-----------------|--------------|-------------|
| analyst         | soc2024      | Analyst     |
| senior_analyst  | senior2024   | Senior      |
| team_lead       | lead2024     | Admin       |
| alice_soc       | alice2024    | Analyst     |
| bob_ir          | bob2024      | Analyst     |

---

## Features

### Pages
| Page | Route | Description |
|------|-------|-------------|
| Login | `/login` | Authentication |
| Dashboard | `/dashboard` | KPIs, recent alerts, categories |
| Alert Library | `/alerts` | 50+ scenarios with filters |
| Investigation | `/investigate/<id>` | Full investigation workflow |
| Log Viewer | `/logs` | Search/filter security logs |
| Report | `/report/<id>` | Incident report generation |
| Leaderboard | `/leaderboard` | Top analysts ranking |

### Alert Categories
- Authentication Attacks (Brute Force, Spraying, Stuffing, Kerberoasting)
- Malware (Ransomware, Cobalt Strike, Emotet, AgentTesla)
- Phishing (BEC, Spear Phishing, Quishing, PDF Lure)
- Network Security (Port Scan, DNS Tunneling, Pass-the-Hash, DDoS)
- Active Directory (DCSync, Golden Ticket, WMI Lateral Movement)
- Cloud Security (S3 Misconfiguration, K8s Dashboard, SPN Exposure)
- Web Attacks (SQLi, XSS, Path Traversal)
- Data Exfiltration (Cloud Upload, Insider Threat, DNS Tunneling)
- Endpoint Security (LOLBins, Rootkit, Scheduled Tasks, Registry Keys)
- Threat Hunting (WMI Persistence, Registry Run Keys, Pastebin C2)

### Log Types Included
- Windows Security Event Logs (4624, 4625, 4688, 4698, 4740, 4769...)
- Linux Syslog (auth.log, sshd, sudo)
- Firewall Logs (Palo Alto, Suricata, Zeek)
- Web Server Logs (Nginx, Apache, WAF/ModSecurity)
- Email Security Logs (ProofPoint, MDO365, SMTP)
- EDR Alerts (CrowdStrike Falcon, Windows Defender ATP)

### Scoring Engine
- Each scenario has a point value (50–250 pts)
- Correct verdict = full points
- Wrong verdict = half points
- Points aggregate on leaderboard

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/submit_investigation` | Submit verdict + notes |
| POST | `/api/save_notes` | Auto-save analyst notes |
| GET | `/api/alert_stats` | Category/severity stats |
| GET | `/api/profile` | Current analyst stats |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | T1566, T1078 |
| Credential Access | T1110, T1558, T1003 |
| Lateral Movement | T1021, T1550 |
| Defense Evasion | T1562, T1218, T1027, T1014 |
| Persistence | T1053, T1546, T1547 |
| Command & Control | T1071, T1102 |
| Collection | T1056, T1213, T1530 |
| Exfiltration | T1567, T1567 |
| Impact | T1486, T1490, T1499 |
| Discovery | T1046, T1083, T1613 |

---

## Resetting the Database

```bash
rm soc_platform.db
python app.py
```

This re-creates and re-seeds all 50+ scenarios.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python Flask |
| Database | SQLite3 |
| Frontend | HTML5, CSS3, Vanilla JS |
| Fonts | JetBrains Mono + Inter |
| Auth | Session-based (SHA256 hashed) |
