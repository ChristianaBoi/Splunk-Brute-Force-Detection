# Splunk Brute Force Detection Project
## Project Overview
This project simulates a brute force login attack detection workflow using Splunk 10.2. It demonstrates core SOC analyst skills including log ingestion, SPL query writing, detection engineering, and dashboard visualization using synthetic Windows Security Event Log data.
## Tools Used
- Splunk Enterprise 10.2.1
- Ubuntu 22.04 (VirtualBox VM)
- Windows Security Event Log (simulated)

## Dataset
Synthetic Windows Security Event Log data created to replicate real-world brute force attack patterns. Fields include:

- **EventID** — 4625 (failed logon) and 4624 (successful logon)
- **SourceIP** — attacker IP address
- **TargetUsername** — account being attacked
- **Status** — 0xC000006D (incorrect credentials, official Microsoft NTSTATUS code)
## Detection 1: Brute Force Login Detection
Identifies source IPs with 3 or more failed login attempts against the same account.

### SPL Query
source=“failed_logins.csv” EventID=4625
| stats count by SourceIP, TargetUsername
| where count >= 3

### Finding
192.168.1.105 made 3+ failed login attempts against the administrator account — a classic brute force pattern requiring immediate investigation.
## Detection 2: Confirmed Breach Detection
Identifies accounts that experienced repeated failed logins followed by a successful login — indicating a successful brute force breach.

### SPL Query
source=“failed_logins.csv” (EventID=4625 OR EventID=4624)
| stats count(eval(EventID=4625)) as failed_count, count(eval(EventID=4624)) as success_count by SourceIP, TargetUsername
| where failed_count >= 2 AND success_count >= 1

### Finding
10.0.0.55 successfully authenticated as mbrown after 2 failed attempts — a confirmed post-brute-force breach scenario that would trigger immediate escalation in a production SOC environment.
## Dashboard
Built a two-panel SOC detection dashboard in Splunk Dashboard Studio displaying:

- **Panel 1:** Brute Force Offenders (3+ Failed Attempts) — shows attacking IPs and targeted accounts
- **Panel 2:** Confirmed Breaches (Failed Attempts Followed by Success) — shows accounts where the attacker successfully logged in after brute forcing
## Key Takeaways
- Detecting failed logins is expected. Detecting the successful login after repeated failures is what separates alert noise from a real incident.
- In a production environment, Detection 2 would trigger a P1 incident requiring immediate account lockout, password reset, and forensic investigation.
- Scheduled alerting would be configured via Splunk Enterprise to notify the SOC team in real time when either threshold is crossed.
## Screenshots
All project screenshots are included in this repository showing:
1. Data ingestion and field extraction
2. SPL detection queries and results
3. SOC dashboard with both detection panels
## Author
Christiana Boi
SOC Analyst | Detection Engineering | Threat Hunting
GitHub: https://github.com/ChristianaBoi
LinkedIn: https://www.linkedin.com/in/christiana-boi

