# User Access Audit Tool

A simple Python script that analyzes user accounts for security risks such as:
- Admin accounts without MFA
- Dormant accounts (90+ days)
- Developers without MFA
- Dormant admin accounts
- Org-wide security issues (too many admins, too many dormant users, low MFA adoption)

## Features
- Per-user findings
- Per-user risk score
- Severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Org-wide findings
- Summary statistics
- Export to JSON, CSV, TXT

## Usage
Run the script:

python audit_tool.py using the example users.json for a example report or if you want use your own

After the report prints, you will be asked if you want to save it in JSON, CSV, or TXT format.

## Configuration
You can modify thresholds at the top of the script:

DORMANCY_THRESHOLD = 90
ADMIN_RATIO_THRESHOLD = 20
DORMANT_RATIO_THRESHOLD = 10
NO_MFA_RATIO_THRESHOLD = 15


## Output
The tool prints:
- Org-wide findings
- Per-user findings
- Summary statistics
- Optional saved reports
