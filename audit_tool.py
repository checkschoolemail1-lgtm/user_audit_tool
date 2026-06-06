import json
import csv


# ============================================================
# EVENT LOG CLASS
# ============================================================

class AuditEventLog:
    """Simple class to store audit events."""
    def __init__(self):
        self.events = []

    def add(self, message: str):
        self.events.append(message)

    def get_all(self):
        return self.events


# ============================================================
# SEVERITY
# ============================================================

def get_severity(score: int) -> str:
    if score >= 30:
        return "CRITICAL"
    elif score >= 20:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    else:
        return "LOW"


# ============================================================
# ANALYSIS ENGINE
# ============================================================

def analyze_users(users):
    """
    Analyze users and return:
    {
        "users": [...],
        "org": [...]
    }
    """

    try:
        # Basic validation
        for u in users:
            if not isinstance(u, dict):
                raise ValueError("User entry must be a dictionary")
            for field in ("user", "role", "mfa", "last_login_days"):
                if field not in u:
                    raise ValueError(f"Missing field '{field}' in user: {u}")

    except Exception as e:
        print(f"[ERROR] Invalid user data: {e}")
        return {"users": [], "org": []}

    user_reports = []
    org_events = AuditEventLog()

    # Pre-calc org-wide stats
    pct_admin = sum(1 for u in users if u["role"] == "admin") / len(users) * 100
    pct_dormant = sum(1 for u in users if u["last_login_days"] >= 90) / len(users) * 100
    pct_no_mfa = sum(1 for u in users if not u["mfa"]) / len(users) * 100

    # ORG-WIDE FINDINGS
    if pct_admin > 20:
        org_events.add(f"High admin ratio ({pct_admin:.2f}%)")

    if pct_dormant > 10:
        org_events.add(f"High dormant ratio ({pct_dormant:.2f}%)")

    if pct_no_mfa > 15:
        org_events.add(f"High no-MFA ratio ({pct_no_mfa:.2f}%)")

    # PER-USER FINDINGS
    for user in users:
        findings = []
        score = 0

        # User-specific rules
        if user["role"] == "admin" and not user["mfa"]:
            findings.append("Admin account without MFA")
            score += 10

        if user["last_login_days"] >= 90:
            findings.append(f"Dormant account ({user['last_login_days']} days)")
            score += 5

        if user["role"] == "admin" and user["last_login_days"] >= 30:
            findings.append(f"Dormant admin ({user['last_login_days']} days)")
            score += 7

        if user["role"] == "developer" and not user["mfa"]:
            findings.append("Developer without MFA")
            score += 5

        if user["last_login_days"] >= 90 and not user["mfa"]:
            findings.append("Dormant + No MFA")
            score += 7

        if user["role"] == "admin" and user["last_login_days"] >= 90 and not user["mfa"]:
            findings.append("Critical: Dormant admin + No MFA")
            score += 15

        user_reports.append({
            "user": user["user"],
            "role": user["role"],
            "findings": findings,
            "score": score,
            "severity": get_severity(score)
        })

    return {
        "users": user_reports,
        "org": org_events.get_all()
    }


# ============================================================
# PRINTING
# ============================================================

def print_user_reports(report):
    print("\n=== USER ACCESS AUDIT REPORT ===\n")

    print("ORG-WIDE FINDINGS:")
    if not report["org"]:
        print("No org-wide issues detected")
    else:
        for f in report["org"]:
            print(f"- {f}")

    print("\n------------------------------")

    for entry in report["users"]:
        print(f"\nUser: {entry['user']}")
        print(f"Role: {entry['role']}")
        print(f"Score: {entry['score']}")
        print(f"Severity: {entry['severity']}")
        print("Findings:")

        if not entry["findings"]:
            print("  No issues detected")
        else:
            for f in entry["findings"]:
                print(f"  - {f}")

    print("\n=== END OF REPORT ===\n")


# ============================================================
# SAVE FUNCTIONS
# ============================================================

def save_to_json(report, filename="audit_report.json"):
    ask = input("\nSave JSON report? (y/n): ").strip().lower()
    if ask not in ("y", "yes"):
        return

    try:
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"JSON saved to {filename}")
    except Exception as e:
        print(f"[ERROR] JSON save failed: {e}")


def save_to_csv(report, filename="audit_report.csv"):
    ask = input("\nSave CSV report? (y/n): ").strip().lower()
    if ask not in ("y", "yes"):
        return

    try:
        with open(filename, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["User", "Role", "Finding", "Score", "Severity"])

            for entry in report["users"]:
                if not entry["findings"]:
                    writer.writerow([entry["user"], entry["role"], "No issues", entry["score"], entry["severity"]])
                else:
                    for finding in entry["findings"]:
                        writer.writerow([entry["user"], entry["role"], finding, entry["score"], entry["severity"]])

        print(f"CSV saved to {filename}")
    except Exception as e:
        print(f"[ERROR] CSV save failed: {e}")


def save_to_txt(report, filename="audit_report.txt"):
    ask = input("\nSave TXT report? (y/n): ").strip().lower()
    if ask not in ("y", "yes"):
        return

    try:
        with open(filename, "w") as f:
            f.write("USER ACCESS AUDIT REPORT\n\n")

            f.write("ORG-WIDE FINDINGS:\n")
            if not report["org"]:
                f.write("No org-wide issues detected\n")
            else:
                for finding in report["org"]:
                    f.write(f"- {finding}\n")

            f.write("\n------------------------------\n\n")

            for entry in report["users"]:
                f.write(f"User: {entry['user']}\n")
                f.write(f"Role: {entry['role']}\n")
                f.write(f"Score: {entry['score']}\n")
                f.write(f"Severity: {entry['severity']}\n")
                f.write("Findings:\n")

                if not entry["findings"]:
                    f.write("  No issues detected\n")
                else:
                    for finding in entry["findings"]:
                        f.write(f"  - {finding}\n")

                f.write("\n")

        print(f"TXT saved to {filename}")
    except Exception as e:
        print(f"[ERROR] TXT save failed: {e}")


# ============================================================
# MAIN
# ============================================================

def main():
    users = [
        {"user": "alice", "role": "developer", "mfa": True, "last_login_days": 3},
        {"user": "bob", "role": "admin", "mfa": False, "last_login_days": 1},
        {"user": "charlie", "role": "developer", "mfa": True, "last_login_days": 180},
        {"user": "dave", "role": "admin", "mfa": True, "last_login_days": 0}
    ]

    try:
        report = analyze_users(users)
        print_user_reports(report)

        save_to_json(report)
        save_to_csv(report)
        save_to_txt(report)

    except Exception as e:
        print(f"[FATAL] Unexpected error: {e}")


if __name__ == "__main__":
    main()
