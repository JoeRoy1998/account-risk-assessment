from datetime import datetime, timezone
# Get the current time in UTC, as a timezone-aware object
utc_now = datetime.now(timezone.utc)
# Format the time into the desired string format
formatted_time = utc_now.strftime('%Y-%m-%dT%H:%M:%S%Z')

def make_account_decision(account, severity_rules):
    # determine severity
    curr_thresh = -1
    curr_sev = "OK"
    failed_logins = account["failed_logins"]
    escalation = "NONE"
    for severity, severity_policy in severity_rules.items():
        if failed_logins >= severity_policy["threshold"] and curr_thresh <= severity_policy["threshold"]:
            curr_thresh = severity_policy["threshold"]
            curr_sev = severity
    # build decision object
    selected_policy = severity_rules[curr_sev]
    username = account["username"]
    role = account["role"]
    lock_state = selected_policy["lock_state"]
    escalation_team = selected_policy["escalation"]
    action = selected_policy["action"]
    decision = {
    "username": username,
    "role": role,
    "severity": curr_sev,
    "recommended_action": action,
    "escalation": escalation_team,
    "account_state": lock_state,
    "reason": f"{failed_logins} failed logins meets {curr_sev} threshold ({curr_thresh}).",
    "event": f"{formatted_time} | {curr_sev} | {username} | {lock_state} | {escalation_team}"
}
    return decision

accounts = [
    {"username": "admin", "role": "IT", "failed_logins": 2, "account_state": ""},
    {"username": "exec", "role": "Executive", "failed_logins": 12, "account_state": ""},
    {"username": "jdoe", "role": "User", "failed_logins": 6, "account_state": ""}
]

event_log = []

severity_rules = {
    "CRITICAL": 
        {"threshold": 10,
         "action": "Lock account immediately and notify security team",
         "escalation": "Security Team",
         "lock_state": "LOCKED"
         },
    "ALERT": 
        {"threshold": 5,
         "action": "Monitor account and notify IT",
         "escalation": "IT Team",
         "lock_state": "ACTIVE"
        },
    "OK": 
        {"threshold": 0,
         "action": "No action required",
         "escalation": "NONE",
         "lock_state": "ACTIVE"
        }
}

for account in accounts:
    decision = make_account_decision(account, severity_rules)
    event_log.append(decision["event"])

    print("User:", decision["username"])
    print("Role:", decision["role"])
    print("Severity:", decision["severity"])
    print("Action:", decision["recommended_action"])
    print("Escalation:", decision["escalation"])
    print("State:", decision["account_state"])
    print("Reason:", decision["reason"])
    print("Event:", decision["event"])
    print("---")

with open("security_log", "a") as file:
    # Operations on the file (read, write, etc.)
    for event in event_log:
        print(event)
        file.write(event + "\n")
        # The file is automatically closed once the code block is exited
