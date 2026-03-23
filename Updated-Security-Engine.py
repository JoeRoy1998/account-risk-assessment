#********
# IMPORTS
#********
import json
from datetime import datetime, timezone

#**********
# CONSTANTS
#**********
SEVERITY_ORDER = ["OK", "ALERT", "CRITICAL"]

severity_rules = {
    "CRITICAL": {
        "threshold": 10,
        "action": "Lock account immediately and notify security team",
        "escalation": "Security Team",
        "lock_state": "LOCKED"
    },
    "ALERT": {
        "threshold": 5,
        "action": "Monitor account and notify IT",
        "escalation": "IT Team",
        "lock_state": "ACTIVE"
    },
    "OK": {
        "threshold": 0,
        "action": "No action required",
        "escalation": "NONE",
        "lock_state": "ACTIVE"
    }
}

accounts = [
    {"username": "admin", "role": "IT", "failed_logins": 2, "account_state": ""},
    {"username": "exec", "role": "Executive", "failed_logins": 6, "account_state": ""},
    {"username": "jdoe", "role": "User", "failed_logins": 6, "account_state": ""}
]

event_log = []

#*****************
# Rules Dictionary
#*****************
ROLE_RULES = {
    "Executive": {
        "severity_boost": 1,
        "reason": "Escalated due to Executive role."
    }
}

#**********
# FUNCTIONS
#**********
def run_detection_engine(account, severity_rules):
    #********************************************************
    # Get the current time in UTC, as a timezone-aware object
    #********************************************************
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    current_threshold = -1
    current_severity = "OK"
    failed_logins = account["failed_logins"]
    role = account["role"]
    #*******************
    # Determine severity
    #*******************
    for severity, severity_policy in severity_rules.items():
        if failed_logins >= severity_policy["threshold"] and current_threshold <= severity_policy["threshold"]:
            current_threshold = severity_policy["threshold"]
            current_severity = severity
    
    baseline_sev = current_severity
    final_severity = current_severity

    #***********
    # Role Rules
    #***********
    if role in ROLE_RULES:
        current_index = SEVERITY_ORDER.index(current_severity)
        rule = ROLE_RULES[role]
        boost = rule["severity_boost"]
        final_severity = SEVERITY_ORDER[current_index + boost]
        rule_reason = rule["reason"]

    if baseline_sev != final_severity:
        reason = f"{failed_logins} failed logins meets {baseline_sev} threshold ({current_threshold}). {rule_reason}"
    else: 
        reason = f"{failed_logins} failed logins meets {baseline_sev} threshold ({current_threshold})."

    #**********************
    # Build decision object
    #**********************
    selected_policy = severity_rules[final_severity]
    username = account["username"]
    role = account["role"]
    lock_state = selected_policy["lock_state"]
    escalation_team = selected_policy["escalation"]
    action = selected_policy["action"]
    decision = {
    "username": username,
    "role": role,
    "severity": final_severity,
    "recommended_action": action,
    "escalation": escalation_team,
    "account_state": lock_state,
    "reason": reason,
    "timestamp": timestamp
}
    return decision

#*******************
# PROGRAM EXECUTION
#*******************
for account in accounts:
    decision = run_detection_engine(account, severity_rules)
    event_log.append(json.dumps(decision))

    print("User:", decision["username"])
    print("Role:", decision["role"])
    print("Severity:", decision["severity"])
    print("Action:", decision["recommended_action"])
    print("Escalation:", decision["escalation"])
    print("State:", decision["account_state"])
    print("Reason:", decision["reason"])
    print("Timestamp:", decision["timestamp"])
    print("---")

with open("security_log", "a") as file:
    #*******************************************
    # Operations on the file (read, write, etc.)
    #*******************************************
    for event in event_log:
        print(event)
        file.write(event + "\n")
        #***************************************************************
        # The file is automatically closed once the code block is exited
        #***************************************************************
