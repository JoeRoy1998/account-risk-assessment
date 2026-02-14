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
    decision = {
    "username": account["username"],
    "role": account["role"],
    "severity": curr_sev,
    "recommended_action": selected_policy["action"],
    "escalation": selected_policy["escalation"],
    "account_state": selected_policy["lock_state"],
    "reason": f"{failed_logins} failed logins meets {curr_sev} threshold ({curr_thresh})."
}
    return decision

accounts = [
    {"username": "admin", "role": "IT", "failed_logins": 2, "account_state": ""},
    {"username": "exec", "role": "Executive", "failed_logins": 12, "account_state": ""},
    {"username": "jdoe", "role": "User", "failed_logins": 6, "account_state": ""}
]

severity_rules = {
    "CRITICAL": 
        {"threshold": 10,
         "action": "Lock account immediately and notify security team",
         "escalation": "Security Team",
         "lock_state": "LOCK"
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


    print("User:", decision["username"])
    print("Role:", decision["role"])
    print("Severity:", decision["severity"])
    print("Action:", decision["recommended_action"])
    print("Escalation:", decision["escalation"])
    print("State:", decision["account_state"])
    print("Reason:", decision["reason"])
    print("---")
