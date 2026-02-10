def make_account_decision(account, severity_rules):
    # determine severity
    curr_thresh = -1
    curr_sev = "OK"
    failed_logins = account["failed_logins"]
    for severity, threshold in severity_rules.items():
        if failed_logins >= threshold and curr_thresh <= threshold:
            curr_thresh = threshold
            curr_sev = severity
    # determine recommended action
    if curr_sev == "CRITICAL":
        action =  "Lock account immediately and notify security team"
    elif curr_sev == "ALERT":
        action =  "Monitor account and notify IT"
    else:
        action =  "No action required"
    # lock or unlock account
    if curr_sev == "CRITICAL":
        account["account_state"] = "LOCKED"
    else:
        account["account_state"] = "ACTIVE"
    # build decision object
    decision = {
    "username": account["username"],
    "role": account["role"],
    "severity": curr_sev,
    "recommended_action": action,
    "account_state": account["account_state"],
    "reason": "Failed logins matched to highest applicable threshold."
}
    return decision

accounts = [
    {"username": "admin", "role": "IT", "failed_logins": 2, "account_state": ""},
    {"username": "exec", "role": "Executive", "failed_logins": 12, "account_state": ""},
    {"username": "jdoe", "role": "User", "failed_logins": 6, "account_state": ""}
]

severity_rules = {
    "CRITICAL": 10,
    "ALERT": 5,
    "OK": 0
}

for account in accounts:
    decision = make_account_decision(account, severity_rules)


    print("User:", decision["username"])
    print("Role:", decision["role"])
    print("Severity:", decision["severity"])
    print("Action:", decision["recommended_action"])
    print("State:", decision["account_state"])
    print("Reason:", decision["reason"])
    print("---")
