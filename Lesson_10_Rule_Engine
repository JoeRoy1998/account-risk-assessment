def get_recommended_action(severity):
    if severity == "CRITICAL":
        return "Lock account immediately and notify security team"
    elif severity == "ALERT":
        return "Monitor account and notify IT"
    else:
        return "No action required"
    
def account_lock(account, severity):
    if severity == "CRITICAL":
        account["account_state"] = "LOCKED"
    else:
        account["account_state"] = "ACTIVE"

def determine_severity(failed_logins, severity_rules):
    curr_thresh = -1
    curr_sev = "OK"
    for severity, threshold in severity_rules.items():
        if failed_logins >= threshold and curr_thresh <= threshold:
            curr_thresh = threshold
            curr_sev = severity
    return curr_sev

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
    failed_logins = account["failed_logins"]
    severity = determine_severity(failed_logins, severity_rules)
    action = get_recommended_action(severity)
    lock = account_lock(account, severity) 


    print("User:", account["username"])
    print("Role:", account["role"])
    print("Severity:", severity)
    print("Action:", action)
    print("Account State:", account["account_state"])
    print("---")
