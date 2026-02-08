def assess_account_risk(username, user_data):
    # analyze user_data here
    failed_logins = user_data["failed_logins"]
    role = user_data["role"]
    account_locked = user_data["account_locked"]

    if role == "Executive":
        if failed_logins >= 5:
            severity = "LOCKED"
            account_locked = True
        else:
            severity = "OK"
            account_locked = False
    elif role == "IT":
        if failed_logins >= 10:
            severity = "LOCKED"
            account_locked = True
        elif failed_logins >= 5:
            severity = "ALERT"
            account_locked = False
        else:
            severity = "OK"
            account_locked = False
    elif role == "User":
        if failed_logins >= 15:
            severity = "LOCKED"
            account_locked = True
        elif failed_logins >= 10:
            severity = "ALERT"
            account_locked = False
        elif failed_logins >= 5:
            severity = "CRITICAL"
            account_locked = False
        else:
            severity = "OK"
            account_locked = False

    # return a message
    if account_locked:
        return f"[{severity}]: {username} ({role}) account is locked. Reach out to IT for further assistance."
    elif severity == "ALERT":
        return f"[{severity}] {username} ({role}) is seeing a large amount of failed logins."
    elif severity == "CRITICAL":
        return f"[{severity}] {username} ({role}) is exhibiting abnormal login behavior!"
    else:
        return f"[{severity}] {username} ({role}) is exhibiting normal behavior."

accounts = {
    "admin": {
        "failed_logins": 2,
        "role": "IT",
        "account_locked": False
    },
    "exec": {
        "failed_logins": 12,
        "role": "Executive",
        "account_locked": True
    },
    "jdoe": {
        "failed_logins": 6,
        "role": "User",
        "account_locked": False
    },
    "jroy": {
        "failed_logins": 20,
        "role": "IT",
        "account_locked": True
    },
    "dseale": {
        "failed_logins": 6,
        "role": "IT",
        "account_locked": True
    }
}

for user, data in accounts.items():
    # call your function and print result
    print(assess_account_risk(user, data))
