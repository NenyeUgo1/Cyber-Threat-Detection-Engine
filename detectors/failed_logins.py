def detect_failed_logins(logs, threshold=10):
    count = 0
    alerts = []

    for line in logs:
        if "Failed password" in line:
            count += 1

    if count >= threshold:
        alerts.append(f"High volume of failed logins detected ({count} events)")

    return alerts
