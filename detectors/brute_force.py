from collections import defaultdict

def detect_brute_force(logs, threshold=5):
    attempts = defaultdict(int)
    alerts = []

    for line in logs:
        if "Failed password" in line:
            parts = line.split()
            ip = parts[-4]  # crude extraction of IP
            attempts[ip] += 1

    for ip, count in attempts.items():
        if count >= threshold:
            alerts.append(f"Brute-force attempt detected from IP {ip} ({count} failed logins)")

    return alerts
