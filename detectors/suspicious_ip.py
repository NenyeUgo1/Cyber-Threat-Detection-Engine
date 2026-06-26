import yaml

def load_suspicious_ips(config_path="config/suspicious_ips.yaml"):
    with open(config_path, "r") as f:
        data = yaml.safe_load(f)
    return set(data.get("suspicious_ips", []))

def detect_suspicious_ip(logs, config_path="config/suspicious_ips.yaml"):
    alerts = []
    suspicious_ips = load_suspicious_ips(config_path)

    for line in logs:
        for ip in suspicious_ips:
            if ip in line:
                alerts.append(f"Activity from suspicious IP {ip}: {line.strip()}")

    return alerts
