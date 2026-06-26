from detectors.brute_force import detect_brute_force
from detectors.failed_logins import detect_failed_logins
from detectors.suspicious_ip import detect_suspicious_ip

def analyze_log(log_path="logs/sample_auth.log"):
    with open(log_path, "r") as f:
        logs = f.readlines()

    alerts = []
    alerts += detect_brute_force(logs)
    alerts += detect_failed_logins(logs)
    alerts += detect_suspicious_ip(logs)

    return alerts

if __name__ == "__main__":
    results = analyze_log()

    print("\n=== Cybersecurity Log Analyzer Report ===\n")
    if not results:
        print("No alerts detected.")
    else:
        for alert in results:
            print(f"[ALERT] {alert}")
