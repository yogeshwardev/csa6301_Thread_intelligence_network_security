from collections import defaultdict

# Create the sample log so the script runs standalone (no upload needed)
with open("login_attempts.log", "w") as f:
    f.write("2026-07-08 09:00:01 LOGIN SUCCESS user=alice ip=10.0.0.5\n")
    f.write("2026-07-08 09:01:15 LOGIN FAILED user=admin ip=203.0.113.99\n")
    f.write("2026-07-08 09:01:20 LOGIN FAILED user=admin ip=203.0.113.99\n")
    f.write("2026-07-08 09:01:25 LOGIN FAILED user=admin ip=203.0.113.99\n")
    f.write("2026-07-08 09:01:30 LOGIN FAILED user=admin ip=203.0.113.99\n")
    f.write("2026-07-08 09:01:35 LOGIN FAILED user=admin ip=203.0.113.99\n")
    f.write("2026-07-08 09:02:00 LOGIN SUCCESS user=bob ip=10.0.0.8\n")


def simple_ids(logfile, threshold=3):
    attempts = defaultdict(int)
    alerts = []
    with open(logfile) as f:
        for line in f:
            if "LOGIN FAILED" in line:
                ip = line.split("ip=")[1].strip()
                attempts[ip] += 1
                if attempts[ip] == threshold:
                    alerts.append(f"IDS ALERT: {threshold}+ failed logins from {ip}")
    return alerts


for alert in simple_ids("login_attempts.log", threshold=3):
    print(alert)
