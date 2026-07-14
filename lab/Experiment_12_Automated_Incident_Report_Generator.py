import datetime


def generate_report(flagged_ips, source_log):
    lines = []
    lines.append("INCIDENT RESPONSE REPORT")
    lines.append(f"Generated: {datetime.datetime.now()}")
    lines.append(f"Source log: {source_log}")
    lines.append("-" * 40)
    if flagged_ips:
        lines.append(f"{len(flagged_ips)} suspicious IP(s) detected:")
        for ip, count in flagged_ips.items():
            lines.append(f"  - {ip}: {count} failed login attempts")
        lines.append("Recommended action: Block listed IPs, force password reset.")
    else:
        lines.append("No suspicious activity detected.")
    return "\n".join(lines)


flagged = {"203.0.113.99": 5}
report = generate_report(flagged, "login_attempts.log")
print(report)

with open("incident_report.txt", "w") as f:
    f.write(report)
