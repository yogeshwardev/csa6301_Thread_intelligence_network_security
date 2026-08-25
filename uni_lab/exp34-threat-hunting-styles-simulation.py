"""
Experiment 34: Threat Hunting Styles (Hypothesis-, Intelligence-, and Analytics-Based)
"""
import statistics

def hypothesis_hunt_powershell(process_logs):
    # Hypothesis: Attackers execute encoded powershell commands
    return [l for l in process_logs if "powershell" in l.get("process", "").lower() and "-enc" in l.get("args", "").lower()]

def intelligence_hunt(network_logs, known_malicious_feed):
    return [l for l in network_logs if l.get("dst_ip") in known_malicious_feed]

def analytics_hunt_anomaly(login_hours_history, new_hour, z_threshold=2.0):
    mean = statistics.mean(login_hours_history)
    stdev = statistics.pstdev(login_hours_history) or 1
    z_score = abs(new_hour - mean) / stdev
    return {"z_score": round(z_score, 2), "is_anomalous": z_score > z_threshold}

# Test Cases
def test_exp34():
    p_logs = [
        {"process": "powershell.exe", "args": "-enc SGVsbG8="},
        {"process": "cmd.exe", "args": "dir"},
    ]
    assert len(hypothesis_hunt_powershell(p_logs)) == 1

    net_logs = [{"dst_ip": "1.1.1.1"}, {"dst_ip": "185.220.101.5"}]
    intel_feed = {"185.220.101.5"}
    assert len(intelligence_hunt(net_logs, intel_feed)) == 1

    history = [9, 9, 10, 9, 8, 9, 10]
    res = analytics_hunt_anomaly(history, new_hour=3)
    assert res["is_anomalous"] is True
    print("Experiment 34: All test cases passed.")

if __name__ == "__main__":
    print("Hypothesis Hunt:", hypothesis_hunt_powershell([{"process": "powershell.exe", "args": "-enc AAA"}]))
    test_exp34()
