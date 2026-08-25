"""
Experiment 19: Simulating Splunk Search Filter (SPL) and Stats Aggregation
"""

splunk_dataset = [
    {"_time": "10:00", "source": "auth", "user": "alice", "action": "login_failed"},
    {"_time": "10:01", "source": "auth", "user": "alice", "action": "login_failed"},
    {"_time": "10:02", "source": "auth", "user": "alice", "action": "login_success"},
    {"_time": "10:05", "source": "firewall", "action": "blocked", "ip": "1.2.3.4"},
    {"_time": "10:06", "source": "auth", "user": "bob", "action": "login_success"},
]

def spl_search(dataset, **kwargs):
    return [row for row in dataset if all(row.get(k) == v for k, v in kwargs.items())]

def spl_stats_count_by(dataset, group_field):
    counts = {}
    for row in dataset:
        key = row.get(group_field, "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts

# Test Cases
def test_exp19():
    failed = spl_search(splunk_dataset, source="auth", action="login_failed")
    assert len(failed) == 2
    assert all(r["user"] == "alice" for r in failed)

    counts = spl_stats_count_by(splunk_dataset, "source")
    assert counts == {"auth": 4, "firewall": 1}
    print("Experiment 19: All test cases passed.")

if __name__ == "__main__":
    print("Search:", spl_search(splunk_dataset, action="login_success"))
    print("Stats by source:", spl_stats_count_by(splunk_dataset, "source"))
    test_exp19()
