splunk_index = [
    {"_time": "09:15", "source": "auth", "user": "jdoe", "action": "login_success"},
    {"_time": "09:17", "source": "auth", "user": "jdoe", "action": "login_failed"},
    {"_time": "09:18", "source": "auth", "user": "jdoe", "action": "login_failed"},
    {"_time": "09:20", "source": "firewall", "ip": "45.33.32.156", "action": "blocked"},
    {"_time": "09:21", "source": "auth", "user": "asmith", "action": "login_success"},
]


def spl_search(index, **filters):
    results = index
    for field, value in filters.items():
        results = [r for r in results if r.get(field) == value]
    return results


def spl_stats_count_by(index, field):
    counts = {}
    for r in index:
        key = r.get(field, "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


failed_logins = spl_search(splunk_index, source="auth", action="login_failed")
counts_by_source = spl_stats_count_by(splunk_index, "source")

print("search source=auth action=login_failed ->", failed_logins)
print("stats count by source ->", counts_by_source)


# Test Cases
def test_experiment21():
    assert len(failed_logins) == 2
    assert all(r["user"] == "jdoe" for r in failed_logins)
    assert counts_by_source == {"auth": 4, "firewall": 1}
    print("Experiment 21: All test cases passed.")


test_experiment21()
