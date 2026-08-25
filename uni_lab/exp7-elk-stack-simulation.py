"""
Experiment 7: ELK Stack Simulator
Simulates Logstash parsing, Elasticsearch indexing, and Kibana aggregation.
"""
import re

raw_logs = [
    "2026-08-25 10:00:01 INFO auth: user=alice action=login_success ip=192.168.1.5",
    "2026-08-25 10:02:15 WARN auth: user=bob action=login_failed ip=192.168.1.50",
    "2026-08-25 10:05:30 ERROR firewall: action=drop src_ip=203.0.113.15",
]

def logstash_parse(log_line):
    pattern = r"(?P<date>\S+) (?P<time>\S+) (?P<level>\w+) (?P<source>\w+): (?P<fields>.*)"
    match = re.match(pattern, log_line)
    if not match:
        return None
    doc = match.groupdict()
    fields_str = doc.pop("fields")
    for kv in fields_str.split():
        if "=" in kv:
            k, v = kv.split("=", 1)
            doc[k] = v
    return doc

def elasticsearch_search(index, **filters):
    return [doc for doc in index if all(doc.get(k) == v for k, v in filters.items())]

def kibana_aggregate(index, field):
    agg = {}
    for doc in index:
        key = doc.get(field, "unknown")
        agg[key] = agg.get(key, 0) + 1
    return agg

# Test Cases
def test_exp7():
    es_index = [logstash_parse(l) for l in raw_logs]
    assert all(doc is not None for doc in es_index)
    search_res = elasticsearch_search(es_index, level="WARN")
    assert len(search_res) == 1
    assert search_res[0]["user"] == "bob"

    kibana_summary = kibana_aggregate(es_index, "level")
    assert kibana_summary == {"INFO": 1, "WARN": 1, "ERROR": 1}
    print("Experiment 7: All test cases passed.")

if __name__ == "__main__":
    index = [logstash_parse(l) for l in raw_logs]
    print("Parsed Docs:", index)
    print("Kibana Levels:", kibana_aggregate(index, "level"))
    test_exp7()
