import re

raw_log_lines = [
    "2026-07-25 09:15:01 INFO auth: user=jdoe action=login_success ip=10.0.0.5",
    "2026-07-25 09:17:32 WARN auth: user=jdoe action=login_failed ip=10.0.0.5",
    "2026-07-25 09:20:10 ERROR firewall: action=blocked ip=45.33.32.156",
]


def logstash_parse(line):
    pattern = r"(?P<date>\S+) (?P<time>\S+) (?P<level>\w+) (?P<source>\w+): (?P<fields>.*)"
    m = re.match(pattern, line)
    if not m:
        return None
    doc = m.groupdict()
    field_str = doc.pop("fields")
    for kv in field_str.split():
        if "=" in kv:
            k, v = kv.split("=", 1)
            doc[k] = v
    return doc


elasticsearch_index = [logstash_parse(l) for l in raw_log_lines]


def es_search(index, **query):
    return [doc for doc in index if all(doc.get(k) == v for k, v in query.items())]


def kibana_aggregate(index, field):
    agg = {}
    for doc in index:
        key = doc.get(field, "unknown")
        agg[key] = agg.get(key, 0) + 1
    return agg


parsed_ok = all(d is not None for d in elasticsearch_index)
failed_search = es_search(elasticsearch_index, action="login_failed")
level_aggregation = kibana_aggregate(elasticsearch_index, "level")

print("Parsed documents:")
for d in elasticsearch_index:
    print(" ", d)
print("Search action=login_failed ->", failed_search)
print("Kibana aggregation by level ->", level_aggregation)


# Test Cases
def test_experiment22():
    assert parsed_ok, "All raw log lines should be parsed by the Logstash-style parser"
    assert len(failed_search) == 1
    assert failed_search[0]["user"] == "jdoe"
    assert level_aggregation == {"INFO": 1, "WARN": 1, "ERROR": 1}
    print("Experiment 22: All test cases passed.")


test_experiment22()
