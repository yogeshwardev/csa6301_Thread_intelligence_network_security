"""
Experiment 25: Evidence Chain-of-Custody Log Validator
Verifies unbroken hash continuity and monotonically increasing timestamps.
"""

def validate_custody_chain(records):
    if not records:
        return {"valid": False, "reason": "Empty custody chain"}

    initial_hash = records[0]["hash"]
    last_time = records[0]["timestamp"]

    for i, record in enumerate(records):
        if record["hash"] != initial_hash:
            return {"valid": False, "broken_at_step": i, "reason": "Evidence hash mismatch"}
        if i > 0 and record["timestamp"] < last_time:
            return {"valid": False, "broken_at_step": i, "reason": "Timestamp out of sequence"}
        last_time = record["timestamp"]

    return {"valid": True, "reason": "Chain of custody intact"}

# Test Cases
def test_exp25():
    good_records = [
        {"handler": "Officer A", "hash": "sha256_abcdef", "timestamp": 1000},
        {"handler": "Analyst B", "hash": "sha256_abcdef", "timestamp": 1050},
        {"handler": "Court Tech C", "hash": "sha256_abcdef", "timestamp": 1100},
    ]
    assert validate_custody_chain(good_records)["valid"] is True

    tampered_records = [
        {"handler": "Officer A", "hash": "sha256_abcdef", "timestamp": 1000},
        {"handler": "Analyst B", "hash": "sha256_TAMPERED", "timestamp": 1050},
    ]
    assert validate_custody_chain(tampered_records)["valid"] is False
    print("Experiment 25: All test cases passed.")

if __name__ == "__main__":
    print("Chain Validation:", validate_custody_chain([{"handler": "Investigator", "hash": "h123", "timestamp": 10}]))
    test_exp25()
