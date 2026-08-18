def validate_custody_chain(records):
    if not records:
        return {
            "is_valid": False,
            "reason": "No records provided",
            "break_index": None,
        }
    original_hash = records[0]["hash"]
    last_timestamp = records[0]["timestamp"]
    for i, record in enumerate(records):
        if record["hash"] != original_hash:
            return {
                "is_valid": False,
                "reason": "Hash mismatch - evidence integrity broken",
                "break_index": i,
            }
        if i > 0 and record["timestamp"] < last_timestamp:
            return {
                "is_valid": False,
                "reason": "Timestamp out of order - custody sequence broken",
                "break_index": i,
            }
        last_timestamp = record["timestamp"]
    return {
        "is_valid": True,
        "reason": "Chain of custody intact",
        "break_index": None,
    }


# Test Cases
def test_experiment36():
    good_chain = [
        {"handler": "Officer A", "hash": "9f8e...ab12", "timestamp": 100},
        {"handler": "Lab Tech B", "hash": "9f8e...ab12", "timestamp": 150},
        {"handler": "Analyst C", "hash": "9f8e...ab12", "timestamp": 220},
    ]
    result1 = validate_custody_chain(good_chain)
    assert result1["is_valid"] is True

    tampered_chain = [
        {"handler": "Officer A", "hash": "9f8e...ab12", "timestamp": 100},
        {"handler": "Lab Tech B", "hash": "9f8e...ab12", "timestamp": 150},
        {"handler": "Analyst C", "hash": "DIFFERENT_HASH", "timestamp": 220},
    ]
    result2 = validate_custody_chain(tampered_chain)
    assert result2["is_valid"] is False and result2["break_index"] == 2

    out_of_order_chain = [
        {"handler": "Officer A", "hash": "abc123", "timestamp": 100},
        {"handler": "Lab Tech B", "hash": "abc123", "timestamp": 90},
    ]
    result3 = validate_custody_chain(out_of_order_chain)
    assert result3["is_valid"] is False and result3["break_index"] == 1

    assert validate_custody_chain([])["is_valid"] is False
    print("Experiment 36: All test cases passed.")


test_experiment36()
