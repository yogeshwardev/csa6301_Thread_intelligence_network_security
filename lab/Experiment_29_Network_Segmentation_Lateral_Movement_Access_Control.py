SEGMENTATION_POLICY = {
    ("Guest", "Guest"): True,
    ("Guest", "Corporate"): False,
    ("Guest", "Medical"): False,
    ("Corporate", "Corporate"): True,
    ("Corporate", "Medical"): False,
    ("Admin", "Medical"): True,
    ("Admin", "Corporate"): True,
    ("Admin", "Admin"): True,
}


def can_communicate(src_segment, dst_segment, policy=SEGMENTATION_POLICY):
    """Fail-safe default: any undefined segment pair is denied."""
    return policy.get((src_segment, dst_segment), False)


# Test Cases
def test_experiment29():
    assert can_communicate("Guest", "Medical") is False
    assert can_communicate("Guest", "Corporate") is False
    assert can_communicate("Admin", "Medical") is True
    assert can_communicate("Admin", "Corporate") is True
    assert can_communicate("Corporate", "Corporate") is True
    assert can_communicate("IoT", "Corporate") is False
    print("Experiment 29: All test cases passed.")


test_experiment29()
