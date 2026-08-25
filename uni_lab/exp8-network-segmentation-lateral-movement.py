"""
Experiment 8: Network Segmentation Access Control Simulator
Demonstrates how segment isolation blocks lateral movement.
"""

SEGMENTATION_POLICY = {
    ("Guest_VLAN", "Guest_VLAN"): True,
    ("Guest_VLAN", "Corporate_VLAN"): False,
    ("Guest_VLAN", "PCI_Database_VLAN"): False,
    ("Corporate_VLAN", "Corporate_VLAN"): True,
    ("Corporate_VLAN", "PCI_Database_VLAN"): False,
    ("Admin_Bastion", "PCI_Database_VLAN"): True,
    ("Admin_Bastion", "Corporate_VLAN"): True,
}

def can_access(src_segment, dst_segment, policy=SEGMENTATION_POLICY):
    return policy.get((src_segment, dst_segment), False)

# Test Cases
def test_exp8():
    # Guest cannot reach Corporate or PCI DB
    assert can_access("Guest_VLAN", "PCI_Database_VLAN") is False
    assert can_access("Guest_VLAN", "Corporate_VLAN") is False

    # Corporate cannot reach PCI DB directly
    assert can_access("Corporate_VLAN", "PCI_Database_VLAN") is False

    # Admin can reach PCI DB
    assert can_access("Admin_Bastion", "PCI_Database_VLAN") is True

    # Unknown segment defaults to False
    assert can_access("Unknown_VLAN", "Corporate_VLAN") is False
    print("Experiment 8: All test cases passed.")

if __name__ == "__main__":
    print("Guest to PCI DB:", can_access("Guest_VLAN", "PCI_Database_VLAN"))
    print("Admin to PCI DB:", can_access("Admin_Bastion", "PCI_Database_VLAN"))
    test_exp8()
