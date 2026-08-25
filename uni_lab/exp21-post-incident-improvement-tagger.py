"""
Experiment 21: Post-Incident Report Improvement Areas Tagger
"""

IMPROVEMENT_RULES = [
    ("Patch Management", ["unpatched", "software outdated", "missing patch", "cve vulnerability"]),
    ("Security Awareness", ["clicked phishing", "unaware of policy", "social engineering awareness", "training needed"]),
    ("Monitoring & Detection", ["undetected for", "no alert was generated", "insufficient log coverage", "visibility gap"]),
    ("Backup Strategy", ["backups outdated", "backup restoration failed", "untested backup"]),
    ("Access Control", ["excessive permissions", "shared admin accounts", "no mfa enforced"]),
]

def tag_improvement_areas(report_text, rules=IMPROVEMENT_RULES):
    text = report_text.lower()
    return [area for area, keywords in rules if any(kw in text for kw in keywords)]

# Test Cases
def test_exp21():
    rep = "The unpatched server allowed intrusion which went undetected for weeks because no alert was generated."
    tags = tag_improvement_areas(rep)
    assert "Patch Management" in tags
    assert "Monitoring & Detection" in tags
    print("Experiment 21: All test cases passed.")

if __name__ == "__main__":
    print("Tags:", tag_improvement_areas("Staff clicked phishing and no MFA enforced on the account."))
    test_exp21()
