def extract_lessons(report_text, tag_rules):
    text = report_text.lower()
    found = []
    for tag, keywords in tag_rules:
        if any(kw in text for kw in keywords):
            found.append(tag)
    return found


LESSON_TAG_RULES = [
    (
        "Patch Management Gap",
        [
            "had not been patched",
            "missing security patch",
            "outdated software version",
        ],
    ),
    (
        "Security Awareness Gap",
        [
            "employee clicked the phishing link",
            "lack of security awareness training",
            "staff were unaware of the policy",
        ],
    ),
    (
        "Monitoring/Detection Gap",
        [
            "went undetected for",
            "no alert was generated",
            "monitoring coverage was insufficient",
        ],
    ),
    (
        "Backup Strategy Gap",
        [
            "backups were outdated",
            "backup had not been tested",
            "no recent backup was available",
        ],
    ),
    (
        "Access Control Gap",
        [
            "excessive permissions were granted",
            "shared administrator credentials were used",
            "no multi-factor authentication was enforced",
        ],
    ),
]


# Test Cases
def test_experiment35():
    r1 = (
        "The exploited server had not been patched for six months, "
        "and the intrusion went undetected for 20 days."
    )
    assert set(extract_lessons(r1, LESSON_TAG_RULES)) == {
        "Patch Management Gap",
        "Monitoring/Detection Gap",
    }
    r2 = (
        "An employee clicked the phishing link, and no multi-factor "
        "authentication was enforced on the account."
    )
    assert set(extract_lessons(r2, LESSON_TAG_RULES)) == {
        "Security Awareness Gap",
        "Access Control Gap",
    }
    r3 = (
        "During recovery, the team discovered backups were outdated and could"
        " not be used."
    )
    assert extract_lessons(r3, LESSON_TAG_RULES) == ["Backup Strategy Gap"]
    r4 = (
        "The investigation found no significant gaps in this particular"
        " incident."
    )
    assert extract_lessons(r4, LESSON_TAG_RULES) == []
    print("Experiment 35: All test cases passed.")


test_experiment35()
