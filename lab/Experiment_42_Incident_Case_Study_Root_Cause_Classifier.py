def classify_root_cause(case_description, rules):
    text = case_description.lower()
    for cause, keywords in rules:
        for kw in keywords:
            if kw in text:
                return cause
    return "Root Cause Undetermined"


ROOT_CAUSE_RULES = [
    (
        "Phishing / Social Engineering",
        [
            "clicked a link in a phishing email",
            "entered their credentials on a fake login page",
            "tricked over a phone call into resetting the password",
        ],
    ),
    (
        "Unpatched Vulnerability",
        [
            "exploited a known unpatched vulnerability",
            "outdated software version that was never patched",
            "known cve was left unaddressed for months",
        ],
    ),
    (
        "Misconfiguration",
        [
            "storage bucket was left publicly accessible by mistake",
            "default administrator credentials were never changed",
            "firewall rule was misconfigured",
        ],
    ),
    (
        "Insider Threat",
        [
            "a disgruntled former employee retained access",
            "an authorized employee intentionally misused their access",
            "insider sold company data",
        ],
    ),
    (
        "Third-Party / Supply Chain Compromise",
        [
            "a trusted vendor's software update was compromised",
            "third-party contractor's credentials were breached",
            "supply chain partner was the initial entry point",
        ],
    ),
]


# Test Cases
def test_experiment42():
    c1 = (
        "An employee clicked a link in a phishing email and entered their"
        " credentials on a fake login page."
    )
    assert (
        classify_root_cause(c1, ROOT_CAUSE_RULES)
        == "Phishing / Social Engineering"
    )
    c2 = (
        "Attackers exploited a known unpatched vulnerability in the company's"
        " web server."
    )
    assert classify_root_cause(c2, ROOT_CAUSE_RULES) == "Unpatched Vulnerability"
    c3 = (
        "A cloud storage bucket was left publicly accessible by mistake,"
        " exposing customer files."
    )
    assert classify_root_cause(c3, ROOT_CAUSE_RULES) == "Misconfiguration"
    c4 = (
        "Investigators determined a disgruntled former employee retained"
        " access after termination."
    )
    assert classify_root_cause(c4, ROOT_CAUSE_RULES) == "Insider Threat"
    c5 = (
        "The breach originated when a trusted vendor's software update was"
        " compromised."
    )
    assert (
        classify_root_cause(c5, ROOT_CAUSE_RULES)
        == "Third-Party / Supply Chain Compromise"
    )
    c6 = (
        "The cause of the incident could not be determined from available logs."
    )
    assert (
        classify_root_cause(c6, ROOT_CAUSE_RULES) == "Root Cause Undetermined"
    )
    print("Experiment 42: All test cases passed.")


test_experiment42()
