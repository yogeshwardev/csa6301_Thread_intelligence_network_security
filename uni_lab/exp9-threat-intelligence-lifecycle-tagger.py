"""
Experiment 9: Threat Intelligence Lifecycle Stage Tagger
Tags activity descriptions with their corresponding TI Lifecycle phase.
"""

TI_LIFECYCLE_RULES = [
    ("Direction", ["define requirements", "planning", "priority intelligence requirement", "pir", "scope of collection"]),
    ("Collection", ["harvesting iocs", "scraping dark web", "ingesting feeds", "collecting raw telemetry", "packet capture"]),
    ("Processing", ["normalizing iocs", "parsing logs", "decoding malware payload", "extracting metadata", "de-duplicating"]),
    ("Analysis", ["correlating indicators", "identifying attacker campaign", "attribution", "evaluating threat trend", "hypothesis"]),
    ("Dissemination", ["publishing intelligence report", "sharing misp feed", "briefing executives", "sending alerts to soc"]),
    ("Feedback", ["evaluating report usefulness", "gap review", "adjusting pir", "post-incident feedback", "lessons learned"]),
]

def tag_ti_lifecycle(activity_desc, rules=TI_LIFECYCLE_RULES):
    text = activity_desc.lower()
    for stage, keywords in rules:
        if any(kw in text for kw in keywords):
            return stage
    return "Unclassified Activity"

# Test Cases
def test_exp9():
    a1 = "Establishing priority intelligence requirements (PIR) for executive threat defense."
    assert tag_ti_lifecycle(a1) == "Direction"

    a2 = "Ingesting feeds and scraping dark web forums for compromised credentials."
    assert tag_ti_lifecycle(a2) == "Collection"

    a3 = "Normalizing IOCs and de-duplicating raw threat feed records into JSON."
    assert tag_ti_lifecycle(a3) == "Processing"

    a4 = "Publishing intelligence report and sharing MISP feed with partner SOCs."
    assert tag_ti_lifecycle(a4) == "Dissemination"
    print("Experiment 9: All test cases passed.")

if __name__ == "__main__":
    sample = "Correlating indicators to attribute the new ransomware campaign to APT29."
    print("Activity Stage:", tag_ti_lifecycle(sample))
    test_exp9()
