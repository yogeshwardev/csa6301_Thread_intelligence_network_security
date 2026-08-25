"""
Experiment 11: Packet Sniffing and Summary Display (Scapy Simulation / Interface)
Sniffs/processes network packets and prints structured packet summaries.
"""

def summarize_packet(pkt_dict):
    # pkt_dict: {"proto": "TCP", "src": "...", "dst": "...", "sport": ..., "dport": ..., "len": ...}
    proto = pkt_dict.get("proto", "IP")
    src = f"{pkt_dict.get('src')}:{pkt_dict.get('sport')}" if 'sport' in pkt_dict else pkt_dict.get('src')
    dst = f"{pkt_dict.get('dst')}:{pkt_dict.get('dport')}" if 'dport' in pkt_dict else pkt_dict.get('dst')
    size = pkt_dict.get("len", 0)
    return f"[{proto}] {src} -> {dst} (Length: {size} bytes)"

def process_packet_stream(packets):
    summaries = []
    for pkt in packets:
        summary = summarize_packet(pkt)
        summaries.append(summary)
    return summaries

# Test Cases
def test_exp11():
    captured_packets = [
        {"proto": "TCP", "src": "192.168.1.10", "sport": 51234, "dst": "93.184.216.34", "dport": 443, "len": 64},
        {"proto": "UDP", "src": "192.168.1.10", "sport": 5353, "dst": "8.8.8.8", "dport": 53, "len": 48},
        {"proto": "ICMP", "src": "192.168.1.10", "dst": "1.1.1.1", "len": 32},
    ]
    results = process_packet_stream(captured_packets)
    assert len(results) == 3
    assert "[TCP] 192.168.1.10:51234 -> 93.184.216.34:443 (Length: 64 bytes)" in results[0]
    print("Experiment 11: All test cases passed.")

if __name__ == "__main__":
    pkts = [{"proto": "TCP", "src": "10.0.0.1", "sport": 1234, "dst": "10.0.0.2", "dport": 80, "len": 128}]
    print("Packet Summary:", process_packet_stream(pkts))
    test_exp11()
