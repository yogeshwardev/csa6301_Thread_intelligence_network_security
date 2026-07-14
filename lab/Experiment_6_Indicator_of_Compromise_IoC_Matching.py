# Step 1: Create the sample files (so this script runs standalone,
# with no file upload needed - works on any online compiler)
with open("ioc_list.txt", "w") as f:
    f.write("45.33.32.156\n198.51.100.23\n203.0.113.99\n")

with open("sample_traffic.log", "w") as f:
    f.write("2026-07-08 10:01:12 connection from 10.0.0.5\n")
    f.write("2026-07-08 10:02:44 connection from 45.33.32.156\n")
    f.write("2026-07-08 10:03:10 connection from 192.168.1.20\n")
    f.write("2026-07-08 10:04:55 connection from 203.0.113.99\n")


# Step 2: Load IoCs and scan the log
def load_iocs(filename):
    with open(filename) as f:
        return set(line.strip() for line in f if line.strip())


def scan_log(logfile, iocs):
    with open(logfile) as f:
        for line in f:
            for ip in iocs:
                if ip in line:
                    print("ALERT: Known malicious IP found ->", line.strip())


iocs = load_iocs("ioc_list.txt")
print("Loaded", len(iocs), "IoCs")
scan_log("sample_traffic.log", iocs)
