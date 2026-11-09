import csv
import os
import re
from collections import Counter, defaultdict

LOG = os.path.expanduser("~/lab/logs/auth.log")
OUT = os.path.expanduser("~/lab/reports")
THRESHOLD = 20

pattern = re.compile(
    r"^(\w{3} +\d+ [\d:]+) \S+ sshd\[\d+\]: (Failed|Accepted) password for (\S+) from (\S+) port (\d+)"
)

failed = Counter()
users = defaultdict(Counter)
first = {}
last = {}
accepted = []

for line in open(LOG):
    m = pattern.match(line)
    if not m:
        continue
    when, status, user, ip, port = m.groups()
    if status == "Failed":
        failed[ip] += 1
        users[ip][user] += 1
        first.setdefault(ip, when)
        last[ip] = when
    else:
        accepted.append((when, user, ip))

suspicious = {ip for ip, n in failed.items() if n >= THRESHOLD}
breaches = [a for a in accepted if a[2] in suspicious]

with open(os.path.join(OUT, "failed_by_ip.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip", "failed_attempts", "first_seen", "last_seen", "usernames_tried", "status"])
    for ip, n in failed.most_common():
        status = "SUSPICIOUS" if ip in suspicious else "normal"
        w.writerow([ip, n, first[ip], last[ip], " ".join(users[ip]), status])

lines = []
lines.append("Total failed logins: " + str(sum(failed.values())))
lines.append("Suspicious IPs (" + str(THRESHOLD) + " or more failures): " + str(len(suspicious)))
for ip in sorted(suspicious, key=lambda x: -failed[x]):
    lines.append("  " + ip + " : " + str(failed[ip]) + " failures")
if breaches:
    lines.append("ALERT: a suspicious IP logged in successfully:")
    for when, user, ip in breaches:
        lines.append("  " + when + " user " + user + " from " + ip)
else:
    lines.append("No successful logins from suspicious IPs.")

text = "\n".join(lines)
print(text)
open(os.path.join(OUT, "summary.txt"), "w").write(text + "\n")
