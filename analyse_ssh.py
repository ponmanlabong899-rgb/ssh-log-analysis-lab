import csv
import os
import re
import sys
from collections import Counter, defaultdict

default_log = "~/lab/logs/ssh_sample.log"
log_path = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else default_log)
threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 5
out_dir = os.path.expanduser("~/lab/reports")
name = os.path.splitext(os.path.basename(log_path))[0]

pattern = re.compile(
    r"^(\w{3} +\d+ [\d:]+) \S+ sshd\[\d+\]: (Failed|Accepted) password for (invalid user )?(\S+) from (\S+) port (\d+)"
)

failed = Counter()
invalid = Counter()
users = defaultdict(set)
all_users = Counter()
first = {}
last = {}
accepted = []
lines_read = 0

for line in open(log_path, errors="replace"):
    lines_read += 1
    m = pattern.match(line)
    if not m:
        continue
    when, status, inv, user, ip, port = m.groups()
    if status == "Failed":
        failed[ip] += 1
        users[ip].add(user)
        all_users[user] += 1
        if inv:
            invalid[ip] += 1
        first.setdefault(ip, when)
        last[ip] = when
    else:
        accepted.append((when, user, ip))

suspicious = {ip for ip, n in failed.items() if n >= threshold}
breaches = [a for a in accepted if a[2] in suspicious]

csv_path = os.path.join(out_dir, name + "_failed_by_ip.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip", "failed_attempts", "invalid_user_attempts", "distinct_usernames", "first_seen", "last_seen", "status"])
    for ip, n in failed.most_common():
        status = "SUSPICIOUS" if ip in suspicious else "low_volume"
        w.writerow([ip, n, invalid[ip], len(users[ip]), first[ip], last[ip], status])

out = []
out.append("Log: " + log_path + " (" + str(lines_read) + " lines)")
out.append("Total failed logins: " + str(sum(failed.values())))
out.append("IPs with failures: " + str(len(failed)))
out.append("Threshold: " + str(threshold) + " failures")
out.append("Suspicious IPs: " + str(len(suspicious)))
out.append("Top 5 IPs:")
for ip, n in failed.most_common(5):
    out.append("  " + ip + " : " + str(n) + " failures, " + str(len(users[ip])) + " usernames")
out.append("Top 5 usernames tried:")
for u, n in all_users.most_common(5):
    out.append("  " + u + " : " + str(n))
if breaches:
    out.append("ALERT: a suspicious IP logged in successfully:")
    for when, user, ip in breaches:
        out.append("  " + when + " user " + user + " from " + ip)
else:
    out.append("No successful logins from suspicious IPs.")

text = "\n".join(out)
print(text)
open(os.path.join(out_dir, name + "_summary.txt"), "w").write(text + "\n")
