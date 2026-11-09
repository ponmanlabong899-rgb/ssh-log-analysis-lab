import os
import random
from datetime import datetime, timedelta

random.seed(7)
attackers = ["203.0.113.45", "198.51.100.23", "192.0.2.77"]
staff = ["10.0.0.5", "10.0.0.8", "10.0.0.12"]
names = ["root", "admin", "test", "oracle", "ubuntu"]
t = datetime(2026, 11, 2, 8, 0, 0)
lines = []

def stamp():
    return t.strftime("%b %d %H:%M:%S")

for i in range(300):
    t += timedelta(seconds=random.randint(5, 90))
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)
    r = random.random()
    if r < 0.6:
        lines.append(f"{stamp()} server sshd[{pid}]: Failed password for {random.choice(names)} from {random.choice(attackers)} port {port} ssh2")
    elif r < 0.9:
        lines.append(f"{stamp()} server sshd[{pid}]: Accepted password for david from {random.choice(staff)} port {port} ssh2")
    else:
        lines.append(f"{stamp()} server sshd[{pid}]: Failed password for david from {random.choice(staff)} port {port} ssh2")

t += timedelta(seconds=30)
lines.append(f"{stamp()} server sshd[4321]: Accepted password for root from 203.0.113.45 port 41234 ssh2")

path = os.path.expanduser("~/lab/logs/auth.log")
open(path, "w").write("\n".join(lines) + "\n")
print(len(lines), "lines written to", path)
