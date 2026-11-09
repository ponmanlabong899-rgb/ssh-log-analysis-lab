# ssh-log-analysis-lab## Files
- make_log.py: builds a practice SSH log (301 lines) with three attacker IPs and one planted root login
- analyse_log.py: analyses the practice log
- analyse_ssh.py: analyses a real OpenSSH log. Usage: python3 analyse_ssh.py LOGFILE THRESHOLD
- practice_failed_by_ip.csv and practice_summary.txt: results for the practice log
- real_failed_by_ip.csv and real_summary.txt: results for the Loghub sample (threshold 10)
