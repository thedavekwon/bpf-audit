# eBPF Security Monitoring Alert System
Final Project for ECE-455 Cybersecurity for Cooper Union

bpf-audit is a security monitoring system using various heuristics to flag and block malicious processes using eBPF. It uses modularlized probes that allow user to choose what to monitor along with accepting user-defined rules to specify the alert-list, blacklist, and thresholds.

UDP, TCP, DNS, open, and exec based alert and blocking is supported. It is also capable of simple port scanning detection. 

# Requirements
* [bcc](https://github.com/iovisor/bcc)
* cachetools

# Usage
```
# Audit
sudo chmod +x audit.py
sudo ./audit.py -c <config file path> --[udp, tcp, open, exec, dns, port, test] 

# To print bpftext for testing
sudo ./audit.py -c <config file path> --test
```