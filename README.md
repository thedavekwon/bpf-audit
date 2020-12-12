# eBPF Security Monitoring Alert System
Final Project for ECE-455 Cybersecurity for Cooper Union

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