nmap 127.0.0.1 -p 80 # single port

sleep 15

nmap 127.0.0.1

# threshold: 100
# command: sudo python3 audit.py -c config/config.ini --tcpreset
# INFO:root:Sent TCP reset packet to 127.0.0.1 with 101 ports within the threshold
# INFO:root:Sent TCP reset packet to 127.0.0.1 with 102 ports within the threshold
# INFO:root:Sent TCP reset packet to 127.0.0.1 with 103 ports within the threshold
# INFO:root:Sent TCP reset packet to 127.0.0.1 with 104 ports within the threshold
# INFO:root:Sent TCP reset packet to 127.0.0.1 with 105 ports within the threshold
# continues.... 

# command: bash exec_test.sh
# Starting Nmap 7.60 ( https://nmap.org ) at 2020-12-12 01:42 KST
# Nmap scan report for localhost (127.0.0.1)
# Host is up (0.00021s latency).

# PORT   STATE  SERVICE
# 80/tcp closed http

# Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds

# Starting Nmap 7.60 ( https://nmap.org ) at 2020-12-12 01:42 KST
# Nmap scan report for localhost (127.0.0.1)
# Host is up (0.000099s latency).
# Not shown: 992 closed ports
# PORT     STATE SERVICE
# 22/tcp   open  ssh
# 631/tcp  open  ipp
# 5432/tcp open  postgresql
# 9000/tcp open  cslistener
# 9002/tcp open  dynamid
# 9003/tcp open  unknown
# 9009/tcp open  pichat

# Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds