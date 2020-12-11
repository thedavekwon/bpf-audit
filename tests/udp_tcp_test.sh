nc -z -v 172.217.6.197 443
nc -z -v 208.80.153.224 443
nc -u -z -v 172.217.6.197 443
nc -u -z -v 208.80.153.224 443

# alertlist: 172.217.6.197
# blacklist: 208.80.153.224

# command: sudo python3 audit.py -c config/config.ini --tcp --udp
# INFO:root:Process with PID 8230 and UID 1000 initiated a TCP over IPv4 connection to remote address 172.217.6.197 on alert list.
# INFO:root:Process with PID 8231 and UID 1000 initiated a TCP over IPv4 connection to remote address 208.80.153.224 on blacklist.
# INFO:root:Successfully terminated process 8231.
# INFO:root:Process with PID 8232 and UID 1000 initiated a UDP over IPv4 connection to remote address 172.217.6.197 on alert list.
# INFO:root:Process with PID 8233 and UID 1000 initiated a UDP over IPv4 connection to remote address 208.80.153.224 on blacklist.
# INFO:root:Successfully terminated process 8233.

# command: bash udp_tcp_test.sh
# Connection to 172.217.6.197 443 port [tcp/https] succeeded!
# Terminated
# Connection to 172.217.6.197 443 port [udp/*] succeeded!
# Terminated

