host facebook.com
host youtube.com

# alertlist: facebook.com
# blacklist: youtube.com
# command: sudo python3 audit.py -c config/config.ini --dns
# INFO:root:Process with PID 6674 and UID 101 initiated a TCP over IPv6 connection to remote domain facebook.com on alert list.
# INFO:root:Process with PID 6674 and UID 101 initiated a TCP over IPv6 connection to remote domain youtube.com on blacklist.
# INFO:root:Successfully terminated process 6674.

# command: bash dns_test.sh

