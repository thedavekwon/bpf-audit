f = open('/etc/passwd', 'r')
f.read()

f = open('/home/dodo/.bashrc', 'r')
f.read()

# alertlist: /etc/passwd
# blacklist: /home/dodo/.bashrc
# command: sudo python3 audit.py -c config/config.ini --open
# INFO:root:Process with PID 14739 and UID 1000 with command python3 opened a file /etc/passwd on alertlist.
# INFO:root:Process with PID 14739 and UID 1000 with command python3 opened a file /home/dodo/.bashrc on blacklist.
# INFO:root:Successfully terminated process 14739.

# command: python3 open_test.py
# [1]    14739 terminated  python3 open_test.py