ls
tree

# alertlist: /bin/ls
# blacklist: /usr/bin/tree
# command: sudo python3 audit.py -c config/config.ini --exec
# INFO:root:Process with PID 16059 and UID 1000 with command /bin/ls execed program /bin/ls on alertlist.
# INFO:root:Process with PID 16060 and UID 1000 with command /usr/bin/tree execed program /usr/bin/tree on blacklist.
# INFO:root:Successfully terminated process 16060.

# command: bash exec_test.sh
# bash exec_test.sh
# exec_test.sh  open_test.py
# exec_test.sh: line 2: 16060 Terminated              tree