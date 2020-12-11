curl -v facebook.com
curl -v youtube.com

# alertlist: facebook.com
# blacklist: youtube.com

# command: sudo python3 audit.py -c config/config.ini --dns
# INFO:root:Process with PID 10814 and UID 1000 initiated a TCP over IPv6 connection to remote domain facebook.com on alert list.
# INFO:root:Process with PID 10446 and UID 101 initiated a TCP over IPv6 connection to remote domain facebook.com on alert list.
# INFO:root:Process with PID 10814 and UID 1000 initiated a TCP over IPv6 connection to remote domain facebook.com on alert list.
# INFO:root:Process with PID 10816 and UID 1000 initiated a TCP over IPv6 connection to remote domain youtube.com on blacklist.
#INFO:root:Successfully terminated process 10816.


# command: bash dns_test.sh
#*   Trying 157.240.0.35:80...
#* TCP_NODELAY set
#* Connected to facebook.com (157.240.0.35) port 80 (#0)
#> GET / HTTP/1.1
#> Host: facebook.com
#> User-Agent: curl/7.68.0
#> Accept: */*
#> 
#* Mark bundle as not supporting multiuse
#< HTTP/1.1 301 Moved Permanently
#< Location: https://facebook.com/
#< Content-Type: text/html; charset="utf-8"
#< X-FB-Debug: DwlQrznKiPZITGr/14WMl6wqAqztbKTEK+aZ194ybwXqyzNxhZKJJ3/+hyeA0CGYnscZ7hMgF0RLBeiAnWOD8A==
#< Date: Fri, 11 Dec 2020 17:36:50 GMT
#< Alt-Svc: h3-29=":443"; ma=3600,h3-27=":443"; ma=3600
#< Connection: keep-alive
#< Content-Length: 0
#< 
#* Connection #0 to host facebook.com left intact
#Terminated

