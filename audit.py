#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb

from socket import AF_INET, AF_INET6, inet_ntop
from struct import pack

from tools import udpconnect

bpf_text = ""
bpf_text += udpconnect.bpf_text

def monitor_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    print(event)
    pass


def monitor_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    pass

# add more monitoring here

b = BPF(text=bpf_text)
b["ipv4_events"].open_perf_buffer(monitor_ipv4_event)
b["ipv6_events"].open_perf_buffer(monitor_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
