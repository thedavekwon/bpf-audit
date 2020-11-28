#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb

from socket import AF_INET, AF_INET6, inet_ntop
from tools import udpconnect, tcpaccept, tcpconnect
from struct import pack

bpf_text = ""
bpf_text += (
    udpconnect.bpf_text
    + tcpconnect.bpf_text
    + tcpaccept.bpf_text
    # + opensnoop.bpf_text
    # + execsnoop.bpf_text
)


def monitor_udp_ipv4_event(cpu, data, size):
    event = b["udp_ipv4_events"].event(data)
    pass


def monitor_udp_ipv6_event(cpu, data, size):
    event = b["udp_ipv6_events"].event(data)
    pass


def monitor_tcpaccept_ipv4_event(cpu, data, size):
    event = b["tcpacc_ipv4_events"].event(data)
    # printb(
    #     b"%-7d %-12.12s %-2d %-16s %-5d %-16s %-5d"
    #     % (
    #         event.pid,
    #         event.task,
    #         event.ip,
    #         inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
    #         event.dport,
    #         inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
    #         event.lport,
    #     )
    # )


def monitor_tcpaccept_ipv6_event(cpu, data, size):
    event = b["tcpacc_ipv6_events"].event(data)
    pass


def monitor_tcpconnect_ipv4_event(cpu, data, size):
    event = b["tcpcon_ipv4_events"].event(data)
    # printb(
    #     b"%-6d %-12.12s %-2d %-16s %-16s %-6d"
    #     % (
    #         event.pid,
    #         event.task,
    #         event.ip,
    #         inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
    #         inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
    #         event.dport,
    #     )
    # )


def monitor_tcpconnect_ipv6_event(cpu, data, size):
    event = b["tcpcon_ipv6_events"].event(data)
    pass


# add more monitoring here

b = BPF(text=bpf_text)

# udpconnect
b["udp_ipv4_events"].open_perf_buffer(monitor_udp_ipv4_event)
b["udp_ipv6_events"].open_perf_buffer(monitor_udp_ipv6_event)

# tcpaccept
b["tcpacc_ipv4_events"].open_perf_buffer(monitor_tcpaccept_ipv4_event)
b["tcpacc_ipv6_events"].open_perf_buffer(monitor_tcpaccept_ipv6_event)

# tcpconnect
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
b["tcpcon_ipv4_events"].open_perf_buffer(monitor_tcpconnect_ipv4_event)
b["tcpcon_ipv6_events"].open_perf_buffer(monitor_tcpconnect_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
