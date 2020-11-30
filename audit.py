#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb

from socket import AF_INET, AF_INET6, inet_ntop
from tools import udpconnect, tcpaccept, tcpconnect, opensnoop, execsnoop
from struct import pack
from collections import defaultdict

bpf_text = ""
bpf_text += (
    udpconnect.bpf_text
    + tcpconnect.bpf_text
    + tcpaccept.bpf_text
    + opensnoop.bpf_text
    + execsnoop.bpf_text
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


def monitor_opensnoop_event(cpu, data, size):
    event = b["opensnoop_events"].event(data)
    # split return value into FD and errno columns
#    if event.ret >= 0:
#     fd_s = event.ret
#     err = 0
#    else:
#     fd_s = -1
#     err = -event.ret
#    printb(
#     b"%-14f %-6d %-6d %-16s %4d %3d %s"
#     % (
#         event.ts,
#         event.uid,
#         event.id & 0xFFFFFFFF >> 32,
#         event.comm,
#         fd_s,
#         err,
#         event.fname)
#     )
    pass

def monitor_execsnoop_event(cpu,data,size):
    event = b["execsnoop_events"].event(data)
    ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
    ppid = b"%d" % ppid if ppid > 0 else b"?"
    argv = defaultdict(list)
    argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
    printb(
     b"%-16s %-6d %-6s %3d %s"
     % (
         event.comm,
         event.pid,
         ppid,
         event.retval,
         argv_text)
     )
    try:
        del(argv[event.pid])
    except Exception:
        pass

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

# opensnoop
b2 = BPF(text="")
fnname_open = b2.get_syscall_prefix().decode() + "open"
fnname_openat = b2.get_syscall_prefix().decode() + "openat"
b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
b.attach_kretprobe(event=fnname_open, fn_name="trace_opensnoop_return")
b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
b.attach_kretprobe(event=fnname_openat, fn_name="trace_opensnoop_return")
b["opensnoop_events"].open_perf_buffer(monitor_opensnoop_event, page_cnt=64)

# execsnoop
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
b["execsnoop_events"].open_perf_buffer(monitor_execsnoop_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
