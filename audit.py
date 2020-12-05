#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb

from socket import AF_INET, AF_INET6, inet_ntop
from filters import udpconnect, tcpaccept, tcpconnect, opensnoop, execsnoop, dns
from struct import pack
from filters.execsnoop import get_ppid, EventType
from collections import defaultdict
from configparser import ConfigParser
import argparse
import os
import signal

parser = argparse.ArgumentParser(description="BPF audit")
parser.add_argument("-c", type=str, help="Config file path", required=True)
parser.add_argument("--udp", help="enable udp", action="store_true")
parser.add_argument("--tcp", help="enable tcp", action="store_true")
parser.add_argument("--open", help="enable open", action="store_true")
parser.add_argument("--exec", help="enable exec", action="store_true")
parser.add_argument("--dns", help="enable dns", action="store_true")
parser.add_argument("--test", help="print bpftext", action="store_true")

args = parser.parse_args()

config = ConfigParser()
config.read(args.c)


def parse_config(config, key):
    blacklist = config[key].get("blacklist", "").strip().split(",")
    alertlist = config[key].get("alertlist", "").strip().split(",")
    return {b.strip(): 1 for b in blacklist}, {a.strip(): 1 for a in alertlist}


ip_blacklist, ip_alertlist = parse_config(config, "IP")
domain_blacklist, domain_alertlist = parse_config(config, "DOMAIN")
fs_blacklist, fs_alertlist = parse_config(config, "FS")


def monitor_udp_ipv4_event(cpu, data, size):
    event = b["udp_ipv4_events"].event(data)
    daddr = inet_ntop(AF_INET, pack("I", event.daddr))
    if daddr in ip_blacklist:
        print("Process with PID {} and UID {} initiated a UDP over IPv4 connection to remote address {} on blacklist.".format(event.pid, event.uid, daddr))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in ip_alertlist:
        print("Process with PID {} and UID {} initiated a UDP over IPv4 connection to remote address {} on alert list.".format(event.pid, event.uid, daddr))


def monitor_udp_ipv6_event(cpu, data, size):
    event = b["udp_ipv6_events"].event(data)
    daddr = inet_ntop(AF_INET, pack("I", event.daddr))
    if daddr in ip_blacklist:
        print("Process with PID {} and UID {} initiated a UDP over IPv6 connection to remote address {} on blacklist.".format(event.pid, event.uid, daddr))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in ip_alertlist:
        print("Process with PID {} and UID {} initiated a UDP over IPv6 connection to remote address {} on alert list.".format(event.pid, event.uid, daddr))


def monitor_tcpaccept_ipv4_event(cpu, data, size):
    event = b["tcpacc_ipv4_events"].event(data)
    daddr = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if daddr in ip_blacklist:
        print("Process with PID {} and UID {} accepted a TCP over IPv4 connection from remote address {} on blacklist.".format(event.pid, event.uid, daddr))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in ip_alertlist:
        print("Process with PID {} and UID {} accepted a TCP over IPv4 connection from remote address {} on alert list.".format(event.pid, event.uid, daddr))
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
    daddr = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if daddr in ip_blacklist:
        print("Process with PID {} and UID {} accepted a TCP over IPv6 connection from remote address {} on blacklist.".format(event.pid, event.uid, daddr))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in ip_alertlist:
        print("Process with PID {} and UID {} accepted a TCP over IPv6 connection from remote address {} on alert list.".format(event.pid, event.uid, daddr))
    


def monitor_tcpconnect_ipv4_event(cpu, data, size):
    event = b["tcpcon_ipv4_events"].event(data)
    daddr = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if daddr in ip_blacklist:
        print("Process with PID {} and UID {} initiated a TCP over IPv4 connection to remote address {} on blacklist.".format(event.pid, event.uid, daddr))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in ip_alertlist:
        print("Process with PID {} and UID {} initiated a TCP over IPv4 connection to remote address {} on alert list.".format(event.pid, event.uid, daddr))
    
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
    daddr = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if daddr in ip_blacklist:
        print("Process with PID {} and UID {} initiated a TCP over IPv6 connection to remote address {} on blacklist.".format(event.pid, event.uid, daddr))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in ip_alertlist:
        print("Process with PID {} and UID {} initiated a TCP over IPv6 connection to remote address {} on alert list.".format(event.pid, event.uid, daddr))


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
    #         event.fname,
    #     )
    #     )
    pass


def print_dns_event(cpu, data, size):
    event = b["dns_events"].event(data)

    payload = event.pkt[:event.buflen]
    # print(size, event.buflen)
    dnspkt = dnslib.DNSRecord.parse(payload)
    # print(event.uid, event.pid, dnspkt.q.qname)
    domain_name = dnspkt.q.qname
    if domain_name in domain_blacklist:
        print("Process with PID {} and UID {} initiated a TCP over IPv6 connection to remote domain {} on blacklist.".format(event.pid, event.uid, domain_name))
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            print("Unable to terminate process {}.", event.pid)
        else:
            print("Successfully terminated process {}.", event.pid)
    if daddr in domain_alertlist:
        print("Process with PID {} and UID {} initiated a TCP over IPv6 connection to remote domain {} on alert list.".format(event.pid, event.uid, domain_name))
    pass


def monitor_execsnoop_event(cpu, data, size):
    event = b["execsnoop_events"].event(data)
    # skip = False

    # argv = defaultdict(list)
    # if event.type == EventType.EVENT_ARG:
    #     argv[event.pid].append(event.argv)
    # elif event.type == EventType.EVENT_RET:
    #     if event.retval != 0:
    #         skip = True
    #     argv[event.pid] = [
    #         b'"' + arg.replace(b'"', b'\\"') + b'"' for arg in argv[event.pid]
    #     ]
    #     if not skip:
    #         ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
    #         ppid = b"%d" % ppid if ppid > 0 else b"?"
    #         argv_text = b" ".join(argv[event.pid]).replace(b"\n", b"\\n")
    #         printb(
    #             b"%-16s %-6d %-6s %3d %s"
    #             % (event.comm, event.pid, ppid, event.retval, argv_text)
    #         )
    #     try:
    #         del argv[event.pid]
    #     except Exception:
    #         pass
    pass


bpf_text = ""
if args.udp:
    bpf_text += udpconnect.bpf_text
if args.tcp:
    bpf_text += tcpconnect.bpf_text + tcpaccept.bpf_text
if args.open:
    bpf_text += opensnoop.bpf_text
if args.exec:
    bpf_text += execsnoop.bpf_text
if args.dns:
    bpf_text += dns.bpf_text

if args.test:
    print(bpf_text)
    exit(0)

b = BPF(text=bpf_text)

# udpconnect
if args.udp:
    b["udp_ipv4_events"].open_perf_buffer(monitor_udp_ipv4_event)
    b["udp_ipv6_events"].open_perf_buffer(monitor_udp_ipv6_event)

# tcpaccept and tcpconnect
if args.tcp:
    b["tcpacc_ipv4_events"].open_perf_buffer(monitor_tcpaccept_ipv4_event)
    b["tcpacc_ipv6_events"].open_perf_buffer(monitor_tcpaccept_ipv6_event)

    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
    b["tcpcon_ipv4_events"].open_perf_buffer(monitor_tcpconnect_ipv4_event)
    b["tcpcon_ipv6_events"].open_perf_buffer(monitor_tcpconnect_ipv6_event)

# opensnoop
if args.open:
#    b2 = BPF(text="")
    fnname_open = b.get_syscall_prefix().decode() + "open"
    fnname_openat = b.get_syscall_prefix().decode() + "openat"
    b.attach_kprobe(event=fnname_open, fn_name="syscall__trace_entry_open")
    b.attach_kretprobe(event=fnname_open, fn_name="trace_opensnoop_return")
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__trace_entry_openat")
    b.attach_kretprobe(event=fnname_openat, fn_name="trace_opensnoop_return")
    b["opensnoop_events"].open_perf_buffer(monitor_opensnoop_event, page_cnt=64)

# execsnoop
if args.exec:
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
    b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
    b["execsnoop_events"].open_perf_buffer(monitor_execsnoop_event)

# dns
if args.dns:
    b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udp_recvmsg")
    b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_ret_recvmsg")
    b["dns_events"].open_perf_buffer(print_dns_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

