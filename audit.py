#!/usr/bin/python3
import argparse
import logging
import os
import subprocess
import signal

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
import dnslib

parser = argparse.ArgumentParser(description="BPF audit")
parser.add_argument("-c", type=str, help="Config file path", required=True)
parser.add_argument("--udp", help="enable udp", action="store_true")
parser.add_argument("--tcp", help="enable tcp", action="store_true")
parser.add_argument("--open", help="enable open", action="store_true")
parser.add_argument("--exec", help="enable exec", action="store_true")
parser.add_argument("--dns", help="enable dns", action="store_true")
parser.add_argument("--test", help="logging.info bpftext", action="store_true")
parser.add_argument("--log", help="enable logging to a file", action="store_true")

args = parser.parse_args()
logging.getLogger().setLevel(logging.INFO)

if args.log:
    fh = logging.FileHandler("log.log")
    fh.setLevel(logging.INFO)
    logging.getLogger().addHandler(fh)

config = ConfigParser()
config.read(args.c)


def parse_config(config, key):
    blacklist = config[key].get("blacklist", "").strip().split(",")
    alertlist = config[key].get("alertlist", "").strip().split(",")
    return (
        {b.strip(): 1 for b in blacklist if b},
        {a.strip(): 1 for a in alertlist if a},
    )


ip_blacklist, ip_alertlist = parse_config(config, "IP")
domain_blacklist, domain_alertlist = parse_config(config, "DOMAIN")
fs_blacklist, fs_alertlist = parse_config(config, "FS")
exec_blacklist, exec_alertlist = parse_config(config, "EXEC")

# For exec arguments
argv = defaultdict(list)


def notitfy(msg):
    subprocess.Popen(["notify-send", "bpf-audit", msg])

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
    daddr = inet_ntop(AF_INET6, event.daddr).encode()
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
    fname = event.fname.decode()
    if fname in fs_blacklist:
        logging.info(
            f"Process with PID {event.pid} and UID {event.uid} with command {event.comm.decode()} opened a file {fname} on blacklist."
        )
        try:
            os.kill(event.pid, signal.SIGTERM)
        except:
            logging.info(f"Unable to terminate process {event.pid}.")
        else:
            logging.info(f"Successfully terminated process {event.pid}.")
    if fname in fs_alertlist:
        logging.info(
            f"Process with PID {event.pid} and UID {event.uid} with command {event.comm.decode()} opened a file {fname} on alertlist."
        )


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
    if domain_name in domain_alertlist:
        print("Process with PID {} and UID {} initiated a TCP over IPv6 connection to remote domain {} on alert list.".format(event.pid, event.uid, domain_name))
    pass


def monitor_execsnoop_event(cpu, data, size):
    event = b["execsnoop_events"].event(data)
    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.retval != 0:
            return
        argv[event.pid] = [arg.decode() for arg in argv[event.pid]]
        prog = argv[event.pid][0]
        full_command = " ".join(argv[event.pid])
        if prog in exec_blacklist:
            logging.info(
                f"Process with PID {event.pid} and UID {event.uid} with command {full_command} execed program {prog} on blacklist."
            )
            try:
                os.kill(event.pid, signal.SIGTERM)
            except:
                logging.info(f"Unable to terminate process {event.pid}.")
            else:
                logging.info(f"Successfully terminated process {event.pid}.")
        if prog in exec_alertlist:
            logging.info(
                f"Process with PID {event.pid} and UID {event.uid} with command {full_command} execed program {prog} on alertlist."
            )

        try:
            del argv[event.pid]
        except Exception:
            logging.error(f"Failed to delete argv for pid {event.pid}.")


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

