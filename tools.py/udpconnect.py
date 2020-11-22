#!/usr/bin/python
# bcc implementation of udpconnect from BPF Performance Tools by Brendan Gregg

from bcc import BPF
from bcc.utils import printb

from socket import AF_INET, AF_INET6, inet_ntop
from struct import pack

bpf_text = """
#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>

struct ipv4_data_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(ipv4_events);

int kprobe__ip4_datagram_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr)
{   
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    if (uaddr->sa_family == AF_INET) {
        struct sockaddr_in * uaddr_in = (struct sockaddr_in *)uaddr;
        
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.uid = bpf_get_current_uid_gid();
        data4.daddr = uaddr_in->sin_addr.s_addr;
        data4.dport = (uaddr_in->sin_port >> 8) | ((uaddr_in->sin_port << 8) & 0xff00);
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    }
    return 0;
}

struct ipv6_data_t {
    u32 pid;
    u32 uid;
    unsigned __int128 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(ipv6_events);

int kprobe__ip6_datagram_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    if (uaddr->sa_family == AF_INET) {
        struct sockaddr_in * uaddr_in = (struct sockaddr_in *)uaddr;
        
        struct ipv6_data_t data6 = {};
        data6.pid = pid;
        data6.uid = bpf_get_current_uid_gid();
        data6.daddr = uaddr_in->sin_addr.s_addr;
        data6.dport = (uaddr_in->sin_port >> 8) | ((uaddr_in->sin_port << 8) & 0xff00);
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    return 0;
}
"""


def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    printb(
        b"%-6s %-6d %-6d %-16s %-6d"
        % (
            "ipv4",
            event.uid,
            event.pid,
            inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
            event.dport,
        )
    )


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    printb(
        b"%-6s %-6d %-6d %-16s %-6d"
        % (
            "ipv6",
            event.uid,
            event.pid,
            inet_ntop(AF_INET6, event.daddr).encode(),
            event.dport,
        )
    )


b = BPF(text=bpf_text)
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
print("%-6s %-6s %-6s %-16s %-6s" % ("TYPE", "UID", "PID", "DADDR", "DPORT"))
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
