#!/usr/bin/python3
# bcc implementation of udpconnect from BPF Performance Tools by Brendan Gregg

from bcc import BPF
from bcc.utils import printb

from socket import AF_INET, AF_INET6, inet_ntop
from struct import pack

bpf_text = """
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>

struct tcpreset_ipv4_data_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
BPF_PERF_OUTPUT(tcpreset_ipv4_events);

int kprobe__tcp_v4_send_reset(struct pt_regs *ctx, const struct sock *sk, struct sk_buff *skb)
{   
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct tcphdr * tcp = (struct tcphdr *)(skb->head + skb->transport_header);
    struct iphdr * ip = (struct iphdr *)(skb->head + skb->network_header);
    
    struct tcpreset_ipv4_data_t data4 = {};
    data4.pid = pid;
    data4.uid = bpf_get_current_uid_gid();
    data4.dport = (tcp->dest >> 8) | ((tcp->dest << 8) & 0xff00);
    data4.sport = (tcp->source >> 8) | ((tcp->source << 8) & 0xff00);   
    data4.daddr = ip->daddr;
    data4.saddr = ip->saddr;
    tcpreset_ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    
    return 0;
}
"""


def print_tcpreset_event(cpu, data, size):
    event = b["tcpreset_ipv4_events"].event(data)
    printb(
        b"%-6d %-6d %-16s %-6d %-16s %-6d"
        % (
            event.uid,
            event.pid,
            inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
            event.dport,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            event.sport,
        )
    )


if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["tcpreset_ipv4_events"].open_perf_buffer(print_tcpreset_event)
    print(
        "%-6s %-6s %-16s %-6s %-16s %-6s"
        % ("UID", "PID", "DADDR", "DPORT", "SADDR", "SPORT")
    )
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
