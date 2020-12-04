#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# modified verion of tcpconnect.py from bcc/tools
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct tcpcon_ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(tcpcon_ipv4_events);

struct tcpcon_ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(tcpcon_ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;

    FILTER_PORT

    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        IPV6_CODE
    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
"""

struct_init = {
    "ipv4": {
        "count": """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               flow_key.dport = ntohs(dport);
               ipv4_count.increment(flow_key);""",
        "trace": """
               struct tcpcon_ipv4_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               data4.dport = ntohs(dport);
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               tcpcon_ipv4_events.perf_submit(ctx, &data4, sizeof(data4));""",
    },
    "ipv6": {
        "count": """
               struct ipv6_flow_key_t flow_key = {};
               bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               flow_key.dport = ntohs(dport);
               ipv6_count.increment(flow_key);""",
        "trace": """
               struct tcpcon_ipv6_data_t data6 = {.pid = pid, .ip = ipver};
               data6.uid = bpf_get_current_uid_gid();
               data6.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               data6.dport = ntohs(dport);
               bpf_get_current_comm(&data6.task, sizeof(data6.task));
               tcpcon_ipv6_events.perf_submit(ctx, &data6, sizeof(data6));""",
    },
}

# This defines an additional BPF program that instruments udp_recvmsg system
# call to locate DNS response packets on UDP port 53. When these packets are
# located, the data is copied to user-space where python will parse them with
# dnslib.
#
# uses a percpu array of length 1 to store the dns_data_t off the stack to
# allow for a maximum DNS packet length of 512 bytes.
dns_bpf_text = """
#include <net/inet_sock.h>

#define MAX_PKT 512
struct dns_data_t {
    u8  pkt[MAX_PKT];
};

BPF_PERF_OUTPUT(dns_events);

// store msghdr pointer captured on syscall entry to parse on syscall return
BPF_HASH(tbl_udp_msg_hdr, u64, struct msghdr *);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(dns_data,struct dns_data_t,1);

int trace_udp_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *is = inet_sk(sk);

    // only grab port 53 packets, 13568 is ntohs(53)
    if (is->inet_dport == 13568) {
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
        tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
    }
    return 0;
}

int trace_udp_ret_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 zero = 0;
    struct msghdr **msgpp = tbl_udp_msg_hdr.lookup(&pid_tgid);
    if (msgpp == 0)
        return 0;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;
    if (msghdr->msg_iter.type != ITER_IOVEC)
        goto delete_and_return;

    int copied = (int)PT_REGS_RC(ctx);
    if (copied < 0)
        goto delete_and_return;
    size_t buflen = (size_t)copied;

    if (buflen > msghdr->msg_iter.iov->iov_len)
        goto delete_and_return;

    if (buflen > MAX_PKT)
        buflen = MAX_PKT;

    struct dns_data_t *data = dns_data.lookup(&zero);
    if (!data) // this should never happen, just making the verifier happy
        return 0;

    void *iovbase = msghdr->msg_iter.iov->iov_base;
    bpf_probe_read(data->pkt, buflen, iovbase);
    dns_events.perf_submit(ctx, data, buflen);

delete_and_return:
    tbl_udp_msg_hdr.delete(&pid_tgid);
    return 0;
}

"""

bpf_text = bpf_text.replace("IPV4_CODE", struct_init["ipv4"]["trace"])
bpf_text = bpf_text.replace("IPV6_CODE", struct_init["ipv6"]["trace"])
bpf_text = bpf_text.replace("FILTER_PID", "")
bpf_text = bpf_text.replace("FILTER_PORT", "")
bpf_text = bpf_text.replace("FILTER_UID", "")
