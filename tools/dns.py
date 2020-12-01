#!/usr/bin/python3
# dns filter inspired by bcc/tools/tcpconnect.py

import dnslib

from bcc import BPF

bpf_text = """
#include <net/inet_sock.h>
#define MAX_PKT 512

struct dns_data_t {
    u32 pid;
    u32 uid;
    u16 buflen;
    u8  pkt[MAX_PKT];
};
BPF_PERF_OUTPUT(dns_events);
BPF_HASH(tbl_udp_msg_hdr, u64, struct msghdr *);
BPF_PERCPU_ARRAY(dns_data,struct dns_data_t,1);

int trace_udp_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *is = inet_sk(sk);
    // 13568 = ntohs(53)
    if (is->inet_dport == 13568) {
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
        tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
    }
    return 0;
}

int trace_udp_ret_recvmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    u32 zero = 0;
    struct msghdr **msgpp = tbl_udp_msg_hdr.lookup(&pid_tgid);
    
    if (msgpp == 0) return 0;
    
    struct msghdr *msghdr = (struct msghdr *)*msgpp;
    
    if (msghdr->msg_iter.type != ITER_IOVEC) goto delete_and_return;
    
    int copied = (int)PT_REGS_RC(ctx);
    
    if (copied < 0) goto delete_and_return;
    
    size_t buflen = (size_t)copied;
    
    if (buflen > msghdr->msg_iter.iov->iov_len) goto delete_and_return;
    
    if (buflen > MAX_PKT) buflen = MAX_PKT;
    
    struct dns_data_t *data = dns_data.lookup(&zero);
    
    if (!data) return 0;
    
    void *iovbase = msghdr->msg_iter.iov->iov_base;
    bpf_probe_read(data->pkt, buflen, iovbase);
    data->uid = uid;
    data->pid = pid;
    data->buflen = buflen;
    dns_events.perf_submit(ctx, data, buflen+10);
    
delete_and_return:
    tbl_udp_msg_hdr.delete(&pid_tgid);
    return 0;
}
"""


def print_dns_event(cpu, data, size):
    event = b["dns_events"].event(data)
    payload = event.pkt[: event.buflen]
    print(size, event.buflen)
    dnspkt = dnslib.DNSRecord.parse(payload)
    print(event.uid, event.pid, dnspkt.q.qname)


if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udp_recvmsg")
    b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_ret_recvmsg")
    b["dns_events"].open_perf_buffer(print_dns_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
