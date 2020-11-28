#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-T] [-x] [-p PID] [-d DURATION] [-t TID] [-n NAME]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Sep-2015   Brendan Gregg   Created this.
# 29-Apr-2016   Allan McAleavy  Updated for BPF_PERF_OUTPUT.
# 08-Oct-2016   Dina Goldshtein Support filtering by PID and TID.
# 28-Dec-2018   Tim Douglas     Print flags argument, enable filtering
# 06-Jan-2019   Takuma Kume     Support filtering by UID

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.utils import printb
from datetime import datetime, timedelta
import os

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_PERF_OUTPUT(events);

BPF_HASH(infotmp, u64, struct val_t);
int trace_opensnoop_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u64 tsp = bpf_ktime_get_ns();
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}

int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename, int flags)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    return 0;
};

int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
    PID_TID_FILTER
    UID_FILTER
    FLAGS_FILTER
    if (container_should_be_filtered()) {
        return 0;
    }
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }
    return 0;
};
"""

bpf_text = bpf_text.replace('PID_TID_FILTER', '')
bpf_text = bpf_text.replace('UID_FILTER', '')
bpf_text = bpf_text.replace('FLAGS_FILTER', '')
bpf_text = '\n'.join(x for x in bpf_text.split('\n')
        if 'EXTENDED_STRUCT_MEMBER' not in x)
