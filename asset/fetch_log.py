#!/bin/env python
# @date     2023-03-03
# @author   Xu.Cao
#
# @history
#       <author>    <time>      <version>               <description>
#       Xu.Cao      2023-03-07  1.0.1                   Format this code
#       Xu.Cao      2023-05-22  1.2.6                   support for old kernel and change the usage
#
import sys
import time
from bcc import BPF
import ctypes as ct
import os
import argparse
import socket
import struct
import signal
from datetime import datetime, timedelta
from threading import Timer, Lock, Thread

syscall = [
    "openat",
    "dup3",
    "renameat",
    "renameat2",
    "read",
    "write",
    "close",
    "unlinkat",
    "mkdirat",
    "exit_group",
    "socket",
    "connect",
    "rename",
    "dup2",
    "mkdir",
    "rmdir",
    "unlink",
    "accept"
]


class BehavT(ct.Structure):
    _fields_ = [
        ("ppid", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 32),
        ("is_net", ct.c_bool),
        ("is_output", ct.c_bool),
        ("syscall", ct.c_uint8),
        ("old_syscall", ct.c_uint8),
        ("flag", ct.c_uint64),
        ("fd", ct.c_int),
        ("sec_fd", ct.c_int),
        ("name", ct.c_char * 32),
        ("sec_name", ct.c_char * 32),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
    ]


parser = argparse.ArgumentParser()
parser.add_argument('-c', '--command', dest='command', type=str, default='cat', help='要监控的命令，如果要监控多个命令，请用逗号隔开')
parser.add_argument('-o', '--out-file', dest='of', type=str, default='../logs/log', help='日志保存的目标文件')
args = parser.parse_args()


def get_cmd_filter() -> str:
    global args

    insert_cmd = ''
    cmds_ = args.command.split(',')
    for cmd_ in cmds_:
        if cmd_ == cmds_[0]:
            insert_cmd = 'ebpf_strcmp("{}", cur->comm)'.format(cmd_)
        else:
            insert_cmd += ' && ebpf_strcmp("{}", cur->comm)'.format(cmd_)
    return insert_cmd


log_file = open(args.of, 'w')
if not log_file:
    print('无法创建该文件')
    exit(-1)
with open("fetch_log.c") as f:
    prog = f.read()
if prog is None or prog == "":
    print("file open error")
    exit(-1)

# operations of eBPF
prog = prog.replace('[FILTER]', get_cmd_filter(), 1)
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write")
b.attach_kprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close")
b.attach_kprobe(event=b.get_syscall_fnname("unlink"), fn_name="syscall__unlink")
b.attach_kprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")
b.attach_kprobe(event=b.get_syscall_fnname("mkdir"), fn_name="syscall__mkdir")
b.attach_kprobe(event=b.get_syscall_fnname("rmdir"), fn_name="syscall__rmdir")
b.attach_kprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat")
b.attach_kprobe(event=b.get_syscall_fnname("rename"), fn_name="syscall__rename")
b.attach_kprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat")
b.attach_kprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2")
b.attach_kprobe(event=b.get_syscall_fnname("dup2"), fn_name="syscall__dup2")
b.attach_kprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3")
b.attach_kprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket")
b.attach_kprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect")
b.attach_kprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept")
# b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="syscall_exit_group")
b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read_return")
b.attach_kretprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write_return")
b.attach_kretprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close_return")
b.attach_kretprobe(event=b.get_syscall_fnname("unlink"), fn_name="syscall__unlink_return")
b.attach_kretprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("mkdir"), fn_name="syscall__mkdir_return")
b.attach_kretprobe(event=b.get_syscall_fnname("rmdir"), fn_name="syscall__rmdir_return")
b.attach_kretprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("rename"), fn_name="syscall__rename_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2_return")
b.attach_kretprobe(event=b.get_syscall_fnname("dup2"), fn_name="syscall__dup2_return")
b.attach_kretprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3_return")
b.attach_kretprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket_return")
b.attach_kretprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect_return")
b.attach_kretprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept_return")

b.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect_return")


def print_event(cpu, data, size):
    global syscall, log_file

    event = ct.cast(data, ct.POINTER(BehavT)).contents
    log_file.write("{} {} {} {} {:o} {} ".format(event.ppid, event.pid, event.comm.decode(),
                                                 syscall[event.syscall], event.flag, event.fd))
    if event.is_net == 0:
        log_file.write("{} {} {}\n".format(event.name.decode(),
                                           '' if event.sec_fd == -1 else event.sec_fd,
                                           event.sec_name.decode()))
    else:
        log_file.write("{}:{} {}:{}\n".format(event.src_ip, event.src_port, event.dst_ip, event.dst_port))


# 想要加入状态机中的命令行为
cmds = [  # 命令名，是否输出日志
    ('touch t1 t2', True),
    ('cat t1 t2', True),
    ('gzip t1 t2', True),
    ('gzip -d t1.gz t2.gz', True),
    ('rm t1 t2', True),
    ('split -l 1 lines', True),
    ('rm xa*', False),
    ('mkdir m1 m2', True),
    ('rmdir m1 m2', True),
    ('zip z.zip z1 z2', True),
    ('zip z.zip z1 z2 z3', True),
    ('unzip z.zip', True),
    ('rm z.zip 4', False),
    ('cp cm1 cm2 extra', True),
    ('cp cm1 cm2 extra', True),
    ('rm extra/*', False),
    ('mv cm1 cm2 extra', True),
    ('cp extra/* ./', False),
    ('mv cm1 cm2 extra', True),
    ('cp extra/* ./', False),
    ('rm extra/*', False)
]

b["behavior"].open_perf_buffer(print_event)
print('BPF loaded now...')
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit(0)
