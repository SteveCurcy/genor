#!/bin/env python
import sys
import time

from bcc import BPF
import ctypes as ct
import os
import socket
import struct
import signal
from datetime import datetime, timedelta
from threading import Timer, Lock, Thread

OPENAT = 1
READ = 2
WRITE = 3
CLOSE = 4
UNLINKAT = 5
MKDIRAT = 6
RENAMEAT = 7
RENAMEAT2 = 8
DUP3 = 9
SOCKET = 10
CONNECT = 11
ACCEPT = 12
EXIT_GROUP = 13

syscall = [
    "",
    "openat",
    "read",
    "write",
    "close",
    "unlinkat",
    "mkdirat",
    "renameat",
    "renameat2",
    "dup3",
    "socket",
    "connect",
    "accept",
    "exit_group"
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


# ======= end of data definition ======


with open("fetch_log.c") as f:
    prog = f.read()
if prog is None or prog == "":
    print("file open error")
    exit(-1)

# operations of eBPF
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
b.attach_kprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write")
b.attach_kprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close")
b.attach_kprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat")
b.attach_kprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat")
b.attach_kprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat")
b.attach_kprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2")
b.attach_kprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3")
b.attach_kprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket")
b.attach_kprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect")
b.attach_kprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept")
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="syscall_exit_group")
b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("read"), fn_name="syscall__read_return")
b.attach_kretprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write_return")
b.attach_kretprobe(event=b.get_syscall_fnname("close"), fn_name="syscall__close_return")
b.attach_kretprobe(event=b.get_syscall_fnname("unlinkat"), fn_name="syscall__unlinkat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("mkdirat"), fn_name="syscall__mkdirat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat"), fn_name="syscall__renameat_return")
b.attach_kretprobe(event=b.get_syscall_fnname("renameat2"), fn_name="syscall__renameat2_return")
b.attach_kretprobe(event=b.get_syscall_fnname("dup3"), fn_name="syscall__dup3_return")
b.attach_kretprobe(event=b.get_syscall_fnname("socket"), fn_name="syscall__socket_return")
b.attach_kretprobe(event=b.get_syscall_fnname("connect"), fn_name="syscall__connect_return")
b.attach_kretprobe(event=b.get_syscall_fnname("accept"), fn_name="syscall__accept_return")

b.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="do_tcp_v4_connect_return")


def print_event(cpu, data, size):
    global syscall, log_file

    if log_file is None:
        return

    event = ct.cast(data, ct.POINTER(BehavT)).contents
    log_file.write("{} {} {} {} {:o} {} ".format(event.ppid, event.pid, event.comm.decode(),
                                                 syscall[event.syscall], event.flag, event.fd))
    if event.is_net == 0:
        log_file.write("{} {} {}\n".format(event.name.decode(),
                                           "" if event.sec_fd == -1 else event.sec_fd,
                                           event.sec_name.decode()))
    else:
        log_file.write("{}:{} {}:{}\n".format(event.src_ip, event.src_port, event.dst_ip, event.dst_port))


b["behavior"].open_ring_buffer(print_event)
is_running = True
log_file = None
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


def event_handler():
    global is_running
    while is_running:
        try:
            b.ring_buffer_consume()
        finally:
            pass


os.system('mkdir -p ../logs/')
os.system('rm -rf extra/*')
os.system('rm -rf logs/*')
for cmd in cmds:

    t = None
    if cmd[1]:
        t = Thread(target=event_handler)
        is_running = True
        file_path = '../logs/{}'.format(cmd[0].replace(' ', '_'))
        if os.path.isfile(file_path):
            file_path += '_cover'
        log_file = open(file_path, 'w')
        t.start()

    os.system(cmd[0])

    if cmd[1]:
        is_running = False
        log_file.close()
        log_file = None
        t.join()
