/*
 * @date    2023-03-03
 * @author  Xu.Cao
 * @details 本程序主要用于返回每个关注的行为的系统调用序列，以单个进程为单位，目的是查看每个进程的行为，多进程的关联不属于本程序的任务
 *
 * @history
 *      <author>    <time>      <version>               <description>
 *      Xu.Cao      2023-03-07  1.0.1                   Format this code
 *      Xu.Cao      2023-05-22  1.2.6                   support for vfs_rename, etc.
 */
#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include "ebpf_string.h"

#define SYS_CALL_OPENAT 0x00
#define SYS_CALL_DUP3 0x01
#define SYS_CALL_RENAMEAT 0x02
#define SYS_CALL_RENAMEAT2 0x03
#define SYS_CALL_READ 0x04
#define SYS_CALL_WRITE 0x05
#define SYS_CALL_CLOSE 0x06
#define SYS_CALL_UNLINKAT 0x07
#define SYS_CALL_MKDIRAT 0x08
#define SYS_CALL_EXIT_GROUP 0x09
#define SYS_CALL_SOCKET 0x0a
#define SYS_CALL_CONNECT 0x0b
#define SYS_CALL_RENAME 0x0c
#define SYS_CALL_DUP2 0x0d
#define SYS_CALL_MKDIR 0x0e
#define SYS_CALL_RMDIR 0x0f
#define SYS_CALL_UNLINK 0x10
#define SYS_CALL_ACCEPT 0x11

struct behav_t {
    u32 ppid, pid;
    char comm[32];
    bool is_net;  // 哪种操作，操作的资源是文件还是套接字
    bool is_output;
    u8 syscall;
    u8 old_syscall;
    u64 flag;   // 系统调用的参数，如文件的打开方式等
    int fd, secondary_fd;
    char filename[32];              // 主要的文件
    char secondary_filename[32];    // 辅助文件名，可能不会用到
    u32 src_ip, dst_ip;
    u16 src_port, dst_port;
};

BPF_HASH(state, u32, struct behav_t, 4096);
BPF_HASH(cur_sock, u32, struct sock *, 32);
BPF_PERF_OUTPUT(behavior);

#define NET_ARG(family, type) (((u64)family << 32) | protocol)

/*
 * @desc  本函数处理除 exit 外的所有系统调用的入口，
 *      - 为了减少申请和释放空间带来的消耗，进程的信息结构体将在进程第一次使用系统调用时创建，最终调用 exit 系统调用时释放。
 *      - 对于套接字的获取我们不使用系统调用直接获取，而是使用底层的内核函数以提高准确性。
 *      - 为了进一步减少冗余，对于连续调用的相同的系统调用，我们只保留一条。
 *      因此，本函数需要传入的参数是除了套接字外的相关信息。
 *
 * @param ctx 进程上下文信息
 * @param syscall 标识哪个系统调用
 * @param flags 系统调用的参数，如打开文件的方式，socket 创建的方式
 * @param type 代表哪一种资源操作，文件还是套接字
 * @param fd_to_cmp 源 fd
 * @param fd_for_update 目标 fd
 * @param name 文件名
 * @param sec_name 辅助文件名
 * @return always 0, routine for ebpf
 */
static int do_entry(struct pt_regs *ctx, u8 syscall, u64 flags, bool type,
        int fd, int sec_fd, const char *name, const char *sec_name) {

    struct behav_t b = {}, *cur = NULL;
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    b.pid = task->pid;
    b.ppid = task->real_parent->pid;
    cur = state.lookup(&b.pid);

    if (0 == cur) {
        cur = &b;
        cur->old_syscall = 0;
    }

    // 除非上一条系统调用与当前这一条相同，否则都重新填充数据，减少不必要的冗余，因为他们语义上只代表该进程做了这样的事
    if (cur->old_syscall == syscall && (syscall == SYS_CALL_READ || syscall == SYS_CALL_WRITE)) {
        cur->is_output = false;
        return 0;
    } if (syscall == SYS_CALL_OPENAT && flags == 0x80000) {
        cur->is_output = false;
        return 0;
    } else {
        cur->is_output = true;
    }
//    bpf_get_current_comm(&(cur->comm), 32);
    bpf_probe_read_kernel_str(cur->comm, 32, task->comm);

    if ([FILTER]) {
        return 0;
    }

    cur->is_net = type;
    cur->syscall = cur->old_syscall = syscall;
    cur->flag = flags;
    cur->fd = fd;
    cur->secondary_fd = sec_fd;
    bpf_probe_read_user_str(cur->filename, sizeof(cur->filename), name);
    bpf_probe_read_user_str(cur->secondary_filename, sizeof(cur->secondary_filename), sec_name);

    state.update(&b.pid, cur);
    return 0;
}

/*
 * @param ctx context of task
 * @return always 0
 *
 * @details This function handles the next possible behavior semantic when function returns. If return-value is invalid,
 *          just abandon the possible behavior semantic.
 */
static int do_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state.lookup(&pid);
    if (0 == cur) {
        return 0;
    }

    if (cur->syscall != SYS_CALL_ACCEPT) {
        int ret_val = PT_REGS_RC(ctx);

        /* skip if no state recording or returning error */
        if (ret_val < 0) {
            return 0;
        }

        if (cur->fd == -1) {
            cur->fd = ret_val;
        }
    }

    if (cur->syscall == SYS_CALL_CLOSE) {
        bpf_probe_read_user_str(cur->filename, sizeof(cur->filename), NULL);
        bpf_probe_read_user_str(cur->secondary_filename, sizeof(cur->secondary_filename), NULL);
    }

    if (!cur->is_output) {
        return 0;
    }

    behavior.perf_submit(ctx, cur, sizeof(struct behav_t));

    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
    return do_entry(ctx, SYS_CALL_OPENAT, FLAG, false, -1, -1, name, NULL);
}

int syscall__openat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__read(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, SYS_CALL_READ, 0, false, fd, -1, NULL, NULL);
}

int syscall__read_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__write(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, SYS_CALL_WRITE, 0, false, fd, -1, NULL, NULL);
}

int syscall__write_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__close(struct pt_regs *ctx, int fd) {
    return do_entry(ctx, SYS_CALL_CLOSE, 0, false, fd, -1, NULL, NULL);
}

int syscall__close_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__unlink(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, SYS_CALL_UNLINK, 0, false, -1, -1, name, NULL);
}

int syscall__unlink_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__unlinkat(struct pt_regs *ctx, int dirfd, const char __user *name, int FLAG) {
return do_entry(ctx, SYS_CALL_UNLINKAT, FLAG, false, -1, -1, name, NULL);
}

int syscall__unlinkat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdir(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, SYS_CALL_MKDIR, 0, false, -1, -1, name, NULL);
}

int syscall__mkdir_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__mkdirat(struct pt_regs *ctx, int dirfd, const char __user *name) {
return do_entry(ctx, SYS_CALL_MKDIRAT, 0, false, -1, -1, name, NULL);
}

int syscall__mkdirat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__rmdir(struct pt_regs *ctx, const char __user *name) {
    return do_entry(ctx, SYS_CALL_RMDIR, 0, false, -1, -1, name, NULL);
}

int syscall__rmdir_return(struct pt_regs *ctx, const char __user *name) {
    return do_return(ctx);
}

int syscall__rename(struct pt_regs *ctx, const char __user *oldname,
                    const char __user *newname) {
    return do_entry(ctx, SYS_CALL_RENAME, 0, false, -1, -1, oldname, newname);
}

int syscall__rename_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat(struct pt_regs *ctx,
                      int olddir, const char __user *oldname,
                      int newdir, const char __user *newname) {
    return do_entry(ctx, SYS_CALL_RENAMEAT, 0, false, -1, -1, oldname, newname);
}

int syscall__renameat_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__renameat2(struct pt_regs *ctx,
                       int olddir, const char *oldname,
                       int newdir, const char *newname,
                       unsigned int FLAG) {
    return do_entry(ctx, SYS_CALL_RENAMEAT2, FLAG, false, -1, -1, oldname, newname);
}

int syscall__renameat2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup2(struct pt_regs *ctx, int oldfd, int newfd) {
    return do_entry(ctx, SYS_CALL_DUP2, 0, false, oldfd, newfd, NULL, NULL);
}

int syscall__dup2_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__dup3(struct pt_regs *ctx, int oldfd, int newfd, int FLAG) {
    return do_entry(ctx, SYS_CALL_DUP3, FLAG, false, oldfd, newfd, NULL, NULL);
}

int syscall__dup3_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__socket(struct pt_regs *ctx,
                    int family, int type, int protocol) {
    return do_entry(ctx, SYS_CALL_SOCKET, NET_ARG(family, type), true, -1, -1, NULL, NULL);
}

int syscall__socket_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

int syscall__connect(struct pt_regs *ctx, int fd,
                     const struct sockaddr __user* addr, u32 addrlen) {
    return do_entry(ctx, SYS_CALL_CONNECT, 0, true, fd, -1, NULL, NULL);
}

int syscall__connect_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

// accept is listened by sshd as daemon, so should put it into state machine
int syscall__accept(struct pt_regs *ctx, int sockfd, struct sockaddr __user* addr) {
    return do_entry(ctx, SYS_CALL_ACCEPT, 0, true, sockfd, -1, NULL, NULL);
}

int syscall__accept_return(struct pt_regs *ctx) {
    return do_return(ctx);
}

//int syscall_exit_group(struct pt_regs *ctx, int sig) {
//    u32 pid = bpf_get_current_pid_tgid() >> 32;
//    struct behav_t *cur = state.lookup(&pid);
//
//    if (!cur) return 0;
//
//    cur->syscall = EXIT_GROUP;
//    state.delete(&pid);
//
//    behavior.ringbuf_output(cur, sizeof(struct behav_t), 0);
//
//    return 0;
//}

/* kernel function to get inode */

int do_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state.lookup(&pid);
    // stash the sock ptr for lookup on return
    if (cur) {
        cur_sock.update(&pid, &sk);
    }

    return 0;
}

int do_tcp_v4_connect_return(struct pt_regs *ctx) {

    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = cur_sock.lookup(&pid);
    struct behav_t *cur = state.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }
    cur_sock.delete(&pid);
    if (cur == 0) {
        return 0;
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        return 0;
    }

    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;

    cur->dst_ip = skp->__sk_common.skc_daddr;
    cur->src_ip = skp->__sk_common.skc_rcv_saddr;
    cur->dst_port = ntohs(dport);
    cur->src_port = lport;

    return 0;
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct behav_t *cur = state.lookup(&pid);
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

    if (0 == cur) {
        return 0;
    }

    // pull in details
    u16 lport = 0, dport;
    lport = newsk->__sk_common.skc_num;
    dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);

    cur->src_ip = newsk->__sk_common.skc_rcv_saddr;
    cur->dst_ip = newsk->__sk_common.skc_daddr;
    cur->src_port = lport;
    cur->dst_port = dport;

    return 0;
}