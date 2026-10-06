/*
 * apply-seccomp.c - Apply seccomp BPF filter in an isolated PID namespace
 *
 * Usage: apply-seccomp <command> [args...]
 *
 * This program applies a baked-in seccomp BPF filter, isolates the
 * target command in a nested user+PID+mount namespace so it cannot see or
 * ptrace any process that lacks the filter, applies the filter with
 * prctl(PR_SET_SECCOMP), and execs the command.
 *
 * Process layout inside the outer bwrap sandbox:
 *
 *   bwrap init (PID 1)          <- outer PID ns, no seccomp
 *   \_ bash / socat ...         <- outer PID ns, no seccomp
 *      \_ apply-seccomp [outer] <- outer PID ns, waits for inner init
 *         ================================================= PID ns boundary
 *         \_ apply-seccomp [inner init] <- inner PID 1, PR_SET_DUMPABLE=0
 *            \_ user command            <- inner PID 2, seccomp applied
 *
 * From the user command's point of view /proc contains only its own process
 * tree. The bwrap init, bash wrapper, and socat helpers are not addressable,
 * so they cannot be ptraced or patched via /proc/N/mem even on systems with
 * kernel.yama.ptrace_scope=0. The inner init (PID 1) sets PR_SET_DUMPABLE=0
 * so it cannot be ptraced either.
 *
 * Any failure to set up the nested namespaces aborts with a non-zero exit
 * status; we never fall back to running the command without isolation.
 *
 * Compile: gcc -static -O2 -o apply-seccomp apply-seccomp.c
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>



#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#if defined(__x86_64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define SRT_HAS_X32 1
#elif defined(__aarch64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#  define SRT_HAS_X32 0
#else
#  define SRT_AUDIT_ARCH 0
#  define SRT_HAS_X32 0
#endif

/* audit arch codes (asm/unistd_32.h / arch-specific audit enums) */
#ifndef AUDIT_ARCH_X86_64
#  define AUDIT_ARCH_X86_64 0xc000003e
#endif
#ifndef AUDIT_ARCH_AARCH64
#  define AUDIT_ARCH_AARCH64 0xc00000b7
#endif
#ifndef AUDIT_ARCH_X32
#  define AUDIT_ARCH_X32 0x32
#endif

/* ---- Optional passive observation filter ---------------------------------
 *
 * When SRT_OBSERVE_SOCK is set the worker installs a second seccomp filter
 * that traps write-intent filesystem syscalls to
 * SECCOMP_RET_USER_NOTIF, then ships the listener fd to the OUTER STUB over
 * a pre-fork socketpair. The outer stub is never under either filter, so it
 * services every notification with SECCOMP_USER_NOTIF_FLAG_CONTINUE — the
 * workload's behaviour is unchanged — and writes one JSON line per
 * observed call to the SRT_OBSERVE_SOCK unix socket (a Node net.Server).
 *
 * Paths are read from the workload's address space with process_vm_readv.
 * That memory is ATTACKER-CONTROLLED and racy (the workload can rewrite the
 * buffer between trap and read). bwrap's mount table is the only enforcement
 * boundary; the path reported here is a HINT for diagnostics and must never
 * gate a policy decision.
 *
 * Every failure path is fail-open: any error before the filter is installed
 * disables observation and proceeds; any error after still drains the notify
 * fd with CONTINUE so the workload cannot wedge. */

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#  define SECCOMP_IOC_MAGIC '!'
#  define SECCOMP_IOCTL_NOTIF_RECV     _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#  define SECCOMP_IOCTL_NOTIF_SEND     _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#  define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW (SECCOMP_IOC_MAGIC, 2, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#  define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#  define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1UL << 4)
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD (-100)
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#  define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef __NR_pidfd_open
#  define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#  define __NR_pidfd_getfd 438
#endif
#ifndef __NR_pipe2
#  define __NR_pipe2 293
#endif

#ifndef __NR_fchmodat2
#  define __NR_fchmodat2 452
#endif

#define OBS_WRITE_MASK ((unsigned)(O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))
#define OBS_PATH_MAX 4096
#define OBS_LINE_CAP (OBS_PATH_MAX * 2 + 256)

/* Single source of truth for the observed-syscall set. The BPF program and
 * the supervisor's name/path-arg lookup are both derived from this table so
 * they cannot drift. flags_arg >= 0 means the BPF gates the trap on
 * args[flags_arg] & OBS_WRITE_MASK; -1 means always trap. */
struct observe_call {
    int nr;
    const char *name;
    int8_t path_arg;
    int8_t path2_arg;
    int8_t flags_arg;
    /* Argument index of the dirfd governing path_arg/path2_arg, or -1 when
     * the path is resolved against the caller's cwd (legacy entry points). */
    int8_t dirfd_arg;
    int8_t dirfd2_arg;
};

static const struct observe_call observe_calls[] = {
    { __NR_openat,     "openat",     1, -1,  2,  0, -1 },
#ifdef __NR_openat2
    { __NR_openat2,    "openat2",    1, -1, -1,  0, -1 },
#endif
    { __NR_unlinkat,   "unlinkat",   1, -1, -1,  0, -1 },
    { __NR_mkdirat,    "mkdirat",    1, -1, -1,  0, -1 },
    { __NR_mknodat,    "mknodat",    1, -1, -1,  0, -1 },
    { __NR_symlinkat,  "symlinkat",  2, -1, -1,  1, -1 },
    { __NR_linkat,     "linkat",     1,  3, -1,  0,  2 },
#ifdef __NR_renameat
    { __NR_renameat,   "renameat",   1,  3, -1,  0,  2 },
#endif
    { __NR_renameat2,  "renameat2",  1,  3, -1,  0,  2 },
    { __NR_fchmodat,   "fchmodat",   1, -1, -1,  0, -1 },
    { __NR_fchmodat2,  "fchmodat2",  1, -1, -1,  0, -1 },
    { __NR_fchownat,   "fchownat",   1, -1, -1,  0, -1 },
    { __NR_utimensat,  "utimensat",  1, -1, -1,  0, -1 },
#ifdef __x86_64__
    /* Legacy non-*at entry points: glibc/coreutils still call these directly
     * on x86_64. aarch64 only ever had the *at forms. */
    { __NR_open,       "open",       0, -1,  1, -1, -1 },
    { __NR_creat,      "creat",      0, -1, -1, -1, -1 },
    { __NR_unlink,     "unlink",     0, -1, -1, -1, -1 },
    { __NR_rmdir,      "rmdir",      0, -1, -1, -1, -1 },
    { __NR_rename,     "rename",     0,  1, -1, -1, -1 },
    { __NR_link,       "link",       0,  1, -1, -1, -1 },
    { __NR_symlink,    "symlink",    1, -1, -1, -1, -1 },
    { __NR_mkdir,      "mkdir",      0, -1, -1, -1, -1 },
    { __NR_mknod,      "mknod",      0, -1, -1, -1, -1 },
    { __NR_truncate,   "truncate",   0, -1, -1, -1, -1 },
    { __NR_chmod,      "chmod",      0, -1, -1, -1, -1 },
    { __NR_chown,      "chown",      0, -1, -1, -1, -1 },
    { __NR_lchown,     "lchown",     0, -1, -1, -1, -1 },
    { __NR_utime,      "utime",      0, -1, -1, -1, -1 },
    { __NR_utimes,     "utimes",     0, -1, -1, -1, -1 },
#endif
};
static const int n_observe_calls = (int)(sizeof(observe_calls)/sizeof(observe_calls[0]));

static const struct observe_call *find_observe_call(int nr) {
    for (int i = 0; i < n_observe_calls; i++)
        if (observe_calls[i].nr == nr) return &observe_calls[i];
    return NULL;
}


/* ---- AF_UNIX gate (abstract-allow / path-deny) + io_uring block --------
 *
 * Replaces the original baked-in "block all AF_UNIX" filter. BPF cannot
 * dereference the sockaddr argument, so the address-binding syscalls
 * (bind/connect/sendto/sendmsg) are routed to SECCOMP_RET_USER_NOTIF and the
 * outer-stub supervisor reads the address: AF_UNIX with an abstract
 * (NUL-first) path is allowed (it is netns-isolated by bwrap's
 * --unshare-net and can never reach a host endpoint — this is what the
 * session file lock needs), while path-based AF_UNIX is denied with EPERM,
 * preserving the original anti-escape behaviour. socket()/socketpair() are
 * allowed (they carry no address); io_uring is blocked with EPERM as before. */

#ifndef AF_UNIX
#  define AF_UNIX 1
#endif
#ifndef EPERM
#  define EPERM 1
#endif

static unsigned gate_syscall_nr(int arch, int nr) {
    unsigned n = (unsigned)nr;
#if defined(__x86_64__)
    switch (arch) {
    case AUDIT_ARCH_X86_64:
        switch (nr) {
        case __NR_bind:       return __NR_bind;
        case __NR_connect:    return __NR_connect;
        case __NR_sendto:     return __NR_sendto;
        case __NR_sendmsg:    return __NR_sendmsg;
        case __NR_io_uring_setup:   return __NR_io_uring_setup;
        case __NR_io_uring_enter:   return __NR_io_uring_enter;
        case __NR_io_uring_register: return __NR_io_uring_register;
        }
        break;
    case AUDIT_ARCH_X32:
        switch (nr) {
        case __NR_bind:       return (unsigned)__NR_bind | 0x40000000u;
        case __NR_connect:    return (unsigned)__NR_connect | 0x40000000u;
        case __NR_sendto:     return (unsigned)__NR_sendto | 0x40000000u;
        case __NR_sendmsg:    return (unsigned)__NR_sendmsg | 0x40000000u;
        }
        break;
    }
#elif defined(__aarch64__)
    if (arch == AUDIT_ARCH_AARCH64) {
        switch (nr) {
        case __NR_bind:       return __NR_bind;
        case __NR_connect:    return __NR_connect;
        case __NR_sendto:     return __NR_sendto;
        case __NR_sendmsg:    return __NR_sendmsg;
        case __NR_io_uring_setup:   return __NR_io_uring_setup;
        case __NR_io_uring_enter:   return __NR_io_uring_enter;
        case __NR_io_uring_register: return __NR_io_uring_register;
        }
    }
#endif
    return n;
}

static int build_gate_bpf(struct sock_filter *f, int cap, int with_observe) {
    int n = 0;
#define EMIT(ins) do { if (n >= cap) return -1; f[n++] = (struct sock_filter)ins; } while (0)

    /* arch check (unknown arch → ALLOW, like build_observe_bpf). */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, arch)));
    int j_arch = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SRT_AUDIT_ARCH, 0, 0)); /* jf→ALLOW */

    /* nr */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, nr)));
    int j_x32 = -1;
#if SRT_HAS_X32
    j_x32 = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 0));    /* jt→ALLOW */
#endif

    /* Address-binding syscalls → USER_NOTIF (supervisor inspects sockaddr). */
    int j_trap[8], ntrap = 0;
    static const int addrsys[] = { __NR_bind, __NR_connect, __NR_sendto,
                                   __NR_sendmsg };
    for (int i = 0; i < (int)(sizeof(addrsys)/sizeof(addrsys[0])); i++) {
        j_trap[ntrap++] = n;
        EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      gate_syscall_nr(SRT_AUDIT_ARCH, addrsys[i]), 0, 0));
    }

    /* io_uring → EPERM (kept from the original unix block). */
    int j_uring[4], nuring = 0;
    static const int uring[] = { __NR_io_uring_setup, __NR_io_uring_enter,
                                 __NR_io_uring_register };
    for (int i = 0; i < (int)(sizeof(uring)/sizeof(uring[0])); i++) {
        j_uring[nuring++] = n;
        EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      gate_syscall_nr(SRT_AUDIT_ARCH, uring[i]), 0, 0));
    }

    /* Optional observe trap set (same structure as build_observe_bpf). */
    int j_obs[64], nobs = 0;
    struct { int jeq, jflags; } gated[4];
    int ngated = 0;
    if (with_observe) {
        for (int i = 0; i < n_observe_calls; i++) {
            if (observe_calls[i].flags_arg >= 0) continue;
            j_obs[nobs++] = n;
            EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          (unsigned)observe_calls[i].nr, 0, 0));
        }
        for (int i = 0; i < n_observe_calls; i++) {
            if (observe_calls[i].flags_arg < 0) continue;
            gated[ngated].jeq = n;
            EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          (unsigned)observe_calls[i].nr, 0, 0));
            EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                          offsetof(struct seccomp_data, args) +
                          (size_t)observe_calls[i].flags_arg * sizeof(__u64)));
            EMIT(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, OBS_WRITE_MASK));
            gated[ngated].jflags = n;
            EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0));          /* jt→ALLOW jf→NOTIFY */
            ngated++;
        }
    }

    int allow_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    int notify_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    int errno_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K,
                  (unsigned)(SECCOMP_RET_ERRNO | EPERM)));

#define TO(idx, tgt) ((unsigned char)((tgt) - (idx) - 1))
    f[j_arch].jf = TO(j_arch, allow_at);
#if SRT_HAS_X32
    f[j_x32].jt  = TO(j_x32, allow_at);
#endif
    for (int i = 0; i < ntrap; i++) f[j_trap[i]].jt = TO(j_trap[i], notify_at);
    for (int i = 0; i < nuring; i++) f[j_uring[i]].jt = TO(j_uring[i], errno_at);
    for (int i = 0; i < nobs; i++) f[j_obs[i]].jt = TO(j_obs[i], notify_at);
    for (int i = 0; i < ngated; i++) {
        int next = (i + 1 < ngated) ? gated[i + 1].jeq : allow_at;
        f[gated[i].jeq].jf    = TO(gated[i].jeq, next);
        f[gated[i].jflags].jt = TO(gated[i].jflags, allow_at);
        f[gated[i].jflags].jf = TO(gated[i].jflags, notify_at);
    }
#undef TO
#undef EMIT
    return n;
}

static int gate_is_addrsys(int nr) {
#if defined(__x86_64__)
    switch (nr) {
    case __NR_bind: case __NR_connect: case __NR_sendto: case __NR_sendmsg:
    case (int)((unsigned)__NR_bind | 0x40000000u):
    case (int)((unsigned)__NR_connect | 0x40000000u):
    case (int)((unsigned)__NR_sendto | 0x40000000u):
    case (int)((unsigned)__NR_sendmsg | 0x40000000u):
        return 1;
    }
#elif defined(__aarch64__)
    switch (nr) {
    case __NR_bind: case __NR_connect: case __NR_sendto: case __NR_sendmsg:
        return 1;
    }
#endif
    return 0;
}

/* Read the socket family (first u16) from the tracee's sockaddr. The tracee
 * is frozen inside the syscall; a bad pointer or torn read returns -1. */
static int gate_read_family(pid_t pid, unsigned long addr) {
    if (addr == 0) return -1;
    unsigned char b[2];
    struct iovec local = { .iov_base = b, .iov_len = 2 };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = 2 };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != 2) return -1;
    return (int)(b[0] | (b[1] << 8));
}

/* sun_path offset is 2 on every supported arch. Abstract unix paths start
 * with NUL (sun_family + NUL + name); path-based ones are absolute paths. */
static int gate_is_abstract(pid_t pid, unsigned long addr) {
    if (addr == 0) return -1;
    unsigned char c;
    struct iovec local = { .iov_base = &c, .iov_len = 1 };
    struct iovec remote = { .iov_base = (void *)(addr + 2), .iov_len = 1 };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != 1) return -1;
    return c == '\0';
}

/* Read a u64 (e.g. msg_name at offset 0 of struct msghdr) from the tracee. */
static int gate_read_u64(pid_t pid, unsigned long addr, unsigned long *out) {
    if (addr == 0) return -1;
    unsigned char b[8];
    struct iovec local = { .iov_base = b, .iov_len = 8 };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = 8 };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != 8) return -1;
    unsigned long v = 0;
    for (int i = 0; i < 8; i++) v |= (unsigned long)b[i] << (8 * i);
    *out = v;
    return 0;
}

/* ---- F3: network-namespace isolation self-check -------------------------
 *
 * The gate allows AF_UNIX *abstract* sockets on the assumption that the
 * sandbox's --unshare-net put the workload in a fresh network namespace,
 * where abstract names are invisible to the host. That assumption only
 * holds under srt's --unshare-net; a standalone gate (no netns) shares the
 * host netns, so a host process can reach the child's abstract socket
 * (reproduced by the v3 probe). This self-check detects whether we are in
 * a fresh netns and lets the gate fail closed otherwise.
 *
 * Source of truth is /proc/net/dev, NOT /sys/class/net. The gate does NOT
 * unshare the network namespace (only PID + mount), so the outer stub, the
 * inner init, and the workload all inherit the SAME netns: under srt it is
 * bwrap's fresh netns, standalone it is the host netns. Files under
 * /proc/net are generated per READING task's network namespace by the
 * kernel, so reading /proc/net/dev from the stub reflects the stub's
 * (= child's) netns.
 * /sys/class/net is a bind mount of the host /sys, so it would
 * wrongly list host interfaces even inside a fresh netns. A fresh netns
 * has only "lo"; any other interface (eth0, tailscale0, docker0, br-*)
 * means we are NOT in a fresh netns -> deny abstract.
 *
 * Returns:
 *    1  fresh netns (no non-loopback interface) -> abstract is safe
 *    0  host netns (a real interface visible) -> deny abstract
 *   -1  could not determine (open/read failure) -> caller fails closed
 */
static int gate_netns_isolated(void) {
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    int saw_real = 0;   /* a non-loopback interface was present */
    int ok = 0;         /* at least the two header lines parsed */
    char line[128];
    /* Two header lines precede the interface list; both must be present. */
    if (fgets(line, sizeof line, f) && fgets(line, sizeof line, f))
        ok = 1;
    while (fgets(line, sizeof line, f)) {
        char *name = strtok(line, " \t");
        if (!name) continue;
        char *colon = strchr(name, ':');
        if (colon) *colon = '\0';
        if (strcmp(name, "lo") != 0)
            saw_real = 1;   /* a real (non-loopback) interface is present */
    }
    fclose(f);
    if (!ok) return -1;
    return saw_real ? 0 : 1;
}

static int send_fd(int sock, int fd, int netns) {
    /* The dummy byte carries the child's netns isolation state (F3):
     * 1 = fresh netns, 0 = host netns, 2 = undetermined. The receiver
     * decodes it; it was an unused 'F' before. */
    char dummy = (char)(netns == 1 ? 1 : netns == 0 ? 0 : 2);
    union { struct cmsghdr align; char ctl[CMSG_SPACE(sizeof(int))]; } u;
    memset(&u, 0, sizeof(u));
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.ctl, .msg_controllen = sizeof(u.ctl) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

/* Receive at most one fd. Returns the fd, or -1 if the peer sent no fd or
 * closed (worker declined to install the filter). `netns` (if non-NULL)
 * receives the isolation state decoded from the dummy byte: 1 = fresh
 * netns, 0 = host netns, 2 = undetermined (peer closed / no byte). */
static int recv_fd(int sock, int *netns) {
    char dummy;
    union { struct cmsghdr align; char ctl[CMSG_SPACE(sizeof(int))]; } u;
    memset(&u, 0, sizeof(u));
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.ctl, .msg_controllen = sizeof(u.ctl) };
    ssize_t r = recvmsg(sock, &msg, 0);
    if (r <= 0) { if (netns) *netns = 2; return -1; }
    if (netns)
        *netns = (unsigned char)dummy == 1 ? 1
                  : (unsigned char)dummy == 0 ? 0 : 2;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            int fd; memcpy(&fd, CMSG_DATA(c), sizeof(int));
            return fd;
        }
    }
    return -1;
}


/* ---- Outer-stub supervisor --------------------------------------------- */

static void json_escape_into(char *dst, size_t dstcap, const char *src, size_t srclen) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < srclen && o + 7 < dstcap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { dst[o++]='\\'; dst[o++]=(char)c; }
        else if (c < 0x20)         { dst[o++]='\\'; dst[o++]='u'; dst[o++]='0'; dst[o++]='0';
                                     dst[o++]=hex[c>>4]; dst[o++]=hex[c&0xf]; }
        else                       { dst[o++]=(char)c; }
    }
    dst[o] = '\0';
}

static ssize_t read_remote_bytes(pid_t pid, unsigned long addr, char *dst, size_t cap) {
    if (addr == 0) return -1;
    struct iovec local  = { .iov_base = dst, .iov_len = cap };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = cap };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static ssize_t read_remote_cstr(pid_t pid, unsigned long addr, char *dst, size_t cap) {
    ssize_t r = read_remote_bytes(pid, addr, dst, cap);
    if (r < 0 && errno == EFAULT) {
        /* String may sit at the tail of a mapping. */
        size_t first = 4096 - (addr & 4095);
        if (first > cap) first = cap;
        r = read_remote_bytes(pid, addr, dst, first);
    }
    if (r <= 0) return -1;
    char *nul = memchr(dst, '\0', (size_t)r);
    return nul ? (nul - dst) : r;
}

/* Resolve a relative path against the tracee's cwd or dirfd via the /proc
 * magic symlinks. The tracee is frozen inside the trapped syscall, so both
 * links are stable for single-threaded callers; a racing sibling thread can
 * at worst mislabel one LOG line (this channel never enforces anything).
 *
 * host_proc_fd is an O_PATH handle to /proc opened BEFORE the pid/mount
 * unshare: the worker later mounts a fresh /proc for the new pid namespace
 * into the mount namespace this process shares with it, which removes the
 * host-pid entries from the PATH "/proc" — but the held fd pins the
 * original superblock, and the notification's pid is a host-namespace pid.
 *
 * Returns the joined length, or 0 on ANY failure — the caller then skips
 * the event entirely (best-effort telemetry: never guess, never block). */
static size_t resolve_relative(int host_proc_fd, pid_t pid,
                               const struct seccomp_notif *req,
                               int dirfd_arg, const char *rel, size_t rellen,
                               char *dst, size_t dstcap) {
    if (host_proc_fd < 0) return 0;
    char link[64];
    /* The dirfd syscall argument is an int; the kernel exposes the raw
     * 64-bit register, so AT_FDCWD arrives zero-extended. Truncate. */
    int dirfd = dirfd_arg >= 0 ? (int)(uint32_t)req->data.args[dirfd_arg]
                               : AT_FDCWD;
    int n;
    if (dirfd == AT_FDCWD) {
        n = snprintf(link, sizeof(link), "%d/cwd", (int)pid);
    } else {
        if (dirfd < 0) return 0;  /* junk fd value */
        n = snprintf(link, sizeof(link), "%d/fd/%d", (int)pid, dirfd);
    }
    if (n <= 0 || (size_t)n >= sizeof(link)) return 0;
    ssize_t bl = readlinkat(host_proc_fd, link, dst, dstcap - 1);
    if (bl <= 0) return 0;              /* pid gone, fd closed, EACCES... */
    if (dst[0] != '/') return 0;        /* memfd:/pipe:/socket: pseudo-name */
    if ((size_t)bl + 1 + rellen + 1 > dstcap) return 0;  /* would truncate */
    size_t o = (size_t)bl;
    dst[o++] = '/';
    memcpy(dst + o, rel, rellen);
    o += rellen;
    dst[o] = '\0';
    return o;
}

static void emit_event(int out, const struct observe_call *oc, int nr, pid_t pid,
                       const char *path, size_t pathlen, const char *enc) {
    if (out < 0) return;
    char esc[OBS_LINE_CAP];
    json_escape_into(esc, sizeof(esc), path, pathlen);
    char line[OBS_LINE_CAP + 512];
    int n;
    if (enc && *enc) {
        n = snprintf(line, sizeof(line),
                     "{\"nr\":%d,\"syscall\":\"%s\",\"pid\":%d,\"path\":\"%s\","
                     "\"encodedCommand\":\"%s\"}\n",
                     nr, oc ? oc->name : "syscall", (int)pid, esc, enc);
    } else {
        n = snprintf(line, sizeof(line),
                     "{\"nr\":%d,\"syscall\":\"%s\",\"pid\":%d,\"path\":\"%s\"}\n",
                     nr, oc ? oc->name : "syscall", (int)pid, esc);
    }
    /* Never wait on the consumer: the pipe is a bounded queue and this
     * channel is best-effort — full pipe drops the note (a short write
     * corrupts at most one line, which the listener already ignores). */
    if (n > 0) {
        (void)!send(out, line,
                    (size_t)(n < (int)sizeof(line) ? n : (int)sizeof(line)-1),
                    MSG_DONTWAIT | MSG_NOSIGNAL);
    }
}

static int connect_observe_sock(const char *path) {
    if (!path || !*path) return -1;
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(sa.sun_path)) {
        close(s); errno = ENAMETOOLONG; return -1;
    }
    strcpy(sa.sun_path, path);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    /* Don't take SIGPIPE if Node drops the connection mid-run. */
    signal(SIGPIPE, SIG_IGN);
    return s;
}

/* Service the notify fd until the inner-init child exits. Runs in the OUTER
 * STUB, which never installed either seccomp filter. `abstract_ok` gates the
 * AF_UNIX abstract-allow decision (1 = the netns self-check confirmed
 * isolation, so abstract names are unreachable from the host; 0 = deny
 * abstract, fail closed). A missing observe listener never wedges the
 * workload. */
static void supervise(pid_t child, int notify_fd, int out_sock,
                      const char *enc, int host_proc_fd, int abstract_ok) {
    struct seccomp_notif_sizes sz;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz) < 0) {
        sz.seccomp_notif = sizeof(struct seccomp_notif);
        sz.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    struct seccomp_notif *req = calloc(1, sz.seccomp_notif);
    struct seccomp_notif_resp *resp = calloc(1, sz.seccomp_notif_resp);
    char *pbuf = malloc(OBS_PATH_MAX);
    char *fbuf1 = malloc(OBS_PATH_MAX * 2);
    char *fbuf2 = malloc(OBS_PATH_MAX * 2);
    if (!req || !resp || !pbuf || !fbuf1 || !fbuf2) return;

    int pidfd = (int)syscall(__NR_pidfd_open, child, 0);

    struct pollfd pfds[2];
    pfds[0].fd = notify_fd; pfds[0].events = POLLIN;
    pfds[1].fd = pidfd;     pfds[1].events = POLLIN;
    nfds_t nfds = pidfd >= 0 ? 2 : 1;
    int tmo = pidfd >= 0 ? -1 : 200;

    for (;;) {
        int pr = poll(pfds, nfds, tmo);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (pfds[0].revents & POLLIN) {
            memset(req, 0, sz.seccomp_notif);
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == 0) {
                /* ---- AF_UNIX gate decision (abstract allow / path deny) ---- */
                if (gate_is_addrsys(req->data.nr)) {
                    unsigned long sa = 0;
                    int addr_known = 1;   /* 0 = could not determine the
                                           * sockaddr pointer -> fail closed */
#if defined(__x86_64__)
                    switch (req->data.nr & 0x3fffffffu) {
                    case __NR_sendto:  sa = req->data.args[4]; break;
                    case __NR_sendmsg:
                        /* args[1] is struct msghdr *; msg_name (the
                         * sockaddr pointer) is the u64 at offset 0. A
                         * NULL msg_name is legitimate (connected socket).
                         * A read FAILURE must NOT be conflated with NULL. */
                        if (gate_read_u64(req->pid,
                                (unsigned long)req->data.args[1], &sa) != 0)
                            addr_known = 0;  /* F2: fail closed on read error */
                        break;
                    default:           sa = req->data.args[1]; break; /* bind/connect */
                    }
#elif defined(__aarch64__)
                    switch (req->data.nr) {
                    case __NR_sendto:  sa = req->data.args[4]; break;
                    case __NR_sendmsg:
                        if (gate_read_u64(req->pid,
                                (unsigned long)req->data.args[1], &sa) != 0)
                            addr_known = 0;  /* F2: fail closed on read error */
                        break;
                    default:           sa = req->data.args[1]; break;
                    }
#endif
                    int fam = (int)sa ? gate_read_family(req->pid, sa) : -1;
                    int allow = 1;
                    if (!addr_known) {
                        /* F2: we could not read msg_name. We cannot tell a
                         * legitimate NULL (connected send) from a hostile
                         * unreadable pointer, so deny. */
                        allow = 0;
                    } else if ((int)sa != 0 && fam == -1) {
                        /* F2: a real sockaddr pointer whose family we could
                         * not read -> we cannot prove it is not a hostile
                         * AF_UNIX path socket. Fail closed. (A NULL sa is
                         * legitimate and stays allowed.) */
                        allow = 0;
                    } else if (fam == AF_UNIX) {
                        if ((int)sa != 0) {
                            int ab = gate_is_abstract(req->pid, sa);
                            /* F2: a read failure (ab==-1) is NOT abstract.
                             * F3: even a true abstract socket is allowed
                             * only when the netns self-check confirmed
                             * isolation; otherwise the host can reach it. */
                            if (!(abstract_ok && ab == 1))
                                allow = 0;
                        }
                        /* sa==0 (NULL addr): no name -> nothing to reach. */
                    }
                    /* fam != AF_UNIX (AF_INET, etc.) -> allow. */
                    memset(resp, 0, sz.seccomp_notif_resp);
                    resp->id = req->id;
                    if (allow)
                        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    else {
                        resp->flags = 0;
                        resp->error = -EPERM;
                        resp->val = 0;
                    }
                    (void)ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
                    continue;
                }
                const struct observe_call *oc = find_observe_call(req->data.nr);
                /* Capture while the caller is frozen (its memory, cwd and
                 * dirfds are stable), but EMIT only after the reply: the
                 * workload's pause must contain no work besides this
                 * capture — never a pipe write. */
                size_t flen[2] = { 0, 0 };
                if (oc && out_sock >= 0 &&
                    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == 0) {
                    int idxs[2]   = { oc->path_arg,  oc->path2_arg  };
                    int dirfds[2] = { oc->dirfd_arg, oc->dirfd2_arg };
                    for (int k = 0; k < 2; k++) {
                        if (idxs[k] < 0) continue;
                        char *out = k == 0 ? fbuf1 : fbuf2;
                        ssize_t l = read_remote_cstr(req->pid,
                                      (unsigned long)req->data.args[idxs[k]],
                                      pbuf, OBS_PATH_MAX);
                        if (l <= 0) continue;
                        if (pbuf[0] == '/') {
                            memcpy(out, pbuf, (size_t)l);
                            flen[k] = (size_t)l;
                            continue;
                        }
                        /* Relative: resolve against the tracee's cwd or
                         * dirfd. Unresolvable → skip (best effort). */
                        flen[k] = resolve_relative(host_proc_fd,
                                     req->pid, req, dirfds[k],
                                     pbuf, (size_t)l, out, OBS_PATH_MAX * 2);
                    }
                }
                memset(resp, 0, sz.seccomp_notif_resp);
                resp->id = req->id;
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                (void)ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
                for (int k = 0; k < 2; k++) {
                    if (flen[k] > 0) {
                        emit_event(out_sock, oc, req->data.nr, req->pid,
                                   k == 0 ? fbuf1 : fbuf2, flen[k], enc);
                    }
                }
            } else if (errno != EINTR && errno != ENOENT) {
                break;
            }
        }
        /* All filtered tasks gone → notify fd reports EOF. */
        if (pfds[0].revents & (POLLHUP | POLLERR)) break;

        if (pidfd >= 0) {
            if (pfds[1].revents) break;
        } else {
            /* WNOWAIT: leave the zombie for the caller's waitpid. */
            siginfo_t si = {0};
            if (waitid(P_PID, (id_t)child, &si, WEXITED|WNOHANG|WNOWAIT) == 0 &&
                si.si_pid == child) break;
        }
    }

    if (pidfd >= 0) close(pidfd);
    free(req); free(resp); free(pbuf); free(fbuf1); free(fbuf2);
}

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len < 0 || (size_t)len >= sizeof(buf)) {
        errno = EOVERFLOW;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t r = write(fd, buf, (size_t)len);
    int saved = errno;
    close(fd);
    if (r != len) {
        errno = (r < 0) ? saved : EIO;
        return -1;
    }
    return 0;
}

/* PID the current process forwards signals to. Used by both the outer stub
 * (forwards to inner init) and the inner init (forwards to the worker).
 * PID 1 ignores signals it has no handler for, so the inner init MUST install
 * these or SIGTERM from the outside is silently dropped. */
static volatile pid_t forward_target = -1;

static void forward_signal(int sig) {
    if (forward_target > 0) {
        kill(forward_target, sig);
    }
}

static void install_forwarders(pid_t target) {
    forward_target = target;
    struct sigaction sa = { .sa_handler = forward_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

/*
 * Wait for `main_child`, reaping any other children that exit first.
 * Returns as soon as `main_child` terminates — the caller then _exit()s,
 * which as PID 1 tears down the namespace and SIGKILLs any stragglers.
 * Returns an exit(3)-style status: exit code, or 128+signal.
 */
static int reap_until(pid_t main_child) {
    int status = 0;
    for (;;) {
        pid_t r = waitpid(-1, &status, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;  /* ECHILD without seeing main_child — shouldn't happen. */
        }
        if (r == main_child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 1;
        }
        /* Reaped an orphan that died before main_child; keep waiting. */
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    char **command_argv = &argv[1];


    /* ---- Optional observation: pre-fork setup --------------------------- */
    const char *observe_sock = getenv("SRT_OBSERVE_SOCK");
    const char *encoded_cmd  = getenv("SRT_ENCODED_CMD");
    int sp[2] = { -1, -1 };
    int wk[2] = { -1, -1 };
    if (SRT_AUDIT_ARCH != 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) < 0) {
            sp[0] = sp[1] = -1;   /* fail open */
        }
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, wk) < 0) {
            wk[0] = wk[1] = -1;   /* fail open */
        }
    }

    /* ---- New PID + mount namespaces. Children (not us) enter the PID ns. ----
     *
     * Two paths to get CAP_SYS_ADMIN for the unshare:
     *   (a) We already hold CAP_SYS_ADMIN in this user namespace. Just
     *       unshare directly. Under the sandbox we never do — bwrap is
     *       given --cap-drop ALL and at most --cap-add CAP_SETFCAP — so
     *       this path is for a standalone run by a privileged caller.
     *   (b) We don't have the cap. Create a nested user namespace to get it,
     *       map uid/gid, then unshare. This also works when apply-seccomp is
     *       run standalone outside bwrap.
     *
     * Path (a) is tried first. If we don't have the cap, the
     * kernel returns EPERM and we fall through to (b). Path (b) can itself
     * fail on hosts where unprivileged user namespaces are gated by an LSM
     * (Ubuntu 24.04's AppArmor restriction, for example) — the unshare
     * succeeds but the new namespace grants no capabilities, so the setgroups
     * write fails. In that case we abort: the caller must supply CAP_SYS_ADMIN.
     */
    /* Pinned handle to the CURRENT /proc: the worker's fresh /proc mount
     * for the new pid namespace lands in the mount namespace we are about
     * to unshare into (fork shares it), hiding host pids from the path
     * "/proc". Only used when observation is active; harmless otherwise. */
    int host_proc_fd = observe_sock && *observe_sock
        ? open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC)
        : -1;

    if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
        if (errno != EPERM) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS)");
        }

        uid_t uid = geteuid();
        gid_t gid = getegid();

        /* If this binary was exec'd without read permission (e.g. installed
         * mode 0111), the kernel marked the process non-dumpable, which
         * makes /proc/self/{setgroups,uid_map,gid_map} root-owned, so the
         * writes below would fail with EACCES. Temporarily flip dumpable
         * on for the uid/gid mapping and restore it right after. While
         * dumpable is 1, a same-uid process can ptrace us (under yama
         * ptrace_scope=0) and dump the mapped pages that mode 0111 is
         * meant to hide; the save/restore keeps that exposure to a
         * few-syscall race window — the same unavoidable window runc and
         * systemd accept for this pattern.
         *
         * prctl failures here are ignored: they are next to impossible for
         * these calls, and if raising dumpable did fail the map writes
         * below fail with their own clearer errors. */
        int dumpable = prctl(PR_GET_DUMPABLE);
        (void)prctl(PR_SET_DUMPABLE, 1);

        if (unshare(CLONE_NEWUSER) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWUSER)");
        }
        if (write_file("/proc/self/setgroups", "deny") < 0) {
            die("apply-seccomp: write /proc/self/setgroups "
                "(nested userns is capability-restricted; "
                "caller must provide CAP_SYS_ADMIN)");
        }
        if (write_file("/proc/self/uid_map", "%u %u 1\n", uid, uid) < 0) {
            die("apply-seccomp: write /proc/self/uid_map");
        }
        if (write_file("/proc/self/gid_map", "%u %u 1\n", gid, gid) < 0) {
            die("apply-seccomp: write /proc/self/gid_map");
        }
        /* PR_SET_DUMPABLE only accepts 0 or 1; if the saved value was
         * SUID_DUMP_ROOT (2) — or the read above failed — restore the more
         * restrictive 0. */
        (void)prctl(PR_SET_DUMPABLE, dumpable == 1 ? 1 : 0);
        if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns");
        }
    }

    pid_t child = fork();
    if (child < 0) {
        die("apply-seccomp: fork");
    }

    if (child > 0) {
        /* Outer stub: still in bwrap's PID namespace. Forward signals,
         * optionally service the USER_NOTIF observation fd, then relay the
         * child's exit status. Never under either seccomp filter. */
        /* sp[0] is the receiver end (we recv_fd the gate listener on it);
         * sp[1] is the sender end held by inner init. Close sp[1] here so
         * the stub never blocks waiting on the worker. */
        if (sp[1] >= 0) close(sp[1]);
        if (wk[0] >= 0) close(wk[0]);
        if (wk[1] >= 0) close(wk[1]);
        install_forwarders(child);

        if (sp[0] >= 0) {
            /* Wait for the gate listener fd. The worker hands its
             * "<nfd>\n" marker to inner init over the wk socketpair;
             * inner init pulls the fd with pidfd_getfd and ships it to
             * us here over sp (send_fd / SCM_RIGHTS). sp carries ONLY
             * that one fd — no marker or ack bytes ever arrive on sp,
             * so recv_fd sees a clean 1-byte payload + SCM fd. A 10 s
             * poll timeout prevents a dead worker from hanging the
             * stub: on timeout we close sp[0] and just waitpid. */
            struct pollfd pfd = { .fd = sp[0], .events = POLLIN };
            int pr = poll(&pfd, 1, 10000);
            if (pr <= 0) {
                close(sp[0]);
            } else {
                int child_netns = 2;
                int notify_fd = recv_fd(sp[0], &child_netns);
                close(sp[0]);
                if (notify_fd >= 0) {
                    /* The gate listener always exists; the observe socket
                     * is optional. Connect only when configured — a NULL
                     * observe_sock means gate-only mode (out stays -1 and
                     * supervise() still services the notify fd). */
                    int out = (observe_sock && *observe_sock)
                        ? connect_observe_sock(observe_sock)
                        : -1;
                    if (out < 0 && observe_sock && *observe_sock) {
                        char buf[256];
                        int n = snprintf(buf, sizeof(buf),
                            "{\"observe_init_error\":\"connect %s: %s\"}\n",
                            observe_sock, strerror(errno));
                        (void)!write(2, buf, (size_t)n);
                    } else if (encoded_cmd && *encoded_cmd) {
                        char hdr[768];
                        int n = snprintf(hdr, sizeof(hdr),
                            "{\"encodedCommand\":\"%.700s\"}\n", encoded_cmd);
                        if (n > 0) {
                            (void)!send(out, hdr, (size_t)n,
                                        MSG_DONTWAIT | MSG_NOSIGNAL);
                        }
                    }
                    /* F3: abstract sockets are safe only when the child's
                     * netns is a fresh one (only "lo" present). The child
                     * computed this (its /proc is readable; the stub's is
                     * masked) and shipped it in the send_fd dummy byte:
                     * 1 = isolated, 0 = host netns, 2 = undetermined.
                     * Only an explicit 1 allows abstract; 0 and 2 both
                     * deny (fail closed). */
                    int abstract_ok = (child_netns == 1);
                    if (!abstract_ok)
                        fprintf(stderr,
                            "apply-seccomp: child not in a fresh netns "
                            "(state=%d); denying AF_UNIX abstract sockets\n",
                            child_netns);
                    supervise(child, notify_fd, out, encoded_cmd,
                              host_proc_fd, abstract_ok);
                    if (out >= 0) close(out);
                    close(notify_fd);
                }
            }
        }

        int status;
        for (;;) {
            pid_t r = waitpid(child, &status, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) die("apply-seccomp: waitpid");
            break;
        }
        if (WIFEXITED(status)) {
            _exit(WEXITSTATUS(status));
        }
        _exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1);
    }

    /* Child side: drop the stub's sp end. Both wk ends stay open here and
     * are split by the worker fork below: inner init keeps wk[0] (the
     * handshake read/ack end), the worker keeps wk[1] (marker/ack end). */
    if (sp[0] >= 0) close(sp[0]);

    /* ================================================================
     * Inner init — PID 1 in the nested PID namespace.
     * ================================================================ */

    /* NOTE: PR_SET_DUMPABLE(0) is deferred until after the pidfd_getfd
     * handshake in the worker>0 branch. pidfd_getfd requires the caller
     * to be dumpable (kernel ≥5.6 security check). While dumpable=1 a
     * same-uid process could ptrace us for a few-syscall window — the
     * same short race the original accepted for uid_map writes. */

    /* Don't let our /proc mount propagate anywhere. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        die("apply-seccomp: mount(MS_PRIVATE)");
    }
    /* EPERM here means a masked /proc is underneath (unprivileged Docker)
     * and the kernel domination check refused the overmount. The nested
     * userns above is the isolation boundary; this remount only hides
     * outer PIDs from `ls /proc`. enableWeakerNestedSandbox targets
     * exactly this environment. */
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0
        && errno != EPERM) {
        die("apply-seccomp: mount(/proc)");
    }

    /* Drop whatever bwrap's --cap-add left in the ambient set (today at most
     * CAP_SETFCAP, which path (b) above has already spent) so it cannot
     * survive the worker's exec.
     *
     * What the worker ends up with depends on its euid. For a non-root
     * caller it execs with no capability at all: the ambient set is empty
     * and there are no file capabilities to raise. For a uid-0 caller the
     * kernel's root rule recomputes the permitted set from the bounding
     * set, which unshare(CLONE_NEWUSER) above reset to full, so the worker
     * holds a full set in the nested namespace — the ambient clear and the
     * PR_SET_NO_NEW_PRIVS the worker sets below do not change that, because
     * the worker already holds those capabilities and so gains nothing at
     * exec. Measured (Linux 6.12): capset()ing the three sets empty before
     * that exec does leave the worker with none, because it turns the root
     * rule's recompute into a gain and NO_NEW_PRIVS clamps a gain back to
     * what was held; dropping the bounding set has the same effect. Neither
     * is done here. What keeps the deny mounts in place for that worker is
     * not its capabilities but that the nested mount namespace's copies of
     * them are locked, having been created across a user-namespace
     * boundary. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_CAP_AMBIENT_CLEAR_ALL)");
    }

    /* Fork the real workload so PID 1 can stay as a non-dumpable reaper. */
    pid_t worker = fork();
    if (worker < 0) {
        die("apply-seccomp: fork(worker)");
    }

    if (worker > 0) {
        /* Inner init: handshake to grab the gate listener fd from the
         * worker via pidfd_getfd, ship it to the outer stub, then
         * defer PR_SET_DUMPABLE(0), install forwarders, and reap.
         *
         * The worker inherited a second copy of sp[1] from our fork, so
         * sp CANNOT carry worker→init traffic (a write to sp[1] delivers
         * to sp[0] = the outer stub). A dedicated wk pair does:
         *   wk[0] worker→init : "<nfd>\n" marker, or "E" on filter failure
         *   wk[0] init→worker : ack byte "A"
         *   sp[1] init→stub   : the listener fd via send_fd (SCM_RIGHTS);
         *                        sp carries ONLY that fd, never bytes.
         *
         * We stay dumpable until the handshake is done (pidfd_getfd needs
         * the caller dumpable) and drop it right after. If the worker sent
         * "E" or the timeout fires, we close sp[1] with no fd → the outer
         * stub sees EOF and fails open. */
        if (wk[1] >= 0) close(wk[1]);          /* worker's end */
        signal(SIGPIPE, SIG_IGN);              /* ack write may hit EPIPE */
        char mbuf[32];
        memset(mbuf, 0, sizeof(mbuf));
        int mlen = 0;
        if (wk[0] >= 0) {
            struct pollfd mp = { .fd = wk[0], .events = POLLIN };
            int pr = poll(&mp, 1, 10000);
            if (pr > 0) {
                mlen = (int)read(wk[0], mbuf, sizeof(mbuf) - 1);
                if (mlen <= 0) mlen = 0;
                mbuf[mlen] = '\0';
            }
        }
        int got = -1;
        int worker_alive = 0;
        if (mlen >= 1 && mbuf[0] != 'E' && mbuf[0] != '0') {
            /* Worker installed the gate and reported its listener fd number.
             * It is alive and waiting for our ack before exec. Pull the fd
             * with pidfd_getfd (needs the caller dumpable — we are, having
             * deferred PR_SET_DUMPABLE(0) to after this). */
            worker_alive = 1;
            int nfd_from_worker = atoi(mbuf);
            int pidfd = (int)syscall(__NR_pidfd_open, worker, 0);
            if (pidfd >= 0) {
                got = (int)syscall(__NR_pidfd_getfd, pidfd, nfd_from_worker, 0);
                close(pidfd);
            }
            if (got < 0 && sp[1] >= 0) {
                static const char msg[] =
                    "apply-seccomp: pidfd_getfd failed, gate unserviced\n";
                (void)!write(2, msg, sizeof(msg) - 1);
            }
        } else if (wk[0] >= 0) {
            /* "E" (filter install failed → worker already exited) or timeout
             * (worker never reported) → fail open: no gate, no listener. */
            static const char msg[] =
                "apply-seccomp: gate not installed, running without filter\n";
            (void)!write(2, msg, sizeof(msg) - 1);
        }
        int netns_isolated = gate_netns_isolated();
        if (got >= 0) {
            /* Ship the listener fd to the outer stub (SCM_RIGHTS). The
             * dummy byte also carries our netns isolation state (F3):
             * the stub's own /proc is masked, so only we can read it.
             * The worker still holds its own reference until the ack
             * below, so the listener never drops to zero. */
            if (sp[1] >= 0) (void)!send_fd(sp[1], got, netns_isolated);
            close(got);
        }
        if (worker_alive && wk[0] >= 0) {
            /* Ack the worker so it execs. If its gate is live but we could
             * not grab/service it, the trapped unix syscalls fail ENOSYS
             * (the safe side); if there is no gate, the workload runs
             * unfiltered but that is the documented fail-open. */
            (void)!write(wk[0], "A", 1);
        }
        if (sp[1] >= 0) close(sp[1]);          /* no fd → stub sees EOF */
        if (wk[0] >= 0) close(wk[0]);
        /* Now that the handshake is done, drop dumpable. */
        if (prctl(PR_SET_DUMPABLE, 0) < 0) {
            die("apply-seccomp: prctl(PR_SET_DUMPABLE)");
        }
        install_forwarders(worker);
        _exit(reap_until(worker));
    }

    /* ---- Worker (inner PID 2): install the merged gate filter and exec. ----
     *
     * Sequence (all post-NO_NEW_PRIVS, under no seccomp yet):
     *   1. Probe kernel for USER_NOTIF support (TSYNC_ESRCH trick)
     *   2. Build merged BPF (gate + optional observe) via build_gate_bpf
     *   3. Install via seccomp(SET_MODE_FILTER, NEW_LISTENER) → nfd
     *   4. Write "<nfd>\n" marker to wk[1] for inner-init's pidfd_getfd
     *   5. Poll wk[0] for the 1-byte ack "A" from inner-init
     *   6. Close both wk ends (nfd is CLOEXEC — exec drops it too)
     *   7. execvp(command_argv)
     *
     * The worker is NOT under the filter until step 3, so the marker write
     * in step 4 is safe. After step 3 the only syscalls before exec are
     * write, poll, read, close, execve — none are trapped by the gate.
     *
     * nfd is CLOEXEC, so exec auto-closes it; we close it explicitly after
     * the ack as well. The listener object itself stays alive throughout
     * because inner-init (via pidfd_getfd) and the outer stub (via
     * recv_fd) each hold their own reference, so the refcount never
     * reaches zero.
     *
     * If the filter install fails (probe / BPF build / NEW_LISTENER), we
     * write "E" to wk[1] and _exit(1): the gate is mandatory (it replaces
     * the original unix-block filter), and running without it would allow
     * path-based AF_UNIX. */
    unsetenv("SRT_OBSERVE_SOCK");
    unsetenv("SRT_ENCODED_CMD");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_NO_NEW_PRIVS)");
    }
    signal(SIGPIPE, SIG_IGN);   /* marker write may hit EPIPE if init died */
    /* sp[0] (receiver end) was closed by inner init before our fork, so
     * it is already gone here; sp[1] (sender end) is the one we inherited.
     * Close it now: we only talk to inner init over wk, and dropping sp[1]
     * lets the outer stub's recv_fd see EOF quickly if the handshake fails
     * instead of holding the pair open.
     *
     * wk is a socketpair: inner init keeps wk[0] and closed wk[1]. We keep
     * wk[1] and must close wk[0] — holding both ends would loop our own
     * marker write back at us and we would read it instead of the ack.
     * Marker: we write wk[1] → arrives at inner init's wk[0].
     * Ack:     inner init writes wk[0] → arrives at our wk[1]. */
    if (sp[1] >= 0) close(sp[1]);
    if (wk[0] >= 0) close(wk[0]);

    /* Probe for USER_NOTIF support (same trick as the original
     * install_observe_filter): if TSYNC_ESRCH is unknown, the kernel
     * is too old for NEW_LISTENER. */
    int observe_active = (observe_sock && *observe_sock) ? 1 : 0;
    if (!(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                  SECCOMP_FILTER_FLAG_TSYNC_ESRCH, NULL) == -1 &&
          errno == EFAULT)) {
        if (wk[1] >= 0) { (void)!write(wk[1], "E", 1); close(wk[1]); }
        static const char msg[] =
            "apply-seccomp: kernel too old for USER_NOTIF, aborting\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        _exit(1);
    }

    struct sock_filter filt[160];
    int len = build_gate_bpf(filt, (int)(sizeof(filt) / sizeof(filt[0])),
                             observe_active);
    if (len < 0) {
        if (wk[1] >= 0) { (void)!write(wk[1], "E", 1); close(wk[1]); }
        static const char msg[] =
            "apply-seccomp: gate BPF build failed, aborting\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        _exit(1);
    }
    struct sock_fprog prog = { .len = (unsigned short)len, .filter = filt };

    int nfd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (nfd < 0) {
        /* EINVAL: kernel <5.0. EBUSY: another listener. Either way,
         * no filter active — abort (the gate is mandatory). */
        if (wk[1] >= 0) { (void)!write(wk[1], "E", 1); close(wk[1]); }
        static const char msg[] =
            "apply-seccomp: seccomp(NEW_LISTENER) failed, aborting\n";
        (void)!write(2, msg, sizeof(msg) - 1);
        _exit(1);
    }

    /* Filter is live. Ship the listener fd number to inner-init via
     * the marker protocol on the wk channel. write() is not trapped by
     * the gate. The ack (if it never arrives) is non-fatal: the listener
     * fd survives via the init/stub references, so we exec regardless. */
    {
        char marker[16];
        int mn = snprintf(marker, sizeof(marker), "%d\n", nfd);
        if (wk[1] >= 0) (void)!write(wk[1], marker, (size_t)mn);
        if (wk[1] >= 0) {
            /* The ack "A" from inner init (sent on its wk[0]) arrives at
             * our wk[1]. */
            struct pollfd ap = { .fd = wk[1], .events = POLLIN };
            (void)poll(&ap, 1, 10000);
            char abuf;
            (void)read(wk[1], &abuf, 1);
            close(wk[1]);
        }
    }
    if (nfd >= 0) close(nfd);   /* CLOEXEC; the listener lives on via
                                  * the init/stub references. */

    execvp(command_argv[0], command_argv);
    die("apply-seccomp: execvp");
    return 1;
}
