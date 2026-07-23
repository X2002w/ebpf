#ifndef SYSCALL_NAMES_H
#define SYSCALL_NAMES_H

#include <sys/syscall.h>

// 系统调用号因架构而异（x86_64 与 ARM64 的 asm-generic 编号不同），
// 通过 __NR_* 宏在编译期取本机架构的编号，本架构不存在的调用自动跳过
static const char *syscall_names[] = {
#ifdef __NR_read
	[__NR_read] = "read",
#endif
#ifdef __NR_write
	[__NR_write] = "write",
#endif
#ifdef __NR_open
	[__NR_open] = "open",
#endif
#ifdef __NR_close
	[__NR_close] = "close",
#endif
#ifdef __NR_stat
	[__NR_stat] = "stat",
#endif
#ifdef __NR_fstat
	[__NR_fstat] = "fstat",
#endif
#ifdef __NR_lstat
	[__NR_lstat] = "lstat",
#endif
#ifdef __NR_poll
	[__NR_poll] = "poll",
#endif
#ifdef __NR_lseek
	[__NR_lseek] = "lseek",
#endif
#ifdef __NR_mmap
	[__NR_mmap] = "mmap",
#endif
#ifdef __NR_mprotect
	[__NR_mprotect] = "mprotect",
#endif
#ifdef __NR_munmap
	[__NR_munmap] = "munmap",
#endif
#ifdef __NR_brk
	[__NR_brk] = "brk",
#endif
#ifdef __NR_rt_sigaction
	[__NR_rt_sigaction] = "rt_sigaction",
#endif
#ifdef __NR_rt_sigprocmask
	[__NR_rt_sigprocmask] = "rt_sigprocmask",
#endif
#ifdef __NR_rt_sigreturn
	[__NR_rt_sigreturn] = "rt_sigreturn",
#endif
#ifdef __NR_ioctl
	[__NR_ioctl] = "ioctl",
#endif
#ifdef __NR_pread64
	[__NR_pread64] = "pread64",
#endif
#ifdef __NR_pwrite64
	[__NR_pwrite64] = "pwrite64",
#endif
#ifdef __NR_readv
	[__NR_readv] = "readv",
#endif
#ifdef __NR_writev
	[__NR_writev] = "writev",
#endif
#ifdef __NR_access
	[__NR_access] = "access",
#endif
#ifdef __NR_pipe
	[__NR_pipe] = "pipe",
#endif
#ifdef __NR_pipe2
	[__NR_pipe2] = "pipe2",
#endif
#ifdef __NR_select
	[__NR_select] = "select",
#endif
#ifdef __NR_sched_yield
	[__NR_sched_yield] = "sched_yield",
#endif
#ifdef __NR_mremap
	[__NR_mremap] = "mremap",
#endif
#ifdef __NR_mincore
	[__NR_mincore] = "mincore",
#endif
#ifdef __NR_madvise
	[__NR_madvise] = "madvise",
#endif
#ifdef __NR_shmget
	[__NR_shmget] = "shmget",
#endif
#ifdef __NR_shmat
	[__NR_shmat] = "shmat",
#endif
#ifdef __NR_dup
	[__NR_dup] = "dup",
#endif
#ifdef __NR_dup2
	[__NR_dup2] = "dup2",
#endif
#ifdef __NR_dup3
	[__NR_dup3] = "dup3",
#endif
#ifdef __NR_nanosleep
	[__NR_nanosleep] = "nanosleep",
#endif
#ifdef __NR_getpid
	[__NR_getpid] = "getpid",
#endif
#ifdef __NR_socket
	[__NR_socket] = "socket",
#endif
#ifdef __NR_connect
	[__NR_connect] = "connect",
#endif
#ifdef __NR_accept
	[__NR_accept] = "accept",
#endif
#ifdef __NR_accept4
	[__NR_accept4] = "accept4",
#endif
#ifdef __NR_sendto
	[__NR_sendto] = "sendto",
#endif
#ifdef __NR_recvfrom
	[__NR_recvfrom] = "recvfrom",
#endif
#ifdef __NR_sendmsg
	[__NR_sendmsg] = "sendmsg",
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg] = "recvmsg",
#endif
#ifdef __NR_bind
	[__NR_bind] = "bind",
#endif
#ifdef __NR_listen
	[__NR_listen] = "listen",
#endif
#ifdef __NR_getsockname
	[__NR_getsockname] = "getsockname",
#endif
#ifdef __NR_setsockopt
	[__NR_setsockopt] = "setsockopt",
#endif
#ifdef __NR_getsockopt
	[__NR_getsockopt] = "getsockopt",
#endif
#ifdef __NR_clone
	[__NR_clone] = "clone",
#endif
#ifdef __NR_fork
	[__NR_fork] = "fork",
#endif
#ifdef __NR_execve
	[__NR_execve] = "execve",
#endif
#ifdef __NR_exit
	[__NR_exit] = "exit",
#endif
#ifdef __NR_wait4
	[__NR_wait4] = "wait4",
#endif
#ifdef __NR_kill
	[__NR_kill] = "kill",
#endif
#ifdef __NR_fcntl
	[__NR_fcntl] = "fcntl",
#endif
#ifdef __NR_flock
	[__NR_flock] = "flock",
#endif
#ifdef __NR_fsync
	[__NR_fsync] = "fsync",
#endif
#ifdef __NR_fdatasync
	[__NR_fdatasync] = "fdatasync",
#endif
#ifdef __NR_getdents
	[__NR_getdents] = "getdents",
#endif
#ifdef __NR_getdents64
	[__NR_getdents64] = "getdents64",
#endif
#ifdef __NR_getcwd
	[__NR_getcwd] = "getcwd",
#endif
#ifdef __NR_chdir
	[__NR_chdir] = "chdir",
#endif
#ifdef __NR_rename
	[__NR_rename] = "rename",
#endif
#ifdef __NR_mkdir
	[__NR_mkdir] = "mkdir",
#endif
#ifdef __NR_mkdirat
	[__NR_mkdirat] = "mkdirat",
#endif
#ifdef __NR_rmdir
	[__NR_rmdir] = "rmdir",
#endif
#ifdef __NR_creat
	[__NR_creat] = "creat",
#endif
#ifdef __NR_unlink
	[__NR_unlink] = "unlink",
#endif
#ifdef __NR_gettimeofday
	[__NR_gettimeofday] = "gettimeofday",
#endif
#ifdef __NR_getrlimit
	[__NR_getrlimit] = "getrlimit",
#endif
#ifdef __NR_getuid
	[__NR_getuid] = "getuid",
#endif
#ifdef __NR_getgid
	[__NR_getgid] = "getgid",
#endif
#ifdef __NR_sigaltstack
	[__NR_sigaltstack] = "sigaltstack",
#endif
#ifdef __NR_statfs
	[__NR_statfs] = "statfs",
#endif
#ifdef __NR_prctl
	[__NR_prctl] = "prctl",
#endif
#ifdef __NR_arch_prctl
	[__NR_arch_prctl] = "arch_prctl",
#endif
#ifdef __NR_setrlimit
	[__NR_setrlimit] = "setrlimit",
#endif
#ifdef __NR_mount
	[__NR_mount] = "mount",
#endif
#ifdef __NR_gettid
	[__NR_gettid] = "gettid",
#endif
#ifdef __NR_futex
	[__NR_futex] = "futex",
#endif
#ifdef __NR_sched_setaffinity
	[__NR_sched_setaffinity] = "sched_setaffinity",
#endif
#ifdef __NR_sched_getaffinity
	[__NR_sched_getaffinity] = "sched_getaffinity",
#endif
#ifdef __NR_epoll_create
	[__NR_epoll_create] = "epoll_create",
#endif
#ifdef __NR_epoll_create1
	[__NR_epoll_create1] = "epoll_create1",
#endif
#ifdef __NR_clock_gettime
	[__NR_clock_gettime] = "clock_gettime",
#endif
#ifdef __NR_clock_getres
	[__NR_clock_getres] = "clock_getres",
#endif
#ifdef __NR_clock_nanosleep
	[__NR_clock_nanosleep] = "clock_nanosleep",
#endif
#ifdef __NR_exit_group
	[__NR_exit_group] = "exit_group",
#endif
#ifdef __NR_epoll_wait
	[__NR_epoll_wait] = "epoll_wait",
#endif
#ifdef __NR_epoll_ctl
	[__NR_epoll_ctl] = "epoll_ctl",
#endif
#ifdef __NR_epoll_pwait
	[__NR_epoll_pwait] = "epoll_pwait",
#endif
#ifdef __NR_epoll_pwait2
	[__NR_epoll_pwait2] = "epoll_pwait2",
#endif
#ifdef __NR_tgkill
	[__NR_tgkill] = "tgkill",
#endif
#ifdef __NR_openat
	[__NR_openat] = "openat",
#endif
#ifdef __NR_openat2
	[__NR_openat2] = "openat2",
#endif
#ifdef __NR_newfstatat
	[__NR_newfstatat] = "newfstatat",
#endif
#ifdef __NR_unlinkat
	[__NR_unlinkat] = "unlinkat",
#endif
#ifdef __NR_renameat
	[__NR_renameat] = "renameat",
#endif
#ifdef __NR_renameat2
	[__NR_renameat2] = "renameat2",
#endif
#ifdef __NR_linkat
	[__NR_linkat] = "linkat",
#endif
#ifdef __NR_readlinkat
	[__NR_readlinkat] = "readlinkat",
#endif
#ifdef __NR_faccessat
	[__NR_faccessat] = "faccessat",
#endif
#ifdef __NR_faccessat2
	[__NR_faccessat2] = "faccessat2",
#endif
#ifdef __NR_pselect6
	[__NR_pselect6] = "pselect6",
#endif
#ifdef __NR_ppoll
	[__NR_ppoll] = "ppoll",
#endif
#ifdef __NR_set_robust_list
	[__NR_set_robust_list] = "set_robust_list",
#endif
#ifdef __NR_eventfd
	[__NR_eventfd] = "eventfd",
#endif
#ifdef __NR_eventfd2
	[__NR_eventfd2] = "eventfd2",
#endif
#ifdef __NR_fallocate
	[__NR_fallocate] = "fallocate",
#endif
#ifdef __NR_perf_event_open
	[__NR_perf_event_open] = "perf_event_open",
#endif
#ifdef __NR_prlimit64
	[__NR_prlimit64] = "prlimit64",
#endif
#ifdef __NR_sched_setattr
	[__NR_sched_setattr] = "sched_setattr",
#endif
#ifdef __NR_getrandom
	[__NR_getrandom] = "getrandom",
#endif
#ifdef __NR_memfd_create
	[__NR_memfd_create] = "memfd_create",
#endif
#ifdef __NR_bpf
	[__NR_bpf] = "bpf",
#endif
#ifdef __NR_execveat
	[__NR_execveat] = "execveat",
#endif
#ifdef __NR_statx
	[__NR_statx] = "statx",
#endif
#ifdef __NR_rseq
	[__NR_rseq] = "rseq",
#endif
#ifdef __NR_io_uring_setup
	[__NR_io_uring_setup] = "io_uring_setup",
#endif
#ifdef __NR_io_uring_enter
	[__NR_io_uring_enter] = "io_uring_enter",
#endif
#ifdef __NR_clone3
	[__NR_clone3] = "clone3",
#endif
#ifdef __NR_close_range
	[__NR_close_range] = "close_range",
#endif
#ifdef __NR_pidfd_getfd
	[__NR_pidfd_getfd] = "pidfd_getfd",
#endif
#ifdef __NR_process_madvise
	[__NR_process_madvise] = "process_madvise",
#endif
};

#endif
