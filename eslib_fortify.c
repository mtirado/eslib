/* (c) 2017 Michael R. Tirado -- GPLv3+, GNU General Public License, version 3 or later
 * contact: mtirado418@gmail.com
 *
 */

#define _GNU_SOURCE
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sched.h>
#include <unistd.h>

#include <malloc.h>
#include <memory.h>
#include <errno.h>

#include <sys/syscall.h>
#include "eslib.h"
#include "eslib_fortify.h"

extern int capset(cap_user_header_t header, cap_user_data_t data);

/* look for system-wide blacklist in this order */
#define MAX_BLACKLISTS 3
char *g_blacklist_files[MAX_BLACKLISTS] = {
	"/etc/eslib/seccomp_blacklist",
	"/etc/jettison/blacklist",
	NULL
};

/* translate config file strings to syscall number */
struct sc_translate
{
	char name[MAX_SYSCALL_NAME];
	int  nr;
};

struct cap_translate
{
	char name[MAX_CAP_NAME];
	int  nr;
};

struct cap_translate cap_table[] = {
{"CAP_CHOWN", CAP_CHOWN },
{"CAP_DAC_OVERRIDE", CAP_DAC_OVERRIDE },
{"CAP_DAC_READ_SEARCH", CAP_DAC_READ_SEARCH },
{"CAP_FOWNER", CAP_FOWNER },
{"CAP_FSETID", CAP_FSETID },
{"CAP_KILL", CAP_KILL },
{"CAP_SETGID", CAP_SETGID },
{"CAP_SETUID", CAP_SETUID },
{"CAP_SETPCAP", CAP_SETPCAP },
{"CAP_LINUX_IMMUTABLE", CAP_LINUX_IMMUTABLE },
{"CAP_NET_BIND_SERVICE", CAP_NET_BIND_SERVICE },
{"CAP_NET_BROADCAST", CAP_NET_BROADCAST },
{"CAP_NET_ADMIN", CAP_NET_ADMIN },
{"CAP_NET_RAW", CAP_NET_RAW },
{"CAP_IPC_LOCK", CAP_IPC_LOCK },
{"CAP_IPC_OWNER", CAP_IPC_OWNER },
{"CAP_SYS_MODULE", CAP_SYS_MODULE },
{"CAP_SYS_RAWIO", CAP_SYS_RAWIO },
{"CAP_SYS_CHROOT", CAP_SYS_CHROOT },
{"CAP_SYS_PTRACE", CAP_SYS_PTRACE },
{"CAP_SYS_PACCT", CAP_SYS_PACCT },
{"CAP_SYS_ADMIN", CAP_SYS_ADMIN },
{"CAP_SYS_BOOT", CAP_SYS_BOOT },
{"CAP_SYS_NICE", CAP_SYS_NICE },
{"CAP_SYS_RESOURCE", CAP_SYS_RESOURCE },
{"CAP_SYS_TIME", CAP_SYS_TIME },
{"CAP_SYS_TTY_CONFIG", CAP_SYS_TTY_CONFIG },
{"CAP_MKNOD", CAP_MKNOD },
{"CAP_LEASE", CAP_LEASE },
{"CAP_AUDIT_WRITE", CAP_AUDIT_WRITE },
{"CAP_AUDIT_CONTROL", CAP_AUDIT_CONTROL },
{"CAP_SETFCAP", CAP_SETFCAP },
{"CAP_MAC_OVERRIDE", CAP_MAC_OVERRIDE },
{"CAP_MAC_ADMIN", CAP_MAC_ADMIN },
{"CAP_SYSLOG", CAP_SYSLOG },
{"CAP_WAKE_ALARM", CAP_WAKE_ALARM },
{"CAP_BLOCK_SUSPEND", CAP_BLOCK_SUSPEND },
/*{"CAP_AUDIT_READ", CAP_AUDIT_READ },*/
};

/* TODO
 * there may be system calls missing if you're on a newer kernel.
 * if on an older kernel, you may need to comment out some syscalls.
 *
 * it would be a real pain to fill out, but expecting a kernel version #defined
 * and using #if check would work better than manually adjusting these arrays.
 *
 * version: 4.1
 */
struct sc_translate sc_table[] = {
{ "__NR_restart_syscall", __NR_restart_syscall },
{ "__NR_exit", __NR_exit },
{ "__NR_fork", __NR_fork },
{ "__NR_read", __NR_read },
{ "__NR_write", __NR_write },
{ "__NR_open", __NR_open },
{ "__NR_close", __NR_close },
{ "__NR_waitpid", __NR_waitpid },
{ "__NR_creat", __NR_creat },
{ "__NR_link", __NR_link },
{ "__NR_unlink", __NR_unlink },
{ "__NR_execve", __NR_execve },
{ "__NR_chdir", __NR_chdir },
{ "__NR_time", __NR_time },
{ "__NR_mknod", __NR_mknod },
{ "__NR_chmod", __NR_chmod },
{ "__NR_lchown", __NR_lchown },
{ "__NR_break", __NR_break },
{ "__NR_oldstat", __NR_oldstat },
{ "__NR_lseek", __NR_lseek },
{ "__NR_getpid", __NR_getpid },
{ "__NR_mount", __NR_mount },
{ "__NR_umount", __NR_umount },
{ "__NR_setuid", __NR_setuid },
{ "__NR_getuid", __NR_getuid },
{ "__NR_stime", __NR_stime },
{ "__NR_ptrace", __NR_ptrace },
{ "__NR_alarm", __NR_alarm },
{ "__NR_oldfstat", __NR_oldfstat },
{ "__NR_pause", __NR_pause },
{ "__NR_utime", __NR_utime },
{ "__NR_stty", __NR_stty },
{ "__NR_gtty", __NR_gtty },
{ "__NR_access", __NR_access },
{ "__NR_nice", __NR_nice },
{ "__NR_ftime", __NR_ftime },
{ "__NR_sync", __NR_sync },
{ "__NR_kill", __NR_kill },
{ "__NR_rename", __NR_rename },
{ "__NR_mkdir", __NR_mkdir },
{ "__NR_rmdir", __NR_rmdir },
{ "__NR_dup", __NR_dup },
{ "__NR_pipe", __NR_pipe },
{ "__NR_times", __NR_times },
{ "__NR_prof", __NR_prof },
{ "__NR_brk", __NR_brk },
{ "__NR_setgid", __NR_setgid },
{ "__NR_getgid", __NR_getgid },
{ "__NR_signal", __NR_signal },
{ "__NR_geteuid", __NR_geteuid },
{ "__NR_getegid", __NR_getegid },
{ "__NR_acct", __NR_acct },
{ "__NR_umount2", __NR_umount2 },
{ "__NR_lock", __NR_lock },
{ "__NR_ioctl", __NR_ioctl },
{ "__NR_fcntl", __NR_fcntl },
{ "__NR_mpx", __NR_mpx },
{ "__NR_setpgid", __NR_setpgid },
{ "__NR_ulimit", __NR_ulimit },
{ "__NR_oldolduname", __NR_oldolduname },
{ "__NR_umask", __NR_umask },
{ "__NR_chroot", __NR_chroot },
{ "__NR_ustat", __NR_ustat },
{ "__NR_dup2", __NR_dup2 },
{ "__NR_getppid", __NR_getppid },
{ "__NR_getpgrp", __NR_getpgrp },
{ "__NR_setsid", __NR_setsid },
{ "__NR_sigaction", __NR_sigaction },
{ "__NR_sgetmask", __NR_sgetmask },
{ "__NR_ssetmask", __NR_ssetmask },
{ "__NR_setreuid", __NR_setreuid },
{ "__NR_setregid", __NR_setregid },
{ "__NR_sigsuspend", __NR_sigsuspend },
{ "__NR_sigpending", __NR_sigpending },
{ "__NR_sethostname", __NR_sethostname },
{ "__NR_setrlimit", __NR_setrlimit },
{ "__NR_getrlimit", __NR_getrlimit },
{ "__NR_getrusage", __NR_getrusage },
{ "__NR_gettimeofday", __NR_gettimeofday },
{ "__NR_settimeofday", __NR_settimeofday },
{ "__NR_getgroups", __NR_getgroups },
{ "__NR_setgroups", __NR_setgroups },
{ "__NR_select", __NR_select },
{ "__NR_symlink", __NR_symlink },
{ "__NR_oldlstat", __NR_oldlstat },
{ "__NR_readlink", __NR_readlink },
{ "__NR_uselib", __NR_uselib },
{ "__NR_swapon", __NR_swapon },
{ "__NR_reboot", __NR_reboot },
{ "__NR_readdir", __NR_readdir },
{ "__NR_mmap", __NR_mmap },
{ "__NR_munmap", __NR_munmap },
{ "__NR_truncate", __NR_truncate },
{ "__NR_ftruncate", __NR_ftruncate },
{ "__NR_fchmod", __NR_fchmod },
{ "__NR_fchown", __NR_fchown },
{ "__NR_getpriority", __NR_getpriority },
{ "__NR_setpriority", __NR_setpriority },
{ "__NR_profil", __NR_profil },
{ "__NR_statfs", __NR_statfs },
{ "__NR_fstatfs", __NR_fstatfs },
{ "__NR_ioperm", __NR_ioperm },
{ "__NR_socketcall", __NR_socketcall },
{ "__NR_syslog", __NR_syslog },
{ "__NR_setitimer", __NR_setitimer },
{ "__NR_getitimer", __NR_getitimer },
{ "__NR_stat", __NR_stat },
{ "__NR_lstat", __NR_lstat },
{ "__NR_fstat", __NR_fstat },
{ "__NR_olduname", __NR_olduname },
{ "__NR_iopl", __NR_iopl },
{ "__NR_vhangup", __NR_vhangup },
{ "__NR_idle", __NR_idle },
{ "__NR_vm86old", __NR_vm86old },
{ "__NR_wait4", __NR_wait4 },
{ "__NR_swapoff", __NR_swapoff },
{ "__NR_sysinfo", __NR_sysinfo },
{ "__NR_ipc", __NR_ipc },
{ "__NR_fsync", __NR_fsync },
{ "__NR_sigreturn", __NR_sigreturn },
{ "__NR_clone", __NR_clone },
{ "__NR_setdomainname", __NR_setdomainname },
{ "__NR_uname", __NR_uname },
{ "__NR_modify_ldt", __NR_modify_ldt },
{ "__NR_adjtimex", __NR_adjtimex },
{ "__NR_mprotect", __NR_mprotect },
{ "__NR_sigprocmask", __NR_sigprocmask },
{ "__NR_create_module", __NR_create_module },
{ "__NR_init_module", __NR_init_module },
{ "__NR_delete_module", __NR_delete_module },
{ "__NR_get_kernel_syms", __NR_get_kernel_syms },
{ "__NR_quotactl", __NR_quotactl },
{ "__NR_getpgid", __NR_getpgid },
{ "__NR_fchdir", __NR_fchdir },
{ "__NR_bdflush", __NR_bdflush },
{ "__NR_sysfs", __NR_sysfs },
{ "__NR_personality", __NR_personality },
{ "__NR_afs_syscall", __NR_afs_syscall },
{ "__NR_setfsuid", __NR_setfsuid },
{ "__NR_setfsgid", __NR_setfsgid },
{ "__NR__llseek", __NR__llseek },
{ "__NR_getdents", __NR_getdents },
{ "__NR__newselect", __NR__newselect },
{ "__NR_flock", __NR_flock },
{ "__NR_msync", __NR_msync },
{ "__NR_readv", __NR_readv },
{ "__NR_writev", __NR_writev },
{ "__NR_getsid", __NR_getsid },
{ "__NR_fdatasync", __NR_fdatasync },
{ "__NR__sysctl", __NR__sysctl },
{ "__NR_mlock", __NR_mlock },
{ "__NR_munlock", __NR_munlock },
{ "__NR_mlockall", __NR_mlockall },
{ "__NR_munlockall", __NR_munlockall },
{ "__NR_sched_setparam", __NR_sched_setparam },
{ "__NR_sched_getparam", __NR_sched_getparam },
{ "__NR_sched_setscheduler", __NR_sched_setscheduler },
{ "__NR_sched_getscheduler", __NR_sched_getscheduler },
{ "__NR_sched_yield", __NR_sched_yield },
{ "__NR_sched_get_priority_max", __NR_sched_get_priority_max },
{ "__NR_sched_get_priority_min", __NR_sched_get_priority_min },
{ "__NR_sched_rr_get_interval", __NR_sched_rr_get_interval },
{ "__NR_nanosleep", __NR_nanosleep },
{ "__NR_mremap", __NR_mremap },
{ "__NR_setresuid", __NR_setresuid },
{ "__NR_getresuid", __NR_getresuid },
{ "__NR_vm86", __NR_vm86 },
{ "__NR_query_module", __NR_query_module },
{ "__NR_poll", __NR_poll },
{ "__NR_nfsservctl", __NR_nfsservctl },
{ "__NR_setresgid", __NR_setresgid },
{ "__NR_getresgid", __NR_getresgid },
{ "__NR_prctl", __NR_prctl },
{ "__NR_rt_sigreturn", __NR_rt_sigreturn },
{ "__NR_rt_sigaction", __NR_rt_sigaction },
{ "__NR_rt_sigprocmask", __NR_rt_sigprocmask },
{ "__NR_rt_sigpending", __NR_rt_sigpending },
{ "__NR_rt_sigtimedwait", __NR_rt_sigtimedwait },
{ "__NR_rt_sigqueueinfo", __NR_rt_sigqueueinfo },
{ "__NR_rt_sigsuspend", __NR_rt_sigsuspend },
{ "__NR_pread64", __NR_pread64 },
{ "__NR_pwrite64", __NR_pwrite64 },
{ "__NR_chown", __NR_chown },
{ "__NR_getcwd", __NR_getcwd },
{ "__NR_capget", __NR_capget },
{ "__NR_capset", __NR_capset },
{ "__NR_sigaltstack", __NR_sigaltstack },
{ "__NR_sendfile", __NR_sendfile },
{ "__NR_getpmsg", __NR_getpmsg },
{ "__NR_putpmsg", __NR_putpmsg },
{ "__NR_vfork", __NR_vfork },
{ "__NR_ugetrlimit", __NR_ugetrlimit },
{ "__NR_mmap2", __NR_mmap2 },
{ "__NR_truncate64", __NR_truncate64 },
{ "__NR_ftruncate64", __NR_ftruncate64 },
{ "__NR_stat64", __NR_stat64 },
{ "__NR_lstat64", __NR_lstat64 },
{ "__NR_fstat64", __NR_fstat64 },
{ "__NR_lchown32", __NR_lchown32 },
{ "__NR_getuid32", __NR_getuid32 },
{ "__NR_getgid32", __NR_getgid32 },
{ "__NR_geteuid32", __NR_geteuid32 },
{ "__NR_getegid32", __NR_getegid32 },
{ "__NR_setreuid32", __NR_setreuid32 },
{ "__NR_setregid32", __NR_setregid32 },
{ "__NR_getgroups32", __NR_getgroups32 },
{ "__NR_setgroups32", __NR_setgroups32 },
{ "__NR_fchown32", __NR_fchown32 },
{ "__NR_setresuid32", __NR_setresuid32 },
{ "__NR_getresuid32", __NR_getresuid32 },
{ "__NR_setresgid32", __NR_setresgid32 },
{ "__NR_getresgid32", __NR_getresgid32 },
{ "__NR_chown32", __NR_chown32 },
{ "__NR_setuid32", __NR_setuid32 },
{ "__NR_setgid32", __NR_setgid32 },
{ "__NR_setfsuid32", __NR_setfsuid32 },
{ "__NR_setfsgid32", __NR_setfsgid32 },
{ "__NR_pivot_root", __NR_pivot_root },
{ "__NR_mincore", __NR_mincore },
{ "__NR_madvise", __NR_madvise },
{ "__NR_getdents64", __NR_getdents64 },
{ "__NR_fcntl64", __NR_fcntl64 },
{ "__NR_gettid", __NR_gettid },
{ "__NR_readahead", __NR_readahead },
{ "__NR_setxattr", __NR_setxattr },
{ "__NR_lsetxattr", __NR_lsetxattr },
{ "__NR_fsetxattr", __NR_fsetxattr },
{ "__NR_getxattr", __NR_getxattr },
{ "__NR_lgetxattr", __NR_lgetxattr },
{ "__NR_fgetxattr", __NR_fgetxattr },
{ "__NR_listxattr", __NR_listxattr },
{ "__NR_llistxattr", __NR_llistxattr },
{ "__NR_flistxattr", __NR_flistxattr },
{ "__NR_removexattr", __NR_removexattr },
{ "__NR_lremovexattr", __NR_lremovexattr },
{ "__NR_fremovexattr", __NR_fremovexattr },
{ "__NR_tkill", __NR_tkill },
{ "__NR_sendfile64", __NR_sendfile64 },
{ "__NR_futex", __NR_futex },
{ "__NR_sched_setaffinity", __NR_sched_setaffinity },
{ "__NR_sched_getaffinity", __NR_sched_getaffinity },
{ "__NR_set_thread_area", __NR_set_thread_area },
{ "__NR_get_thread_area", __NR_get_thread_area },
{ "__NR_io_setup", __NR_io_setup },
{ "__NR_io_destroy", __NR_io_destroy },
{ "__NR_io_getevents", __NR_io_getevents },
{ "__NR_io_submit", __NR_io_submit },
{ "__NR_io_cancel", __NR_io_cancel },
{ "__NR_fadvise64", __NR_fadvise64 },
{ "__NR_exit_group", __NR_exit_group },
{ "__NR_lookup_dcookie", __NR_lookup_dcookie },
{ "__NR_epoll_create", __NR_epoll_create },
{ "__NR_epoll_ctl", __NR_epoll_ctl },
{ "__NR_epoll_wait", __NR_epoll_wait },
{ "__NR_remap_file_pages", __NR_remap_file_pages },
{ "__NR_set_tid_address", __NR_set_tid_address },
{ "__NR_timer_create", __NR_timer_create },
{ "__NR_timer_settime", __NR_timer_settime },
{ "__NR_timer_gettime", __NR_timer_gettime },
{ "__NR_timer_getoverrun", __NR_timer_getoverrun },
{ "__NR_timer_delete", __NR_timer_delete },
{ "__NR_clock_settime", __NR_clock_settime },
{ "__NR_clock_gettime", __NR_clock_gettime },
{ "__NR_clock_getres", __NR_clock_getres },
{ "__NR_clock_nanosleep", __NR_clock_nanosleep },
{ "__NR_statfs64", __NR_statfs64 },
{ "__NR_fstatfs64", __NR_fstatfs64 },
{ "__NR_tgkill", __NR_tgkill },
{ "__NR_utimes", __NR_utimes },
{ "__NR_fadvise64_64", __NR_fadvise64_64 },
{ "__NR_vserver", __NR_vserver },
{ "__NR_mbind", __NR_mbind },
{ "__NR_get_mempolicy", __NR_get_mempolicy },
{ "__NR_set_mempolicy", __NR_set_mempolicy },
{ "__NR_mq_open", __NR_mq_open },
{ "__NR_mq_unlink", __NR_mq_unlink },
{ "__NR_mq_timedsend", __NR_mq_timedsend },
{ "__NR_mq_timedreceive", __NR_mq_timedreceive },
{ "__NR_mq_notify", __NR_mq_notify },
{ "__NR_mq_getsetattr", __NR_mq_getsetattr },
{ "__NR_kexec_load", __NR_kexec_load },
{ "__NR_waitid", __NR_waitid },
{ "__NR_add_key", __NR_add_key },
{ "__NR_request_key", __NR_request_key },
{ "__NR_keyctl", __NR_keyctl },
{ "__NR_ioprio_set", __NR_ioprio_set },
{ "__NR_ioprio_get", __NR_ioprio_get },
{ "__NR_inotify_init", __NR_inotify_init },
{ "__NR_inotify_add_watch", __NR_inotify_add_watch },
{ "__NR_inotify_rm_watch", __NR_inotify_rm_watch },
{ "__NR_migrate_pages", __NR_migrate_pages },
{ "__NR_openat", __NR_openat },
{ "__NR_mkdirat", __NR_mkdirat },
{ "__NR_mknodat", __NR_mknodat },
{ "__NR_fchownat", __NR_fchownat },
{ "__NR_futimesat", __NR_futimesat },
{ "__NR_fstatat64", __NR_fstatat64 },
{ "__NR_unlinkat", __NR_unlinkat },
{ "__NR_renameat", __NR_renameat },
{ "__NR_linkat", __NR_linkat },
{ "__NR_symlinkat", __NR_symlinkat },
{ "__NR_readlinkat", __NR_readlinkat },
{ "__NR_fchmodat", __NR_fchmodat },
{ "__NR_faccessat", __NR_faccessat },
{ "__NR_pselect6", __NR_pselect6 },
{ "__NR_ppoll", __NR_ppoll },
{ "__NR_unshare", __NR_unshare },
{ "__NR_set_robust_list", __NR_set_robust_list },
{ "__NR_get_robust_list", __NR_get_robust_list },
{ "__NR_splice", __NR_splice },
{ "__NR_sync_file_range", __NR_sync_file_range },
{ "__NR_tee", __NR_tee },
{ "__NR_vmsplice", __NR_vmsplice },
{ "__NR_move_pages", __NR_move_pages },
{ "__NR_getcpu", __NR_getcpu },
{ "__NR_epoll_pwait", __NR_epoll_pwait },
{ "__NR_utimensat", __NR_utimensat },
{ "__NR_signalfd", __NR_signalfd },
{ "__NR_timerfd_create", __NR_timerfd_create },
{ "__NR_eventfd", __NR_eventfd },
{ "__NR_fallocate", __NR_fallocate },
{ "__NR_timerfd_settime", __NR_timerfd_settime },
{ "__NR_timerfd_gettime", __NR_timerfd_gettime },
{ "__NR_signalfd4", __NR_signalfd4 },
{ "__NR_eventfd2", __NR_eventfd2 },
{ "__NR_epoll_create1", __NR_epoll_create1 },
{ "__NR_dup3", __NR_dup3 },
{ "__NR_pipe2", __NR_pipe2 },
{ "__NR_inotify_init1", __NR_inotify_init1 },
{ "__NR_preadv", __NR_preadv },
{ "__NR_pwritev", __NR_pwritev },
{ "__NR_rt_tgsigqueueinfo", __NR_rt_tgsigqueueinfo },
{ "__NR_perf_event_open", __NR_perf_event_open },
{ "__NR_recvmmsg", __NR_recvmmsg },
{ "__NR_fanotify_init", __NR_fanotify_init },
{ "__NR_fanotify_mark", __NR_fanotify_mark },
{ "__NR_prlimit64", __NR_prlimit64 },
{ "__NR_name_to_handle_at", __NR_name_to_handle_at },
{ "__NR_open_by_handle_at", __NR_open_by_handle_at },
{ "__NR_clock_adjtime", __NR_clock_adjtime },
{ "__NR_syncfs", __NR_syncfs },
{ "__NR_sendmmsg", __NR_sendmmsg },
{ "__NR_setns", __NR_setns },
{ "__NR_process_vm_readv", __NR_process_vm_readv },
{ "__NR_process_vm_writev", __NR_process_vm_writev },
{ "__NR_kcmp", __NR_kcmp },
{ "__NR_finit_module", __NR_finit_module },
/* 3.10 */

/* 4.1 */
/*{ "__NR_sched_setattr", __NR_sched_setattr },
{ "__NR_sched_getattr", __NR_sched_getattr },
{ "__NR_renameat2", __NR_renameat2 },
{ "__NR_seccomp", __NR_seccomp },
{ "__NR_getrandom", __NR_getrandom },
{ "__NR_memfd_create", __NR_memfd_create },
{ "__NR_bpf", __NR_bpf },
{ "__NR_execveat", __NR_execveat },
*/

/* 4.3
 * fine grained socket calls,
 * TODO warning if socketcall is whitelisted with these enabled
 */
/*{ "__NR_socket", __NR_socket },
{ "__NR_socketpair", __NR_socketpair },
{ "__NR_bind", __NR_bind },
{ "__NR_connect", __NR_connect },
{ "__NR_listen", __NR_listen },
{ "__NR_accept4", __NR_accept4 },
{ "__NR_getsockopt", __NR_getsockopt },
{ "__NR_setsockopt", __NR_setsockopt },
{ "__NR_getsockname", __NR_getsockname },
{ "__NR_getpeername", __NR_getpeername },
{ "__NR_sendto", __NR_sendto },
{ "__NR_sendmsg", __NR_sendmsg },
{ "__NR_recvfrom", __NR_recvfrom },
{ "__NR_recvmsg", __NR_recvmsg },
{ "__NR_shutdown", __NR_shutdown },
{ "__NR_userfaultfd", __NR_userfaultfd },
{ "__NR_membarrier", __NR_membarrier },
TODO update this, lol
*/
};

unsigned int syscall_tablesize()
{
	return (sizeof(sc_table) / sizeof(struct sc_translate));
}

unsigned int syscall_gethighest()
{
	const unsigned int count = sizeof(sc_table) / sizeof(struct sc_translate);
	unsigned int i;
	int high = 0;
	for (i = 0; i < count; ++i)
	{
		if (sc_table[i].nr > high)
			high = sc_table[i].nr;
	}
	return high;
}

void syscall_printknown()
{
	const unsigned int count = sizeof(sc_table) / sizeof(struct sc_translate);
	unsigned int i;
	if (count > MAX_SYSCALLS) {
		printf("error, system call table too big!\n");
		return;
	}
	printf("-----------------------------------------------------\n");
	printf("known system calls: \n");
	printf("-----------------------------------------------------\n");
	for (i = 0; i < sizeof(sc_table)/sizeof(struct sc_translate); ++i)
	{
		printf("%d\t%s\n", sc_table[i].nr, sc_table[i].name);
	}
}

int syscall_getnum(char *defstring)
{
	const unsigned int count = sizeof(sc_table) / sizeof(struct sc_translate);
	unsigned int i;
	char buf[MAX_SYSCALL_NAME];

	if (!defstring || count > MAX_SYSCALLS)
		return -1;

	strncpy(buf, defstring, MAX_SYSCALL_NAME-1);
	buf[MAX_SYSCALL_NAME-1] = '\0';
	for (i = 0; i < count; ++i)
	{
		if (strncmp(buf, sc_table[i].name, MAX_SYSCALL_NAME) == 0)
			return sc_table[i].nr;
	}
	return -1;
}

char *syscall_getname(long syscall_nr)
{
	const unsigned int  count = sizeof(sc_table) / sizeof(struct sc_translate);
	unsigned int i;

	if (syscall_nr < 0 || count > MAX_SYSCALLS)
		return NULL;

	for (i = 0; i < count; ++i)
	{
		if (sc_table[i].nr == syscall_nr)
			return sc_table[i].name;
	}
	return NULL;
}

unsigned int count_syscalls(int *syscalls, unsigned int maxcount)
{
	unsigned int i;

	if (!syscalls || maxcount > MAX_SYSCALLS)
		return 0;

	for (i = 0; i < maxcount; ++i)
	{
		if (syscalls[i] == -1)
			return i;
	}
	return maxcount;
}

int cap_getnum(char *defstring)
{
	const unsigned int count = sizeof(cap_table) / sizeof(struct cap_translate);
	unsigned int i;
	char buf[MAX_CAP_NAME];

	if (!defstring || count > NUM_OF_CAPS)
		return -1;

	strncpy(buf, defstring, MAX_CAP_NAME-1);
	buf[MAX_CAP_NAME-1] = '\0';
	for (i = 0; i < count; ++i)
	{
		if (strncmp(buf, cap_table[i].name, MAX_CAP_NAME) == 0)
			return cap_table[i].nr;
	}
	return -1;
}

char *cap_getname(int cap_nr)
{
	const unsigned int count = sizeof(cap_table) / sizeof(struct cap_translate);
	unsigned int i;

	if (cap_nr < 0 || count > NUM_OF_CAPS)
		return NULL;

	for (i = 0; i < count; ++i)
	{
		if (cap_table[i].nr == cap_nr)
			return cap_table[i].name;
	}
	return NULL;
}

/*
 * de-uglify seccomp-bpf instructions
 * note: i is incremented by this macro!
 */
#define SECBPF_INSTR(p__, i__, c__, t__, f__, k__)	\
{							\
	p__[i__].code = c__;				\
	p__[i__].jt   = t__;				\
	p__[i__].jf   = f__;				\
	p__[i__].k    = k__;				\
	++i__;						\
}
#define SECBPF_LD_ABSW(p_,i_,k_)   SECBPF_INSTR(p_,i_,(BPF_LD|BPF_W|BPF_ABS),0,0,k_)
#define SECBPF_JEQ(p_,i_,k_,t_,f_) SECBPF_INSTR(p_,i_,(BPF_JMP|BPF_JEQ|BPF_K),t_,f_,k_)
#define SECBPF_JMP(p_,i_,k_)       SECBPF_INSTR(p_,i_,(BPF_JMP|BPF_JA),0,0,k_)
#define SECBPF_RET(p_,i_,k_)       SECBPF_INSTR(p_,i_,(BPF_RET|BPF_K),0,0,k_)
#define SECDAT_ARG0                offsetof(struct seccomp_data,args[0])
#define SECDAT_ARCH                offsetof(struct seccomp_data,arch)
#define SECDAT_NR                  offsetof(struct seccomp_data,nr)

static struct sock_filter *build_seccomp_filter(int  arch,
						int *whitelist,
						int *blocklist,
						unsigned int  wcount,
						unsigned int  bcount,
						unsigned int *instr_count,
						unsigned int  options,
						long retaction)
{
	unsigned int i,z;
	unsigned int proglen;
	unsigned int count;
	struct sock_filter *prog = NULL;

	if (bcount > 0 && wcount <= 0) {
		printf("error, cannot use seccomp_block without any seccomp_allow\n");
		return NULL;
	}
	count = wcount + bcount;
	if (count > MAX_SYSCALLS) {
		printf("%d syscalls maximum\n", MAX_SYSCALLS);
		return NULL;
	}

	proglen = 4 + (count * 2) + 1;
	/* whitelist for init process */
	if (count > 0)
		proglen += 18;
	if (options & SECCOPT_BLOCKNEW) {
		proglen += 7;
	}
	if (!(options & SECCOPT_PTRACE)) {
		proglen += 2;
	}

	prog = malloc(proglen * sizeof(struct sock_filter));
	if (prog == NULL)
		return NULL;

	/* create seccomp bpf filter */
	memset(prog, 0, proglen * sizeof(struct sock_filter));
	i = 0;

	/* validate arch */
	SECBPF_LD_ABSW(prog, i, SECDAT_ARCH);
	SECBPF_JEQ(prog, i, arch, 1, 0);
	SECBPF_RET(prog, i, SECCOMP_RET_KILL);

	/* load syscall number */
	SECBPF_LD_ABSW(prog, i, SECDAT_NR);

	 /* we must not allow ptrace if process can install filters
	  * or if filter may contain SECCOMP_RET_TRACE see documentation.
	  * to be safe, lets just outright banish ptrace inside sandbox
	  * unless user requests this (ptrace debuggers/crash reporters)
	  */
	if (!(options & SECCOPT_PTRACE)) {
		SECBPF_JEQ(prog, i, __NR_ptrace, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_KILL);
	}
	/* has to be done at start of filter, which degrades performance.
	 * we can eliminate this with a new prctl to block filters
	 * will save cpu time on high frequency system calls.
	 */
	if (options & SECCOPT_BLOCKNEW) {
#ifdef __NR_seccomp /* since kernel 3.17 */
		SECBPF_JEQ(prog, i, __NR_seccomp, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
#else
		SECBPF_JMP(prog, i, 1);
		SECBPF_JMP(prog, i, 0);
#endif
		SECBPF_JEQ(prog, i, __NR_prctl, 0, 4);
		SECBPF_LD_ABSW(prog, i, SECDAT_ARG0); /* load prctl arg0 */
		SECBPF_JEQ(prog, i, PR_SET_SECCOMP, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
		SECBPF_LD_ABSW(prog, i, SECDAT_NR); /* restore */
	}


	/* everything is whitelisted if count is 0, this is end of filter */
	if (count == 0) {
		SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
		*instr_count = proglen;
		return prog;
	}

	/* generate whitelist jumps */
	for (z = 0; z < wcount; ++z)
	{
		if (whitelist[z] == -1) {
			printf("invalid syscall: z(%d)\n", z);
			free(prog);
			return NULL;
		}
		SECBPF_JEQ(prog, i, whitelist[z], 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	}

	/* generate blocklist jumps */
	for (z = 0; z < bcount; ++z)
	{
		if (blocklist[z] == -1) {
			printf("invalid syscall: z(%d)\n", z);
			free(prog);
			return NULL;
		}
		SECBPF_JEQ(prog, i, blocklist[z], 0, 1);
		SECBPF_RET(prog,i,SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
	}

	/* our init process needs to setup signals, fork exec waitpid kill exit */
	SECBPF_JEQ(prog, i, __NR_sigaction, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_sigreturn, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_clone, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_waitpid, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_kill, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_nanosleep, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_exit, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_exit_group, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	/* TODO some decent hack to disable exec after init calls it
	 * though programs could still patch themselves, dlopen, etc...
	 * on most linux kernels :( */
	SECBPF_JEQ(prog, i, __NR_execve, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);

	/* set return action */
	switch (retaction)
	{
	case SECCOMP_RET_TRAP:
		SECBPF_RET(prog,i,SECCOMP_RET_TRAP|(SECCRET_DENIED & SECCOMP_RET_DATA));
		break;
	case SECCOMP_RET_KILL:
		SECBPF_RET(prog,i,SECCOMP_RET_KILL);
		break;
	case SECCOMP_RET_ERRNO:
		SECBPF_RET(prog,i,SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
		break;
	default:
		printf("invalid return action\n");
		free(prog);
		return NULL;
	}

	*instr_count = proglen;
	return prog;
}

static struct sock_filter *build_blacklist_filter(int arch, int *blocklist,
		unsigned int bcount, unsigned int *instr_count, long retaction)
{
	unsigned int i,z;
	unsigned int proglen;
	struct sock_filter *prog = NULL;

	if (bcount > MAX_SYSCALLS || bcount == 0) {
		printf("blacklist count error\n");
		return NULL;
	}

	proglen = 4 + (bcount * 2) + 1;

	prog = malloc(proglen * sizeof(struct sock_filter));
	if (prog == NULL)
		return NULL;

	/* create seccomp bpf filter */
	memset(prog, 0, proglen * sizeof(struct sock_filter));
	i = 0;

	/* validate arch */
	SECBPF_LD_ABSW(prog, i, SECDAT_ARCH);
	SECBPF_JEQ(prog, i, arch, 1, 0);
	SECBPF_RET(prog, i, SECCOMP_RET_KILL);

	/* load syscall number */
	SECBPF_LD_ABSW(prog, i, SECDAT_NR);

	/* generate blocklist jumps */
	for (z = 0; z < bcount; ++z)
	{
		if (blocklist[z] == -1) {
			printf("invalid syscall: z(%d)\n", z);
			free(prog);
			return NULL;
		}
		SECBPF_JEQ(prog, i, blocklist[z], 0, 1);
		switch (retaction)
		{
		case SECCOMP_RET_TRAP:
			SECBPF_RET(prog,i,SECCOMP_RET_TRAP
					|(SECCRET_DENIED & SECCOMP_RET_DATA));
			break;
		case SECCOMP_RET_KILL:
			SECBPF_RET(prog,i,SECCOMP_RET_KILL);
			break;
		case SECCOMP_RET_ERRNO:
			SECBPF_RET(prog,i,SECCOMP_RET_ERRNO
					|(ENOSYS & SECCOMP_RET_DATA));
			break;
		default:
			printf("invalid return action\n");
			free(prog);
			return NULL;
		}
	}
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	*instr_count = proglen;
	return prog;
}

int filter_syscalls(int arch, int *whitelist, int *blocklist,
		    unsigned int wcount, unsigned int bcount,
		    unsigned int options, long retaction)
{
	struct sock_filter *filter;
	struct sock_fprog prog;
	unsigned int instr_count;

	if (!whitelist && !blocklist)
		return -1;
	else if (!whitelist) {
		if (bcount > 0) {
			printf("building blacklist bcount: %d\n", bcount);
			filter = build_blacklist_filter(arch, blocklist,
					bcount, &instr_count, retaction);
			printf("blacklist instr count: %d\n", instr_count);
		}
		else {
			printf("WARNING! no seccomp filter in use\n");
			return 0;
		}
	}
	else {
		if (!blocklist) {
			bcount = 0;
		}
		filter = build_seccomp_filter(arch, whitelist, blocklist, wcount,
				      bcount, &instr_count, options, retaction);
	}
	if (filter == NULL)
		return -1;

	memset(&prog, 0, sizeof(prog));
	prog.len = instr_count;
	prog.filter = filter;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
		printf("error installing seccomp filter: %s\n", strerror(errno));
		free(filter);
		return -1;
	}
	free(filter);
	return 0;
}


/*
 * capabilities listed here could potentially be used to defeat security measures
 * returns 1 if globally blacklisted
 */
int cap_blacklisted(unsigned long cap)
{
	if (cap >= NUM_OF_CAPS) {
		printf("cap out of bounds\n");
		return 1;
	}

	switch(cap)
	{
		case CAP_MKNOD:
			printf("CAP_MKNOD is prohibited\n");
			return 1;
		case CAP_SYS_MODULE:
			printf("CAP_SYS_MODULE is prohibited\n");
			return 1;
		case CAP_SETPCAP:
			printf("CAP_SETPCAP is prohibited\n");
			return 1;
		case CAP_SETFCAP:
			printf("CAP_SETFCAP is prohibited\n");
			return 1;
		case CAP_DAC_OVERRIDE:
			printf("CAP_DAC_OVERRIDE is prohibited\n");
			return 1;
		case CAP_SYS_ADMIN: /* don't ever allow remounts... */
			printf("CAP_SYS_ADMIN is prohibited\n");
			return 1;
		case CAP_LINUX_IMMUTABLE:
			printf("CAP_LINUX_IMMUTABLE is prohibited\n");
			return 1;
		case CAP_MAC_OVERRIDE:
			printf("CAP_MAC_OVERRIDE is prohibited\n");
			return 1;
		case CAP_MAC_ADMIN:
			printf("CAP_MAC_ADMIN is prohibited\n");
			return 1;
		case CAP_CHOWN:
			printf("CAP_CHOWN is prohibited\n");
			return 1;
		case CAP_BLOCK_SUSPEND:
			printf("CAP_BLOCK_SUSPEND is prohibited\n");
			return 1;
		case CAP_SETUID:
			printf("CAP_SETUID is prohibited\n");
			return 1;
		case CAP_SETGID:
			printf("CAP_SETGID is prohibited\n");
			return 1;
		case CAP_FSETID:
			printf("CAP_SETFUID is prohibited\n");
			return 1;
		case CAP_KILL:
			printf("CAP_KILL is prohibited\n");
			return 1;
		case CAP_SYS_TIME:
			printf("CAP_SYS_TIME is prohibited\n");
			return 1;
		case CAP_SYSLOG:
			printf("CAP_SYSLOG is prohibited\n");
			return 1;
		case CAP_SYS_CHROOT:
			printf("CAP_SYS_CHROOT is prohibited\n");
			return 1;
		case CAP_IPC_OWNER:
			printf("CAP_IPC_OWNER is prohibited\n");
			return 1;
		case CAP_SYS_PTRACE:
			printf("CAP_SYS_PTRACE is prohibited\n");
			return 1;
		/*case CAP_DAC_READ_SEARCH:
			printf("CAP_DAC_READ_SEARCH is prohibited\n");
			return 1;*/
	default:
		return 0;
	}
}

/* b,e,p,i bounding effective, permitted, and inheritable capability sets.
 * to gain effective capability it must already be in permitted set.
 * caps that are not set in cap_i will be cleared unless they are set in cap_b,
 * and cap_i always implies cap_b to preserve it across execve call.
 * array size is NUM_OF_CAPS and you can just pass NULL to clear a set.
 *
 * this function will also set NO_NEW_PRIVS if bounding set is empty.
 */
int set_caps(int *cap_b, int *cap_e, int *cap_p, int *cap_i, int ignore_blacklist)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];
	int i;
	int inheriting = 0;
	unsigned long secbits;
	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.pid = syscall(__NR_gettid);
	hdr.version = _LINUX_CAPABILITY_VERSION_3;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		if (cap_e && cap_e[i]) {
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
			printf("effective: %s\n", cap_getname(i));
			data[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
		}
		if (cap_p && cap_p[i]) {
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
			printf("permitted: %s\n", cap_getname(i));
			data[CAP_TO_INDEX(i)].permitted	|= CAP_TO_MASK(i);
		}
		if (cap_i && cap_i[i]) {
			printf("inherited: %s\n", cap_getname(i));
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
			data[CAP_TO_INDEX(i)].inheritable |= CAP_TO_MASK(i);
			inheriting = 1;
		}

		/* clear bounding set if not requested or inheriting */
		if (cap_b && cap_b[i] == 1) {
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
		}
		else if (cap_i && cap_i[i] != 1) {
			if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) {
				if (i > CAP_LAST_CAP) {
					break;
				}
				else if (errno == EINVAL) {
					printf("cap not found: %d\n", i);
					return -1;
				}
				printf("PR_CAPBSET_DROP: %s\n", strerror(errno));
				return -1;
			}
		}
	}
	secbits = SECBIT_KEEP_CAPS_LOCKED
		| SECBIT_NO_SETUID_FIXUP
		| SECBIT_NO_SETUID_FIXUP_LOCKED;
	if (!inheriting) {
		secbits |= SECBIT_NOROOT
			|  SECBIT_NOROOT_LOCKED;
	}
	if (prctl(PR_SET_SECUREBITS, secbits)) {
		printf("prctl(): %s\n", strerror(errno));
		return -1;
	}
	if (capset(&hdr, data)) {
		printf("capset: %s\n", strerror(errno));
		printf("cap version: %p\n", (void *)hdr.version);
		printf("pid: %d\n", hdr.pid);
		eslib_proc_print_caps();
		return -1;
	}
	return 0;
}

/* caller must unshare mount/pid ns and do bind mounts before calling fortify */
int fortify(char *chroot_path,
		 uid_t set_resuid,
		 gid_t set_resgid,
		 int  *whitelist,
		 int  *blocklist,
		 unsigned long seccomp_opts,
		 int *cap_b,
		 int *cap_e,
		 int *cap_p,
		 int *cap_i,
		 int ignore_cap_blacklist,
		 int fs_write,
		 int fs_exec)
{

	int freeblk = 0;
	unsigned int cnt = 0;
	unsigned long remountflags = MS_REMOUNT
				   | MS_NOSUID
				   | MS_NODEV;

	if (eslib_file_path_check(chroot_path))
		return -1;

	if (!whitelist && !blocklist) {
		blocklist = alloc_sysblacklist(&cnt);
		if (!blocklist) {
			/* TODO flags to clean up args, let user tell us
			 * if they realllly don't want any seccomp filter
			 */
			printf("unable to load blacklist file(s)\n");
			return -1;
		}
		freeblk = 1;
	}

	if (!fs_write)
		remountflags |= MS_RDONLY;
	if (!fs_exec)
		remountflags |= MS_NOEXEC;

	if (mount(chroot_path, chroot_path, "bind", MS_BIND, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(chroot_path, chroot_path, "bind", MS_BIND|remountflags, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	/* TODO let them have non-private mount propagation?
	 * or at least option to not recursively set them private?
	 * do the benefits seem worth potential trouble?
	 * i'm leaning towards yes for at least MS_SLAVE
	 */
	if (mount(NULL, chroot_path, NULL, MS_PRIVATE|MS_REC, NULL)) {
		printf("could not make private: %s\n", strerror(errno));
		return -1;
	}
	if (chdir(chroot_path)) {
		printf("chdir(\"%s\") failed: %s\n", chroot_path, strerror(errno));
		return -1;
	}
	if (mount(chroot_path, "/", NULL, MS_MOVE, NULL)) {
		printf("mount / MS_MOVE failed: %s\n", strerror(errno));
		return -1;
	}
	if (chroot(chroot_path)) {
		printf("chroot failed: %s\n", strerror(errno));
		return -1;
	}
	if (chdir("/")) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return -1;
	}

	if (set_caps(cap_b, cap_e, cap_p, cap_i, ignore_cap_blacklist)) {
		printf("set_caps failed\n");
		return -1;
	}
	if (set_resgid && setresgid(set_resgid, set_resgid, set_resgid)) {
		printf("error setting gid(%d): %s\n", set_resgid, strerror(errno));
		return -1;
	}
        if (set_resuid && setresuid(set_resuid, set_resuid, set_resuid)) {
		printf("error setting uid(%d): %s\n", set_resuid, strerror(errno));
		return -1;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("no new privs failed: %s\n", strerror(errno));
		return -1;
	}
	if (whitelist) {
	       if (filter_syscalls(SYSCALL_ARCH,
				       whitelist,
				       blocklist,
				       count_syscalls(whitelist, MAX_SYSCALLS),
				       count_syscalls(blocklist, MAX_SYSCALLS),
				       seccomp_opts,
				       SECCOMP_RET_ERRNO)) {
			/* TODO allow user to pass SECCOMP_RET_KILL since blocklist
			 * is meant to prevent killing specific calls */
			printf("unable to apply seccomp filter\n");
			return -1;
	       }
	}
	else {
		if (!blocklist)
			return -1;
		if (filter_syscalls(SYSCALL_ARCH,
				       NULL,
				       blocklist,
				       0,
				       count_syscalls(blocklist, MAX_SYSCALLS),
				       seccomp_opts,
				       SECCOMP_RET_ERRNO)) {
			/* TODO allow caller to pass other ret actions */
			printf("unable to apply seccomp filter\n");
			return -1;
		}
		if (freeblk && blocklist)
			free(blocklist);
	}
	return 0;
}

/* TODO eslib_string, and get rid of fopen/fgets to minimize libc exposure
 *  since this lib is mostly linux / *nix specific anyway
 */
static int chop_trailing(char *string, unsigned int size, const char match)
{
	unsigned int i;
	int chopped;
	if (!string)
		return -1;
	i = strnlen(string, size);
	if (i == 0 || i >= size)
		return -1;

	chopped = 0;
	while (1)
	{
		--i;
		if(string[i] == match) {
			string[i] = '\0';
			if (++chopped <= 0)
				return -1;
		}
		else {
			return chopped; /* no matches */
		}
		if (i == 0) {
			return chopped;
		}
	}
	return -1;
}

int *alloc_seccomp_sclist(char *file, unsigned int *outcount)
{
	int syscalls[MAX_SYSCALLS];
	char rdline[MAX_SYSCALL_NAME*2];
	FILE *f;
	int syscall_nr;
	unsigned int i;
	unsigned int count;
	int *outcalls = NULL;

	if (!file || !outcount)
		return NULL;
	*outcount = 0;

	f = fopen(file, "r");
	if (f == NULL) {
		printf("fopen(%s): %s\n", file, strerror(errno));
		return NULL;
	}
	for (i = 0; i < MAX_SYSCALLS; ++i)
	{
		syscalls[i] = -1;
	}

	count = 0;
	while (1)
	{
		if (fgets(rdline, sizeof(rdline), f) == NULL) {
			fclose(f);
			break;
		}
		chop_trailing(rdline, sizeof(rdline), '\n');
		if (rdline[0] == '\0')
			continue;
		syscall_nr = syscall_getnum(rdline);
		if (syscall_nr < 0) {
			printf("could not find syscall: %s\n", rdline);
			goto fail;
		}
		syscalls[count] = syscall_nr;
		printf("sc(%d): %s\n", count, syscall_getname(syscall_nr));
		if (++count >= MAX_SYSCALLS)
			goto fail;
	}
	outcalls = malloc(sizeof(int) * (count + 1));
	if (outcalls == NULL)
		return NULL;
	*outcount = count;
	for (i = 0; i < count; ++i)
	{
		outcalls[i] = syscalls[i];
	}
	outcalls[count] = -1;
	return outcalls;
fail:
	fclose(f);
	return NULL;
}

int *alloc_sysblacklist(unsigned int *outcount)
{
	char *trypath;
	unsigned int i;
	int *sclist = NULL;
	for (i = 0; i < MAX_BLACKLISTS; ++i)
	{
		trypath = g_blacklist_files[i];
		if (trypath == NULL)
			continue;
		sclist = alloc_seccomp_sclist(trypath, outcount);
		if (sclist)
			return sclist;
	}
	return NULL;
}
