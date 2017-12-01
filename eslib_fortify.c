/* Copyright (C) 2017 Michael R. Tirado <mtirado418@gmail.com> -- GPLv3+
 *
 * This program is libre software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details. You should have
 * received a copy of the GNU General Public License version 3
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
	short  nr;
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
{ "restart_syscall", __NR_restart_syscall },
{ "exit", __NR_exit },
{ "fork", __NR_fork },
{ "read", __NR_read },
{ "write", __NR_write },
{ "open", __NR_open },
{ "close", __NR_close },
{ "waitpid", __NR_waitpid },
{ "creat", __NR_creat },
{ "link", __NR_link },
{ "unlink", __NR_unlink },
{ "execve", __NR_execve },
{ "chdir", __NR_chdir },
{ "time", __NR_time },
{ "mknod", __NR_mknod },
{ "chmod", __NR_chmod },
{ "lchown", __NR_lchown },
{ "break", __NR_break },
{ "oldstat", __NR_oldstat },
{ "lseek", __NR_lseek },
{ "getpid", __NR_getpid },
{ "mount", __NR_mount },
{ "umount", __NR_umount },
{ "setuid", __NR_setuid },
{ "getuid", __NR_getuid },
{ "stime", __NR_stime },
{ "ptrace", __NR_ptrace },
{ "alarm", __NR_alarm },
{ "oldfstat", __NR_oldfstat },
{ "pause", __NR_pause },
{ "utime", __NR_utime },
{ "stty", __NR_stty },
{ "gtty", __NR_gtty },
{ "access", __NR_access },
{ "nice", __NR_nice },
{ "ftime", __NR_ftime },
{ "sync", __NR_sync },
{ "kill", __NR_kill },
{ "rename", __NR_rename },
{ "mkdir", __NR_mkdir },
{ "rmdir", __NR_rmdir },
{ "dup", __NR_dup },
{ "pipe", __NR_pipe },
{ "times", __NR_times },
{ "prof", __NR_prof },
{ "brk", __NR_brk },
{ "setgid", __NR_setgid },
{ "getgid", __NR_getgid },
{ "signal", __NR_signal },
{ "geteuid", __NR_geteuid },
{ "getegid", __NR_getegid },
{ "acct", __NR_acct },
{ "umount2", __NR_umount2 },
{ "lock", __NR_lock },
{ "ioctl", __NR_ioctl },
{ "fcntl", __NR_fcntl },
{ "mpx", __NR_mpx },
{ "setpgid", __NR_setpgid },
{ "ulimit", __NR_ulimit },
{ "oldolduname", __NR_oldolduname },
{ "umask", __NR_umask },
{ "chroot", __NR_chroot },
{ "ustat", __NR_ustat },
{ "dup2", __NR_dup2 },
{ "getppid", __NR_getppid },
{ "getpgrp", __NR_getpgrp },
{ "setsid", __NR_setsid },
{ "sigaction", __NR_sigaction },
{ "sgetmask", __NR_sgetmask },
{ "ssetmask", __NR_ssetmask },
{ "setreuid", __NR_setreuid },
{ "setregid", __NR_setregid },
{ "sigsuspend", __NR_sigsuspend },
{ "sigpending", __NR_sigpending },
{ "sethostname", __NR_sethostname },
{ "setrlimit", __NR_setrlimit },
{ "getrlimit", __NR_getrlimit },
{ "getrusage", __NR_getrusage },
{ "gettimeofday", __NR_gettimeofday },
{ "settimeofday", __NR_settimeofday },
{ "getgroups", __NR_getgroups },
{ "setgroups", __NR_setgroups },
{ "select", __NR_select },
{ "symlink", __NR_symlink },
{ "oldlstat", __NR_oldlstat },
{ "readlink", __NR_readlink },
{ "uselib", __NR_uselib },
{ "swapon", __NR_swapon },
{ "reboot", __NR_reboot },
{ "readdir", __NR_readdir },
{ "mmap", __NR_mmap },
{ "munmap", __NR_munmap },
{ "truncate", __NR_truncate },
{ "ftruncate", __NR_ftruncate },
{ "fchmod", __NR_fchmod },
{ "fchown", __NR_fchown },
{ "getpriority", __NR_getpriority },
{ "setpriority", __NR_setpriority },
{ "profil", __NR_profil },
{ "statfs", __NR_statfs },
{ "fstatfs", __NR_fstatfs },
{ "ioperm", __NR_ioperm },
{ "socketcall", __NR_socketcall },
{ "syslog", __NR_syslog },
{ "setitimer", __NR_setitimer },
{ "getitimer", __NR_getitimer },
{ "stat", __NR_stat },
{ "lstat", __NR_lstat },
{ "fstat", __NR_fstat },
{ "olduname", __NR_olduname },
{ "iopl", __NR_iopl },
{ "vhangup", __NR_vhangup },
{ "idle", __NR_idle },
{ "vm86old", __NR_vm86old },
{ "wait4", __NR_wait4 },
{ "swapoff", __NR_swapoff },
{ "sysinfo", __NR_sysinfo },
{ "ipc", __NR_ipc },
{ "fsync", __NR_fsync },
{ "sigreturn", __NR_sigreturn },
{ "clone", __NR_clone },
{ "setdomainname", __NR_setdomainname },
{ "uname", __NR_uname },
{ "modify_ldt", __NR_modify_ldt },
{ "adjtimex", __NR_adjtimex },
{ "mprotect", __NR_mprotect },
{ "sigprocmask", __NR_sigprocmask },
{ "create_module", __NR_create_module },
{ "init_module", __NR_init_module },
{ "delete_module", __NR_delete_module },
{ "get_kernel_syms", __NR_get_kernel_syms },
{ "quotactl", __NR_quotactl },
{ "getpgid", __NR_getpgid },
{ "fchdir", __NR_fchdir },
{ "bdflush", __NR_bdflush },
{ "sysfs", __NR_sysfs },
{ "personality", __NR_personality },
{ "afs_syscall", __NR_afs_syscall },
{ "setfsuid", __NR_setfsuid },
{ "setfsgid", __NR_setfsgid },
{ "_llseek", __NR__llseek },
{ "getdents", __NR_getdents },
{ "_newselect", __NR__newselect },
{ "flock", __NR_flock },
{ "msync", __NR_msync },
{ "readv", __NR_readv },
{ "writev", __NR_writev },
{ "getsid", __NR_getsid },
{ "fdatasync", __NR_fdatasync },
{ "_sysctl", __NR__sysctl },
{ "mlock", __NR_mlock },
{ "munlock", __NR_munlock },
{ "mlockall", __NR_mlockall },
{ "munlockall", __NR_munlockall },
{ "sched_setparam", __NR_sched_setparam },
{ "sched_getparam", __NR_sched_getparam },
{ "sched_setscheduler", __NR_sched_setscheduler },
{ "sched_getscheduler", __NR_sched_getscheduler },
{ "sched_yield", __NR_sched_yield },
{ "sched_get_priority_max", __NR_sched_get_priority_max },
{ "sched_get_priority_min", __NR_sched_get_priority_min },
{ "sched_rr_get_interval", __NR_sched_rr_get_interval },
{ "nanosleep", __NR_nanosleep },
{ "mremap", __NR_mremap },
{ "setresuid", __NR_setresuid },
{ "getresuid", __NR_getresuid },
{ "vm86", __NR_vm86 },
{ "query_module", __NR_query_module },
{ "poll", __NR_poll },
{ "nfsservctl", __NR_nfsservctl },
{ "setresgid", __NR_setresgid },
{ "getresgid", __NR_getresgid },
{ "prctl", __NR_prctl },
{ "rt_sigreturn", __NR_rt_sigreturn },
{ "rt_sigaction", __NR_rt_sigaction },
{ "rt_sigprocmask", __NR_rt_sigprocmask },
{ "rt_sigpending", __NR_rt_sigpending },
{ "rt_sigtimedwait", __NR_rt_sigtimedwait },
{ "rt_sigqueueinfo", __NR_rt_sigqueueinfo },
{ "rt_sigsuspend", __NR_rt_sigsuspend },
{ "pread64", __NR_pread64 },
{ "pwrite64", __NR_pwrite64 },
{ "chown", __NR_chown },
{ "getcwd", __NR_getcwd },
{ "capget", __NR_capget },
{ "capset", __NR_capset },
{ "sigaltstack", __NR_sigaltstack },
{ "sendfile", __NR_sendfile },
{ "getpmsg", __NR_getpmsg },
{ "putpmsg", __NR_putpmsg },
{ "vfork", __NR_vfork },
{ "ugetrlimit", __NR_ugetrlimit },
{ "mmap2", __NR_mmap2 },
{ "truncate64", __NR_truncate64 },
{ "ftruncate64", __NR_ftruncate64 },
{ "stat64", __NR_stat64 },
{ "lstat64", __NR_lstat64 },
{ "fstat64", __NR_fstat64 },
{ "lchown32", __NR_lchown32 },
{ "getuid32", __NR_getuid32 },
{ "getgid32", __NR_getgid32 },
{ "geteuid32", __NR_geteuid32 },
{ "getegid32", __NR_getegid32 },
{ "setreuid32", __NR_setreuid32 },
{ "setregid32", __NR_setregid32 },
{ "getgroups32", __NR_getgroups32 },
{ "setgroups32", __NR_setgroups32 },
{ "fchown32", __NR_fchown32 },
{ "setresuid32", __NR_setresuid32 },
{ "getresuid32", __NR_getresuid32 },
{ "setresgid32", __NR_setresgid32 },
{ "getresgid32", __NR_getresgid32 },
{ "chown32", __NR_chown32 },
{ "setuid32", __NR_setuid32 },
{ "setgid32", __NR_setgid32 },
{ "setfsuid32", __NR_setfsuid32 },
{ "setfsgid32", __NR_setfsgid32 },
{ "pivot_root", __NR_pivot_root },
{ "mincore", __NR_mincore },
{ "madvise", __NR_madvise },
{ "getdents64", __NR_getdents64 },
{ "fcntl64", __NR_fcntl64 },
{ "gettid", __NR_gettid },
{ "readahead", __NR_readahead },
{ "setxattr", __NR_setxattr },
{ "lsetxattr", __NR_lsetxattr },
{ "fsetxattr", __NR_fsetxattr },
{ "getxattr", __NR_getxattr },
{ "lgetxattr", __NR_lgetxattr },
{ "fgetxattr", __NR_fgetxattr },
{ "listxattr", __NR_listxattr },
{ "llistxattr", __NR_llistxattr },
{ "flistxattr", __NR_flistxattr },
{ "removexattr", __NR_removexattr },
{ "lremovexattr", __NR_lremovexattr },
{ "fremovexattr", __NR_fremovexattr },
{ "tkill", __NR_tkill },
{ "sendfile64", __NR_sendfile64 },
{ "futex", __NR_futex },
{ "sched_setaffinity", __NR_sched_setaffinity },
{ "sched_getaffinity", __NR_sched_getaffinity },
{ "set_thread_area", __NR_set_thread_area },
{ "get_thread_area", __NR_get_thread_area },
{ "io_setup", __NR_io_setup },
{ "io_destroy", __NR_io_destroy },
{ "io_getevents", __NR_io_getevents },
{ "io_submit", __NR_io_submit },
{ "io_cancel", __NR_io_cancel },
{ "fadvise64", __NR_fadvise64 },
{ "exit_group", __NR_exit_group },
{ "lookup_dcookie", __NR_lookup_dcookie },
{ "epoll_create", __NR_epoll_create },
{ "epoll_ctl", __NR_epoll_ctl },
{ "epoll_wait", __NR_epoll_wait },
{ "remap_file_pages", __NR_remap_file_pages },
{ "set_tid_address", __NR_set_tid_address },
{ "timer_create", __NR_timer_create },
{ "timer_settime", __NR_timer_settime },
{ "timer_gettime", __NR_timer_gettime },
{ "timer_getoverrun", __NR_timer_getoverrun },
{ "timer_delete", __NR_timer_delete },
{ "clock_settime", __NR_clock_settime },
{ "clock_gettime", __NR_clock_gettime },
{ "clock_getres", __NR_clock_getres },
{ "clock_nanosleep", __NR_clock_nanosleep },
{ "statfs64", __NR_statfs64 },
{ "fstatfs64", __NR_fstatfs64 },
{ "tgkill", __NR_tgkill },
{ "utimes", __NR_utimes },
{ "fadvise64_64", __NR_fadvise64_64 },
{ "vserver", __NR_vserver },
{ "mbind", __NR_mbind },
{ "get_mempolicy", __NR_get_mempolicy },
{ "set_mempolicy", __NR_set_mempolicy },
{ "mq_open", __NR_mq_open },
{ "mq_unlink", __NR_mq_unlink },
{ "mq_timedsend", __NR_mq_timedsend },
{ "mq_timedreceive", __NR_mq_timedreceive },
{ "mq_notify", __NR_mq_notify },
{ "mq_getsetattr", __NR_mq_getsetattr },
{ "kexec_load", __NR_kexec_load },
{ "waitid", __NR_waitid },
{ "add_key", __NR_add_key },
{ "request_key", __NR_request_key },
{ "keyctl", __NR_keyctl },
{ "ioprio_set", __NR_ioprio_set },
{ "ioprio_get", __NR_ioprio_get },
{ "inotify_init", __NR_inotify_init },
{ "inotify_add_watch", __NR_inotify_add_watch },
{ "inotify_rm_watch", __NR_inotify_rm_watch },
{ "migrate_pages", __NR_migrate_pages },
{ "openat", __NR_openat },
{ "mkdirat", __NR_mkdirat },
{ "mknodat", __NR_mknodat },
{ "fchownat", __NR_fchownat },
{ "futimesat", __NR_futimesat },
{ "fstatat64", __NR_fstatat64 },
{ "unlinkat", __NR_unlinkat },
{ "renameat", __NR_renameat },
{ "linkat", __NR_linkat },
{ "symlinkat", __NR_symlinkat },
{ "readlinkat", __NR_readlinkat },
{ "fchmodat", __NR_fchmodat },
{ "faccessat", __NR_faccessat },
{ "pselect6", __NR_pselect6 },
{ "ppoll", __NR_ppoll },
{ "unshare", __NR_unshare },
{ "set_robust_list", __NR_set_robust_list },
{ "get_robust_list", __NR_get_robust_list },
{ "splice", __NR_splice },
{ "sync_file_range", __NR_sync_file_range },
{ "tee", __NR_tee },
{ "vmsplice", __NR_vmsplice },
{ "move_pages", __NR_move_pages },
{ "getcpu", __NR_getcpu },
{ "epoll_pwait", __NR_epoll_pwait },
{ "utimensat", __NR_utimensat },
{ "signalfd", __NR_signalfd },
{ "timerfd_create", __NR_timerfd_create },
{ "eventfd", __NR_eventfd },
{ "fallocate", __NR_fallocate },
{ "timerfd_settime", __NR_timerfd_settime },
{ "timerfd_gettime", __NR_timerfd_gettime },
{ "signalfd4", __NR_signalfd4 },
{ "eventfd2", __NR_eventfd2 },
{ "epoll_create1", __NR_epoll_create1 },
{ "dup3", __NR_dup3 },
{ "pipe2", __NR_pipe2 },
{ "inotify_init1", __NR_inotify_init1 },
{ "preadv", __NR_preadv },
{ "pwritev", __NR_pwritev },
{ "rt_tgsigqueueinfo", __NR_rt_tgsigqueueinfo },
{ "perf_event_open", __NR_perf_event_open },
{ "recvmmsg", __NR_recvmmsg },
{ "fanotify_init", __NR_fanotify_init },
{ "fanotify_mark", __NR_fanotify_mark },
{ "prlimit64", __NR_prlimit64 },
{ "name_to_handle_at", __NR_name_to_handle_at },
{ "open_by_handle_at", __NR_open_by_handle_at },
{ "clock_adjtime", __NR_clock_adjtime },
{ "syncfs", __NR_syncfs },
{ "sendmmsg", __NR_sendmmsg },
{ "setns", __NR_setns },
{ "process_vm_readv", __NR_process_vm_readv },
{ "process_vm_writev", __NR_process_vm_writev },
{ "kcmp", __NR_kcmp },
{ "finit_module", __NR_finit_module },
/* 3.10 */
{ "sched_setattr", __NR_sched_setattr },
{ "sched_getattr", __NR_sched_getattr },
{ "renameat2", __NR_renameat2 },
/* 3.17 */
{ "seccomp", __NR_seccomp },
{ "getrandom", __NR_getrandom },
{ "memfd_create", __NR_memfd_create },
{ "bpf", __NR_bpf },
{ "execveat", __NR_execveat },

#ifndef BLACKLIST_CFG_SIZE
	#define BLACKLIST_CFG_SIZE (4096*2)
#endif

/* 4.3
 * fine grained socket calls,
 * TODO warning if socketcall is whitelisted with these enabled
 */
/*{ "socket", __NR_socket },
{ "socketpair", __NR_socketpair },
{ "bind", __NR_bind },
{ "connect", __NR_connect },
{ "listen", __NR_listen },
{ "accept4", __NR_accept4 },
{ "getsockopt", __NR_getsockopt },
{ "setsockopt", __NR_setsockopt },
{ "getsockname", __NR_getsockname },
{ "getpeername", __NR_getpeername },
{ "sendto", __NR_sendto },
{ "sendmsg", __NR_sendmsg },
{ "recvfrom", __NR_recvfrom },
{ "recvmsg", __NR_recvmsg },
{ "shutdown", __NR_shutdown },
{ "userfaultfd", __NR_userfaultfd },
{ "membarrier", __NR_membarrier },
TODO update this, lol
*/
};

unsigned int syscall_tablesize()
{
	return (sizeof(sc_table) / sizeof(struct sc_translate));
}

unsigned short syscall_gethighest()
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

short syscall_getnum(char *defstring)
{
	const unsigned int count = sizeof(sc_table) / sizeof(struct sc_translate);
	unsigned int i;
	char buf[MAX_SYSCALL_NAME];

	if (!defstring || count > MAX_SYSCALLS)
		return -1;

	if (es_strcopy(buf, defstring, MAX_SYSCALL_NAME, NULL))
		return -1;
	for (i = 0; i < count; ++i)
	{
		if (strncmp(buf, sc_table[i].name, MAX_SYSCALL_NAME) == 0)
			return sc_table[i].nr;
	}
	return -1;
}

char *syscall_getname(short syscall_nr)
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

unsigned int count_syscalls(short *syscalls, unsigned int maxcount)
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

	if (es_strcopy(buf, defstring, MAX_CAP_NAME, NULL))
		return -1;
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

void seccomp_program_init(struct seccomp_program *filter)
{
	unsigned int i;
	memset(filter, 0, sizeof(struct seccomp_program));
	filter->retaction = SECCOMP_RET_ERRNO;
	for (i = 0; i < MAX_SYSCALLS; ++i)
	{
		filter->white.list[i] = -1;
		filter->black.list[i] = -1;
	}
}

int syscall_list_loadarray(struct syscall_list *list, short *src)
{
	unsigned int i;
	syscall_list_clear(list);
	for (i = 0; i < MAX_SYSCALLS; ++i)
	{
		if (src[i] == -1) {
			if (i == 0) {
				printf("syscall src array is empty\n");
				goto fail;
			}
			break;
		}
		if (src[i] < 0 || src[i] > (short)syscall_gethighest())
			goto fail;
		list->list[i] = src[i];
	}
	if (i >= MAX_SYSCALLS)
		goto fail;
	list->count = i;
	return 0;
fail:
	syscall_list_clear(list);
	return -1;
}

int syscall_list_loadfile(struct syscall_list *list, char *file)

{
	short syscalls[MAX_SYSCALLS];
	char fbuf[BLACKLIST_CFG_SIZE];
	size_t flen;
	unsigned int fpos;
	short syscall_nr;
	unsigned int i;
	unsigned int count;

	if (!file || !list)
		return -1;

	memset(fbuf, 0, sizeof(fbuf));
	for (i = 0; i < MAX_SYSCALLS; ++i)
		syscalls[i] = -1;

	if (eslib_file_read_full(file, fbuf, BLACKLIST_CFG_SIZE-1, &flen)) {
		printf("problem reading file: %s\n", strerror(errno));
		return -1;
	}
	if (eslib_string_tokenize(fbuf, flen, "\n")) {
		printf("tokenize file failed\n");
		return -1;
	}
	count = 0;
	fpos = 0;
	while (fpos < flen)
	{
		unsigned int advance = 0;
		char *line = eslib_string_toke(fbuf, fpos, flen, &advance);
		if (line == NULL || *line == '#') {
			if (advance == 0)
				return -1;
			fpos += advance;
			continue;
		}
		fpos += advance;

		syscall_nr = syscall_getnum(line);
		if (syscall_nr < 0) {
			printf("could not find syscall: %s\n", line);
			if (*line == ' ' || *line == '\t') {
				printf("leading whitespace not supported\n");
			}
			return -1;
		}
		syscalls[count] = syscall_nr;
		if (++count >= MAX_SYSCALLS)
			return -1;
	}
	if (syscall_list_loadarray(list, syscalls))
		return -1;
	return 0;
}

int syscall_list_load_sysblacklist(struct syscall_list *list)
{
	char *trypath;
	unsigned int i;
	for (i = 0; i < MAX_BLACKLISTS; ++i)
	{
		trypath = g_blacklist_files[i];
		if (trypath == NULL)
			continue;
		if (syscall_list_loadfile(list, trypath) == 0)
			return 0;
	}
	syscall_list_clear(list);
	return -1;
}

int syscall_list_addnum(struct syscall_list *list, short num)
{
	if (list->count >= MAX_SYSCALLS-1)
		return -1;
	if (num < 0 || num > (short)syscall_gethighest())
		return -1;
	list->list[list->count] = num;
	++list->count;
	return 0;
}
int syscall_list_addname(struct syscall_list *list, char *name)
{
	return syscall_list_addnum(list, syscall_getnum(name));
}
void syscall_list_clear(struct syscall_list *list)
{
	int i;
	for (i = 0; i < MAX_SYSCALLS; ++i)
	{
		list->list[i] = -1;
	}
	list->count = 0;
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
	if (++i__ >= MAX_BPFINSTRUCTIONS)		\
		_exit(-1);				\
}
#define SECBPF_LD_ABSW(p_,i_,k_)   SECBPF_INSTR(p_,i_,(BPF_LD|BPF_W|BPF_ABS),0,0,k_)
#define SECBPF_JEQ(p_,i_,k_,t_,f_) SECBPF_INSTR(p_,i_,(BPF_JMP|BPF_JEQ|BPF_K),t_,f_,k_)
#define SECBPF_JMP(p_,i_,k_)       SECBPF_INSTR(p_,i_,(BPF_JMP|BPF_JA),0,0,k_)
#define SECBPF_RET(p_,i_,k_)       SECBPF_INSTR(p_,i_,(BPF_RET|BPF_K),0,0,k_)
#define SECDAT_ARG0                offsetof(struct seccomp_data,args[0])
#define SECDAT_ARCH                offsetof(struct seccomp_data,arch)
#define SECDAT_NR                  offsetof(struct seccomp_data,nr)

static int build_graylist_filter(struct seccomp_program *filter)
{
	unsigned int i,z;
	unsigned int proglen;
	unsigned int wcount;
	unsigned int bcount;
	unsigned int count;
	struct sock_filter *prog = NULL;
	short *whitelist;
	short *blocklist;

	whitelist = filter->white.list;
	blocklist = filter->black.list;
	wcount    = filter->white.count;
	bcount    = filter->black.count;
	count = wcount + bcount;
	if (count >= MAX_SYSCALLS) {
		printf("seccomp syscall count(%d+%d) error\n", wcount, bcount);
		printf("%d syscalls allowed\n", MAX_SYSCALLS);
		return -1;
	}

	if (filter->retaction == SECCOMP_RET_TRAP) {
		filter->seccomp_opts |= SECCOPT_BLOCKNEW;
	}

	/* arch validation, load number, call list, ret action */
	proglen = 4 + (count * 2) + 1;
	prog = filter->bpf_stack;
	memset(prog, 0, MAX_BPFINSTRUCTIONS * sizeof(struct sock_filter));

	i = 0;
	/* validate arch */
	SECBPF_LD_ABSW(prog, i, SECDAT_ARCH);
	SECBPF_JEQ(prog, i, SYSCALL_ARCH, 1, 0);
	SECBPF_RET(prog, i, SECCOMP_RET_KILL);

	/* load syscall number */
	SECBPF_LD_ABSW(prog, i, SECDAT_NR);

	 /* we must not allow ptrace if process can install filters
	  * or if filter may contain SECCOMP_RET_TRACE see documentation.
	  * to be safe, lets just outright banish ptrace inside sandbox
	  * unless user requests this (ptrace debuggers/crash reporters)
	  */
	if (!(filter->seccomp_opts & SECCOPT_PTRACE)) {
		proglen += 2;
		SECBPF_JEQ(prog, i, __NR_ptrace, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_KILL);
	}
	/* has to be done at start of filter, which degrades performance.
	 * could eliminate this with a prctl to block new filters,
	 */
	if (filter->seccomp_opts & SECCOPT_BLOCKNEW) {
		proglen += 7;
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
		filter->prog.len = proglen;
		filter->prog.filter = prog;
		return 0;
	}

	/* generate whitelist jumps */
	for (z = 0; z < wcount; ++z)
	{
		if (whitelist[z] < 0) {
			printf("invalid  wsyscall: %d\n", z);
			return -1;
		}
		SECBPF_JEQ(prog, i, whitelist[z], 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	}

	/* generate blocklist jumps */
	for (z = 0; z < bcount; ++z)
	{
		if (blocklist[z] < 0) {
			printf("invalid bsyscall: %d\n", z);
			return -1;
		}
		SECBPF_JEQ(prog, i, blocklist[z], 0, 1);
		SECBPF_RET(prog,i,SECCOMP_RET_ERRNO|(ENOSYS & SECCOMP_RET_DATA));
	}

	proglen += 6;
	SECBPF_JEQ(prog, i, __NR_sigreturn, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_exit, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	SECBPF_JEQ(prog, i, __NR_exit_group, 0, 1);
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);

	/* set return action */
	switch (filter->retaction)
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
		return -1;
	}

	filter->prog.len = proglen;
	filter->prog.filter = prog;
	return 0;
}

static int build_blacklist_filter(struct seccomp_program *filter)
{
	unsigned int i,z;
	unsigned int proglen, bcount;
	struct sock_filter *prog = NULL;
	short *blacklist;

	if (!filter)
		return -1;

	blacklist = filter->black.list;
	bcount    = filter->black.count;
	if (bcount >= MAX_SYSCALLS)
		return -1;

	if (filter->retaction == SECCOMP_RET_TRAP) {
		filter->seccomp_opts |= SECCOPT_BLOCKNEW;
	}

	proglen = 4 + (bcount * 2) + 1;
	prog = filter->bpf_stack;
	memset(prog, 0, MAX_BPFINSTRUCTIONS * sizeof(struct sock_filter));

	i = 0;
	/* validate arch */
	SECBPF_LD_ABSW(prog, i, SECDAT_ARCH);
	SECBPF_JEQ(prog, i, SYSCALL_ARCH, 1, 0);
	SECBPF_RET(prog, i, SECCOMP_RET_KILL);
	/* load syscall number */
	SECBPF_LD_ABSW(prog, i, SECDAT_NR);

	/* seccomp_opts */
	if (!(filter->seccomp_opts & SECCOPT_PTRACE)) {
		proglen += 2;
		SECBPF_JEQ(prog, i, __NR_ptrace, 0, 1);
		SECBPF_RET(prog, i, SECCOMP_RET_KILL);
	}
	if (filter->seccomp_opts & SECCOPT_BLOCKNEW) {
		proglen += 7;
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

	/* generate blacklist jumps */
	for (z = 0; z < bcount; ++z)
	{
		if (blacklist[z] < 0) {
			printf("invalid syscall: z(%d)\n", z);
			return -1;
		}
		SECBPF_JEQ(prog, i, blacklist[z], 0, 1);
		switch (filter->retaction)
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
			return -1;
		}
	}
	SECBPF_RET(prog, i, SECCOMP_RET_ALLOW);
	filter->prog.filter = prog;
	filter->prog.len = proglen;
	return 0;
}

/* build either a straight blacklist, or mix white/blacklists */
int seccomp_program_build(struct seccomp_program *filter)
{
	if (!filter)
		return -1;

	if (!filter->white.count) {
		if (build_blacklist_filter(filter)) {
			printf("could not build seccomp blacklist filter\n");
			return -1;
		}
	}
	else {
		if (build_graylist_filter(filter)) {
			printf("could not build seccomp graylist filter\n");
			return -1;
		}
	}

	return 0;
}

int seccomp_program_install(struct seccomp_program *filter)
{
	if (!filter || !filter->prog.filter || !filter->prog.len)
		return -1;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter->prog) == -1) {
		printf("error installing seccomp filter: %s\n", strerror(errno));
		return -1;
	}
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
	hdr.version = _LINUX_CAPABILITY_VERSION_3;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		if (cap_e && cap_e[i]) {
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
			data[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
		}
		if (cap_p && cap_p[i]) {
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
			data[CAP_TO_INDEX(i)].permitted	|= CAP_TO_MASK(i);
		}
		if (cap_i && cap_i[i]) {
			if (!ignore_blacklist && cap_blacklisted(i))
				return -1;
			data[CAP_TO_INDEX(i)].inheritable |= CAP_TO_MASK(i);
			inheriting = 1;
		}

		/* clear bounding set if not requested or inheriting */
		if (cap_b && cap_b[i] == 1) {
			if (!ignore_blacklist && cap_blacklisted(i)) {
				return -1;
			}
			continue;
		}
		if (cap_i && cap_i[i] == 1) {
			continue;
		}
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

int eslib_fortify_prepare(char *chroot_path, int mountproc)
{
	if (eslib_file_path_check(chroot_path))
		return -1;
	if (eslib_file_mkdirpath(chroot_path, 0755))
		return -1;
	if (unshare(CLONE_NEWNS | CLONE_NEWPID)) {
		printf("unshare: %s\n", strerror(errno));
		return -1;
	}
	if (mountproc)
	{
		char path[MAX_SYSTEMPATH];
		unsigned long remountflags = MS_REMOUNT
					   | MS_NOEXEC
					   | MS_NOSUID
					   | MS_NODEV;
		if (mountproc > 0) /* use -1 for +w */
			remountflags |= MS_RDONLY;

		if (es_sprintf(path, sizeof(path), NULL, "%s/proc", chroot_path))
			return -1;
		if (eslib_file_mkdirpath(path, 0755))
			return -1;

		if (mount(0, path, "proc", 0, 0)) {
			printf("mount proc: %s\n", strerror(errno));
			return -1;
		}
		if (mount(path, path, "proc", remountflags, NULL)) {
			printf("remount proc: %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int eslib_fortify_install_file(char *chroot_path, char *file,
		unsigned long mntflags, unsigned long esflags)
{
	char dest[MAX_SYSTEMPATH];
	if (eslib_file_path_check(chroot_path) || eslib_file_path_check(file))
		return -1;
	if (es_sprintf(dest, sizeof(dest), NULL, "%s%s", chroot_path, file))
		return -1;
	if (eslib_file_bind(file, dest, mntflags, esflags))
		return -1;
	return 0;
}

int eslib_fortify(char *chroot_path,
		 uid_t set_resuid, /* if these are 0, no setresuid call is made */
		 gid_t set_resgid,
		 struct seccomp_program *filter,
		 int cap_b[NUM_OF_CAPS],
		 int cap_e[NUM_OF_CAPS],
		 int cap_p[NUM_OF_CAPS],
		 int cap_i[NUM_OF_CAPS],
		 unsigned long fortflags)
{

	int ignore_cap_blacklist = 0;
	unsigned long remountflags = MS_REMOUNT
				   | MS_NOSUID
				   | MS_NODEV;

	if (eslib_file_path_check(chroot_path))
		return -1;

	ignore_cap_blacklist = fortflags & ESLIB_FORTIFY_IGNORE_CAP_BLACKLIST;
	remountflags |= MS_RDONLY;
	remountflags |= MS_NOEXEC;

	if (!(fortflags & ESLIB_FORTIFY_SHARE_NET)) {
		if (unshare(CLONE_NEWNET)) {
			printf("unshare(CLONE_NEWNET): %s\n", strerror(errno));
			return -1;
		}
	}

	if (mount(chroot_path, chroot_path, "bind", MS_BIND, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(chroot_path, chroot_path, "bind", MS_BIND|remountflags, NULL)) {
		printf("could not bind mount: %s\n", strerror(errno));
		return -1;
	}
	/* TODO let them have non-private / mount propagation?
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
	if (filter && seccomp_program_install(filter)) {
		printf("unable to apply seccomp filter\n");
		return -1;
	}
	return 0;
}


