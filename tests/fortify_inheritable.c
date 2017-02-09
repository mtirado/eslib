/* (c) 2017 Michael R. Tirado -- GPLv3+, GNU General Public License, version 3 or later
 * contact: mtirado418@gmail.com
 *
 * test passing inheritable capabilities to fortified process
 * caps are tricky, this test is to illustrate how to use inheritable
 * set from a setuid program.
 *
 * note: needs setuid root (chown 0:0 && chmod u+s && cd TESTDIR)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <linux/unistd.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "../eslib.h"
#include "../eslib_fortify.h"
#define TESTPROG "test_fortify_inheritable"
#define TESTDIR "/test"
#define FORTDIR "/test/fort"
char *g_null[] = { NULL, NULL };
uid_t g_uid;
gid_t g_gid;
int prntout()
{
	off_t fsize;
	char *fdata;
	printf("**********************************************************\n");
	fsize = eslib_procfs_readfile("/proc/self/status", &fdata);
	if (fsize <= 0)
		printf("error reading /proc/self/status\n");
	else
		 printf("%s\n", fdata);
	printf("**********************************************************\n\n");
	fsize = eslib_procfs_readfile("/proc/mounts", &fdata);
	if (fsize <= 0)
		printf("error reading /proc/self/status\n");
	else
		 printf("%s\n", fdata);
	printf("**********************************************************\n");
	return 0;
}
int g_whitelist[] = {
	__NR_waitpid,
	__NR_write,
	__NR_rt_sigaction,
	__NR_read,
	__NR_open,
	__NR_close,
	__NR_execve,
	__NR_chdir,
	__NR_time,
	__NR_lseek,
	__NR_mount,
	__NR_access,
	__NR_pipe,
	__NR_brk,
	__NR_ioctl,
	__NR_setpgid,
	__NR_chroot,
	__NR_munmap,
	__NR_sigreturn,
	__NR_clone,
	__NR_uname,
	__NR_mprotect,
	__NR_prctl,
	__NR_rt_sigprocmask,
	__NR_capset,
	__NR_mmap2,
	__NR_stat64,
	__NR_fstat64,
	__NR_getuid32,
	__NR_getgid32,
	__NR_setresuid32,
	__NR_setresgid32,
	__NR_setuid32,
	__NR_fcntl64,
	__NR_gettid,
	__NR_set_thread_area,
	__NR_pselect6,
	__NR_unshare,
	-1,
};
void exec_prntout()
{
	char src[256];
	char dst[256];
	int *cap_b = NULL;
	int  cap_e[NUM_OF_CAPS];
	int  cap_p[NUM_OF_CAPS];
	int  cap_i[NUM_OF_CAPS];
	int *sc_blacklist = NULL;
	int *sc_whitelist = NULL;
	unsigned int cnt;
	unsigned long esflags = ESLIB_BIND_UNBINDABLE | ESLIB_BIND_CREATE;
	snprintf(src, sizeof(src), "%s/%s", TESTDIR, TESTPROG);
	snprintf(dst, sizeof(dst), "%s/%s", FORTDIR, TESTPROG);
	memset(cap_e, 0, sizeof(cap_e));
	memset(cap_p, 0, sizeof(cap_p));
	memset(cap_i, 0, sizeof(cap_i));
	cap_p[CAP_NET_RAW] = 1;
	cap_i[CAP_NET_RAW] = 1;

	sc_blacklist = alloc_sysblacklist(&cnt);
	if (!sc_blacklist) {
		printf("unable to load blacklist file(s)\n");
		sc_whitelist = g_whitelist;
	}
	if (eslib_file_bind_private(src, dst, MS_RDONLY|MS_NOSUID, 1, esflags))
		goto fail;
	snprintf(dst, sizeof(dst), "%s/bin", FORTDIR);
	if (eslib_file_bind_private("/bin", dst, MS_RDONLY, 1, esflags))
		goto fail;
	snprintf(dst, sizeof(dst), "%s/lib", FORTDIR);
	if (eslib_file_bind_private("/lib", dst, MS_RDONLY, 1, esflags))
		goto fail;
	snprintf(dst, sizeof(dst), "%s/proc", FORTDIR);
	if (eslib_file_mkdirpath(dst, 0755))
		goto fail;
	if (mount(0, dst, "proc", 0, 0))
		goto fail;
	if (fortify(FORTDIR, 0, g_gid,
			     sc_whitelist, sc_blacklist, 0,
			     cap_b, cap_e, cap_p, cap_i,
			     0, 0, 1))
		goto fail;
	if (setuid(g_uid))
		goto fail;
	if (seteuid(0)) /* unless euid is 0, caps will not be inherited */
		goto fail;
	execve(TESTPROG, g_null, g_null);
fail:
	printf("fortify failed\n");
	return;
}
int forkexec_prntout()
{
	int status;
	pid_t p;
	unshare(CLONE_NEWNS | CLONE_NEWPID);
       	p = fork();
	if (p == -1)
		return -1;
	else if (p == 0) {
		exec_prntout();
		_exit(-1);
	}
	while (1)
	{
		pid_t r;
		r = waitpid(p, &status, 0);
		if (r == p) {
			break;
		}
		else if (r == - 1) {
			if (errno != EINTR) {
				printf("waitpid: %s\n", strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}
int main(int argc, char *argv[])
{
	g_uid = getuid();
	g_gid = getgid();
	if (argc == 0 && argv) {
		return prntout();
	}
	return forkexec_prntout();
}
