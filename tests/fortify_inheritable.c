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
 *
 *
 * caps are a minefield, this test is to illustrate how to use inheritable set
 * from a setuid launcher and exec as user. other forms of caps are not supported.
 * WARNING: see comments in eslib_fortify.h regarding security issues with caps.
 *
 * note: needs setuid root (chown 0:0 && chmod u+s && su user && cd TESTDIR)
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
#define TESTDIR  "/test"
#define TESTPROG "/test/test_fortify_inheritable"
#define FORTDIR  "/test/fort"
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
	/*execve(TESTPROG, g_null, g_null);*/
	return 0;
}
short g_whitelist[] = {
	__NR_waitpid,
	__NR_write,
	__NR_rt_sigaction,
	__NR_read,
	__NR_open,
	__NR_close,
	__NR_chdir,
	__NR_time,
	__NR_lseek,
	__NR_access,
	__NR_pipe,
	__NR_brk,
	__NR_ioctl,
	__NR_setpgid,
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
	__NR_execve,
	-1
};
void exec_prntout()
{
	struct seccomp_program filter;
	int *cap_b = NULL;
	int  cap_e[NUM_OF_CAPS];
	int  cap_p[NUM_OF_CAPS];
	int  cap_i[NUM_OF_CAPS];
	unsigned long mflags  = MS_NOSUID | MS_RDONLY;
	unsigned long esflags = ESLIB_BIND_PRIVATE
			      | ESLIB_BIND_UNBINDABLE
			      | ESLIB_BIND_CREATE;
	/* setup caps */
	memset(cap_e, 0, sizeof(cap_e));
	memset(cap_p, 0, sizeof(cap_p));
	memset(cap_i, 0, sizeof(cap_i));
	cap_p[CAP_NET_RAW] = 1;
	cap_i[CAP_NET_RAW] = 1;
	/* setup seccomp filter */
	seccomp_program_init(&filter);
	if (syscall_list_load_sysblacklist(&filter.black))
		printf("unable to load blacklist file(s)\n");
	if (syscall_list_loadarray(&filter.white, g_whitelist))
		printf("unable to load whitelist\n");
	filter.seccomp_opts = SECCOPT_BLOCKNEW;
	filter.retaction    = SECCOMP_RET_KILL;
	if (seccomp_program_build(&filter)) {
		printf("could not build secccomp filter\n");
		goto fail;
	}
	/* build fs */
	if (eslib_fortify_prepare(FORTDIR, 1, 0))
		goto fail;
	if (eslib_fortify_install_file(FORTDIR, TESTPROG, mflags, esflags))
		goto fail;
	if (eslib_fortify_install_file(FORTDIR, "/bin", mflags, esflags))
		goto fail;
	if (eslib_fortify_install_file(FORTDIR, "/lib", mflags, esflags))
		goto fail;
	/*fortify */
	if (eslib_fortify(FORTDIR, 0, g_gid, &filter, cap_b, cap_e, cap_p, cap_i, 0))
		goto fail;
	/* setup uid for exec and inherit caps */
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
