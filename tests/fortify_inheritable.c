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
void exec_prntout()
{
	int *cap_b = NULL;
	int  cap_e[NUM_OF_CAPS];
	int  cap_p[NUM_OF_CAPS];
	int  cap_i[NUM_OF_CAPS];
	char src[256];
	char dst[256];
	unsigned long esflags = ESLIB_BIND_UNBINDABLE | ESLIB_BIND_CREATE;
	snprintf(src, sizeof(src), "%s/%s", TESTDIR, TESTPROG);
	snprintf(dst, sizeof(dst), "%s/%s", FORTDIR, TESTPROG);
	memset(cap_e, 0, sizeof(cap_e));
	memset(cap_p, 0, sizeof(cap_p));
	memset(cap_i, 0, sizeof(cap_i));
	cap_p[CAP_NET_RAW] = 1;
	cap_i[CAP_NET_RAW] = 1;

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
	if (fortify(FORTDIR,0,g_gid, 0,0,0, cap_b, cap_e, cap_p, cap_i, 0,0,1))
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
