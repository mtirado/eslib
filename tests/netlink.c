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
 * you will have to run this with root or CAP_NET_ADMIN
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sched.h>
#include "../eslib.h"
#include "../eslib_rtnetlink.h"

#define rtnetlink_checkret(r)		\
if (r == -1){				\
	printf("netlink error\n");	\
	return -1;			\
}					\
else if (r == 1) {			\
	printf("netlink NACK\n");	\
	return -1;			\
}

static int test_veth()
{
	int r;

	printf("creating \"blarg\" veth device\n");
	r = eslib_rtnetlink_linknew("blarg", "veth", NULL);
	rtnetlink_checkret(r);

	printf("blarg1 set up\n");
	usleep(100000);

	r = eslib_rtnetlink_linksetup("blarg1");
	rtnetlink_checkret(r);

	printf("blarg2 set up\n");
	usleep(50000);

	r = eslib_rtnetlink_linksetup("blarg2");
	rtnetlink_checkret(r);

	printf("setting blarg1 ip addr 10.0.0.1/24\n");
	usleep(50000);

	r = eslib_rtnetlink_linkaddr("blarg1", "10.0.0.1", 24);
	rtnetlink_checkret(r);

	printf("setting blarg2 ip addr 10.0.0.2/24\n");
	usleep(50000);

	r = eslib_rtnetlink_linkaddr("blarg2", "10.0.0.2", 24);
	rtnetlink_checkret(r);

	printf("deleteing \"blarg1\" veth device\n");
	usleep(50000);

	r = eslib_rtnetlink_linkdel("blarg1");
	rtnetlink_checkret(r);

	printf("[pass] veth\n");
	return 0;
}

static int test_ipvlan()
{
	int r;
	int status;
	int ipc[2];
	char c;
	pid_t p;

	printf("creating \"blarg\" veth device\n");
	r = eslib_rtnetlink_linknew("blarg", "ipvlan", "eth0");
	rtnetlink_checkret(r);

	printf("changing name, blarg to blaah\n");
	usleep(50000);

	r = eslib_rtnetlink_linksetname("blarg", "blaah");
	rtnetlink_checkret(r);

	printf("moving blaaah to new namespace");
	usleep(50000);

	if (pipe(ipc))
		return -1;
	p = fork();
	if (p == -1)
		return -1;
	else if (p == 0)
	{
		const char k = 'K';
		if (unshare(CLONE_NEWNET))
			_exit(-1);
		write(ipc[1], &k, 1);
		printf("    newnetns forked.\n");
		usleep(700000);
		printf("deleting blaaah\n");
		eslib_rtnetlink_linkdel("blaah");
		rtnetlink_checkret(r);
		_exit(0);
	}
	if (read(ipc[0], &c, 1) != 1) {
		printf("ipc\n");
		close(ipc[0]);
		close(ipc[1]);
		return -1;
	}
	close(ipc[0]);
	close(ipc[1]);
	eslib_rtnetlink_linksetns("blaah", (unsigned int)p, 1);
	rtnetlink_checkret(r);
	if (waitpid(p, &status, 0) != p) {
		printf("waitpid\n");
		return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("newnet proc error\n");
		return -1;
	}
	printf("[pass] ipvlan\n");
	return 0;
}

int main()
{
	if (test_ipvlan())
		return -1;
	if (test_veth())
		return -1;
	printf("test pass\n");
	return 0;
}
