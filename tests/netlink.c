/*
 *  you will have to run this with root or CAP_NET_ADMIN
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include "../eslib.h"

static int test_veth()
{
	int r;

	printf("creating \"blarg\" veth device\n");
	r = eslib_rtnetlink_linknew("blarg", "veth", NULL);
	if (r == -1){
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("create veth NACK'd\n");
		return -1;
	}

	printf("ok..\n");
	printf("blarg1 set up\n");
	usleep(100000);

	r = eslib_rtnetlink_linkset("blarg1", RTNL_LINKUP);
	if (r == -1){
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("link set up NACK'd\n");
		return -1;
	}

	printf("ok..\n");
	printf("blarg2 set up\n");
	usleep(50000);

	r = eslib_rtnetlink_linkset("blarg2", RTNL_LINKUP);
	if (r == -1){
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("link set up NACK'd\n");
		return -1;
	}


	printf("ok..\n");
	printf("setting blarg1 ip addr 10.0.0.1/24\n");
	usleep(50000);

	r = eslib_rtnetlink_linkaddr("blarg1", "10.0.0.1", 24);
	if (r == -1){
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("add addr NACK'd\n");
		return -1;
	}

	printf("ok..\n");
	printf("setting blarg2 ip addr 10.0.0.2/24\n");
	usleep(50000);

	r = eslib_rtnetlink_linkaddr("blarg2", "10.0.0.2", 24);
	if (r == -1){
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("add addr NACK'd\n");
		return -1;
	}


	printf("ok..\n");
	printf("deleteing \"blarg\" veth device\n");
	usleep(50000);
	r = eslib_rtnetlink_linkdel("blarg1");
	if (r == -1) {
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("delete blarg1 veth NACK'd\n");
		return -1;
	}


	printf("[pass] veth\n");
	return 0;
}

static int test_ipvlan()
{
	int r;

	printf("creating \"blarg\" veth device\n");
	r = eslib_rtnetlink_linknew("blarg", "ipvlan", "eth0");
	if (r == -1){
		printf("netlink error\n");
		return -1;
	}
	else if (r == 1) {
		printf("create veth NACK'd\n");
		return -1;
	}

	printf("ok..\n");
	usleep(50000);

	printf("[pass] ipvlan\n");

	return 0;
}

int main()
{
	if (test_ipvlan())
		return -1;
	return 0;
	if (test_veth())
		return -1;
	printf("test pass\n");
	return 0;
}
