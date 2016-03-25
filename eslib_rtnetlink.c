/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <linux/veth.h>
#include <netlink/netlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include "eslib.h"

#define  BUFSIZE (1024 * 16) /* 16KB XXX MSG_TRUNC is unhandled,
				increase buffer if this is an issue... */
/* gets next aligned attr location */
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
/* interface request */
struct rtnl_iface_req {
	struct nlmsghdr hdr;
	struct ifinfomsg ifmsg;
	char buf[BUFSIZE];
};

/* open netlink connection */
static int netlink_open(int protocol)
{
	struct sockaddr_nl addr;
	int fd = -1;
	int bufsize = BUFSIZE;

	fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, protocol);
	if (fd == -1) {
		printf("socket: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize))) {
		close(fd);
		printf("setsockopt: %s\n", strerror(errno));
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize))) {
		printf("setsockopt: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	/* extra error checking? XXX */
	return fd;
}

/* add attribute to netlink message */
static struct rtattr *nlmsg_addattr(struct nlmsghdr *nlmsg, unsigned short maxlen,
			     unsigned short type, char *data, unsigned short size)
{
	struct rtattr *attr;
	unsigned short len = RTA_LENGTH(size); /* add header size */
	errno = 0;
	if (nlmsg == NULL)
		return NULL;

	/* check size after alignment */
	if (NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		errno = E2BIG;
		printf("nlmsg_len too long\n");
		return NULL;
	}

	attr = NLMSG_TAIL(nlmsg);
	attr->rta_type = type;
	attr->rta_len  = len;
	if (data && size)
		memcpy(RTA_DATA(attr), data, size);
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(len);

	return attr;
}
/* end nested attribute by updating starting rta's size */
static int nlmsg_nest_end(struct nlmsghdr *nlmsg, struct rtattr *start)
{
	if (nlmsg == NULL || start == NULL)
		return -1;
	start->rta_len = (char *)NLMSG_TAIL(nlmsg) - (char *)start;
	return 0;
}

/* ack is first nlmsghdr returned, attached by kernel */
#define ACKSIZE (sizeof(struct nlmsghdr) + sizeof(unsigned int))
/* blocks until sent, checks for valid ack */
static int nlmsg_send(void *req, unsigned int size)
{
	char buf[BUFSIZE+ACKSIZE];
	int r;
	int nlfd = -1;
	struct nlmsghdr *msg;
	unsigned int seqnum;
	unsigned int ack_err;

	if (req == NULL)
		return -1;

	memset(buf, 0, sizeof(buf));
	seqnum = ((struct nlmsghdr *)req)->nlmsg_seq;

	nlfd = netlink_open(NETLINK_ROUTE);
	if (nlfd == -1) {
		printf("couldn't open netlink socket\n");
		goto fail;
	}

	/* send request */
	while (1)
	{
		errno = 0;
		r = send(nlfd, req, size, 0);
		if (r == -1 && errno == EINTR) {
			continue;
		}
		else if (r <= 0) {
			printf("rtnl sendmsg: %s\n", strerror(errno));
			goto fail;
		}
		else if ((unsigned int)r == size) {
			break;
		}
		else {
			printf("send size error\n");
			goto fail;
		}
	}

	/* recv netlink ACK */
	while (1)
	{
		errno = 0;
		r = recv(nlfd, buf, sizeof(buf), 0);
		if (r == -1 && errno == EINTR) {
			continue;
		}
		else if (r <= 0) {
			printf("rtnl recvmsg error: %s\n", strerror(errno));
			goto fail;
		}
		else if ((unsigned int)r >= ACKSIZE) {
			break;
		}
		else {
			printf("recv size error\n");
			goto fail;
		}
	}
	/* check ACK */
	msg = (struct nlmsghdr *)buf;
	if (msg->nlmsg_len < ACKSIZE) {
		printf("invalid response\n");
		goto fail;
	}
	if (msg->nlmsg_type != NLMSG_ERROR) {
		printf("unexpected message\n");
		goto fail;
	}
	/* get error code */
	ack_err = *((unsigned int *)(msg+1));
	if (ack_err == 0) {
		/* proper ACK */
		goto ok;
	}

	/* NACK'd, contains original message */
	if ((unsigned int)r != size+ACKSIZE) {
		printf("invalid nack\n");
		goto fail;
	}

	/* verify NACK is for the message we just sent
	 * XXX may need to keep looping until we find it?
	 * but this seems to work ok so far. */
	msg = (struct nlmsghdr *)(buf+ACKSIZE);
	if (msg->nlmsg_len != size) {
		printf("bad netlink msg\n");
		goto fail;
	}
	if (msg->nlmsg_seq != seqnum) {
		printf("bad netlink sequence number\n");
		goto fail;
	}
	if (msg->nlmsg_type == NLMSG_ERROR) {
		printf("netlink message error\n");
		goto fail;
	}

	/* proper NACK */
	close(nlfd);
	return 1;
fail:
	close(nlfd);
	return -1;
ok:
	close(nlfd);
	return 0;
}

/* delete link by name, should we change to by index and make by name a wrapper? */
int eslib_rtnetlink_delete_link(char *name)
{
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int namelen;

	namelen = strnlen(name, IFNAMSIZ);
	if (namelen >= IFNAMSIZ) {
		printf("name too long or no null terminator\n");
		return -1;
	}
	memset(&req, 0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	/* msg header */
	req.hdr.nlmsg_type   = RTM_DELLINK;
	req.hdr.nlmsg_flags  = NLM_F_ACK|NLM_F_REQUEST;
	req.hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_seq    = seqnum;
	req.ifmsg.ifi_family = AF_UNSPEC;
	req.ifmsg.ifi_index  = if_nametoindex(name);

	if (req.ifmsg.ifi_index == 0) {
		printf("could not get index for iface: %s\n", name);
		return -1;
	}

	return nlmsg_send(&req, req.hdr.nlmsg_len);
}
/* create a pair of veth devices <name>1 and <name>2 */
int eslib_rtnetlink_create_veth(char *name)
{
	char name1[IFNAMSIZ];
	char name2[IFNAMSIZ];
	struct rtnl_iface_req req;
	struct rtattr *linkinfo, *infodata, *infopeer;
	unsigned int seqnum;
	unsigned short namelen;
	struct timespec t;

	if (name == NULL || *name == '\0') {
		return -1;
	}
	namelen = strnlen(name, sizeof(name1)) + 1; /* add digit */
	if (namelen >= sizeof(name1)) {
		printf("veth interface name too long\n");
		return -1;
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	memset(&req, 0, sizeof(req));
	snprintf(name1, sizeof(name1), "%s1", name);
	snprintf(name2, sizeof(name2), "%s2", name);

	/* msg header */
	req.hdr.nlmsg_type   = RTM_NEWLINK;
	req.hdr.nlmsg_flags  = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE|NLM_F_ACK;
	req.hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_seq    = seqnum;
	req.ifmsg.ifi_family = AF_UNSPEC;

	/* set interface 1 name,  namelen+(null terminator)*/
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFLA_IFNAME, name1, namelen+1) == NULL)
		goto attr_fail;
	/* nest linkinfo */
	linkinfo = nlmsg_addattr(&req.hdr, sizeof(req), IFLA_LINKINFO, NULL, 0);
	if (linkinfo == NULL)
		goto attr_fail;
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFLA_INFO_KIND, "veth", 4) == NULL)
		goto attr_fail;
	/* nest info data */
	infodata = nlmsg_addattr(&req.hdr, sizeof(req), IFLA_INFO_DATA, NULL, 0);
	if (infodata == NULL)
		goto attr_fail;
	/* nest veth peer info */
	infopeer = nlmsg_addattr(&req.hdr, sizeof(req), VETH_INFO_PEER, NULL, 0);
	if (infopeer == NULL)
		goto attr_fail;
	/* peer interface info header, all zero's in this case */
	req.hdr.nlmsg_len += sizeof(struct ifinfomsg);
	/* set interface 2 name */
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFLA_IFNAME, name2, namelen+1) == NULL)
		goto attr_fail;

	/* update attribute nest lengths */
	if (nlmsg_nest_end(&req.hdr, infopeer))
		goto attr_fail;
	if (nlmsg_nest_end(&req.hdr, infodata))
		goto attr_fail;
	if (nlmsg_nest_end(&req.hdr, linkinfo))
		goto attr_fail;

	/* send netlink message */
	return nlmsg_send(&req, req.hdr.nlmsg_len);

attr_fail:
	printf("veth addattr failure\n");
	return -1;
}
