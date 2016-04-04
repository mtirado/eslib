/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <linux/veth.h>
#include <linux/if_addr.h>
#include <netlink/netlink.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
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
/* address request */
struct rtnl_addr_req {
	struct nlmsghdr hdr;
	struct ifaddrmsg addrmsg;
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
	return fd;
}

/* add attribute to netlink message */
static struct rtattr *nlmsg_addattr(struct nlmsghdr *nlmsg, unsigned short maxlen,
				    unsigned short type, void *data, unsigned short size)
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

/* if NLM_F_ACK flag is set, kernel attaches ack as first nlmsghdr returned */
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

/* add address (ipv4), prefix_len is subnet mask: 24 = 255.255.255.0 */
int eslib_rtnetlink_linkaddr(char *name, char *addr, unsigned char prefix_len)
{
	struct rtnl_addr_req req;
	struct timespec t;
	struct in_addr ipaddr;
	const unsigned int bytelen = 4;
	unsigned int seqnum;
	unsigned int namelen;

	if (prefix_len > 32) {
		printf("invalid prefix len\n");
		return -1;
	}
	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ) {
		printf("name too long or no null terminator\n");
		return -1;
	}
	memset(&ipaddr, 0, sizeof(ipaddr));
	memset(&req, 0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());

	if (inet_pton(AF_INET, addr, &ipaddr) <= 0) {
		printf("bad ipv4 address\n");
		return -1;
	}

	/* msg header */
	req.hdr.nlmsg_type  = RTM_NEWADDR;
	req.hdr.nlmsg_flags = NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK|NLM_F_REQUEST;
	req.hdr.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.hdr.nlmsg_seq   = seqnum;
	req.addrmsg.ifa_family    = AF_INET; /*32bit*/
	req.addrmsg.ifa_index     = if_nametoindex(name);
	req.addrmsg.ifa_prefixlen = prefix_len;

	if (req.addrmsg.ifa_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFA_LOCAL, &ipaddr, bytelen) == NULL) {
		printf("adattr failed\n");
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFA_ADDRESS, &ipaddr, bytelen) == NULL) {
		printf("adattr failed\n");
		return -1;
	}
	return nlmsg_send(&req, req.hdr.nlmsg_len);
}
/* either up or down */
int eslib_rtnetlink_linkset(char *name, int up)
{
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int namelen;

	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ) {
		printf("name too long or no null terminator\n");
		return -1;
	}
	memset(&req, 0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	/* msg header */
	req.hdr.nlmsg_type    = RTM_NEWLINK;
	req.hdr.nlmsg_flags   = NLM_F_ACK|NLM_F_REQUEST;
	req.hdr.nlmsg_len     = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_seq     = seqnum;
	req.ifmsg.ifi_family  = AF_UNSPEC;
	req.ifmsg.ifi_index   = if_nametoindex(name);
	req.ifmsg.ifi_change |= IFF_UP;
	if (up)
		req.ifmsg.ifi_flags |= IFF_UP;
	else
		req.ifmsg.ifi_flags &= ~IFF_UP;

	if (req.ifmsg.ifi_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}

	return nlmsg_send(&req, req.hdr.nlmsg_len);

}

/* delete link by name, should we change to by index and make by name a wrapper? */
int eslib_rtnetlink_linkdel(char *name)
{
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int namelen;

	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ) {
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
		printf("could not get index for interface: %s\n", name);
		return -1;
	}

	return nlmsg_send(&req, req.hdr.nlmsg_len);
}

static int create_veth(struct rtnl_iface_req *req, char *name)
{
	char name1[IFNAMSIZ];
	char name2[IFNAMSIZ];
	unsigned int namelen;
	struct rtattr *linkinfo, *infodata, *infopeer;

	namelen = strnlen(name, sizeof(name1)+1) + 1; /* add digit */
	if (namelen > sizeof(name1)) {
		printf("veth interface name too long\n");
		return -1;
	}
	snprintf(name1, sizeof(name1), "%s1", name);
	snprintf(name2, sizeof(name2), "%s2", name);

	/* set interface 1 name,  namelen+(null terminator)*/
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_IFNAME, name1, namelen) == NULL)
		goto attr_fail;
	/* nest linkinfo */
	linkinfo = nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_LINKINFO, NULL, 0);
	if (linkinfo == NULL)
		goto attr_fail;
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_INFO_KIND, "veth", 4) == NULL)
		goto attr_fail;
	/* nest info data */
	infodata = nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	if (infodata == NULL)
		goto attr_fail;
	/* nest veth peer info */
	infopeer = nlmsg_addattr(&req->hdr, sizeof(*req), VETH_INFO_PEER, NULL, 0);
	if (infopeer == NULL)
		goto attr_fail;
	/* peer interface info header, all zero's in this case */
	req->hdr.nlmsg_len += sizeof(struct ifinfomsg);
	/* set interface 2 name */
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_IFNAME, name2, namelen) == NULL)
		goto attr_fail;

	/* update attribute nest lengths */
	if (nlmsg_nest_end(&req->hdr, infopeer))
		goto attr_fail;
	if (nlmsg_nest_end(&req->hdr, infodata))
		goto attr_fail;
	if (nlmsg_nest_end(&req->hdr, linkinfo))
		goto attr_fail;

	return 0;
attr_fail:
	printf("veth addattr failure\n");
	return -1;
}

static int create_ipvlan(struct rtnl_iface_req *req, char *name, char *master)
{
	struct rtattr *linkinfo, *infodata;
	unsigned int namelen;
	__u32 mindex;
	__u16 mode = IPVLAN_MODE_L2;

	if (master == NULL || *master == '\0') {
		printf("no master interface\n");
		return -1;
	}
	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ || namelen == 0) {
		printf("bad name\n");
		return -1;
	}
	if (strnlen(master, IFNAMSIZ+1) > IFNAMSIZ) {
		printf("bad master name\n");
		return -1;
	}


	mindex = if_nametoindex(master);
	if (mindex == 0) {
		printf("cannot find master interface: %s\n", master);
		return -1;
	}

	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_LINK,
				&mindex, sizeof(mindex)) == NULL)
		goto attr_fail;
	/* set interface name,  namelen+(null terminator)*/
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_IFNAME, name, namelen) == NULL)
		goto attr_fail;
	/* nest linkinfo */
	linkinfo = nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_LINKINFO, NULL, 0);
	if (linkinfo == NULL)
		goto attr_fail;
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_INFO_KIND, "ipvlan", 6) == NULL)
		goto attr_fail;
	/* nest info data */
	infodata = nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	if (infodata == NULL)
		goto attr_fail;
	/* set mode */
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_IPVLAN_MODE,
				&mode, sizeof(mode)) == NULL)
		goto attr_fail;

	/* update nest lengths */
	if (nlmsg_nest_end(&req->hdr, infodata))
		goto attr_fail;
	if (nlmsg_nest_end(&req->hdr, linkinfo))
		goto attr_fail;

	return 0;

attr_fail:
	printf("veth addattr failure\n");
	return -1;
}

/* create a pair of veth devices <name>1 and <name>2 */
int eslib_rtnetlink_linknew(char *name, char *kind, void *typedat)
{
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int devkind;

	if (name == NULL || *name == '\0') {
		return -1;
	}
	printf("linknew(%s, %s, %s)\n", name, kind, (char *)typedat);
	if (strncmp(kind, "veth", 4) == 0) {
		devkind = RTNL_KIND_VETH;
	}
	else if (strncmp(kind, "ipvlan", 6) == 0) {
		devkind = RTNL_KIND_IPVLAN;
	}
	else {
		printf("unknown kind: %s\n", kind);
		return -1;
	}

	/* msg header */
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_type   = RTM_NEWLINK;
	req.hdr.nlmsg_flags  = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE|NLM_F_ACK;
	req.hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_seq    = seqnum;
	req.ifmsg.ifi_family = AF_UNSPEC;

	switch (devkind)
	{
		/* these are basic ethernet socketpairs */
	case RTNL_KIND_VETH:
		if (create_veth(&req, name))
			return -1;
		break;
		/* at a quick glance ipvlan seems to be the most simple
		 * minimal solution, so let's start with this one. */
	case RTNL_KIND_IPVLAN:
		if (create_ipvlan(&req, name, typedat))
			return -1;
		break;
	default:
		printf("switch default\n");
		return -1;
	}
	/* send netlink message */
	return nlmsg_send(&req, req.hdr.nlmsg_len);
}


int eslib_rtnetlink_linksetns(char *name, pid_t target)
{
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int namelen;

	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ) {
		printf("name too long or no null terminator\n");
		return -1;
	}

	memset(&req, 0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	/* msg header */
	req.hdr.nlmsg_type    = RTM_NEWLINK;
	req.hdr.nlmsg_flags   = NLM_F_ACK|NLM_F_REQUEST;
	req.hdr.nlmsg_len     = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_seq     = seqnum;
	req.ifmsg.ifi_family  = AF_UNSPEC;
	req.ifmsg.ifi_index   = if_nametoindex(name);
	if (req.ifmsg.ifi_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFLA_NET_NS_PID, &target, 4) == NULL) {
		printf("addattr fail\n");
		return -1;
	}


	return nlmsg_send(&req, req.hdr.nlmsg_len);
}

int eslib_rtnetlink_linksetname(char *name, char *newname)
{
	/* can we do this with netlink? */
	struct ifreq req;
	int fd;
	if (strnlen(name, IFNAMSIZ+1) > IFNAMSIZ) {
		printf("name too long\n");
		return -1;
	}
	if (strnlen(newname, IFNAMSIZ+1) > IFNAMSIZ) {
		printf("name too long\n");
		return -1;
	}
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, name, IFNAMSIZ);
	strncpy(req.ifr_newname, newname, IFNAMSIZ);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		fd = socket(AF_PACKET, SOCK_DGRAM, 0);
		if (fd == -1) {
			fd = socket(AF_INET6, SOCK_DGRAM, 0);
			if (fd == -1) {
				printf("couldn't open socket\n");
				return -1;
			}
		}
	}
	if (ioctl(fd, SIOCSIFNAME, &req)) {
		printf("SIOCSIFNAME: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}
