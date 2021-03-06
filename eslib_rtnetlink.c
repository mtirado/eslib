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
#include <linux/veth.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <limits.h>
#include "eslib.h"
#include "eslib_rtnetlink.h"

#define  BUFSIZE (1024 * 32) /* 32KB XXX MSG_TRUNC is unhandled,
				increase buffer if this is an issue... */
/* gets next aligned attr location */
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *)(((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
/* set values */
void rtnl_decode_setinput(struct rtnl_decode_io *dio, void *ptr, __u32 size)
{
	dio->in = ptr;
	dio->insize = size;
}
void rtnl_decode_setoutput(struct rtnl_decode_io *dio, void *ptr, __u32 size)
{
	dio->out = ptr;
	dio->outsize = size;
}
void rtnl_decode_setcallback(struct rtnl_decode_io *dio, rtnl_decode_callback decode)
{
	dio->decode = decode;
}
int rtnl_decode_check(struct rtnl_decode_io *dio, __u32 insize, __u32 outsize,
			__u32 type, __u32 msgsize, __u32 tblcount)
{
	if (dio == NULL || dio->decode == NULL)
		return -1;
	if (dio->in && dio->insize < insize)
	       return -1;
	if (dio->out && dio->outsize < outsize)
		return -1;
	switch (type)
	{
	case RTM_GETROUTE:
		if (msgsize != sizeof(struct rtmsg) || tblcount != __RTA_MAX)
			return -1;
		break;
	case RTM_GETLINK:
		if (msgsize != sizeof(struct ifinfomsg) || tblcount != __IFLA_MAX)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

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
/* route request */
struct rtnl_rt_req {
	struct nlmsghdr hdr;
	struct rtmsg rmsg;
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
		printf("setsockopt: %s\n", strerror(errno));
		close(fd);
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
	unsigned short len = (unsigned short)RTA_LENGTH(size); /* add header size */
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
	if (nlmsg == NULL || start == NULL || (char *)start >= (char *)NLMSG_TAIL(nlmsg))
		return -1;
	start->rta_len = (unsigned short)((char *)NLMSG_TAIL(nlmsg) - (char *)start);
	return 0;
}
/* blocks */
static int nlmsg_do_send(int nlfd, void *req, unsigned int size)
{
	int r;
	if (size > BUFSIZE || req == NULL)
		return -1;
	/* send request */
	while (1)
	{
		errno = 0;
		r = send(nlfd, req, size, 0);
		if (r == -1 && errno == EINTR)
			continue;
		else if ((unsigned int)r == size)
			return 0;
		else if (r <= 0) {
			printf("rtnl send: %s\n", strerror(errno));
			return -1;
		}
		else {
			printf("rtnl send returned unexpected size\n");
			return -1;
		}
	}
}
/* also blocks */
static int nlmsg_do_recv(int nlfd, char *buf, unsigned int size)
{
	int r;
	if (size > BUFSIZE || buf == NULL)
		return -1;
	while(1)
	{
		r = recv(nlfd, buf, BUFSIZE, 0);
		if (r == -1 && errno == EINTR)
			continue;
		else if (r > 0 && (unsigned int)r < BUFSIZE)
			return r;
		else if (r == -1) {
			printf("recv error: %s\n", strerror(errno));
			return -1;
		}
		else {
			printf("recv error(%d).\n", r);
			return -1;
		}
	}
}
/* if NLM_F_ACK flag is set, kernel attaches ack as first nlmsghdr returned */
#define ACKSIZE (sizeof(struct nlmsghdr) + sizeof(unsigned int))
/* blocks until sent, checks for valid ack
 *
 * returns 0 if ok, -1 on error
 * on NACK, returns positive nlmsg error code and sets errno to this.
 */
static int nlmsg_send(void *req, unsigned int size)
{
	char buf[BUFSIZE+ACKSIZE];
	int r;
	int nlfd = -1;
	struct nlmsghdr *msg;
	unsigned int seqnum;
	unsigned int ack_err;

	errno = 0;
	if (req == NULL)
		return -1;

	memset(buf, 0, sizeof(buf));
	seqnum = ((struct nlmsghdr *)req)->nlmsg_seq;

	nlfd = netlink_open(NETLINK_ROUTE);
	if (nlfd == -1) {
		printf("couldn't open netlink socket\n");
		goto fail;
	}

	if (nlmsg_do_send(nlfd, req, size)) {
		printf("send error\r\n");
		goto fail;
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

	/* proper NACK, return error code */
	close(nlfd);
	errno = -(int)ack_err;
	return errno;
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
	__u32 ipaddr;
	__u32 bcast;
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
	memcpy(&bcast, &ipaddr, sizeof(bcast));
	if (prefix_len < 31) {
		int i;
		for (i = 31; i >= prefix_len; --i)
		{
			bcast |= htonl((unsigned int)1<<(31-i));
		}
	}

	/* msg header */
	req.hdr.nlmsg_type  = RTM_NEWADDR;
	req.hdr.nlmsg_flags = NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK|NLM_F_REQUEST;
	req.hdr.nlmsg_len   = NLMSG_LENGTH(sizeof(req.addrmsg));
	req.hdr.nlmsg_seq   = seqnum;
	req.addrmsg.ifa_family    = AF_INET; /*32bit*/
	req.addrmsg.ifa_index     = if_nametoindex(name);
	req.addrmsg.ifa_prefixlen = prefix_len;

	if (req.addrmsg.ifa_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFA_LOCAL, &ipaddr, 4) == NULL) {
		printf("adattr failed\n");
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFA_ADDRESS, &ipaddr, 4) == NULL) {
		printf("adattr failed\n");
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), IFA_BROADCAST, &bcast, 4) == NULL) {
		printf("adattr failed\n");
		return -1;
	}
	return nlmsg_send(&req, req.hdr.nlmsg_len);
}

#define MAX_HWADDR 128
int eslib_rtnetlink_linkhwaddr(char *name, char *hwaddr)
{
	char inbuf[MAX_HWADDR];
	char outbuf[MAX_HWADDR];
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int namelen;
	unsigned int addrlen;
	unsigned int wrpos, rdpos, rdstart;

	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ) {
		printf("name too long or no null terminator\n");
		return -1;
	}
	addrlen = strnlen(hwaddr, MAX_HWADDR);
	if (addrlen >= MAX_HWADDR) {
		printf("hwaddr too long\n");
		return -1;
	}
	memset(inbuf,  0, sizeof(inbuf));
	memset(outbuf, 0, sizeof(outbuf));
	if (es_strcopy(inbuf, hwaddr, MAX_HWADDR, NULL))
		return -1;

	memset(&req,   0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	/* msg header */
	req.hdr.nlmsg_type    = RTM_NEWLINK;
	req.hdr.nlmsg_flags   = NLM_F_ACK|NLM_F_REQUEST;
	req.hdr.nlmsg_len     = NLMSG_LENGTH(sizeof(req.ifmsg));
	req.hdr.nlmsg_seq     = seqnum;
	req.ifmsg.ifi_family  = AF_UNSPEC;
	req.ifmsg.ifi_index   = (int)if_nametoindex(name);
	if (req.ifmsg.ifi_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}

	/* prepare address for kernel */
	rdpos = 0;
	wrpos = 0;
	rdstart = 0;
	while (rdpos < addrlen+1)
	{
		if (inbuf[rdpos] == ':' || inbuf[rdpos] == '\0') {
			int brk = 0;
			char *err = NULL;
			long val;
			if (inbuf[rdpos] == '\0') {
				brk = 1;
			}
			inbuf[rdpos] = '\0';
			errno = 0;
			val = strtol(&inbuf[rdstart], &err, 16);
			if (err == NULL || *err || errno || val < 0 || val > 255) {
				printf("bad hwaddress\n");
				return -1;
			}
			outbuf[wrpos] = (char)val;
			rdstart = rdpos+1;
			++wrpos;
			if (brk)
				break;
		}
		++rdpos;
	}

	addrlen = strnlen(outbuf, MAX_HWADDR);
	if (addrlen >= MAX_HWADDR)
		return -1;
	if (nlmsg_addattr(&req.hdr, sizeof(req),IFLA_ADDRESS,outbuf,
				(unsigned short)(1+addrlen))==NULL)
		return -1;
	return nlmsg_send(&req, req.hdr.nlmsg_len);

}

/* either up or down */
static int eslib_rtnetlink_linkset(char *name, int up)
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
	req.hdr.nlmsg_len     = NLMSG_LENGTH(sizeof(req.ifmsg));
	req.hdr.nlmsg_seq     = seqnum;
	req.ifmsg.ifi_family  = AF_UNSPEC;
	req.ifmsg.ifi_index   = (int)if_nametoindex(name);
	req.ifmsg.ifi_change |= IFF_UP;
	if (up)
		req.ifmsg.ifi_flags |= IFF_UP;
	else
		req.ifmsg.ifi_flags &= (unsigned int)~IFF_UP;

	if (req.ifmsg.ifi_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}

	return nlmsg_send(&req, req.hdr.nlmsg_len);

}
int eslib_rtnetlink_linksetup(char *name)
{
	return eslib_rtnetlink_linkset(name, 1);
}
int eslib_rtnetlink_linksetdown(char *name)
{
	return eslib_rtnetlink_linkset(name, 0);
}
/* delete link by name */
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
	req.hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(req.ifmsg));
	req.hdr.nlmsg_seq    = seqnum;
	req.ifmsg.ifi_family = AF_UNSPEC;
	req.ifmsg.ifi_index  = (int)if_nametoindex(name);

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
	unsigned short namelen;
	struct rtattr *linkinfo, *infodata, *infopeer;

	namelen = (unsigned short)(strnlen(name, sizeof(name1)+1)+1);/*+space for 1digit*/
	if (namelen > sizeof(name1)) {
		printf("veth interface name too long\n");
		return -1;
	}
	if (es_sprintf(name1, sizeof(name1), NULL, "%s1", name))
		return -1;
	if (es_sprintf(name2, sizeof(name2), NULL, "%s2", name))
		return -1;

	/* set interface 1 name */
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
	req->hdr.nlmsg_len += sizeof(req->ifmsg);
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

#ifdef NEWNET_IPVLAN
static int create_ipvlan(struct rtnl_iface_req *req, char *name, char *master)
{
	struct rtattr *linkinfo, *infodata;
	unsigned short namelen;
	__u32 mindex;
	__u16 mode = IPVLAN_MODE_L2;

	if (master == NULL || *master == '\0') {
		printf("no master interface\n");
		return -1;
	}
	namelen = (unsigned short)strnlen(name, IFNAMSIZ+1);
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
		printf("error, master interface(%s): %s\n", master, strerror(errno));
		return -1;
	}

	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_LINK,
				&mindex, sizeof(mindex)) == NULL)
		goto attr_fail;
	/* set interface name */
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
	printf("create ipvlan failure\n");
	return -1;
}
#endif
#ifdef NEWNET_MACVLAN
static int create_macvlan(struct rtnl_iface_req *req, char *name, char *master)
{
	struct rtattr *linkinfo;/*, *infodata;*/
	unsigned short namelen;
	__u32 mindex;
	/*__u16 mode = MACVLAN_MODE_PASSTHRU;*/
	if (master == NULL || *master == '\0') {
		printf("no master interface\n");
		return -1;
	}
	namelen = (unsigned short)strnlen(name, IFNAMSIZ+1);
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
		printf("error, master interface(%s): %s\n", master, strerror(errno));
		return -1;
	}

	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_LINK,
				&mindex, sizeof(mindex)) == NULL)
		goto attr_fail;
	/* set interface name */
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_IFNAME, name, namelen) == NULL)
		goto attr_fail;
	/* nest linkinfo */
	linkinfo = nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_LINKINFO, NULL, 0);
	if (linkinfo == NULL)
		goto attr_fail;
	if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_INFO_KIND, "macvlan", 7) == NULL)
		goto attr_fail;
	/* nest info data */
	/*infodata = nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	if (infodata == NULL)
		goto attr_fail;
	*//* set mode */
	/*if (nlmsg_addattr(&req->hdr, sizeof(*req), IFLA_MACVLAN_MODE,
				&mode, sizeof(mode)) == NULL)
		goto attr_fail;
	*/
	/* update nest lengths */
	/*if (nlmsg_nest_end(&req->hdr, infodata))
		goto attr_fail;
	*/if (nlmsg_nest_end(&req->hdr, linkinfo))
		goto attr_fail;

	return 0;

attr_fail:
	printf("create macvlan failure\n");
	return -1;
}
#endif

int eslib_rtnetlink_linknew(char *name, char *kind, void *typedat)
{
	struct rtnl_iface_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int devkind;

	if (name == NULL || *name == '\0') {
		return -1;
	}
	if (strncmp(kind, "veth", 4) == 0) {
		devkind = ESRTNL_KIND_VETHBR;
	}
	else if (strncmp(kind, "ipvlan", 6) == 0) {
		devkind = ESRTNL_KIND_IPVLAN;
	}
	else if (strncmp(kind, "macvlan", 7) == 0) {
		devkind = ESRTNL_KIND_MACVLAN;
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
	req.hdr.nlmsg_len    = NLMSG_LENGTH(sizeof(req.ifmsg));
	req.hdr.nlmsg_seq    = seqnum;
	req.ifmsg.ifi_family = AF_UNSPEC;

	switch (devkind)
	{
	case ESRTNL_KIND_VETHBR:
		if (create_veth(&req, name))
			return -1;
		break;
/* ------------------------------------------------ */
	case ESRTNL_KIND_IPVLAN:
#ifdef NEWNET_IPVLAN
		if (create_ipvlan(&req, name, typedat))
			return -1;
#else
		return -1;
#endif
		break;
	case ESRTNL_KIND_MACVLAN:
#ifdef NEWNET_MACVLAN
		if (create_macvlan(&req, name, typedat))
			return -1;
#else
		return -1;
#endif
		break;
/* ------------------------------------------------ */
	default:
		printf("switch default: %p\n", typedat);
		return -1;
	}
	return nlmsg_send(&req, req.hdr.nlmsg_len);
}


int eslib_rtnetlink_linksetns(char *name, __u32 target, int is_pid)
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
	req.hdr.nlmsg_len     = NLMSG_LENGTH(sizeof(req.ifmsg));
	req.hdr.nlmsg_seq     = seqnum;
	req.ifmsg.ifi_family  = AF_UNSPEC;
	req.ifmsg.ifi_index   = (int)if_nametoindex(name);
	if (req.ifmsg.ifi_index == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req),
				is_pid ? IFLA_NET_NS_PID : IFLA_NET_NS_FD,
				&target,
				4) == NULL) {
		printf("addattr fail\n");
		return -1;
	}


	return nlmsg_send(&req, req.hdr.nlmsg_len);
}

int eslib_rtnetlink_linksetname(char *name, char *newname)
{
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
	if (es_strcopy(req.ifr_name, name, IFNAMSIZ, NULL))
		return -1;
	if (es_strcopy(req.ifr_newname, newname, IFNAMSIZ, NULL))
		return -1;
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

int eslib_rtnetlink_setgateway(char *name, char *addr)
{
	struct rtnl_rt_req req;
	struct timespec t;
	unsigned int seqnum;
	unsigned int namelen;
	__u32 gwaddr;
	__u32 idx;
	namelen = strnlen(name, IFNAMSIZ+1);
	if (namelen > IFNAMSIZ) {
		printf("name too long or no null terminator\n");
		return -1;
	}

	if (inet_pton(AF_INET, addr, &gwaddr) <= 0) {
		printf("bad ipv4 gateway address(%s)\n", addr);
		return -1;
	}
	memset(&req, 0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	/* msg header */
	req.hdr.nlmsg_type     = RTM_NEWROUTE;
	req.hdr.nlmsg_flags    = NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	req.hdr.nlmsg_len      = NLMSG_LENGTH(sizeof(req.rmsg));
	req.hdr.nlmsg_seq      = seqnum;
	req.rmsg.rtm_family    = AF_INET;
	req.rmsg.rtm_table     = RT_TABLE_MAIN;
	req.rmsg.rtm_scope     = RT_SCOPE_UNIVERSE;
	req.rmsg.rtm_type      = RTN_UNICAST;
	req.rmsg.rtm_protocol  = RTPROT_BOOT;
	idx = if_nametoindex(name);
	if (idx == 0) {
		printf("could not get index for interface: %s\n", name);
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), RTA_GATEWAY, &gwaddr, 4) == NULL) {
		printf("addattr fail\n");
		return -1;
	}
	if (nlmsg_addattr(&req.hdr, sizeof(req), RTA_OIF, &idx, 4) == NULL) {
		printf("addattr fail\n");
		return -1;
	}

	return nlmsg_send(&req, req.hdr.nlmsg_len);
}

static int rtnetlink_get_dumptbl(struct rtattr *tbl[], unsigned int tblcount,
		   char *msgdat, unsigned int bounds, int type)
{
	unsigned short rtatype;
	struct rtattr *rta;

	/* handle type specific header sizes */
	switch (type)
	{
	case RTM_GETROUTE:
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		if (tblcount != __RTA_MAX) {
			printf("bad tblcount\n");
			return -1;
		}
		rta = RTM_RTA(msgdat);
		break;
	case RTM_GETLINK:
	case RTM_NEWLINK:
	case RTM_DELLINK:
		if (tblcount != __IFLA_MAX) {
			printf("bad tblcount\n");
			return -1;
		}
		rta = IFLA_RTA(msgdat);
		break;
	default:
		printf("dumptbl error\n");
		return -1;
	}
	memset(tbl, 0, sizeof(struct rtattr *) * tblcount);
	while(RTA_OK(rta, bounds))
	{
		rtatype = rta->rta_type;
		if (rtatype >= tblcount) {
			printf("unexpected rtatype: %d\n", rtatype);
			return -1;
		}
		if (tbl[rtatype] == NULL) {
			tbl[rtatype] = rta;
		}
		rta = RTA_NEXT(rta, bounds);
	}
	return 0;
}

struct rtattr *rtnetlink_get_attr(struct rtattr *attr, unsigned int bounds,
                                  unsigned short rta_type)
{
	errno = 0;
	if (!attr) {
		errno = EINVAL;
		return NULL;
	}
	while (RTA_OK(attr, bounds))
	{
		if (attr->rta_type == rta_type)
			return attr;
		attr = RTA_NEXT(attr, bounds);
	}
	errno = ESRCH;
	return NULL;
}

static const char *get_rtm_typestr(int type)
{
	switch (type)
	{
		case RTM_GETLINK:
			return "RTM_GETLINK";
		case RTM_GETADDR:
			return "RTM_GETADDR";
		case RTM_GETROUTE:
			return "RTM_GETROUTE";
		case RTM_GETNEIGH:
			return "RTM_GETNEIGH";
		case RTM_GETRULE:
			return "RTM_GETRULE";
		case RTM_GETQDISC:
			return "RTM_GETQDISC";
		case RTM_GETTCLASS:
			return "RTM_GETTCLASS";
		case RTM_GETTFILTER:
			return "RTM_GETTFILTER";
		case RTM_GETACTION:
			return "RTM_GETACTION";
		case RTM_GETMULTICAST:
			return "RTM_GETMULTICAST";
		case RTM_GETANYCAST:
			return "RTM_GETANYCAST";
		case RTM_GETNEIGHTBL:
			return "RTM_GETNEIGHTBL";
		case RTM_GETADDRLABEL:
			return "RTM_GETADDRLABEL";
		case RTM_GETDCB:
			return "RTM_GETDCB";
		case RTM_GETMDB:
			return "RTM_GETMDB";
		case RTM_GETNSID:
			return "RTM_GETNSID";
		case RTM_GETSTATS:
			return "RTM_GETSTATS";
		default:
			return "unspecified";
	}
}

/*
 *  dio is a struct containing function pointer with input/output pointers,
 *  type is the dump type, RTM_GETLINK, RTM_GETROUTE, etc..
 */
int eslib_rtnetlink_dump(struct rtnl_decode_io *dio, unsigned short type)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifmsg;
		struct rtattr ext __attribute__ ((aligned(NLMSG_ALIGNTO)));
		__u32 ext_filter_mask;
	} req;
	char buf[BUFSIZE];
	struct timespec t;
	struct nlmsghdr *msg;
	unsigned int seqnum;
	int nlfd;
	int r;
	unsigned int msgsize;
	int intr = 0;
	unsigned int msgdat_size = 0;
	unsigned int tblcount = 0;
	struct rtattr **tbl;
	unsigned int msgcount = 0;

	if (dio == NULL)
		return -1;

	nlfd = netlink_open(NETLINK_ROUTE);
	if (nlfd == -1) {
		printf("couldn't open netlink socket\n");
		return -1;
	}

	errno = 0;
	memset(buf,  0, sizeof(buf));
	memset(&req, 0, sizeof(req));
	clock_gettime(CLOCK_MONOTONIC_RAW, &t);
	seqnum = (unsigned int)((t.tv_sec + t.tv_nsec)^getpid());
	/* msg header */
	req.hdr.nlmsg_type     = type;
	req.hdr.nlmsg_flags    = NLM_F_DUMP|NLM_F_REQUEST;
	req.hdr.nlmsg_len      = sizeof(req);
	req.hdr.nlmsg_seq      = seqnum;
	req.ifmsg.ifi_family   = AF_INET;
	req.ext.rta_type       = IFLA_EXT_MASK;
	req.ext.rta_len	       = RTA_LENGTH(4);
	req.ext_filter_mask    = RTEXT_FILTER_VF;
	if (nlmsg_do_send(nlfd, &req, req.hdr.nlmsg_len)) {
		close(nlfd);
		return -1;
	}

	r = nlmsg_do_recv(nlfd, buf, sizeof(buf));
	if (r <= 0 || (unsigned int)r > sizeof(buf)) {
		printf("recv linkdump failure\n");
		close(nlfd);
		return -1;
	}
	msgsize = (unsigned int)r;
	close(nlfd);
	msg = (struct nlmsghdr *)buf;
	if (msg->nlmsg_seq != seqnum) {
		printf("seqnum mismatch %d %d\n", msg->nlmsg_seq, seqnum);
		return -1;
	}

	switch (type)
	{
	case RTM_GETROUTE:
		tblcount = __RTA_MAX;
		msgdat_size = sizeof(struct rtmsg);
		break;
	case RTM_GETLINK:
		tblcount = __IFLA_MAX;
		msgdat_size = sizeof(struct ifinfomsg);
		break;
	default:
		printf("unsupported dump type\n");
		return -1;
	}
	tbl = malloc(sizeof(struct rtattr *) * tblcount);
	if (tbl == NULL)
		return -1;

	/* parse each message */
	while(NLMSG_OK(msg, msgsize))
	{
		char *msgdat;
		unsigned int size;

		if (msg->nlmsg_flags & NLM_F_DUMP_INTR) {
			intr = 1;
		}
		if (msg->nlmsg_type == NLMSG_DONE) {
			break;
		}
		if (msg->nlmsg_type == NLMSG_ERROR) {
			printf("NLMSG_ERROR\n");
			goto free_err;
		}

		/* dump */
		msgdat = NLMSG_DATA(msg);
		if (msg->nlmsg_len - NLMSG_LENGTH(msgdat_size) <= 0) {
			printf("bad nlmsg_len\n");
			goto free_err;
		}
		size = msg->nlmsg_len - NLMSG_LENGTH(msgdat_size);
		if (rtnetlink_get_dumptbl(tbl, tblcount, msgdat, size, msg->nlmsg_type)) {
			printf("dumptbl failed\n");
			goto free_err;
		}
		/* decode callback */
		if (dio->decode(dio, msgdat, msgdat_size, tbl, tblcount)) {
			printf("decode error\n");
			goto free_err;
		}
		msg = NLMSG_NEXT(msg, msgsize);
		if (++msgcount == 0)
			_exit(-1);
	}

	free(tbl);
	if (intr)
	{
		printf("dump was interrupted\n");
		errno = EAGAIN;
		return -1;
	}
	if (msgsize) {
		if (msgcount == 0) {
			printf("empty rtnetlink msg\n");
			printf("msg type(%d): %s\n", type, get_rtm_typestr(type));
			return -1;
		}
		else {
			printf("unexpected leftover bytes: %d\n", msgsize);
			printf("msg type(%d): %s\n", type, get_rtm_typestr(type));
		}
		_exit(-1);
	}

	return 0;

free_err:
	free(tbl);
	return -1;

}

#define GWSIZE 16
int decode_gateway(struct rtnl_decode_io *dio, void *msg, unsigned int msgsize,
		    struct rtattr *tbl[], unsigned int tblcount)
{
	char gateway[GWSIZE];
	int ifidx;
	struct rtmsg *rtm = msg;
	if (rtm == NULL || tbl == NULL)
		return -1;
	if (rtnl_decode_check(dio, sizeof(ifidx), sizeof(gateway),
				RTM_GETROUTE, msgsize, tblcount))
		return -1;

	memcpy(&ifidx, dio->in, sizeof(ifidx));

	/* GW decode */
	if (rtm->rtm_family != AF_INET) {
		printf("NOT AF_INET\r\n");
		return 0;
	}
	if (tbl[RTA_GATEWAY]) {
		int oif = 0;
		if (tbl[RTA_OIF])
			memcpy(&oif, (int *)RTA_DATA(tbl[RTA_OIF]), sizeof(int));
		else
			return 0;
		if (oif != ifidx)
			return 0;

		if (inet_ntop(AF_INET, RTA_DATA(tbl[RTA_GATEWAY]),
					gateway, sizeof(gateway)) == NULL) {
			printf("inet_ntop: %s\n", strerror(errno));
			return -1;
		}
		gateway[GWSIZE-1] = '\0';
		memcpy(dio->out, gateway, GWSIZE);
	}

	return 0;
}

char g_gateway[GWSIZE];
char *eslib_rtnetlink_getgateway(char *name)
{
	struct rtnl_decode_io dio;
	__u32 idx;

	memset(&g_gateway, 0, GWSIZE);
	memset(&dio, 0, sizeof(dio));
	idx = if_nametoindex(name);
	if (idx == 0) {
		printf("could not get index for interface: %s\n", name);
		return NULL;
	}

	rtnl_decode_setcallback(&dio, decode_gateway);
	rtnl_decode_setinput(&dio, &idx, sizeof(idx));
	rtnl_decode_setoutput(&dio, g_gateway, GWSIZE);

	if (eslib_rtnetlink_dump(&dio, RTM_GETROUTE))
		return NULL;
	else
		return g_gateway;
}

