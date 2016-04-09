/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */

#ifndef __ESLIB_RTNETLINK_H_
#define __ESLIB_RTNETLINK_H_

#include <linux/types.h>

#define RTNL_LINKDOWN 0
#define RTNL_LINKUP   1

#define RTNL_KIND_INVALID 0
#define RTNL_KIND_UNKNOWN 1
#define RTNL_KIND_LOOP    2
#define RTNL_KIND_VETHBR  3
#define RTNL_KIND_IPVLAN  4


/* an abstract way of parsing rtnetlink device dump */
struct rtnl_decode_io;
struct rtattr;
struct rtmsg;

typedef int (*rtnl_decode_callback)(struct rtmsg *rtm,
				    struct rtattr *tbl[],
				    struct rtnl_decode_io *dio);
struct rtnl_decode_io {
	rtnl_decode_callback decode;
	void *in;
	void *out;
	__u32 insize;
	__u32 outsize;
};
void rtnl_decode_setcallback(struct rtnl_decode_io *dio, rtnl_decode_callback decode);
void rtnl_decode_setinput(struct rtnl_decode_io  *dio, void *v, __u32 size);
void rtnl_decode_setoutput(struct rtnl_decode_io *dio, void *v, __u32 size);
int rtnl_decode_check(struct rtnl_decode_io *dio, __u32 insize, __u32 outsize);

/* returns -1 and errno set to EAGAIN if dump was interrupted */
int eslib_rtnetlink_dump(struct rtnl_decode_io *dio, char *name, int type);


#endif