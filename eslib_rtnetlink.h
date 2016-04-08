/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */

#ifndef __ESLIB_RTNETLINK_H_
#define __ESLIB_RTNETLINK_H_

/* an abstract way of parsing rtnetlink device dump */
struct rtnl_decode_io;
struct rtattr;

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
void rtnl_decode_setinput(struct rtnl_decode_io  *dio, void *v, __u32 size);
void rtnl_decode_setoutput(struct rtnl_decode_io *dio, void *v, __u32 size);

/* returns -1 and errno set to EAGAIN if dump was interrupted */
int eslib_rtnetlink_dump(char *name, int type,
			 rtnl_decode_callback decode,
			 struct rtnl_decode_io *dio);
#endif
