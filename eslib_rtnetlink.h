/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */

#ifndef __ESLIB_RTNETLINK_H_
#define __ESLIB_RTNETLINK_H_

#include <linux/types.h>

#define ESRTNL_KIND_INVALID   0
#define ESRTNL_KIND_UNKNOWN   1
#define ESRTNL_KIND_LOOP      2
#define ESRTNL_KIND_VETHBR    3
#define ESRTNL_KIND_IPVLAN    4
#define ESRTNL_KIND_MACVLAN   5

#define ESRTNL_DUMP_LINK      0
#define ESRTNL_DUMP_LINK_INFO 1
#define ESRTNL_DUMP_ROUTE     2

/* an abstract way of parsing rtnetlink device dump */
struct rtnl_decode_io;
struct rtattr;

typedef int (*rtnl_decode_callback)(struct rtnl_decode_io *dio,
				    void *msg, /* type specific struct */
				    unsigned int msgsize,
				    struct rtattr *tbl[],
				    unsigned int tblcount);
struct rtnl_decode_io {
	rtnl_decode_callback decode;
	void *in;
	void *out;
	__u32 insize;
	__u32 outsize;
};

/* set the dio function pointer */
void rtnl_decode_setcallback(struct rtnl_decode_io *dio, rtnl_decode_callback decode);
/* set input parameters */
void rtnl_decode_setinput(struct rtnl_decode_io  *dio, void *v, __u32 size);
/* set output parameters */
void rtnl_decode_setoutput(struct rtnl_decode_io *dio, void *v, __u32 size);
/* verify type specific data, and io parameters */
int rtnl_decode_check(struct rtnl_decode_io *dio, __u32 insize, __u32 outsize,
			__u32 type, __u32 msgsize, __u32 tblcount);
/* returns -1 and errno set to EAGAIN if dump was interrupted */
int eslib_rtnetlink_dump(struct rtnl_decode_io *dio, int type);

/* return nested attr of specific type */
struct rtattr *rtnetlink_get_attr(struct rtattr *attr, unsigned int bounds,
                                  unsigned short rta_type);
int eslib_rtnetlink_linknew(char *name, char *type, void *typedat);
int eslib_rtnetlink_linkdel(char *name);
int eslib_rtnetlink_linksetup(char *name);
int eslib_rtnetlink_linksetdown(char *name);
int eslib_rtnetlink_linkaddr(char *name, char *addr, unsigned char prefix_len);
int eslib_rtnetlink_linksetns(char *name, __u32 target, int is_pid);
int eslib_rtnetlink_linksetname(char *name, char *newname);

int eslib_rtnetlink_setgateway(char *name, char *addr);
/* returns either NULL or pointer to a local gateway string */
char *eslib_rtnetlink_getgateway(char *name);

#endif
