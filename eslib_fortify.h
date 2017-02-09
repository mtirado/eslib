/* (c) 2017 Michael R. Tirado -- GPLv3+, GNU General Public License, version 3 or later
 * contact: mtirado418@gmail.com
 *
 * TODO ambient caps /+ ifdefs
 */

#ifndef ESLIB_FORTIFY_H__
#define ESLIB_FORTIFY_H__

#include <linux/audit.h>
#include <linux/seccomp.h>

#define MAX_SYSCALLS 1000
#define MAX_SYSCALL_NAME 64
#define MAX_CAP_NAME 64
#define NUM_OF_CAPS 64

/* SECCOMP_RET_DATA values,
 * this is only reliable if process only has one seccomp filter
 * and cannot install additional filters, use SECCOPT_BLOCKNEW.
 */
#define SECCRET_DENIED 0xF0FF

/* seccomp filter options */
#define SECCOPT_BLOCKNEW 0x1
#define SECCOPT_PTRACE   0x2

#ifdef __x86_64__ /* TODO this is untested... add other arch's */
	#define SYSCALL_ARCH AUDIT_ARCH_X86_64
#elif __i386__
	#define SYSCALL_ARCH AUDIT_ARCH_I386
#else
	#error arch lacks systemcall define, add it and test!
#endif

/* try to load blacklist from /etc/eslib/seccomp_blacklist or other locations */
int *alloc_sysblacklist(unsigned int *outcount);
/* caller must free the syscall array returned here */
int *alloc_seccomp_sclist(char *file, unsigned int *outcount);
/* set caps, and if locking set secbits/no_new_privs accordingly */
int set_caps(int *cap_b, int *cap_e, int *cap_p, int *cap_i, int ignore_blacklist);
/* check if capability is globally blacklisted */
int cap_blacklisted(unsigned long cap);
/* call this after mnt namespace is unshared and if any chroot_path mounts are setup */
int fortify(char *chroot_path,
		 uid_t set_resuid, /* if these are 0, no setresuid call is made */
		 gid_t set_resgid,
		 int  *whitelist,
		 int  *blocklist,
		 unsigned long seccomp_opts,
		 int cap_b[NUM_OF_CAPS],
		 int cap_e[NUM_OF_CAPS],
		 int cap_p[NUM_OF_CAPS],
		 int cap_i[NUM_OF_CAPS],
		 int ignore_cap_blacklist,
		 int fs_write,
		 int fs_exec);

/* return number syscalls in array terminated by -1 */
unsigned int count_syscalls(int *syscalls, unsigned int maxcount);
/*
 * builds a seccomp filter program for arch specified.
 * whitelist should be an array that holds (count) syscall numbers.
 * blocklist is placed after whitelist, these syscalls will be rejected so if
 * retaction is SECCOMP_RET_KILL program gets ENOSYS instead of a swift sigkill
 *
 * if whitelist is not specified blocklist becomes a simple blacklist
 * and currently options are ignored for simple blacklist.
 * TODO fix this and add BLOCKNEW if using RET_TRAP
 * TODO use option for implicit pid1 whitelist (exec clone kill ...)
 *
 * arch: AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, etc.
 */
int filter_syscalls(int arch, int *whitelist, int *blocklist,
		    unsigned int wcount, unsigned int bcount,
		    unsigned int options, long retaction);
/* defstring should be the syscalls #define name,
 * e.g: "__NR_fork"
 * returns the value of the define, or -1 on error
 */
int syscall_getnum(char *defstring);
/* returns pointer to string name of that system call
 * NULL if not recognized.
 */
char *syscall_getname(long syscall_nr);
/* print systemcalls in sc_translate table */
void syscall_printknown();
/* returns total number of systemcall entries in sc_translate table */
unsigned int syscall_tablesize();
/* return the highest system call number */
unsigned int syscall_gethighest();
/*
 * return value of capability, defined in <linux/capability.h>
 * -1/NULL is an error
 */
int cap_getnum(char *defstring);
char *cap_getname(int cap_nr);


#endif
