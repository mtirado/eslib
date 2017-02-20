/* (c) 2017 Michael R. Tirado -- GPLv3+, GNU General Public License, version 3 or later
 * contact: mtirado418@gmail.com
 *
 */

#ifndef ESLIB_FORTIFY_H__
#define ESLIB_FORTIFY_H__

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#define MAX_SYSCALLS 500
#define MAX_SYSCALL_NAME 64
#define MAX_CAP_NAME 64
#define NUM_OF_CAPS 64
#define MAX_BPFSTACK ((MAX_SYSCALLS * 2)+64)
/* SECCOMP_RET_DATA values,
 * this is only reliable if process only has one seccomp filter
 * and cannot install additional filters, use SECCOPT_BLOCKNEW.
 */
#define SECCRET_DENIED 0xF0FF

/* seccomp filter options */
#define SECCOPT_BLOCKNEW      1 /* block additional seccomp filters     */
#define SECCOPT_PTRACE        2 /* allow ptrace                         */

#ifdef __x86_64__ /* TODO this is untested... add other arch's */
	#define SYSCALL_ARCH AUDIT_ARCH_X86_64
#elif __i386__
	#define SYSCALL_ARCH AUDIT_ARCH_I386
#else
	#error arch lacks systemcall define, add it and test!
#endif

/* fortify flags */
#define ESLIB_FORTIFY_IGNORE_CAP_BLACKLIST 1 /* dangerously ignore the cap blacklist  */
#define ESLIB_FORTIFY_SHARE_NET	  	   2 /* share network namespaces              */
#define ESLIB_FORTIFY_STRICT	  	   4 /* seccomp kills if not graylisted       */

struct syscall_list {
	int *list;
	unsigned int count;
};
struct seccomp_program {
	struct sock_filter  bpf_stack[MAX_BPFSTACK];
	struct sock_fprog   prog;
	struct syscall_list white;
	struct syscall_list black;
	unsigned long seccomp_opts;
	long retaction;
};
void seccomp_program_init(struct seccomp_program *filter);
/*
 * builds a seccomp filter program for SYSCALL_ARCH.
 * list are int[MAX_SYSCALLS] that holds syscall numbers.
 * if whitelist is missing a simple blacklist is installed.
 * if white & black exist,  blocklist is placed after whitelist, these syscalls
 * will be rejected so if using ESLIB_FORTIFY_STRICT, program gets ENOSYS
 * instead of a swift sigkill
 *
 * TODO blacklist opts
 */
int  seccomp_program_build(struct seccomp_program *filter);
int  seccomp_program_install(struct seccomp_program *filter);

/*
 * the only privileges supported are ones directly inherited, no file caps.
 * and there are some dangerous pitfalls to know if you need this feature.
 * here is some advice instead of trying to write complex generalized sanity checks:
 *
 * 1) avoid inheriting caps completely unless you're sufficiently paranoid >.<
 * 2) chroot_path should be chown 0:0 chmod 0755 or with absolutely no user control!!!
 * 3) before installing files make sure none of them are controlled by user if they may
 *    influence the privileged process in \any\ way.
 * 4) make sure all dirs are owned 0:0 0755
 * 5) if you want a home dir that is ok i guess for +wx.
 *    TODO eslib_warp_file like jettison home option with checks to make sure it's not
 *    exposing somewhere user cannot read/search.
 * 6) be 100% sure no unexpected files exist.
 *
 * so what's actually the issue here?
 *    some programs use dlopen, read config files, etc, if they exist at certain paths
 *    on startup. so an attacker could possibly gain arbitrary execution in a
 *    privileged process if they can write to these runtime paths, or other forms
 *    of control by writing config/data files.
 *
 * why no file caps?
 *   too complex for the scope of this lib, and always having NO_NEW_PRIVS is nice.
 */


/*
 * unshares mount/pid namespaces, create chroot dir and mount proc (use -1 for +w)
 */
int eslib_fortify_prepare(char *chroot_path, int mountproc);

/* bind file in chroot after calling prepare
 *
 * NOTICE:
 * caller is responsible for sorting paths, as to not mount an upper level directory
 * after already mounting a leaf file which could destroy mntflags on the leaf file.
 * e.g: first mount /usr as rdonly,noexec  then  /usr/bin /usr/lib as rdonly
 *
 * also if running with uid 0 you probably want to make sure everything is rdonly 
 */
int eslib_fortify_install_file(char *chroot_path, char *file,
		int mntflags, unsigned long esflags);


/* call this after mnt namespace is unshared and if any chroot_path mounts are setup
 * whitelist and blocklist are arrays terminated by -1
 * TODO add close tty opt
 */
int eslib_fortify(char *chroot_path,
		 uid_t set_resuid, /* if these are 0, no setresuid call is made */
		 gid_t set_resgid,
		 struct seccomp_program *filter,
		 int cap_b[NUM_OF_CAPS],
		 int cap_e[NUM_OF_CAPS],
		 int cap_p[NUM_OF_CAPS],
		 int cap_i[NUM_OF_CAPS],
		 unsigned long fortflags);


/* caller must free the syscall array returned here */
int *alloc_seccomp_sclist(char *file, unsigned int *outcount);
/* try to load blacklist from /etc/eslib/seccomp_blacklist or other locations,
 * caller must free the syscall array returned here*/
int *alloc_sysblacklist(unsigned int *outcount);
/* set caps, and if locking set secbits/no_new_privs accordingly */
int set_caps(int *cap_b, int *cap_e, int *cap_p, int *cap_i, int ignore_blacklist);
/* check if capability is globally blacklisted */
int cap_blacklisted(unsigned long cap);
/* return number syscalls in array terminated by -1 */
unsigned int count_syscalls(int *syscalls, unsigned int maxcount);
/*int filter_syscalls(struct seccomp_program *filter);*/
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
