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

#ifndef ESLIB_H__
#define ESLIB_H__

#include <sys/types.h>
#ifndef MAX_SYSTEMPATH
	#define MAX_SYSTEMPATH 2048
#endif

#define ESLIB_LOG_MAXMSG 1024
#define ESLIB_MAX_PROCNAME 32

/* eslib_file_bind bit flags */
#define ESLIB_BIND_PRIVATE      0  /* private is the implied default                  */
#define ESLIB_BIND_SHARED 	1  /* shared & slave can't both be true, if they are  */
#define ESLIB_BIND_SLAVE 	2  /* slave has priority                              */
#define ESLIB_BIND_NONRECURSIVE	4  /* apply propagation flag non-recursively          */
#define ESLIB_BIND_UNBINDABLE 	8
#define ESLIB_BIND_CREATE	16 /* create destination paths(0755) and files        */

/* =====================================
 * 		sockets
 * =====================================
 */
struct ucred;

/*
 *  calls shutdown and close on socket. shutdown will render the socket
 *  useless for other threads, if forking and sharing use close instead.
 *  returns
 *   0	- ok
 *  -1	- error (can ignore)
 */
int eslib_sock_axe(int sock);

/*
 *  set socket as nonblocking
 *  returns
 *   0	- ok
 *  -1	- error
 */
int eslib_sock_setnonblock(int sock);

/*
 *  create a passive socket with given connection backlog size at path.
 *  creates the full path if needed with 0755 permission, use caution!
 *  returns
 *   fd - ok
 *  -1	- error
 */
int eslib_sock_create_passive(char *path, int backlog);

/*
 *  send fd over socket, data will be single character 'F'
 *  returns
 *   0  - ok
 *  -1	- error
 */
int eslib_sock_send_fd(int sock, int fd);

/*
 *  receive fd in fd_out over socket, data must be single character 'F'
 *  returns
 *   0	- ok
 *  -1	- errno EAGAIN set if nonblocking socket, try again.
 *  		other error codes may also be set from recvmsg.
 */
int eslib_sock_recv_fd(int sock, int *fd_out);

/* send/recv process credentials */
int eslib_sock_send_cred(int sock);
int eslib_sock_recv_cred(int sock, struct ucred *out_creds);


/* =====================================
 * 		files
 * =====================================
 */


/*
 *  validate a system path.
 *  the stringlen should be less than MAX_SYSTEMPATH
 *  must be a full path, starting with /
 *  //'s and ..'s are not permitted.
 *  must not end with / unles len == 1
 *
 *  returns
 *   0	- ok
 *  -1	- bad path
 */
int eslib_file_path_check(char *path);

/*
 *  copy into outpath the parent directory of inpath filename.
 *  outpath must point to a char array big enough to hold
 *  MAX_SYSTEMPATH characters
 *  returns
 *   0	- ok
 *  -1	- bad path
 */
int eslib_file_getparent(char *inpath, char outpath[MAX_SYSTEMPATH]);

/*
 *  check if file exists
 *  returns
 *   1	- yes
 *   0	- no
 *  -1  - error
 */
int eslib_file_exists(char *path);

/*
 *  check if file is a regular file
 *  returns
 *   1	- yes
 *   0	- no
 *  -1  - error
 */
int eslib_file_isfile(char *path);

/*
 *  check if file is a directory
 *  returns
 *   1	- yes
 *   0	- no
 *  -1  - error
 */
int eslib_file_isdir(char *path);

/*
 *  create the full path if any directories did not exist using mode
 *  sets ownership of new directories to process real uid/gid
 *  use with caution if potentially creating sensitive root system paths!
 *  returns
 *   0  - ok
 *  -1  - error
 *
 */
int eslib_file_mkdirpath(char *path, mode_t mode);

/*
 *  create file, and any directories needed to complete path using dirmode
 *  0700 permission is used for new file
 *  use with caution if potentially creating sensitive root system files/paths!
 *  returns
 *   0  - ok
 *  -1	- error
 */
int eslib_file_mkfile(char *path, mode_t dirmode);

/*
 *  returns
 *   ptr  - pointer to the filename portion of path
 *   NULL - bad path
 */
char *eslib_file_getname(char *path);

/*
 *  returns
 *  uid - file owner's uid
 *   -1 - error
 */
uid_t eslib_file_getuid(char *path);

/*
 *  returns
 *  ino - file inode number
 *    0	- error
 */
ino_t eslib_file_getino(char *path);

/*
 * bind mount files
 * src, dest  - source file and destination mount point
 * mntflags   - remount with these flags, e.g: MS_RDONLY|MS_NOSUID etc...
 * esflags    - ESLIB_BIND_* flags, mount propagation is private/recursive
 *
 * avoid using shared mounts wherever possible.
 *
 * returns
 *  0  - ok
 * -1  - error
 */
int eslib_file_bind(char *src, char *dest,unsigned long mntflags,unsigned long esflags);

/* read the entire file into supplied buffer.
 * note: if you are reading text files you might want to add your own null terminator
 *       to be on the safe side. this function is meant for general purpose file reads.
 * filename - path to file
 * buf      - buffer to copy file into
 * buf_size - size of buffer
 * out_len  - number of bytes written to buffer, may be 0 if file is empty.
 *
 * returns
 *  0 - ok
 * -1 - error
 *    + EOVERFLOW
 *  	buffer was too small. out_len will be set to file size so caller can
 *  	adjust buffer size.
 *    + ENOTSUP
 *      buffer was too small and file does not support lseek(SEEK_END).
 *      caller should blindly increase the buffer size.
 */
int eslib_file_read_full(char *filename, char *buf, size_t buf_size, size_t *out_len);

/* =====================================
 * 		process
 * =====================================
 */

/*  get the count of open files for given pid's proc entry.
 *  returns
 *  count of open fd's
 *  >0  - count of open fd's in outlist
 *   0  - no open fds
 *  -1	- error
 */
int eslib_proc_numfds(pid_t pid);

/*  get a list of open files for a given pid's proc entry.
 *  returns
 *  outlist is set to a malloc'd array of open fd's,
 *  you should free this when done.
 *  >0  - count of open fd's in outlist
 *   0  - no open fd's
 *  -1	- error
 */
int eslib_proc_alloc_fdlist(pid_t pid, int **outlist);


/*
 *  return environment variable string.
 *  null if not found,
 *  null if duplicates found, errno == ENOTUNIQ
 */
char *eslib_proc_getenv(char *name);

/*
 *  set environment variable.
 *
 *  return  0 if success
 *         -1 on error
 *  errno = ENOTUNIQ if already exists
 */
int eslib_proc_setenv(char *name, char *val);

/*
 * parses /proc/pid/cmdline once for process name
 * always returns a string, no-procname if unable to read cmdline
 */
char *eslib_proc_getname();

/*
 *  reads entire file using a single malloc
 *  return file size, or -1 on error. if file size is 0 nothing is allocated,
 *  and out pointer will be set to null. on success out points to file contents.
 *  caller is responsible for freeing out buffer.
 */
off_t eslib_procfs_readfile(char *path, char **out);

/*
 * print current process capabilities to stdout
 */
int eslib_proc_print_caps();

/* =====================================
 * 		debug halp!
 * =====================================
 */
void eslib_dbg_print_backtrace();

/* sends message to syslog, and print error message to stderr
 * using a null name will attempt to read from /proc/pid/cmdline
 */
int eslib_logmsg(char *name, char *msg);
int eslib_logerror(char *name, char *msg);
int eslib_logcritical(char *name, char *msg);

/* for log events that may be spammy, use timer.
 * timer must be initialized to 0!
 * message will not be repeated until seconds has elapsed
 */
int eslib_logmsg_t(char *name, char *msg, time_t *timer, unsigned int seconds);
int eslib_logerror_t(char *name, char *msg, time_t *timer, unsigned int seconds);
int eslib_logcritical_t(char *name, char *msg, time_t *timer, unsigned int seconds);


/* =====================================
 * 		string
 * =====================================
 */

int eslib_string_is_sane(char *buf, unsigned int len);
unsigned int eslib_string_linelen(char *buf, unsigned int size);
int eslib_string_tokenize(char *buf, const unsigned int size, char *delimiter);
char *eslib_string_toke(char *buf, unsigned int idx,
			const unsigned int size, unsigned int *advance);
int eslib_string_to_int(char *str, int *out);
int eslib_string_sprintf(char *dst, const unsigned int size,
			 unsigned int *outlen, const char *fmt, ...);
int eslib_string_copy(char *dst, const char *src,
		      const unsigned int size, unsigned int *outlen);

/* =====================================
 * 		macros
 * =====================================
 */

#define es_sprintf eslib_string_sprintf
#define es_strcopy  eslib_string_copy


/*
 * compare two timevals, returns (current - start > millisec)
 * do not use this for a long term timer, unless 64bit types!
 */
#define eslib_ms_elapsed(curtime_, start_, millisec_)		\
	((curtime_.tv_sec - start_.tv_sec) * 1000		\
	 + (curtime_.tv_usec - start_.tv_usec) / 1000 > millisec_ )


#endif
