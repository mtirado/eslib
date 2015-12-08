/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#ifndef ESLIB_H__
#define ESLIB_H__

#include <sys/types.h>


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
 *  send fd over socket
 *  returns
 *   0  - ok
 *  -1	- error
 */
int eslib_sock_send_fd(int sock, int fd);

/*
 *  receive fd in fd_out over socket
 *  returns
 *   0	- ok
 *  -1	- errno EAGAIN set if nonblocking socket, try again.
 *  		other error codes may also be set from recvmsg.
 */
int eslib_sock_recv_fd(int sock, int *fd_out);

#if 0
int eslib_sock_send_cred(int sock);
int eslib_sock_recv_cred(int sock, struct ucred *out_creds);
#endif





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
 *  use with caution if potentially creating root system paths!
 *  returns
 *   0  - ok
 *  -1  - error
 *
 */
int eslib_file_mkdirpath(char *path, mode_t mode);

/*
 *  create file, and any directories needed to complete path using dirmode
 *  0700 permission is used for new file
 *  use with caution if potentially creating root system files/paths!
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
int eslib_proc_getfds(pid_t pid, int **outlist);





/* =====================================
 * 		debug halp!
 * =====================================
 */
void eslib_dbg_print_backtrace();

#endif
