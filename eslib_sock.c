/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "eslib.h"


/*
 *  completely disconnect socket.
 */
int eslib_sock_axe(int sock)
{
	shutdown(sock, SHUT_RDWR);
	if (close(sock)) {
		printf("socket close error: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}


int eslib_sock_setnonblock(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		printf("fcntl F_GET_FL: %s\n", strerror(errno));
		return -1;
	}
	flags |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, flags)) {
		printf("fcntl F_SET_FL: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}


int eslib_sock_create_passive(char *path, int backlog)
{
	int r;
	int sock;
	struct sockaddr_un addr;
	if (path == NULL)
		return -1;

	/* will be truncated at sizeof addr.sun_path - 1*/
	if (strnlen(path, MAX_SYSTEMPATH) >= MAX_SYSTEMPATH) {
		printf("path too long\n");
		return -1;
	}

	/* set socket path, and type */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

	path = addr.sun_path;

	/* create path if it does not exist */
	r = eslib_file_exists(path);
	if (r == 0) {
		printf("file does not exist, will create: %s \n", path);
		if (eslib_file_mkfile(path, 0755))
			printf("mkfile error\n");
	}
	else if (r == -1)
		return -1;

	/* new socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return -1;
	if (eslib_sock_setnonblock(sock))
		goto fail;


	if (unlink(path)) {
		printf("error removing socket file: %s\n", strerror(errno));
		goto fail;
	}
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind(): %s\n", strerror(errno));
		goto fail;
	}

	/* passive mode */
	if (listen(sock, backlog)) {
		printf("listen(): %s\n", strerror(errno));
		goto fail;
	}

	/* set rw permission */
	chmod(path, 0766);
	return sock;

fail:
	close(sock);
	return -1;
}



/*
 *  will block for around 5(+) milliseconds if EINTR before failing
 */
int eslib_sock_send_fd(int sock, int fd)
{
	union {
		struct cmsghdr cmh;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmhp;
	struct msghdr msgh;
	struct iovec iov;
	int  retval;
	char data = 'F';
	int  i;

	if (sock == -1 || fd == -1) {
		printf("invalid descriptor\n");
		return -1;
	}

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_control = control_un.control;
	msgh.msg_controllen = sizeof(control_un.control);

	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	cmhp = CMSG_FIRSTHDR(&msgh);
	cmhp->cmsg_len = CMSG_LEN(sizeof(int));
	cmhp->cmsg_level = SOL_SOCKET;
	cmhp->cmsg_type = SCM_RIGHTS;
	*((int *)CMSG_DATA(cmhp)) = fd;
	for (i = 0; i < 100; ++i) {
		retval = sendmsg(sock, &msgh, MSG_DONTWAIT);
		if (retval == -1 && errno == EINTR) {
			usleep(50);
			continue;
		}
		else {
			break;
		}
	}

	if (retval != (int)iov.iov_len){
		printf("sendmsg returned: %d\n", retval);
		if (retval == -1)
			printf("sendmsg error(%d): %s\n",
					retval, strerror(errno));
		return -1;
	}

	return 0;
}



int eslib_sock_recv_fd(int sock, int *fd_out)
{
	union {
		struct cmsghdr cmh;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmhp;
	struct msghdr msgh;
	struct iovec iov;
	char data;
	int fd;
	int retval;

	errno = 0;
	if (fd_out == NULL)
		return -1;
	*fd_out = -1;

	memset(&control_un, 0, sizeof(control_un));
	control_un.cmh.cmsg_len = CMSG_LEN(sizeof(int));
	control_un.cmh.cmsg_level = SOL_SOCKET;
	control_un.cmh.cmsg_type = SCM_RIGHTS;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_control = control_un.control;
	msgh.msg_controllen = sizeof(control_un.control);
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	retval = recvmsg(sock, &msgh, MSG_DONTWAIT);
	if (retval == -1 && (errno == EAGAIN || errno == EINTR)) {
		return -1;
	}
	else if (retval == 0 || retval == -1 ) {
		if (retval == 0)
			errno = ECONNRESET;
		return -1;
	}
	cmhp = CMSG_FIRSTHDR(&msgh);
	if (cmhp == NULL) {
		printf("recv_fd error, no message header\n");
		return -1;
	}
	if ( cmhp->cmsg_len != CMSG_LEN(sizeof(int))) {
		printf("cmhp(%p)\n", (void *)cmhp);
		printf("bad cmsg header / message length\n");
		return -1;
	}
	if (cmhp->cmsg_level != SOL_SOCKET) {
		printf("cmsg_level != SOL_SOCKET");
		return -1;
	}
	if (cmhp->cmsg_type != SCM_RIGHTS) {
		printf("cmsg_type != SCM_RIGHTS");
		return -1;
	}

	fd = *((int *) CMSG_DATA(cmhp));
	if (data != 'F') {
		printf("received an improper file, closing.\n");
		close(fd);
		return -1;
	}
	*fd_out = fd;
	return 0;
}



/* blocks for 5(+)ms if EINTR */
int eslib_sock_send_cred(int sock)
{
	int r, i, e;
	int optval = 1;
	const char msg = 'C';

	if (sock == -1)
		return -1;

	e = 0;
	errno = 0;
	/* set socket opt temporarily to attach credentials */
	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval,sizeof(optval))){
		printf("couldn't set socket option: %s\n", strerror(errno));
		return -1;
	}
	for (i = 0; i < 100; ++i) {
		r = send(sock, &msg, 1, MSG_DONTWAIT);
		if (r == -1 && errno == EINTR) {
			usleep(50);
			continue;
		}
		else {
			e = errno;
			break;
		}
	}
	optval = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval,sizeof(optval)))
		printf("couldn't set socket option: %s\n", strerror(errno));
	if (r != 1) {
		printf("send_cred(): %s\n", strerror(e));
		return -1;
	}
	return 0;
}


/*
 * sets socket option to recv credentials, waits for a message containing 'C'
 * copies credential data into out_creds
 * returns
 *  0 		- success
 * -1 		- error
 *  		  errno = EAGAIN if you should try again.
 */
int eslib_sock_recv_cred(int sock, struct ucred *out_creds)
{
	union {
		struct cmsghdr cmh;
		char control[CMSG_SPACE(sizeof(struct ucred))];
	} control_un;
	struct msghdr msgh;
	struct iovec  iov;
	char data = 0;
	struct cmsghdr *cmhp;
	struct ucred *creds;
	int retval;
	int optval = 1;

	errno = 0;
	if (sock == -1 || !out_creds)
		return -1;

	/* set socket opt temporarily to retreive credentials */
	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval,sizeof(optval))){
		printf("couldn't set socket option: %s\n", strerror(errno));
		return -1;
	}

	memset(&control_un, 0, sizeof(control_un));
	control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
	control_un.cmh.cmsg_level = SOL_SOCKET;
	control_un.cmh.cmsg_type = SCM_CREDENTIALS;
	cmhp = CMSG_FIRSTHDR(&msgh);

	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_control = control_un.control;
	msgh.msg_controllen = sizeof(control_un.control);
	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	retval = recvmsg(sock, &msgh, MSG_DONTWAIT);
	if (retval == -1 && (errno == EAGAIN || errno == EINTR)) {
		goto out;
	}
	else if (retval == -1 || retval == 0) {
		if (retval == 0)
			errno = ECONNRESET;
		goto out;
	}
	cmhp = CMSG_FIRSTHDR(&msgh);
	retval = -1;
	if (cmhp == NULL) {
		printf("recv_cred error, no message header\n");
		goto out;
	}
	if (cmhp->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
		printf("cmhp(%p)\n", (void *)cmhp);
		printf("bad cmsg header / message length\n");
		goto out;
	}
	if (cmhp->cmsg_level != SOL_SOCKET) {
		printf("cmsg_level != SOL_SOCKET");
		goto out;
	}
	if (cmhp->cmsg_type != SCM_CREDENTIALS) {
		printf("cmsg_type != SCM_CREDENTIALS");
		goto out;
	}
	if (data != 'C') {
		printf("invalid cred message(%d)\n", (int)data);
		goto out;
	}
	retval = 0;

	creds = (struct ucred *)CMSG_DATA(cmhp);
	memcpy(out_creds, creds, sizeof(*creds));
out:
	optval = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)))
		printf("couldn't set socket option: %s\n", strerror(errno));
	return retval;

}







