/* (c) 2016 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "eslib.h"

#define ESLOG_MSG  1
#define ESLOG_ERR  2
#define ESLOG_CRIT 3

static int logmsg(char *name, char *msg, int lvl)
{
	char msgbuf[ESLIB_LOG_MAXMSG];
	char namebuf[64];
	struct sockaddr_un addr;
	unsigned int msglen;
	int devlog;

	if (name == NULL)
		snprintf(namebuf, sizeof(namebuf),
				"%s [%d]", eslib_proc_getname(), getpid());
	else
		snprintf(namebuf, sizeof(namebuf),
				"%s [%d]", name, getpid());
	if (msg == NULL)
		msg = namebuf;

	switch (lvl)
	{
	default:
	case ESLOG_MSG:
		snprintf(msgbuf, sizeof(msgbuf), "%s info: %s", namebuf, msg);
		break;
	case ESLOG_ERR:
		snprintf(msgbuf, sizeof(msgbuf), "%s error: %s", namebuf, msg);
		break;
	case ESLOG_CRIT:
		snprintf(msgbuf, sizeof(msgbuf), "%s critical: %s", namebuf, msg);
		break;
	}

	msglen = strnlen(msgbuf, ESLIB_LOG_MAXMSG);
	if (msglen >= ESLIB_LOG_MAXMSG)
		msglen = ESLIB_LOG_MAXMSG-1;
	msgbuf[msglen] = '\0';

	/* print to stderr */
	fprintf(stderr, msgbuf);
	fprintf(stderr, "\n");

	/* send to /dev/log */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/dev/log", sizeof(addr.sun_path)-1);

	devlog = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (devlog == -1) {
		printf("devlog socket error: %s\n", strerror(errno));
		return -1;
	}

	while (1)
	{
		int r = sendto(devlog, msgbuf, msglen+1, MSG_DONTWAIT,
				(struct sockaddr *)&addr, sizeof(addr));
		if (r == -1 && (errno == EINTR || errno == EAGAIN))
			continue;
		else if (r > 0)
			break;
		else {
			printf("devlog sendto: %s\n", strerror(errno));
			close(devlog);
			return -1;
		}
	}
	close(devlog);
	return 0;
}

static int logmsg_t(char *name, char *msg, time_t *timer, unsigned int seconds, int lvl)
{
	time_t t;

	if (timer == NULL || seconds == 0)
		return logmsg(name, msg, lvl);

	t = time(NULL);
	if (t < *timer + (time_t)seconds)
		return 0;
	*timer = t;
	return logmsg(name, msg, lvl);
}

int eslib_logmsg(char *name, char *msg)
{
	return logmsg(name, msg, ESLOG_MSG);
}
int eslib_logerror(char *name, char *msg)
{
	return logmsg(name, msg, ESLOG_ERR);
}
int eslib_logcritical(char *name, char *msg)
{
	return logmsg(name, msg, ESLOG_CRIT);
}
int eslib_logmsg_t(char *name, char *msg, time_t *timer, unsigned int seconds)
{
	return logmsg_t(name, msg, timer, seconds, ESLOG_MSG);
}
int eslib_logerror_t(char *name, char *msg, time_t *timer, unsigned int seconds)
{
	return logmsg_t(name, msg, timer, seconds, ESLOG_ERR);
}
int eslib_logcritical_t(char *name, char *msg, time_t *timer, unsigned int seconds)
{
	return logmsg_t(name, msg, timer, seconds, ESLOG_CRIT);
}


