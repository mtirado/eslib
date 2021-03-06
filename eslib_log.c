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
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <time.h>
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
		es_sprintf(namebuf, sizeof(namebuf), NULL,
				"%s [%d]", eslib_proc_getname(), getpid());
	else
		es_sprintf(namebuf, sizeof(namebuf), NULL,
				"%s [%d]", name, getpid());
	if (msg == NULL)
		msg = namebuf;

	switch (lvl)
	{
	default:
	case ESLOG_MSG:
		es_sprintf(msgbuf, sizeof(msgbuf), NULL, "%s info: %s", namebuf, msg);
		break;
	case ESLOG_ERR:
		es_sprintf(msgbuf, sizeof(msgbuf), NULL, "%s error: %s", namebuf, msg);
		break;
	case ESLOG_CRIT:
		es_sprintf(msgbuf, sizeof(msgbuf), NULL, "%s critical: %s", namebuf, msg);
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
	if (es_strcopy(addr.sun_path, "/dev/log", sizeof(addr.sun_path), NULL))
		return -1;

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


