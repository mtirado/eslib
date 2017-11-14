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
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/capability.h>

#include "eslib.h"

extern char **environ;
extern int capget(cap_user_header_t header, const cap_user_data_t data);

int eslib_proc_numfds(pid_t pid)
{
	char path[256];
	int count;
	struct dirent *dent;
	DIR *dir;

	if (pid <= 0)
		return -1;
	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	dir = opendir(path);
	if (dir == NULL) {
		printf("error opening %s: %s\n", path, strerror(errno));
		return -1;
	}
	count = 0;
	while (1)
	{
		dent = readdir(dir);
		if (dent == NULL)
			break;
		++count;
		if (count >= INT_MAX)
			break;
       	}
	return count;

}

int eslib_proc_alloc_fdlist(pid_t pid, int **outlist)
{
	char path[256];
	struct dirent *dent;
	unsigned int fdnum;
	int first_count;
	int count;
	DIR *dir;
	char *err = NULL;
	int *fdlist = NULL;

	errno = 0;
	if (!outlist)
		return -1;
	if (pid <= 0)
		return -1;

	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	dir = opendir(path);
	if (dir == NULL) {
		printf("error opening %s: %s\n", path, strerror(errno));
		return -1;
	}

	/* get count for malloc */
	count = 0;
	while (1)
	{
		dent = readdir(dir);
		if (dent == NULL)
			break;
		++count;
		if (count >= INT_MAX)
			break;
       	}
	if (count == 0) {
		closedir(dir);
		errno = ENOENT;
		return -1;
	}

	fdlist = malloc(sizeof(int) * count);
	if (!fdlist)
		goto failed;

	first_count = count;
	rewinddir(dir);
	count = 0;
	while (1)
	{
		dent = readdir(dir);
		if (dent == NULL)
			break;
		/* ignore . and .. dir entries on 2'nd pass */
		if (dent->d_name[0] == '.') {
			if (dent->d_name[1] == '\0')
				continue;
			else if (dent->d_name[1] == '.') {
				if (dent->d_name[2] == '\0')
					continue;
			}
		}
		errno = 0;
		fdnum = strtol(dent->d_name, &err, 10);
		if (err == NULL || *err || errno) {
			printf("error reading fdnum: %s\n", dent->d_name);
			goto failed;
		}
		fdlist[count] = fdnum;
		++count;
		if (count >= first_count)
			break; /* don't write oob if new files appeared */
		/* . and .. dir entries are counted on first pass so 2 new
		 * files can be tolerated, but note this may need modification
		 * if for some crazy reason you are using INT_MAX
		 * as processes file descriptor limit
		 */
       	}
	closedir(dir);
	*outlist = fdlist;
	return count;

failed:
	if (fdlist)
		free(fdlist);
	closedir(dir);
	return -1;
}

char *eslib_proc_getenv(char *name)
{
	int found = 0;
	size_t namelen;
	char **e;
	char *str = NULL;

	if (!name)
		return NULL;

	namelen = strlen(name);

	errno = 0;
	e = environ;
	while (*e != NULL)
	{
		if (strncmp(name, *e, namelen) == 0) {
			if (found) {
				errno = ENOTUNIQ;
				return NULL;
			}
			if ((*e)[namelen] == '=') {
				str = &(*e)[namelen+1];
				found = 1;
			}
		}
		++e;
	}
	return str;
}

int eslib_proc_setenv(char *name, char *val)
{
	size_t len;
	char **e;
	char *str;
	int idx, count;
	static int mallocd = 0;

	if (!name || !val)
		return -1;

	errno = 0;
	len = strlen(name);

	e = environ;
	idx = -1;
	count = 0;
	while (*e != NULL)
	{
		if (strncmp(name, *e, len+1) == 0) {
			if (idx != -1) {
				printf("duplicate entry found\n");
				errno = ENOTUNIQ;
				return -1;
			}
			idx = count;
		}
		++e;
		++count;
		if (count < 0)
			return -1;
	}

	len = strlen(name) + 1 + strlen(val) + 1; /*name=val\0*/
	str = malloc(len); /* will leak if set twice, TODO use realloc? */
	if (str == NULL)
		return -1;

	snprintf(str, len, "%s=%s", name, val);
	if (idx != -1) {
		/* replace existing */
		environ[idx] = str;
		return 0;
	}
	else {
		/* create new entry, alloc new list */
		char **newenv;
		int i;
		int newsize = sizeof(char *) * (count + 2);
		if (!mallocd) {
			newenv = malloc(newsize);
			if (newenv == NULL) {
				free(str);
				return -1;
			}
			for (i = 0; i < count; ++i)
				newenv[i] = environ[i];

		}
		else {
			newenv = realloc(environ, newsize);
			if (newenv == NULL) {
				free(str);
				return -1;
			}
		}

		environ = newenv;
		environ[count] = str;
		environ[count+1] = NULL;
		mallocd = 1;
	}

	return 0;
}

char *eslib_proc_getname()
{
	static char name[ESLIB_MAX_PROCNAME];
	static int  once = 1;

	if (once)
	{
		char buf[64];
		int fd;
		/* parse /proc/pid/cmdline */
		snprintf(buf, sizeof(buf), "/proc/%d/cmdline", getpid());
		fd = open(buf, O_CLOEXEC|O_RDONLY|O_NOCTTY);
		if (fd == -1) {
			printf("could not open %s\n", buf);
			goto err;
		}
		while (1)
		{
			int r = read(fd, name, ESLIB_MAX_PROCNAME-1);
			if (r == -1 && (errno == EINTR || errno == EAGAIN))
				continue;
			else if (r > 0)
				break;
			else
				goto err;
		}
		once = 0;
	}
	name[ESLIB_MAX_PROCNAME-1] = '\0';
	return name;
err:
	once = 0;
	snprintf(name, ESLIB_MAX_PROCNAME, "no-procname");
	return name;
}

off_t eslib_procfs_readfile(char *path, char **out)
{
	char tmp[4096];
	char *buf, *cur;
	off_t size, bytes_left;
	int fd;
	char eof_check;
	int retries = 1000;

start_over:
	errno = 0;
	if (--retries <= 0) {
		printf("proc file is changing too rapidly\n");
		errno = EAGAIN;
		return -1;
	}

	if (!out) {
		errno = EINVAL;
		return -1;
	}
	*out = NULL;
	buf = NULL;
	/* open file, setup buffer */
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		printf("open(%s): %s\n", path, strerror(errno));
		return -1;
	}
	/* get filesize, SEEK_END fails with EINVAL on procfs */
	size = 0;
	while (1)
	{
		int r = read(fd, tmp, sizeof(tmp));
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		else if (r < 0) {
			printf("read(%d): %s\n", r, strerror(errno));
			goto failure;
		}
		else if (r == 0) {
			break;
		}
		else {
			size += r;
			if (size <= 0)
				goto failure;
		}
	}
	if (size == 0) {
		close(fd);
		return 0; /* empty */
	}
	if (size+1 <= 1) {
		goto failure;
	}

	if (lseek(fd, 0, SEEK_SET)) {
		printf("lseek: %s\n", strerror(errno));
		goto failure;
	}
	buf = malloc(size+1); /* + null terminator */
	if (buf == NULL) {
		printf("malloc: %s\n", strerror(errno));
		goto failure;
	}
	cur = buf;
	bytes_left = size;
	/* read file */
	while (1)
	{
		int r = read(fd, cur, bytes_left);
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		else if (r < 0) {
			printf("read(%d): %s\n", r, strerror(errno));
			goto failure;
		}
		else if (r == 0) {
			/*printf("file shrunk\n");*/
			goto try_again;
		}
		else {
			if (r == bytes_left) {
				break;
			}
			bytes_left -= r;
			cur += r;
			if (bytes_left < 0)
				goto failure;
		}
	} /* next read should be eof */
	if (read(fd, &eof_check, 1) != 0) {
		/*printf("file grew\n");*/
		goto try_again;
	}

	close(fd);
	buf[size] = '\0';
	*out = buf;
	return size+1;

try_again:
	close(fd);
	if(buf)
		free(buf);
	goto start_over;

failure:
	close(fd);
	if (buf)
		free(buf);
	return -1;

}

int eslib_proc_print_caps()
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];

	hdr.pid = getpid();
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	if (capget(&hdr, data)) {
		printf("capget: %s\r\n", strerror(errno));
		return -1;
	}
	printf("\reffective: %08x", data[1].effective);
	printf("%08x\r\n", data[0].effective);
	printf("permitted: %08x", data[1].permitted);
	printf("%08x\r\n", data[0].permitted);
	printf("inheritable: %08x", data[1].inheritable);
	printf("%08x\r\n", data[0].inheritable);
	return 0;
}
