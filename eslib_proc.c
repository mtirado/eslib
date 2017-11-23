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
#define PROCFS_MAXREAD (4096 * 100000) /* 400MB */

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
	size_t size;
	size_t len = 0;
	char *buf;
	int r;

	size = 4096;
	buf = malloc(size);
	if (buf == NULL) {
		printf("malloc(): %s\n", strerror(errno));
		return -1;
	}

	while (size <= PROCFS_MAXREAD)
	{
		r = eslib_file_read_full(path, buf, size-1, &len);
		if (r == 0) {
			break;
		}
		else {
			if (errno != ENOTSUP) {
				printf("file_read_full(): %s\n", strerror(errno));
				goto err_free;
			}
			size *= 5;
			buf = realloc(buf, size);
			if (buf == NULL) {
				printf("realloc(): %s\n", strerror(errno));
				goto err_free;
			}
		}
	}
	if (size > PROCFS_MAXREAD || size < 4096 || len == 0)
		goto err_free;
	buf[len] = '\0';
	*out = buf;
	return len+1;

err_free:
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
