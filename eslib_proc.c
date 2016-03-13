/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
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

#include "eslib.h"

extern char **environ;

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

int eslib_proc_getfds(pid_t pid, int **outlist)
{
	char path[256];
	struct dirent *dent;
	unsigned int fdnum;
	int first_count;
	int count;
	DIR *dir;
	char *err = NULL;
	int *fdlist = NULL;

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
		return 0;
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

	errno = 0;
	len = strlen(name);

	e = environ;
	idx = -1;
	count = 0;
	while (*e != NULL)
	{
		if (strncmp(name, *e, len) == 0) {
			if (idx != -1) {
				printf("duplicate entry found\n");
				errno = ENOTUNIQ;
				return -1;
			}
			if (name[len] == '\0') {
				idx = count;
			}
		}
		++e;
		++count;
	}

	len = strlen(name) + 1 + strlen(val) + 1; /*name=val\0*/
	str = malloc(len);
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
		if (!mallocd)
			newenv = malloc(sizeof(char *) * (count + 2));
		else
			newenv = realloc(environ, sizeof(char *) * (count + 2));

		if (newenv == NULL)
			return -1;

		for (i = 0; i < count; ++i)
			newenv[i] = environ[i];

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
	off_t size, bytes;
	int fd;
	char eof_check;
	errno = 0;

	if (out == NULL) {
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
	/* get filesize */
	bytes = 0;
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
			bytes += r;
		}
	}
	size = bytes;
	if (size < 0) {
		goto failure;
	}
	if (size == 0) {
		close(fd);
		return 0;
	}
	if (lseek(fd, 0, SEEK_SET)) {
		printf("lseek: %s\n", strerror(errno));
		goto failure;
	}
	buf = malloc(size);
	if (buf == NULL) {
		printf("malloc: %s\n", strerror(errno));
		goto failure;
	}
	cur = buf;
	bytes = size;
	/* read file */
	while (1)
	{
		int r = read(fd, cur, bytes);
		if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
			continue;
		}
		else if (r < 0) {
			printf("read(%d): %s\n", r, strerror(errno));
			goto failure;
		}
		else if (r == 0) {
			/*printf("file size shrunk\n");*/
			errno = EAGAIN;
			goto failure;
		}
		else {
			if (r == bytes) {
				break;
			}
			bytes -= r;
			cur += r;
			if (bytes < 0)
				goto failure;
		}
	} /* next read should be eof */
	if (read(fd, &eof_check, 1) != 0) {
		/*printf("file size grew\n");*/
		errno = EAGAIN;
		goto failure;
	}

	close(fd);
	*out = buf;
	return size;

failure:
	close(fd);
	if (buf != NULL)
		free(buf);
	return -1;

}













