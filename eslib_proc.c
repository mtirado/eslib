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
	char *err;
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
		if (*err || errno) {
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

















