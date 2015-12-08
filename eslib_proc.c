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







