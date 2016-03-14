#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "../eslib.h"

struct path_node
{
	char path[MAX_SYSTEMPATH];
	struct path_node *next;
};

static struct path_node *proc_readmounts()
{
	char *fbuf;
	struct path_node *mountpts = NULL;
	off_t fsize;
	off_t cur, start, end;
	unsigned int len;

	errno = 0;
	fsize = eslib_procfs_readfile("/proc/mounts", &fbuf);
	if (fsize == -1) {
		printf("error reading /proc/mounts\n");
		return NULL;
	}
	else if (fsize == 0 || fbuf == NULL) {
		printf("/proc/mounts is empty\n");
		errno = ESRCH;
		return NULL;
	}
	cur = 0;
	while (1)
	{
		struct path_node *pt = NULL;
		start = cur;
		/* seek to separator */
		while (fbuf[start] != ' ' && fbuf[start] != '\t')
		{
			if (++start >= fsize) {
				printf("start: %li, fsize: %li\n", start, fsize);
				printf("%s\n", fbuf);
				printf("/proc/mounts error1\n");
				goto failure;
			}
		}
		/* handle potentially  repeating separator */
		while (fbuf[start] == ' ' || fbuf[start] == '\t')
		{
			if (++start >= fsize) {
				printf("/proc/mounts error2\n");
				goto failure;
			}
		}
		/* get end of field 2 */
		end = start;
		while (fbuf[end] != ' ' && fbuf[end] != '\t')
		{
			if (++end >= fsize) {
				printf("/proc/mounts error3\n");
				goto failure;
			}
		}
		len = end-start;
		if (len >= MAX_SYSTEMPATH-1) {
			printf("mountpoint path is too long\n");
			goto failure;
		}
		/* allocate new path node */
		pt = malloc(sizeof(*pt));
		if (pt == NULL) {
			printf("malloc: %s\n", strerror(errno));
			goto failure;
		}
		strncpy(pt->path, &fbuf[start], len);
		pt->path[len] = '\0';
		pt->next = mountpts;
		mountpts = pt;

		/* go to next line */
		while(fbuf[end] != '\n')
		{
			if (++end >= fsize) {
				goto done;
			}
		}
		/* consume trailing newlines */
		while(fbuf[end] == '\n')
		{
			if (++end >= fsize) {
				goto done;
			}
		}
		cur = end;
	}

failure:
	while (mountpts)
	{
		struct path_node *tmp = mountpts->next;
		free(mountpts);
		mountpts = tmp;
	}
	free(fbuf);
	errno = EIO;
	return NULL;

done:
	free(fbuf);
	return mountpts;
}

/* verifies /dev is mounted */
static int test_read_mountpoints()
{
	struct path_node *pts = proc_readmounts();
	if (pts == NULL) {
		printf("check mountpts error\n");
		return -1;
	}

	printf("\ntest_read_mountpoints -- list mount points:\n\n");
	while (pts)
	{
		struct path_node *pt = pts;
		printf("%s\n", pt->path);
		pts = pt->next;
		free(pt);
	}
	return 0;
}

int main()
{
	if (test_read_mountpoints()) {
		printf("test_read_mountpoints failed\n");
		return -1;
	}
	return 0;
}
