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
	size_t fsize;
	size_t fpos = 0;
	errno = 0;
	fsize = eslib_procfs_readfile("/proc/mounts", &fbuf);
	if (fsize == (size_t)-1) {
		printf("error reading /proc/mounts\n");
		return NULL;
	}
	else if (fsize == 0 || fbuf == NULL) {
		printf("/proc/mounts is empty\n");
		errno = ESRCH;
		return NULL;
	}
	while (fpos < fsize)
	{
		char *line = NULL;
		char *token = NULL;
		struct path_node *pt = NULL;
		unsigned int linepos = 0;
		unsigned int linelen = 0;
		unsigned int advance = 0;

		line = &fbuf[fpos];
		linelen = eslib_string_linelen(line, fsize - fpos);
		if (linelen >= fsize - fpos)
			goto failure;
		if (!eslib_string_is_sane(line, linelen))
			goto failure;
		if (eslib_string_tokenize(line, linelen, " \t"))
			goto failure;

		/* skip first field */
		token = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;
		if (!token)
			goto failure;

		token = eslib_string_toke(line, linepos, linelen, &advance);
		if (!token)
			goto failure;

		/* allocate new path node */
		pt = malloc(sizeof(*pt));
		if (pt == NULL) {
			printf("malloc: %s\n", strerror(errno));
			goto failure;
		}
		snprintf(pt->path, sizeof(pt->path), "%s", token);
		pt->next = mountpts;
		mountpts = pt;

		fpos += linelen+1;
		if (fpos > fsize)
			goto failure;
		else if (fpos == fsize)
			break;
	}

	free(fbuf);
	return mountpts;

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
		printf("{%s}\n", pt->path);
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
	else {
		printf("test_read_mountpoints passed\n");
	}
	return 0;
}
