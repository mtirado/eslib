/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <malloc.h>
#include "eslib.h"


/*
 * validate this is a full path, and no funny business!
 * must start with /
 * no double slashes
 * no double dots!
 * cannot end in a slash. (unless len == 1)
 */
int eslib_file_path_check(char *path)
{
	int len;
	int i;
	int adot = 0;
	int aslash = 0;

	if (path == NULL)
	       return -1;

	len = strnlen(path, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH || len == 0)
		return -1;

	if (path[0] != '/') {
		printf("path must begin with /\n");
		goto bad_path;
	}

	/* check doubles */
	for (i = 0; i < len; ++i)
	{
		switch (path[i])
		{
		case '.':
			if (adot) {
				printf(".. not permitted\n");
				goto bad_path;
			}
			adot = 1;
			break;
		case '/':
			if (aslash) {
				printf("// not permitted\n");
				goto bad_path;
			}
			aslash = 1;
			break;
		default:
			adot = 0;
			aslash = 0;
			break;
		}
	}
	if (path[i-1] == '/' && len > 1) {
		printf("trailing slash not permitted: %s\n", path);
		return -1;
	}
	return 0;
bad_path:
	printf("bad path: %s\n", path);
	return -1;
}


/*
 * copy inpath to outpath, nullify characters until at parent path
 * error if no slash,
 */
int eslib_file_getparent(char *inpath, char outpath[MAX_SYSTEMPATH])
{
	int i;

	if (!inpath || !outpath)
		return -1;

	if (eslib_file_path_check(inpath))
		return -1;

	i = strnlen(inpath, MAX_SYSTEMPATH);
	if (i >= MAX_SYSTEMPATH)
		return -1;

	strncpy(outpath, inpath, i);
	outpath[i] = '\0';

	/* find next slash back */
	while(i >= 0)
	{
		if (outpath[i] == '/') {
			outpath[i] = '\0';
			break;
		}
		outpath[i] = '\0';
		--i;
	}
	if (i < 0) {
		printf("eslib bad path?\n");
		return -1;
	}
	if (i == 0)
		goto return_root;

	return 0;

return_root:
	outpath[0] = '/';
	outpath[1] = '\0';
	return 0;
}


int eslib_file_exists(char *path)
{
	struct stat st;
	int ret;

	if (path == NULL)
		return -1;

	memset(&st, 0, sizeof(st));
	ret = stat(path, &st);
	if (ret != -1)
		return 1;
	if (errno == ENOENT)
		return 0;

	printf("stat(%s): %s\n", path, strerror(errno));
	return -1;
}


int eslib_file_isfile(char *path)
{
	struct stat st;
	int ret;

	if (path == NULL)
		return -1;

	memset(&st, 0, sizeof(st));
	ret = stat(path, &st);

	if (ret == -1) {
		printf("stat(%s): %s\n", path, strerror(errno));
		return -1;
	}
	if (ret != -1 && S_ISREG(st.st_mode))
		return 1;

	return 0;
}


int eslib_file_isdir(char *path)
{
	struct stat st;
	int ret;

	if (path == NULL)
		return -1;

	memset(&st, 0, sizeof(st));
	ret = stat(path, &st);
	if (ret == -1) {
		printf("stat(%s): %s\n", path, strerror(errno));
		return -1;
	}
	if (ret != -1 && S_ISDIR(st.st_mode))
		return 1;

	return 0;
}


int eslib_file_mkdirpath(char *path, mode_t mode, int use_realid)
{
	int i;
	char curdir[MAX_SYSTEMPATH];
	int ret;

	if (eslib_file_path_check(path))
		return -1;

	memset(curdir, 0, MAX_SYSTEMPATH);

	/* find '/' and mkdir when we hit one */
	for (i = 1; i < MAX_SYSTEMPATH-1; ++i)
	{
		/* find next slash in path */
		while(i < MAX_SYSTEMPATH-1)
		{
			/* found slash or null */
			if (path[i] == '/' || path[i] == '\0')
				break;
			++i;
		}
		if (i >= MAX_SYSTEMPATH-1)
			break;

		strncpy(curdir, path, i);
		curdir[i] = '\0';

		/* if directory doesnt exist, create it. */
		ret = eslib_file_exists(curdir);
		if (ret == 0) {
			if (mkdir(curdir, mode) == -1) {
				printf("error creating directory: %s\n",
						strerror(errno));
				return -1;
			}
			if (chmod(curdir, mode)) {
				printf("chmod(%s): %s\n", curdir, strerror(errno));
				return -1;
			}
			if (use_realid) {
				chown(curdir, getuid(), getgid());
			}
		}
		else if (ret == 1) {
			if (eslib_file_isdir(curdir) != 1) {
				printf("path exists but not a directory:%s\n",
						curdir);
				return -1;
			}
		}
		else {
			printf("file error(%s): %s\n",curdir,strerror(errno));
			return -1;
		}

		if (path[i] == '\0')
			break;
	}
	return 0;
}


int eslib_file_mkfile(char *path, mode_t dirmode, int use_realid)
{
	unsigned int i;
	unsigned int slashidx = 0;
	char dirpath[MAX_SYSTEMPATH];
	int fd;

	if (eslib_file_path_check(path))
		return -1;

	/* find index of the last slash */
	for (i = 0; i < MAX_SYSTEMPATH; ++i)
	{
		if (path[i] == '\0')
			break;
		if (path[i] == '/')
			slashidx = i;
	}
	if (i >= MAX_SYSTEMPATH)
		return -1;

	/* error if at index 0, or end of path is a slash */
	if (i == 0 || slashidx >= i-1)
		return -1;

	/* create path */
	if (slashidx != 0) { /* don't try to create root dir */
		memset(dirpath, 0, sizeof(dirpath));
		strncpy(dirpath, path, slashidx);
		dirpath[MAX_SYSTEMPATH-1] = '\0'; 
		if (eslib_file_mkdirpath(dirpath, dirmode, use_realid)) {
			printf("mkfile error creating directory path\n");
			return -1;
		}
	}

	/* create file */
	fd = open(path, O_WRONLY|O_CREAT, 0700);
	if (fd == -1) {
		printf("mkfile(%s) error, open: %s\n", path, strerror(errno));
		return -1;
	}
	close(fd);
	if (use_realid)
		chown(path, getuid(), getgid());
	return 0;

}


char *eslib_file_getname(char *path)
{
	int len;
	int i;

	len = strnlen(path, MAX_SYSTEMPATH);
	i = len;
	if (len >= MAX_SYSTEMPATH)
		return NULL;

	while (--i >= 0)
	{
		if (path[i] == '/') {
			if (i == len - 1)
				return NULL; /* was the last char */
			else {
				++i;
				break;
			}
		}
	}
	if (i < 0)
		i = 0; /* no slash, return full path */

	return &path[i];
}


uid_t eslib_file_getuid(char *path)
{
	struct stat st;
	int ret;

	if (path == NULL)
		return -1;

	memset(&st, 0, sizeof(st));
	ret = stat(path, &st);
	if (ret) {
		printf("getuid stat: %s\n", strerror(errno));
		return -1;
	}

	return st.st_uid;
}


ino_t eslib_file_getino(char *path)
{
	struct stat st;
	int ret;

	if (path == NULL)
		return 0;

	memset(&st, 0, sizeof(st));
	ret = stat(path, &st);
	if (ret) {
		printf("getino stat: %s\n", strerror(errno));
		return 0;
	}

	return st.st_ino;
}
