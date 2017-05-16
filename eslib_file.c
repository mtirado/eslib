/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <malloc.h>
#include "eslib.h"


/*
 * enforce simple absolute path rules:
 * must start with /
 * no double slashes
 * no double dots!
 * no single dot directories!!
 * cannot end in a slash. (unless len == 1)
 */
int eslib_file_path_check(char *path)
{
	size_t len;
	size_t i;
	int adot = 0;
	int aslash = 0;
	int slashing = 0;

	if (path == NULL)
		return -1;

	len = strnlen(path, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH || len == 0) {
		printf("bad pathlen(%d)\n", len);
		return -1;
	}

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
			aslash = 0;
			break;
		case '/':
			if (aslash) {
				printf("// not permitted\n");
				goto bad_path;
			}
			if (adot && slashing) {
				printf("/. not permitted\n");
				goto bad_path;
			}
			slashing = 1;
			aslash = 1;
			adot = 0;
			break;
		default:
			slashing = 0;
			adot = 0;
			aslash = 0;
			break;
		}
	}
	if (len >= 2 && path[i-1] == '/') {
		printf("trailing slash not permitted: %s\n", path);
		return -1;
	}
	else if (len >= 2 && path[i-2] == '/' && path[i-1] == '.') {
		printf("/. not permitted\n");
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

	if (inpath == NULL || outpath == NULL)
		return -1;

	if (eslib_file_path_check(inpath))
		return -1;

	i = strnlen(inpath, MAX_SYSTEMPATH);
	if (i >= MAX_SYSTEMPATH || i == 0)
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


int eslib_file_mkdirpath(char *path, mode_t mode)
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


int eslib_file_mkfile(char *path, mode_t dirmode)
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
		if (eslib_file_mkdirpath(dirpath, dirmode)) {
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
	return 0;

}


char *eslib_file_getname(char *path)
{
	int len;
	int i;

	if (path == NULL)
		return NULL;

	len = strnlen(path, MAX_SYSTEMPATH);
	if (len >= MAX_SYSTEMPATH || len < 1)
		return NULL;

	i = len;
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

static int file_confirm_mountpoint(char *src, char *dest, unsigned long esflags)
{
	int r;
	int exists = 0;
	const mode_t mode = 0755; /* mode for new directories */

	if (eslib_file_path_check(src) || eslib_file_path_check(dest))
		return -1;

	r = eslib_file_exists(dest);
	if (r == -1)
		goto err;
	exists = r;

	/* directory */
	r = eslib_file_isdir(src);
	if (r == 1) {
		if (exists) {
			/* fail if dest is not a directory */
			if (eslib_file_isdir(dest) != 1) {
				printf("dest(%s) is not a directory.\n", dest);
				return -1;
			}
		}
		else {
			if (esflags & ESLIB_BIND_CREATE) {
				if (eslib_file_mkdirpath(dest, mode)) {
					printf("mkdirpath(%s) failed\n", dest);
					return -1;
				}
			}
			else {
				printf("dest(%s) did not exist\n", dest);
				return -1;
			}
		}
		return 0;
	}
	else if (r == -1) {
		goto err;
	}

	/* non-directory */
	if (exists) {
		/* fail if dest is a directory */
		r = eslib_file_isdir(dest);
		if (r == 1) {
			printf("dest(%s) should not be a directory\n", dest);
			return -1;
		}
		if (r == 0) {
			return 0;
		}
		else {
			goto err;
		}
	}
	else {
		if (esflags & ESLIB_BIND_CREATE) {
			if (eslib_file_mkfile(dest, mode)) {
				printf("mkfile(%s) failed\n", dest);
				return -1;
			}
		}
		else {
			printf("dest(%s) did not exist\n", dest);
			return -1;
		}
		return 0;
	}
err:
	printf("create mountpoint(%s, %s) failed\n", src, dest);
	return -1;
}

static int file_bind(char *src, char *dest,
		unsigned long mntflags, unsigned long propflags, unsigned long esflags)
{
	if (src == NULL || dest == NULL)
		return -1;
	if (file_confirm_mountpoint(src, dest, esflags))
		return -1;
	if (mount(src, dest, NULL, MS_BIND, NULL)) {
		printf("mount: %s\n", strerror(errno));
		return -1;
	}
	if (mount(NULL, dest, NULL, MS_BIND|MS_REMOUNT|mntflags, NULL)) {
		printf("remount: %s\n", strerror(errno));
		if (umount(dest))
			printf("umount: %s\n", strerror(errno));
		return -1;
	}
	if (esflags & ESLIB_BIND_UNBINDABLE) {
		unsigned long ubflags = MS_UNBINDABLE;
		if (!(esflags & ESLIB_BIND_NONRECURSIVE))
			ubflags |= MS_REC;
		if (mount(NULL, dest, NULL, ubflags, NULL)) {
			printf("remount: %s\n", strerror(errno));
			if (umount(dest))
				printf("umount: %s\n", strerror(errno));
			return -1;
		}
	}
	if (mount(NULL, dest, NULL, propflags, NULL)) {
		printf("remount: %s\n", strerror(errno));
		if (umount(dest))
			printf("umount: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int eslib_file_bind(char *src, char *dest,
		unsigned long mntflags, unsigned long esflags)
{
	unsigned long propflags;

	if (esflags & ESLIB_BIND_SLAVE)
		propflags = MS_SLAVE;
	else if (esflags & ESLIB_BIND_SHARED)
		propflags = MS_SHARED;
	else
		propflags = MS_PRIVATE;

	if (!(esflags & ESLIB_BIND_NONRECURSIVE))
		propflags |= MS_REC;

	return file_bind(src, dest, mntflags, propflags, esflags);
}
