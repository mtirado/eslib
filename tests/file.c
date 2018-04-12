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
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "../eslib.h"

int test_path_check()
{
	int r;
	char buf[MAX_SYSTEMPATH+1];
	memset(buf, 'A', sizeof(buf));
	buf[0] = '/';

	/* bad path */
	r = eslib_file_path_check(buf);
	if (!r) return -1;
	buf[MAX_SYSTEMPATH] = '\0';
	r = eslib_file_path_check(buf);
	if (!r) return -1;
	buf[MAX_SYSTEMPATH-2] = '/';
	buf[MAX_SYSTEMPATH-1] = '\0';
	r = eslib_file_path_check(buf);
	if (!r) return -1;

	r = eslib_file_path_check("an/invalid/path");
	if (!r) return -1;
	r = eslib_file_path_check("//invalid/double/slash");
	if (!r) return -1;
	r = eslib_file_path_check("/invalid/dbl//slash");
	if (!r) return -1;
	r = eslib_file_path_check("/invalid/trailing/slash//");
	if (!r) return -1;
	r = eslib_file_path_check("/double/../troubles");
	if (!r) return -1;
	r = eslib_file_path_check("/invalid/./dot");
	if (!r) return -1;
	r = eslib_file_path_check("/invalid/trailing/dot/.");
	if (!r) return -1;
	r = eslib_file_path_check("");
	if (!r) return -1;
	r = eslib_file_path_check("/././");
	if (!r) return -1;

	/* good path */
	r = eslib_file_path_check("/a/valid/path");
	if (r) return -1;
	r = eslib_file_path_check("/.a");
	if (r) return -1;
	r = eslib_file_path_check("/a.");
	if (r) return -1;
	r = eslib_file_path_check("/a/valid/.path");
	if (r) return -1;
	r = eslib_file_path_check("/a/valid./.path.");
	if (r) return -1;
	r = eslib_file_path_check("/");
	if (r) return -1;

	memset(buf, 'A', sizeof(buf));
	buf[0] = '/';
	buf[MAX_SYSTEMPATH-1] = '\0';
	r = eslib_file_path_check(buf);
	if (r) return -1;

	return 0;
}

#define WRFILENAME "temporarytestfile"
#define LARGE_SIZE (1024 * 1024 * 128)
int test_file_write()
{
	char wrbuf[256];
	char rdbuf[256];
	size_t rdlen;
	char *largefile = NULL;

	memset(wrbuf, 0, sizeof(wrbuf));
	memset(rdbuf, 0, sizeof(rdbuf));
	snprintf(wrbuf, sizeof(wrbuf), "blah\ntest...\ntest file!\n%d\n", getpid());

	if (unlink(WRFILENAME) && errno != ENOENT)
		goto failure;
	if (eslib_file_write_full(WRFILENAME, wrbuf, sizeof(wrbuf)))
		goto failure;
	if (eslib_file_read_full(WRFILENAME, rdbuf, sizeof(rdbuf), &rdlen))
		goto failure;
	if (rdlen != sizeof(wrbuf))
		goto failure;
	if (strncmp(rdbuf, wrbuf, sizeof(wrbuf)) != 0)
		goto failure;

	largefile = malloc(LARGE_SIZE);
	if (largefile == NULL)
		goto failure;
	memset(largefile, 'A', LARGE_SIZE);
	if (unlink(WRFILENAME))
		goto failure;
	if (eslib_file_write_full(WRFILENAME, largefile, LARGE_SIZE))
		goto failure;
	free(largefile);

	return 0;
failure:
	printf("write failed in an unexpected way\n");
	printf("%s\n", strerror(errno));
	return -1;
}

int test_file_read()
{
	char *full;
	char buf[16];
	size_t flen;

	/* normal file */
	system("echo '123456789' > ./testfile");
	if (eslib_file_read_full("./testfile", buf, sizeof(buf)-1, &flen))
		goto failure;
	buf[flen] = '\0';
	printf("file contents = {%s}\n", buf);

	if (eslib_file_read_full("./testfile", buf, 10, &flen))
		goto failure;
	if (eslib_file_read_full("./testfile", buf, 9, &flen)) {
		if (errno != EOVERFLOW || flen != 10)
			goto failure;
	}
	if (eslib_file_read_full("./testfile", buf, 0, &flen)) {
		if (errno != EINVAL || flen != 0)
			goto failure;
	}

	/* empty file */
	system("rm ./testfile");
	system("touch ./testfile");

	if (eslib_file_read_full("./testfile", buf, 1, &flen))
		goto failure;
	if (flen != 0)
		goto failure;
	if (eslib_file_read_full("./testfile", buf, sizeof(buf), &flen))
		goto failure;
	if (flen != 0)
		goto failure;

	/* procfs */
	if (eslib_file_read_full("/proc/self/maps", buf, 10, &flen) == 0) {
		goto failure;
	}
	if (errno != EOVERFLOW) {
		printf("*NOTE* procfs might have gained support for SEEK_END\n");
		goto failure;
	}
	full = malloc(flen+1);
	if (full == NULL)
		goto failure;
	if (eslib_file_read_full("/proc/self/maps", full, flen+1, &flen)) {
		goto failure;
	}
	printf("%s\n", full);
	free(full);
	return 0;

failure:
	printf("read failed in an unexpected way\n");
	return -1;
}

int main()
{
	printf("----------------------------------------------------------\n");
	if (test_path_check()) {
		printf("----------------------------------------------------------\n");
		printf("eslib_file_path_check: fail\n");
		printf("----------------------------------------------------------\n");
		return -1;
	}
	printf("----------------------------------------------------------\n");
	printf("eslib_file_path_check: passed\n");
	printf("----------------------------------------------------------\n");



	if (test_file_read()) {
		printf("----------------------------------------------------------\n");
		printf("test_file_read: failed\n");
		printf("----------------------------------------------------------\n");
		return -1;
	}

	printf("----------------------------------------------------------\n");
	printf("test_file_read: passed\n");
	printf("----------------------------------------------------------\n");



	if (test_file_write()) {
		printf("----------------------------------------------------------\n");
		printf("test_file_write: failed\n");
		printf("----------------------------------------------------------\n");
		return -1;
	}

	printf("----------------------------------------------------------\n");
	printf("test_file_write: passed\n");
	printf("----------------------------------------------------------\n");


	return 0;

}
