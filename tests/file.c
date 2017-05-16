#include <stdio.h>
#include <memory.h>
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
	return 0;

}
