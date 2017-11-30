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

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "../eslib.h"

char single_line_file[] = "1 3 567";

char test_file[] = "\n\
token1 token2 token3\n\
that  one 	was fairly standard, how about\n\
	N	O	W	?  	  	\n\
	with a leading tab? egads!\n\
 and a space!\n\
 	oh my.\n\
# these next two lines are broken\n\
but how does it handle rogue nulls??\0\n\
these c\0uld cause trouble\n\
\n\
\n\
another busted line\0 here\n\
\n\
\n	\
	\n	\
       		\n\
# this scandalous line is ok because comments are \0 skipped\n\
\n\
only	time will  tell	\n\
stay tuned for the stunning conclusion of\n\
strings.c\n\
";

int test_toke()
{
	unsigned int i = 0;
	unsigned int line_num = 0;

	printf("----------------------------------------------------------\n");
	printf("%s\n", test_file);
	printf("----------------------------------------------------------\n");

	while (i < sizeof(test_file))
	{
		char *line;
		unsigned int linepos = 0;
		unsigned int linelen = 0;
		unsigned int advance;
		char *token;

		line = &test_file[i];
		++line_num;

		linelen = eslib_string_linelen(line, sizeof(test_file) - i);
		if (linelen >= sizeof(test_file) - i) {
			printf("bad line\n");
			goto failure;
		}
		else if (linelen == 0) {
			++i; /* blank line */
			continue;
		}

		/* ignore comments */
		if (test_file[i] == '#') {
			i += linelen + 1;
			continue;
		}

		/* test some bad lines */
		if (line_num == 9 || line_num == 10 || line_num == 13) {
			if (eslib_string_is_sane(line, linelen)) {
				printf("insane line was not caught\n");
				goto failure;
			}
			i += linelen + 1;
			continue;
		}
		else if (!eslib_string_is_sane(line, linelen)) {
			printf("invalid line(%d){%s}\n", *line, line);
			goto failure;
		}

		if (eslib_string_tokenize(line, linelen, "") == 0) {
			printf("tokenize with blank delimiter didn't fail\n");
			goto failure;
		}
		if (eslib_string_tokenize(line, linelen, " \t")) {
			printf("tokenize failed\n");
			goto failure;
		}

		while (1)
		{
			token = eslib_string_toke(line, linepos, linelen, &advance);
			linepos += advance;
			if (token) {
				printf("toked(%d)={%s}\n", linepos, token);
			}
			else {
				break;
			}
		}

		i += linepos;
		if (i == sizeof(test_file)) {
			break;
		}
		else if (i > sizeof(test_file)) {
			printf("i > file size\n");
			goto failure;
		}
	}

	return 0;
failure:
	printf("bad line_num=%d\n", line_num);
	return -1;
}

int test_type_conv()
{
	char good[]   = "9999";
	char good2[]  = "-12";
	char good3[]  = "+1234567";
	char bad[]    = "n0p3";
	char bad2[]   = "789abc";
	char ugly[]   = "54321 ";
	char ugly2[]  = " 12345";
	char nasty[]  = "1000000000000";
	char nasty2[] = "-1000000000000";
	int val;

	if (eslib_string_to_int(good, &val))
		return -1;
	if (val != 9999)
		return -1;
	if (eslib_string_to_int(good2, &val))
		return -1;
	if (val != -12)
		return -1;
	if (eslib_string_to_int(good3, &val))
		return -1;
	if (val != 1234567)
		return -1;
	if (eslib_string_to_int(bad, &val) == 0)
		return -1;
	if (errno != EINVAL)
		return -1;
	if (eslib_string_to_int(bad2, &val) == 0)
		return -1;
	if (errno != EINVAL)
		return -1;
	if (eslib_string_to_int(ugly, &val) == 0)
		return -1;
	if (errno != EINVAL)
		return -1;
	if (eslib_string_to_int(ugly2, &val) == 0)
		return -1;
	if (errno != EINVAL)
		return -1;
	if (eslib_string_to_int(nasty, &val) == 0)
		return -1;
	if (errno != EOVERFLOW)
		return -1;
	if (eslib_string_to_int(nasty2, &val) == 0)
		return -1;
	if (errno != EOVERFLOW)
		return -1;
	return 0;
}

static int test_sprintf()
{
	char dst[16];
	const char str[] = "abcd";
	const char good_msg[] = "this fits!";
	const char bad_msg[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	unsigned int len;


	if (es_sprintf(dst, sizeof(dst), &len, "%s", bad_msg) != -1) {
		printf("bad sprintf 1 did not fail\n");
		return -1;
	}
	if (errno != EOVERFLOW) {
		printf("didn't detect massive string size\n");
		return -1;
	}

	if (es_sprintf(dst, sizeof(dst), &len, "%s", "") != -1) {
		printf("bad sprintf 2 didn't fail\n");
		return -1;
	}
	if (errno != ECANCELED) {
		printf("didn't detect 0 len write\n");
		return -1;
	}

	if (es_sprintf(dst, INT_MAX, &len, "%s", good_msg) != -1) {
		printf("bad sprintf 3 did not fail\n");
		return -1;
	}
	if (errno != EINVAL) {
		printf("didn't detect massive string size input\n");
		return -1;
	}


	if (es_sprintf(dst, sizeof(dst), &len, "%s", good_msg)) {
		printf("good sprintf 1 failed\n");
		return -1;
	}
	if (len != strlen(good_msg)) {
		printf("unexpected len\n");
		return -1;
	}

	if (es_sprintf(dst, sizeof(dst), &len, "%s5%d%c", str, 678, '9')) {
		printf("good sprintf 2 failed\n");
		return -1;
	}
	if (len != 9) {
		printf("expected {%s} len == 9\n", dst);
		return -1;
	}


	return 0;
}

static int test_copy()
{
	char dst[16];
	const char good_msg[] = "1234567890";
	const char bad_msg[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
	unsigned int len;

	if (es_strcopy(dst, good_msg, sizeof(dst), &len))
		return -1;
	if (len != strlen(good_msg))
		return -1;
	if (es_strcopy(dst, bad_msg, sizeof(dst), &len) == 0)
		return -1;
	if (errno != EOVERFLOW)
		return -1;
	if (es_strcopy(dst, "", sizeof(dst), &len) == 0)
		return -1;
	if (errno != ECANCELED || len != 0)
		return -1;
	return 0;
}

#define fail_print(str)	{								\
		printf("----------------------------------------------------------\n"); \
		printf("%s failed\n", str);						\
		printf("----------------------------------------------------------\n");	\
		return -1;								\
}
#define pass_print(str) {								\
		printf("----------------------------------------------------------\n"); \
		printf("%s passed\n", str);						\
		printf("----------------------------------------------------------\n");	\
		printf("\n");								\
}

int main()
{
	if (test_toke())
		fail_print("toke");
	pass_print("toke");

	if (test_type_conv())
		fail_print("type_conv");
	pass_print("type_conv");

	if (test_sprintf())
		fail_print("sprintf");
	pass_print("sprintf");

	if (test_copy())
		fail_print("test_copy");
	pass_print("test_copy");

	return 0;
}
