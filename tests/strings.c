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
#include "../eslib.h"

char single_line_file[] = "1 3 567";

char test_file[] = "#ignore comments\n\
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
strings.c";

int main()
{
	unsigned int i = 0;
	unsigned int line_num = 0;

	printf("----------------------------------------------------------\n");
	printf("%s\n", test_file);
	printf("----------------------------------------------------------\n");

	/* check line endings */
	if (eslib_string_linelen(single_line_file, 5) < 5) {
		printf("single_line_file linelen didn't fail\n");
		goto failure;
	}
	if (eslib_string_linelen(single_line_file, 8) >= 8) {
		printf("single_line_file missing ending\n");
		goto failure;
	}
	if (eslib_string_linelen(test_file, 5) < 5) {
		printf("test_file linelen didn't fail\n");
		goto failure;
	}

	while (i < sizeof(test_file))
	{
		char *line;
		unsigned int linepos = 0;
		unsigned int linelen = 0;
		unsigned int advance;
		char *token;

		line = &test_file[i];

		linelen = eslib_string_linelen(line, sizeof(test_file) - i);
		if (linelen >= sizeof(test_file) - i) {
			printf("bad line\n");
			goto failure;
		}
		else if (linelen == 0) {
			/* blank line */
			if (i > 0 && test_file[i-1] == '\n')
				++line_num;
			++i;
			continue;
		}
		++line_num;

		/* ignore comments */
		if (test_file[i] == '#') {
			i += linelen;
			continue;
		}

		/* test some bad lines */
		if (line_num == 9 || line_num == 10 || line_num == 13) {
			if (eslib_string_is_sane(line, linelen)) {
				printf("insane line was not caught\n");
				goto failure;
			}
			i += linelen;
			continue;
		}
		else if (!eslib_string_is_sane(line, linelen)) {
			printf("invalid line(%d){%s}\n", *line, line);
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

	printf("test passed\n");
	return 0;
failure:
	printf("test failed, line_num=%d\n", line_num);
	return -1;
}