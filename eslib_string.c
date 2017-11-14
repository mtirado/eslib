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

#include <errno.h>
#include <stddef.h>
#include <limits.h>
#define STR_MAX (UINT_MAX - 1)
#define DELIM_MAX 255
#define is_eol(chr)  ( chr == '\n' || chr == '\0' )

/* len should be at least bufsize - 1 */
int eslib_string_is_sane(char *buf, const unsigned int len)
{
	unsigned int idx;
	for (idx = 0; idx < len; ++idx)
	{
		unsigned char c = buf[idx];
		/* you're on your own for 8-bit ascii */
		if (c < 32 || c >= 127) {
			if (c != '\n' && c != '\t') {
				return 0;
			}
		}
	}
	return 1;
}

/* returns == size if missing newline, or terminator at eol */
unsigned int eslib_string_linelen(char *buf, const unsigned int size)
{
	unsigned int idx;
	for (idx = 0; idx < size; ++idx)
	{
		if (buf[idx] == '\n') {
			break;
		}
	}
	if (idx == size && size > 0 && buf[size - 1] == '\0')
		return size - 1;
	return idx;
}

/* converts delimiters into null terminators, for toke consumption
 * so use a copy if you need to preserve the original data!
 * len should be at least bufsize - 1
 */
int eslib_string_tokenize(char *buf, const unsigned int len, char *delimiter)
{
	unsigned int buf_idx;
	unsigned int delim_idx;
	unsigned int delim_count = 0;

	for (delim_idx = 0; delim_idx < DELIM_MAX; ++delim_idx)
	{
		if (delimiter[delim_idx] == '\0') {
			delim_count = delim_idx;
			break;
		}
	}
	if (delim_count == 0 || delim_count >= DELIM_MAX) {
		errno = EINVAL;
		return -1;
	}

	for (buf_idx = 0; buf_idx < len; ++buf_idx)
	{
		if (buf[buf_idx] == '\0') {
			break;
		}
		for (delim_idx = 0; delim_idx < delim_count; ++delim_idx)
		{
			if (buf[buf_idx] == delimiter[delim_idx])
				buf[buf_idx] = '\0';
		}
	}
	buf[buf_idx] = '\0';
	return 0;
}

/* len should be at least bufsize - 1,
 * advance returns how many characters to increment cursor position
 * a value of zero would indicate an error.
 */
char *eslib_string_toke(char *buf, unsigned int idx,
		const unsigned int len, unsigned int *advance)
{
	unsigned int cursor_start = idx;
	unsigned int token_start;

	*advance = 0;
	if (len == 0 || len >= STR_MAX || idx > len) {
		return NULL;
	}
	else if (idx == len) {
		/* delimiter was at end of line */
		*advance = 1;
		return NULL;
	}
	/* skip blank space */
	while (idx <= len)
	{
		if (buf[idx] != '\0')
			break;
		++idx;
	}
	if (idx > len) {
		*advance = idx - cursor_start;
		return NULL;
	}

	token_start = idx;

	/* get token len */
	while (idx <= len)
	{
		if (is_eol(buf[idx])) {
			break;
		}
		++idx;
	}
	if (idx > len) {
		return NULL;
	}
	*advance = ++idx - cursor_start;
	return &buf[token_start];
}
