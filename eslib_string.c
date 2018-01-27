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
 *
 *
 * obvious assumptions:
 *
 *       len <= size - 1
 *       ESLIB_STR_MAX < INT_MAX
 *
 * not so obvious:
 *
 * FIXME this won't work on systems where long < 32 or long long < 64
 *       since our use of strto(u)l and strto(u)ll currently make these assumptions.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "eslib.h"

#define DELIM_MAX 255

#define safe_char(chr) (			\
			   chr == ' '		\
			|| chr == '\n'		\
			|| chr == '\t'		\
)

int eslib_string_is_sane(char *buf, const unsigned int len)
{
	unsigned int idx;
	if (len == 0)
		return -1;
	for (idx = 0; idx < len; ++idx)
	{
		char c = buf[idx];
		/* you're on your own for 8-bit ascii */
		if (c < 32 || c >= 127) {
			if (!safe_char(c)) {
				return 0;
			}
		}
	}
	return 1;
}

/* return the length of line, not including newline or terminator.
 * returns == size if missing newline or terminator at end of buffer */
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
 *
 */
int eslib_string_tokenize(char *buf, const unsigned int len, char *delimiter)
{
	unsigned int buf_idx;
	unsigned int delim_idx;
	unsigned int delim_count = 0;

	if (len == 0) {
		errno = EINVAL;
		return -1;
	}
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

/* advance returns how many characters to increment idx
 * a value of zero would indicate an error.
 * after returning on the last toke, advance + idx may be out of bounds.
 * the next call will return NULL. advance is for convenience while not
 * relying on an internal state, not for calculating token lengths
 */
char *eslib_string_toke(char *buf, unsigned int idx,
		const unsigned int len, unsigned int *advance)
{
	unsigned int cursor_start = idx;
	unsigned int token_start;

	*advance = 0;
	if (len == 0 || len >= ESLIB_STR_MAX || idx > len) {
		return NULL;
	}
	else if (idx == len) {
		/* delimiter was at end of line */
		*advance = 1;
		return NULL;
	}
	/* skip leading blank space */
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
	while (idx < len + 1)
	{
		if (buf[idx] == '\0') {
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

int eslib_string_to_s32(char *str, int32_t *out, int base)
{
	int32_t ret;
	char *err = NULL;
	char c = str[0];

	errno = 0;
	if (base != 10) { /* TODO, hex, oct, binary, etc. */
		errno = EINVAL;
		return -1;
	}
	/* don't allow unexpected leading chars */
	if ((c < '0' || c > '9') && c != '-' && c != '+') {
		errno = EIO;
		return -1;
	}

	ret = strtol(str, &err, 10);
	if (err == NULL || *err || errno) {
		if (errno == ERANGE)
			errno = EOVERFLOW;
		else
			errno = EIO;
		return -1;
	}

	*out = ret;
	return 0;
}

int eslib_string_to_u32(char *str, uint32_t *out, int base)
{
	uint32_t ret;
	char *err = NULL;
	char c = str[0];

	errno = 0;
	if (base != 10) { /* TODO, hex, oct, binary, etc. */
		errno = EINVAL;
		return -1;
	}
	/* don't allow unexpected leading chars */
	if ((c < '0' || c > '9') && c != '+') {
		errno = EIO;
		return -1;
	}

	ret = strtoul(str, &err, 10);
	if (err == NULL || *err || errno) {
		if (errno == ERANGE)
			errno = EOVERFLOW;
		else
			errno = EIO;
		return -1;
	}

	*out = ret;
	return 0;
}

int eslib_string_to_s64(char *str, int64_t *out, int base)
{
	int64_t ret;
	char *err = NULL;
	char c = str[0];

	errno = 0;
	if (base != 10) { /* TODO, hex, oct, binary, etc. */
		errno = EINVAL;
		return -1;
	}
	/* don't allow unexpected leading chars */
	if ((c < '0' || c > '9') && c != '-' && c != '+') {
		errno = EIO;
		return -1;
	}

	ret = strtoll(str, &err, 10);
	if (err == NULL || *err || errno) {
		if (errno == ERANGE)
			errno = EOVERFLOW;
		else
			errno = EIO;
		return -1;
	}

	*out = ret;
	return 0;
}

int eslib_string_to_u64(char *str, uint64_t *out, int base)
{
	uint64_t ret;
	char *err = NULL;
	char c = str[0];

	errno = 0;
	if (base != 10) { /* TODO, hex, oct, binary, etc. */
		errno = EINVAL;
		return -1;
	}
	/* don't allow unexpected leading chars */
	if ((c < '0' || c > '9') && c != '+') {
		errno = EIO;
		return -1;
	}

	ret = strtoull(str, &err, 10);
	if (err == NULL || *err || errno) {
		if (errno == ERANGE)
			errno = EOVERFLOW;
		else
			errno = EIO;
		return -1;
	}

	*out = ret;
	return 0;
}
/* extra safe snprintf, returns 0 or -1 + errno. outlen is optional
 * size must be < ESLIB_STR_MAX
 * printing 0 chars or >= size is an error, but copy truncated string anyway
 * dst buffer gets fully zero'd if error is encountered in vsnprintf call
 */
int eslib_string_sprintf(char *dst, const unsigned int size,
			unsigned int *outlen, const char *fmt, ...)
{
	va_list args;
	int ret = 0;
	int r;

	errno = 0;
	if (size >= ESLIB_STR_MAX || !dst || !fmt) {
		dst[0] = '\0';
		errno = EINVAL;
		return -1;
	}

	va_start(args, fmt);
	r = vsnprintf(dst, size, fmt, args);
	va_end(args);

	if (r == 0) {
		errno = ECANCELED;
		ret = -1;
	}
	else if (r < 0) {
		errno = EIO;
		goto failed;
	}
	else if (r >= (int)size) {
		errno = EOVERFLOW;
		ret = -1;
		r = (int)size - 1;
	}
	dst[r] = '\0';

	if (outlen)
		*outlen = (unsigned int)r;

	return ret;

failed:
	memset(dst, 0, size);
	return -1;
}

/*
 * copying len 0 is error. so is len >= dst_size, but copy truncated string anyway.
 * if dst_size >= ESLIB_STR_MAX string is terminated at beginning
 */
int eslib_string_copy(char *dst,
		      const char *src,
		      const unsigned int dst_size,
		      unsigned int *outlen)
{
	size_t len;
	int ret = 0;
	errno = 0;
	if (dst_size == 0 || dst_size >= ESLIB_STR_MAX || !dst || !src) {
		dst[0] = '\0';
		errno = EINVAL;
		return -1;
	}

	len = strnlen(src, dst_size);
	if (len >= dst_size) {
		ret = -1;
		errno = EOVERFLOW;
		len = dst_size - 1;
	}
	else if (len == 0) {
		ret = -1;
		errno = ECANCELED;
	}

	memcpy(dst, src, len);
	dst[len] = '\0';
	if (outlen)
		*outlen = (unsigned int)len;

	return ret;
}
