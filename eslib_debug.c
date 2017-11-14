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
#include <malloc.h>
#include <execinfo.h> /* backtrace */

/* XXX needs -rdynamic set in LDFLAGS for function names*/
void eslib_dbg_print_backtrace()
{
	void *funcptrs[256];
	int count = backtrace(funcptrs, 256);
	char **funcstr = backtrace_symbols(funcptrs, count);
	int i;

	for (i = 0; i < count; ++i)
	{
		printf("-- %s\n", funcstr[i]);
	}
	free(funcstr);
}
