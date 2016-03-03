/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 */

#include <stdio.h>
#include <malloc.h>
#include <errno.h>
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
