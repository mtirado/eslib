/* (c) 2016 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 */
#include <stdio.h>
#include "../eslib.h"
int main()
{
	int i;
	time_t timer = 0;

	if (eslib_logmsg(NULL, "null procname msg"))
		return -1;
	if (eslib_logmsg("devlog-test", "specified procname msg"))
		return -1;
	if (eslib_logerror("devlog-test", "specified procname error"))
		return -1;
	if (eslib_logcritical("devlog-test", "specified procname critical"))
		return -1;

	for (i = 0; i < 13000000; ++i)
	{
		if (eslib_logmsg_t("timer test", "delay @ 1s", &timer, 1))
			return -1;
	}

	return 0;
}
