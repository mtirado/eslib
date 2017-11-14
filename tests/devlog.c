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
