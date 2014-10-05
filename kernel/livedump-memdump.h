/* livedump-memdump.h - Live Dump's memory dumping management
 * Copyright (C) 2012 Hitachi, Ltd.
 * Author: YOSHIDA Masanori <masanori.yoshida.tv@hitachi.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#ifndef _LIVEDUMP_MEMDUMP_H
#define _LIVEDUMP_MEMDUMP_H

#include <linux/fs.h>

extern int livedump_memdump_init(unsigned long *pgbmp, const char *bdevpath);

extern void livedump_memdump_uninit(void);

extern void livedump_memdump_handle_page(unsigned long pfn, int for_sweep);

#endif /* _LIVEDUMP_MEMDUMP_H */
