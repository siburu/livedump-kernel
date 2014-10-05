/* wrprortect.h - Kernel space write protection support
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

#ifndef _WRPROTECT_H
#define _WRPROTECT_H

typedef void (*fn_handle_page_t)(unsigned long pfn, int for_sweep);

extern unsigned long *wrprotect_create_page_bitmap(void);
extern void wrprotect_destroy_page_bitmap(unsigned long *pgbmp);

extern int wrprotect_init(
		unsigned long *pgbmp,
		fn_handle_page_t fn_handle_page);
extern void wrprotect_uninit(void);

extern int wrprotect_start(void);
extern int wrprotect_sweep(void);

extern void wrprotect_unselect_pages(
		unsigned long *pgbmp,
		unsigned long start,
		unsigned long len);

extern int wrprotect_is_on;
extern int wrprotect_page_fault_handler(unsigned long error_code);

#endif /* _WRPROTECT_H */
