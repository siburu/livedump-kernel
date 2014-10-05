/* livedump.c - Live Dump's main
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

#include <asm/wrprotect.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/reboot.h>

#define DEVICE_NAME	"livedump"

#define LIVEDUMP_IOC(x)	_IO(0xff, x)
#define LIVEDUMP_IOC_START LIVEDUMP_IOC(1)
#define LIVEDUMP_IOC_SWEEP LIVEDUMP_IOC(2)
#define LIVEDUMP_IOC_INIT LIVEDUMP_IOC(100)
#define LIVEDUMP_IOC_UNINIT LIVEDUMP_IOC(101)

unsigned long *pgbmp;

static void do_uninit(void)
{
	wrprotect_uninit();
	if (pgbmp) {
		wrprotect_destroy_page_bitmap(pgbmp);
		pgbmp = NULL;
	}
}

static int do_init(void)
{
	int ret;

	ret = -ENOMEM;
	pgbmp = wrprotect_create_page_bitmap();
	if (!pgbmp)
		goto err;

	ret = wrprotect_init(pgbmp, NULL);
	if (WARN(ret, "livedump: Failed to initialize Protection manager.\n"))
		goto err;

	return 0;
err:
	do_uninit();
	return ret;
}

static long livedump_ioctl(
		struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case LIVEDUMP_IOC_START:
		return wrprotect_start();
	case LIVEDUMP_IOC_SWEEP:
		return wrprotect_sweep();
	case LIVEDUMP_IOC_INIT:
		return do_init();
	case LIVEDUMP_IOC_UNINIT:
		do_uninit();
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

static const struct file_operations livedump_fops = {
	.unlocked_ioctl = livedump_ioctl,
};
static struct miscdevice livedump_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &livedump_fops,
};

static int livedump_exit(struct notifier_block *_, unsigned long __, void *___)
{
	misc_deregister(&livedump_misc);
	do_uninit();
	return NOTIFY_DONE;
}
static struct notifier_block livedump_nb = {
	.notifier_call = livedump_exit
};

static int __init livedump_init(void)
{
	int ret;

	ret = misc_register(&livedump_misc);
	if (WARN_ON(ret))
		return ret;

	ret = register_reboot_notifier(&livedump_nb);
	if (WARN_ON(ret)) {
		livedump_exit(NULL, 0, NULL);
		return ret;
	}

	return 0;
}
device_initcall(livedump_init);
