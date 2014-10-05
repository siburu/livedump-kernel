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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/reboot.h>

#define DEVICE_NAME	"livedump"

#define LIVEDUMP_IOC(x)	_IO(0xff, x)

static long livedump_ioctl(
		struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
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
