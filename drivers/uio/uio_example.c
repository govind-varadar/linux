// SPDX-License-Identifier: GPL-2.0

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uio_driver.h>

#include <asm/io.h>

#define uio_info(format, ...)	pr_info("UIO_EXAMPLE: " format, ##__VA_ARGS__)

struct uio_info example_info;

static int __init uio_example_init(void)
{
	int ret;

	uio_info("UIO_EXAMPLE: INIT\n");

	example_info.name = "uio_example";
	example_info.version = "2023.1";
	example_info.irq = UIO_IRQ_NONE;

	ret = uio_register_device(NULL, &example_info);
	uio_info("uio_register_device: %d\n", ret);
	if (ret)
		return -1;
	return 0;
}

static void __exit uio_example_exit(void)
{
	uio_info("UIO_EXAMPLE: EXIT\n");
	uio_unregister_device(&example_info);
}

module_init(uio_example_init)
module_exit(uio_example_exit)
MODULE_LICENSE("GPL v2");
