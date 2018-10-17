#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>

#include "enic.h"

extern struct bus_type enic_bus;

static int enic_rdma_probe(struct device *dev)
{
	struct enic *enic = container_of(dev, struct enic, rdma_device);
	struct net_device *netdev = enic->netdev;

	/* probe RDMA driver here */
	netdev_err(netdev, "rdma probe");
	return 0;
}

static int enic_rdma_remove(struct device *dev)
{
	struct enic* enic = container_of(dev, struct enic, rdma_device);
	struct net_device *netdev = enic->netdev;

	/* remove RDMA driver here */
	netdev_err(netdev, "rdma remove");
	return 0;
}

static struct device_driver enic_rdma_driver = {
	.name = "enic_rdma",
	.bus = &enic_bus,
	.probe = enic_rdma_probe,
	.remove = enic_rdma_remove,
};

static int __init enic_rdma_init(void)
{
	pr_err("Hiya, this is rdma bus_type driver for %s", enic_bus.name);

	return driver_register(&enic_rdma_driver);;
}

static void __exit enic_rdma_exit(void)
{
	pr_err("Cheers m8.");
	driver_unregister(&enic_rdma_driver);
}

module_init(enic_rdma_init);
module_exit(enic_rdma_exit);

MODULE_LICENSE("GPL");
