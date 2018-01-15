/*
 *
 * Linux Driver for Mylex DAC960/AcceleRAID/eXtremeRAID PCI RAID Controllers
 *
 * Copyright 2017 Hannes Reinecke, SUSE Linux GmbH <hare@suse.com>
 *
 * Based on the original DAC960 driver,
 * Copyright 1998-2001 by Leonard N. Zubkoff <lnz@dandelion.com>
 * Portions Copyright 2002 by Mylex (An IBM Business Unit)
 *
 * This program is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License Version 2 as published by the
 *  Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for complete details.
 */


#define DAC960_DriverName			"myr"

#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/blkpg.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/reboot.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/raid_class.h>
#include <asm/io.h>
#include <asm/unaligned.h>
#include <linux/uaccess.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_tcq.h>
#include "myr.h"

static DEFINE_MUTEX(DAC960_mutex);
static int DAC960_ControllerCount;

struct raid_template *myrb_raid_template;
struct raid_template *myrs_raid_template;

static void DAC960_MonitoringWork(struct work_struct *work);

/*
  init_dma_loaf() and slice_dma_loaf() are helper functions for
  aggregating the dma-mapped memory for a well-known collection of
  data structures that are of different lengths.

  These routines don't guarantee any alignment.  The caller must
  include any space needed for alignment in the sizes of the structures
  that are passed in.
*/

bool init_dma_loaf(struct pci_dev *dev, struct dma_loaf *loaf, size_t len)
{
	void *cpu_addr;
	dma_addr_t dma_handle;

	cpu_addr = pci_alloc_consistent(dev, len, &dma_handle);
	if (cpu_addr == NULL)
		return false;

	loaf->cpu_free = loaf->cpu_base = cpu_addr;
	loaf->dma_free =loaf->dma_base = dma_handle;
	loaf->length = len;
	memset(cpu_addr, 0, len);
	return true;
}

void *slice_dma_loaf(struct dma_loaf *loaf, size_t len, dma_addr_t *dma_handle)
{
	void *cpu_end = loaf->cpu_free + len;
	void *cpu_addr = loaf->cpu_free;

	BUG_ON(cpu_end > loaf->cpu_base + loaf->length);
	*dma_handle = loaf->dma_free;
	loaf->cpu_free = cpu_end;
	loaf->dma_free += len;
	return cpu_addr;
}

static void free_dma_loaf(struct pci_dev *dev, struct dma_loaf *loaf_handle)
{
	if (loaf_handle->cpu_base != NULL)
		pci_free_consistent(dev, loaf_handle->length,
				    loaf_handle->cpu_base, loaf_handle->dma_base);
}

/*
  myr_err_status reports Controller BIOS Messages passed through
  the Error Status Register when the driver performs the BIOS handshaking.
  It returns true for fatal errors and false otherwise.
*/

bool myr_err_status(myr_hba *c, unsigned char ErrorStatus,
		    unsigned char Parameter0, unsigned char Parameter1)
{
	struct pci_dev *pdev = c->pdev;

	switch (ErrorStatus) {
	case 0x00:
		dev_info(&pdev->dev,
			 "Physical Device %d:%d Not Responding\n",
			 Parameter1, Parameter0);
		break;
	case 0x08:
		if (c->DriveSpinUpMessageDisplayed)
			break;
		dev_notice(&pdev->dev, "Spinning Up Drives\n");
		c->DriveSpinUpMessageDisplayed = true;
		break;
	case 0x30:
		dev_notice(&pdev->dev, "Configuration Checksum Error\n");
		break;
	case 0x60:
		dev_notice(&pdev->dev, "Mirror Race Recovery Failed\n");
		break;
	case 0x70:
		dev_notice(&pdev->dev, "Mirror Race Recovery In Progress\n");
		break;
	case 0x90:
		dev_notice(&pdev->dev, "Physical Device %d:%d COD Mismatch\n",
			   Parameter1, Parameter0);
		break;
	case 0xA0:
		dev_notice(&pdev->dev, "Logical Drive Installation Aborted\n");
		break;
	case 0xB0:
		dev_notice(&pdev->dev, "Mirror Race On A Critical Logical Drive\n");
		break;
	case 0xD0:
		dev_notice(&pdev->dev, "New Controller Configuration Found\n");
		break;
	case 0xF0:
		dev_err(&pdev->dev, "Fatal Memory Parity Error\n");
		return true;
	default:
		dev_err(&pdev->dev, "Unknown Initialization Error %02X\n",
			ErrorStatus);
		return true;
	}
	return false;
}

/*
 * DAC960_DetectCleanup releases the resources that were allocated
 * during DAC960_DetectController().  DAC960_DetectController can
 * has several internal failure points, so not ALL resources may
 * have been allocated.  It's important to free only
 * resources that HAVE been allocated.  The code below always
 * tests that the resource has been allocated before attempting to
 * free it.
 */
static void DAC960_DetectCleanup(myr_hba *c)
{
	struct pci_dev *pdev = c->pdev;

	/* Free the memory mailbox, status, and related structures */
	if (c->FirmwareType == DAC960_V2_Controller)
		myrs_unmap(c);
	else
		free_dma_loaf(pdev, &c->DmaPages);

	if (c->MemoryMappedAddress) {
		myr_disable_intr(c);
		iounmap(c->MemoryMappedAddress);
	}
	if (c->IRQ_Channel)
		free_irq(c->IRQ_Channel, c);
	if (c->IO_Address)
		release_region(c->IO_Address, 0x80);
	pci_set_drvdata(pdev, NULL);
	pci_disable_device(pdev);
	destroy_workqueue(c->work_q);
	scsi_host_put(c->host);
}


/*
  DAC960_DetectController detects Mylex DAC960/AcceleRAID/eXtremeRAID
  PCI RAID Controllers by interrogating the PCI Configuration Space for
  Controller Type.
*/

static myr_hba *
DAC960_DetectController(struct pci_dev *pdev,
			const struct pci_device_id *entry)
{
	struct DAC960_privdata *privdata =
		(struct DAC960_privdata *)entry->driver_data;
	irq_handler_t InterruptHandler = privdata->InterruptHandler;
	unsigned int MemoryWindowSize = privdata->MemoryWindowSize;
	myr_hba *c = NULL;

	if (privdata->FirmwareType == DAC960_V1_Controller)
		c = myrb_alloc_host(pdev, entry);
	else
		c = myrs_alloc_host(pdev, entry);

	if (!c) {
		dev_err(&pdev->dev, "Unable to allocate Controller\n");
		return NULL;
	}
	c->ControllerNumber = DAC960_ControllerCount++;
	c->FirmwareType = privdata->FirmwareType;
	c->HardwareType = privdata->HardwareType;
	c->pdev = pdev;
	strcpy(c->FullModelName, "DAC960");

	snprintf(c->work_q_name, sizeof(c->work_q_name),
		 "myr_wq_%d", c->host->host_no);
	c->work_q = create_singlethread_workqueue(c->work_q_name);
	if (!c->work_q)
		goto Failure;

	if (pci_enable_device(pdev))
		goto Failure;

	switch (c->HardwareType) {
	case DAC960_PD_Controller:
	case DAC960_P_Controller:
		c->IO_Address = pci_resource_start(pdev, 0);
		c->PCI_Address = pci_resource_start(pdev, 1);
		break;
	default:
		c->PCI_Address = pci_resource_start(pdev, 0);
		break;
	}

	pci_set_drvdata(pdev, c);
	spin_lock_init(&c->queue_lock);
	/*
	  Map the Controller Register Window.
	*/
	if (MemoryWindowSize < PAGE_SIZE)
		MemoryWindowSize = PAGE_SIZE;
	c->MemoryMappedAddress =
		ioremap_nocache(c->PCI_Address & PAGE_MASK, MemoryWindowSize);
	if (c->MemoryMappedAddress == NULL) {
		dev_err(&pdev->dev,
			"Unable to map Controller Register Window\n");
		goto Failure;
	}

	c->io_addr = c->MemoryMappedAddress + (c->PCI_Address & ~PAGE_MASK);
	if (privdata->HardwareInit(pdev, c, c->io_addr))
		goto Failure;

	/*
	  Acquire shared access to the IRQ Channel.
	*/
	if (request_irq(pdev->irq, InterruptHandler, IRQF_SHARED,
			c->FullModelName, c) < 0) {
		dev_err(&pdev->dev,
			"Unable to acquire IRQ Channel %d\n", pdev->irq);
		goto Failure;
	}
	c->IRQ_Channel = pdev->irq;
	return c;

Failure:
	dev_err(&pdev->dev,
		"Failed to initialize Controller\n");
	DAC960_DetectCleanup(c);
	DAC960_ControllerCount--;
	return NULL;
}

static bool DAC960_CreateAuxiliaryStructures(myr_hba *c)
{
	struct pci_dev *pdev = c->pdev;

	if (c->FirmwareType == DAC960_V1_Controller)
		return myrb_create_mempools(pdev, c);
	else
		return myrs_create_mempools(pdev, c);
}

static void DAC960_DestroyAuxiliaryStructures(myr_hba *c)
{
	if (c->FirmwareType == DAC960_V1_Controller)
		myrb_destroy_mempools(c);
	else
		myrs_destroy_mempools(c);
}


/*
  DAC960_Probe verifies controller's existence and
  initializes the DAC960 Driver for that controller.
*/

static int
DAC960_Probe(struct pci_dev *dev, const struct pci_device_id *entry)
{
	myr_hba *c;
	int ret;

	c = DAC960_DetectController(dev, entry);
	if (!c)
		return -ENODEV;

	ret = c->ReadControllerConfiguration(c);
	if (ret < 0) {
		DAC960_DetectCleanup(c);
		return ret;
	}

	if (!DAC960_CreateAuxiliaryStructures(c)) {
		ret = -ENOMEM;
		goto failed;
	}

	/*
	  Initialize the Monitoring Timer.
	*/
	INIT_DELAYED_WORK(&c->monitor_work, DAC960_MonitoringWork);
	queue_delayed_work(c->work_q, &c->monitor_work, 1);

	ret = scsi_add_host(c->host, &dev->dev);
	if (ret) {
		dev_err(&dev->dev, "scsi_add_host failed with %d\n", ret);
		cancel_delayed_work_sync(&c->monitor_work);
		DAC960_DestroyAuxiliaryStructures(c);
		goto failed;
	}
	scsi_scan_host(c->host);
	return 0;
failed:
	DAC960_DetectCleanup(c);
	return ret;
}


/*
  DAC960_Remove removes the DAC960 Driver.
*/

static void DAC960_Remove(struct pci_dev *pdev)
{
	myr_hba *c = pci_get_drvdata(pdev);

	if (c == NULL)
		return;

	cancel_delayed_work_sync(&c->monitor_work);
	if (c->FirmwareType == DAC960_V1_Controller) {
		shost_printk(KERN_NOTICE, c->host, "Flushing Cache...");
		myrb_flush_cache(c);
	} else {
		shost_printk(KERN_NOTICE, c->host, "Flushing Cache...");
		myrs_flush_cache(c);
	}
	DAC960_DestroyAuxiliaryStructures(c);
	DAC960_DetectCleanup(c);
}


/*
  DAC960_MonitoringTimerFunction is the timer function for monitoring
  the status of DAC960 Controllers.
*/

static void DAC960_MonitoringWork(struct work_struct *work)
{
	myr_hba *c = container_of(work, myr_hba, monitor_work.work);
	unsigned long interval;

	dev_dbg(&c->host->shost_gendev, "monitor tick\n");
	if (c->FirmwareType == DAC960_V1_Controller)
		interval = myrb_monitor(c);
	else
		interval = myrs_monitor(c);

	if (interval > 1)
		c->PrimaryMonitoringTime = jiffies;
	queue_delayed_work(c->work_q, &c->monitor_work, interval);
}

static const struct pci_device_id DAC960_id_table[] = {
	{
		.vendor		= PCI_VENDOR_ID_MYLEX,
		.device		= PCI_DEVICE_ID_MYLEX_DAC960_GEM,
		.subvendor	= PCI_VENDOR_ID_MYLEX,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long) &DAC960_GEM_privdata,
	},
	{
		.vendor		= PCI_VENDOR_ID_MYLEX,
		.device		= PCI_DEVICE_ID_MYLEX_DAC960_BA,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long) &DAC960_BA_privdata,
	},
	{
		.vendor		= PCI_VENDOR_ID_MYLEX,
		.device		= PCI_DEVICE_ID_MYLEX_DAC960_LP,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long) &DAC960_LP_privdata,
	},
	{
		.vendor		= PCI_VENDOR_ID_DEC,
		.device		= PCI_DEVICE_ID_DEC_21285,
		.subvendor	= PCI_VENDOR_ID_MYLEX,
		.subdevice	= PCI_DEVICE_ID_MYLEX_DAC960_LA,
		.driver_data	= (unsigned long) &DAC960_LA_privdata,
	},
	{
		.vendor		= PCI_VENDOR_ID_MYLEX,
		.device		= PCI_DEVICE_ID_MYLEX_DAC960_PG,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long) &DAC960_PG_privdata,
	},
	{
		.vendor		= PCI_VENDOR_ID_MYLEX,
		.device		= PCI_DEVICE_ID_MYLEX_DAC960_PD,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long) &DAC960_PD_privdata,
	},
	{
		.vendor		= PCI_VENDOR_ID_MYLEX,
		.device		= PCI_DEVICE_ID_MYLEX_DAC960_P,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long) &DAC960_P_privdata,
	},
	{0, },
};

MODULE_DEVICE_TABLE(pci, DAC960_id_table);

static struct pci_driver DAC960_pci_driver = {
	.name		= "DAC960",
	.id_table	= DAC960_id_table,
	.probe		= DAC960_Probe,
	.remove		= DAC960_Remove,
};

static int __init DAC960_init_module(void)
{
	int ret;

	myrb_raid_template = raid_class_attach(&myrb_raid_functions);
	if (!myrb_raid_template)
		return -ENODEV;
	myrs_raid_template = raid_class_attach(&myrs_raid_functions);
	if (!myrs_raid_template) {
		raid_class_release(myrb_raid_template);
		return -ENODEV;
	}

	ret = pci_register_driver(&DAC960_pci_driver);
	if (ret) {
		raid_class_release(myrs_raid_template);
		raid_class_release(myrb_raid_template);
	}
	return ret;
}

static void __exit DAC960_cleanup_module(void)
{
	pci_unregister_driver(&DAC960_pci_driver);
	raid_class_release(myrs_raid_template);
	raid_class_release(myrb_raid_template);
}

module_init(DAC960_init_module);
module_exit(DAC960_cleanup_module);

MODULE_DESCRIPTION("Mylex DAC960/AcceleRAID/eXtremeRAID driver");
MODULE_AUTHOR("Hannes Reinecke <hare@suse.com>");
MODULE_LICENSE("GPL");
