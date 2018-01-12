/*
 *
 * Linux Driver for Mylex DAC960/AcceleRAID/eXtremeRAID PCI RAID Controllers
 *
 * Copyright 2017 Hannes Reinecke, SUSE Linux GmbH <hare@suse.com>
 *
 * Base on the original DAC960 driver,
 * Copyright 1998-2001 by Leonard N. Zubkoff <lnz@dandelion.com>
 *
 * This program is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License Version 2 as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for complete details.
 *
 */

#ifndef _MYR_H
#define _MYR_H

/*
  Define the maximum number of DAC960 Controllers supported by this driver.
*/

#define DAC960_MaxControllers			8


/*
  Define the maximum number of Logical Drives supported by DAC960
  V1 and V2 Firmware Controllers.
*/

#define DAC960_MaxLogicalDrives			32


#define DAC960_MAILBOX_TIMEOUT 1000000

extern struct raid_template *myrb_raid_template;
extern struct raid_template *myrs_raid_template;

/*
  dma_loaf is used by helper routines to divide a region of
  dma mapped memory into smaller pieces, where those pieces
  are not of uniform size.
 */

struct dma_loaf {
	void	*cpu_base;
	dma_addr_t dma_base;
	size_t  length;
	void	*cpu_free;
	dma_addr_t dma_free;
};


/*
  Define the DAC960 Driver IOCTL requests.
*/

#define DAC960_IOCTL_GET_CONTROLLER_COUNT	0xDAC001
#define DAC960_IOCTL_GET_CONTROLLER_INFO	0xDAC002
#define DAC960_IOCTL_V1_EXECUTE_COMMAND		0xDAC003
#define DAC960_IOCTL_V2_EXECUTE_COMMAND		0xDAC004
#define DAC960_IOCTL_V2_GET_HEALTH_STATUS	0xDAC005


/*
  Define the DAC960_IOCTL_GET_CONTROLLER_INFO reply structure.
*/

typedef struct DAC960_ControllerInfo
{
	unsigned char ControllerNumber;
	unsigned char FirmwareType;
	unsigned char Channels;
	unsigned char Targets;
	unsigned char PCI_Bus;
	unsigned char PCI_Device;
	unsigned char PCI_Function;
	unsigned char IRQ_Channel;
	phys_addr_t PCI_Address;
	unsigned char ModelName[20];
	unsigned char FirmwareVersion[12];
}
DAC960_ControllerInfo_T;


/*
  Define the maximum Driver Queue Depth and Controller Queue Depth supported
  by DAC960 V1 and V2 Firmware Controllers.
*/

#define DAC960_MaxDriverQueueDepth		511
#define DAC960_MaxControllerQueueDepth		512


/*
  Define the DAC960 Controller Monitoring Timer Interval.
*/

#define DAC960_MonitoringTimerInterval		(10 * HZ)


/*
  Define the DAC960 Controller Secondary Monitoring Interval.
*/

#define DAC960_SecondaryMonitoringInterval	(60 * HZ)


/*
  Define the DAC960 Controller Health Status Monitoring Interval.
*/

#define DAC960_HealthStatusMonitoringInterval	(1 * HZ)


/*
  Define the DAC960 Controller Progress Reporting Interval.
*/

#define DAC960_ProgressReportingInterval	(60 * HZ)

/*
  Define the DAC960 Controller fixed Block Size and Block Size Bits.
*/

#define DAC960_BlockSize			512
#define DAC960_BlockSizeBits			9


/*
  Define the Controller Line Buffer, Progress Buffer, User Message, and
  Initial Status Buffer sizes.
*/

#define DAC960_LineBufferSize			100


/*
  Define the DAC960 Controller Firmware Types.
*/

typedef enum
{
	DAC960_V1_Controller =			1,
	DAC960_V2_Controller =			2
}
DAC960_FirmwareType_T;


/*
  Define the DAC960 Controller Hardware Types.
*/

typedef enum
{
	DAC960_BA_Controller =			1,	/* eXtremeRAID 2000 */
	DAC960_LP_Controller =			2,	/* AcceleRAID 352 */
	DAC960_LA_Controller =			3,	/* DAC1164P */
	DAC960_PG_Controller =			4,	/* DAC960PTL/PJ/PG */
	DAC960_PD_Controller =			5,	/* DAC960PU/PD/PL/P */
	DAC960_P_Controller =			6,	/* DAC960PU/PD/PL/P */
	DAC960_GEM_Controller =			7,	/* AcceleRAID 4/5/600 */
}
DAC960_HardwareType_T;

struct myr_hba_s;

typedef int (*DAC960_HardwareInit_T)(struct pci_dev *pdev,
				     struct myr_hba_s *c, void __iomem *base);

struct DAC960_privdata {
	DAC960_HardwareType_T	HardwareType;
	DAC960_FirmwareType_T	FirmwareType;
	DAC960_HardwareInit_T	HardwareInit;
	irq_handler_t		InterruptHandler;
	unsigned int		MemoryWindowSize;
};

#define DAC960_DirectCommandIdentifier 1
#define DAC960_MonitoringIdentifier 2

typedef struct myr_hba_s
{
	void __iomem *io_addr;
	void __iomem *MemoryMappedAddress;
	DAC960_FirmwareType_T FirmwareType;
	DAC960_HardwareType_T HardwareType;
	phys_addr_t IO_Address;
	phys_addr_t PCI_Address;
	struct pci_dev *pdev;
	struct Scsi_Host *host;
	unsigned char ControllerNumber;
	unsigned char ControllerName[4];
	unsigned char ModelName[20];
	unsigned char FullModelName[28];
	unsigned char FirmwareVersion[12];
	unsigned char IRQ_Channel;
	unsigned char MemorySize;
	unsigned char LogicalDriveCount;
	unsigned char PhysicalChannelCount;
	unsigned char PhysicalChannelMax;
	unsigned char LogicalChannelCount;
	unsigned char LogicalChannelMax;
	struct dma_loaf DmaPages;
	unsigned long PrimaryMonitoringTime;
	unsigned long SecondaryMonitoringTime;
	unsigned long ShutdownMonitoringTimer;
	unsigned long LastProgressReportTime;
	unsigned long LastCurrentStatusTime;
	bool DriveSpinUpMessageDisplayed;
	bool SuppressEnclosureMessages;
	struct workqueue_struct *work_q;
	struct delayed_work monitor_work;
	struct pci_pool *ScatterGatherPool;
	spinlock_t queue_lock;
	char work_q_name[20];
	int (*ReadControllerConfiguration)(struct myr_hba_s *);
	void (*DisableInterrupts)(void __iomem *);
	void (*Reset)(void __iomem *);
} myr_hba;

#define myr_disable_intr(c) (c->DisableInterrupts)(c)

/*
 * dma_addr_writeql is provided to write dma_addr_t types
 * to a 64-bit pci address space register.  The controller
 * will accept having the register written as two 32-bit
 * values.
 *
 * In HIGHMEM kernels, dma_addr_t is a 64-bit value.
 * without HIGHMEM,  dma_addr_t is a 32-bit value.
 *
 * The compiler should always fix up the assignment
 * to u.wq appropriately, depending upon the size of
 * dma_addr_t.
 */
static inline
void dma_addr_writeql(dma_addr_t addr, void __iomem *write_address)
{
	union {
		u64 wq;
		uint wl[2];
	} u;

	u.wq = addr;

	writel(u.wl[0], write_address);
	writel(u.wl[1], write_address + 4);
}

bool init_dma_loaf(struct pci_dev *, struct dma_loaf *, size_t);
void *slice_dma_loaf(struct dma_loaf *, size_t, dma_addr_t *);

bool myr_err_status(myr_hba *,
		    unsigned char, unsigned char, unsigned char);

/*
 * myraid block:
 * driver for the older, block-based firmware interface
 */
extern struct raid_function_template myrb_raid_functions;
extern struct scsi_host_template myrb_template;

bool myrb_create_mempools(struct pci_dev *pdev, myr_hba *c);
void myrb_destroy_mempools(myr_hba *c);
void myrb_flush_cache(myr_hba *c);
unsigned long myrb_monitor(myr_hba *c);
void myrb_get_ctlr_info(myr_hba *c);
myr_hba *myrb_alloc_host(struct pci_dev *, const struct pci_device_id *);

extern struct DAC960_privdata DAC960_LA_privdata;
extern struct DAC960_privdata DAC960_PG_privdata;
extern struct DAC960_privdata DAC960_PD_privdata;
extern struct DAC960_privdata DAC960_P_privdata;

/*
 * myraid scsi:
 * driver for the newer, scsi-based firmware interface
 */
extern struct raid_function_template myrs_raid_functions;
extern struct scsi_host_template myrs_template;

bool myrs_create_mempools(struct pci_dev *pdev, myr_hba *c);
void myrs_destroy_mempools(myr_hba *c);
void myrs_flush_cache(myr_hba *c);
unsigned long myrs_monitor(myr_hba *c);
void myrs_get_ctlr_info(myr_hba *c);
myr_hba *myrs_alloc_host(struct pci_dev *, const struct pci_device_id *);

extern struct DAC960_privdata DAC960_GEM_privdata;
extern struct DAC960_privdata DAC960_BA_privdata;
extern struct DAC960_privdata DAC960_LP_privdata;

#endif /* _MYR_H */
