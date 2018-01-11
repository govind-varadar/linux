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


#define DAC960_DriverName			"Mylex"

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
#include "mylex.h"

#define DAC960_MAILBOX_TIMEOUT 1000000


static DEFINE_MUTEX(DAC960_mutex);
static int DAC960_ControllerCount;

static struct raid_template *mylex_v1_raid_template;
static struct raid_template *mylex_v2_raid_template;

static struct DAC960_V1_DriveStateTbl {
	myr_v1_devstate state;
	char *name;
} DAC960_V1_DriveStateNames[] = {
	{ DAC960_V1_Device_Dead, "Dead" },
	{ DAC960_V1_Device_WriteOnly, "WriteOnly" },
	{ DAC960_V1_Device_Online, "Online" },
	{ DAC960_V1_Device_Critical, "Critical" },
	{ DAC960_V1_Device_Standby, "Standby" },
	{ DAC960_V1_Device_Offline, NULL },
};

static char *DAC960_V1_DriveStateName(myr_v1_devstate state)
{
	struct DAC960_V1_DriveStateTbl *entry =
		DAC960_V1_DriveStateNames;

	while (entry && entry->name) {
		if (entry->state == state)
			return entry->name;
		entry++;
	}
	return (state == DAC960_V1_Device_Offline) ? "Offline" : "Unknown";
}

static struct DAC960_V1_RAIDLevelTbl {
	DAC960_V1_RAIDLevel_T level;
	char *name;
} DAC960_V1_RAIDLevelNames[] = {
	{ DAC960_V1_RAID_Level0, "RAID0" },
	{ DAC960_V1_RAID_Level1, "RAID1" },
	{ DAC960_V1_RAID_Level3, "RAID3" },
	{ DAC960_V1_RAID_Level5, "RAID5" },
	{ DAC960_V1_RAID_Level6, "RAID6" },
	{ DAC960_V1_RAID_JBOD, "JBOD" },
	{ 0xff, NULL }
};

static char *DAC960_V1_RAIDLevelName(DAC960_V1_RAIDLevel_T level)
{
	struct DAC960_V1_RAIDLevelTbl *entry =
		DAC960_V1_RAIDLevelNames;

	while (entry && entry->name) {
		if (entry->level == level)
			return entry->name;
		entry++;
	}
	return NULL;
}

static struct DAC960_V2_DriveStateTbl {
	DAC960_V2_DriveState_T state;
	char *name;
} DAC960_V2_DriveStateNames[] = {
	{ DAC960_V2_Device_Unconfigured, "Unconfigured" },
	{ DAC960_V2_Device_Online, "Online" },
	{ DAC960_V2_Device_Rebuild, "Rebuild" },
	{ DAC960_V2_Device_Missing, "Missing" },
	{ DAC960_V2_Device_SuspectedCritical, "SuspectedCritical" },
	{ DAC960_V2_Device_Offline, "Offline" },
	{ DAC960_V2_Device_Critical, "Critical" },
	{ DAC960_V2_Device_SuspectedDead, "SuspectedDead" },
	{ DAC960_V2_Device_CommandedOffline, "CommandedOffline" },
	{ DAC960_V2_Device_Standby, "Standby" },
	{ DAC960_V2_Device_InvalidState, NULL },
};

static char *DAC960_V2_DriveStateName(DAC960_V2_DriveState_T state)
{
	struct DAC960_V2_DriveStateTbl *entry =
		DAC960_V2_DriveStateNames;

	while (entry && entry->name) {
		if (entry->state == state)
			return entry->name;
		entry++;
	}
	return NULL;
}

static struct DAC960_V2_RAIDLevelTbl {
	DAC960_V2_RAIDLevel_T level;
	char *name;
} DAC960_V2_RAIDLevelNames[] = {
	{ DAC960_V2_RAID_Level0, "RAID0" },
	{ DAC960_V2_RAID_Level1, "RAID1" },
	{ DAC960_V2_RAID_Level3, "RAID3 right asymmetric parity" },
	{ DAC960_V2_RAID_Level5, "RAID5 right asymmetric parity" },
	{ DAC960_V2_RAID_Level6, "RAID6" },
	{ DAC960_V2_RAID_JBOD, "JBOD" },
	{ DAC960_V2_RAID_NewSpan, "New Mylex SPAN" },
	{ DAC960_V2_RAID_Level3F, "RAID3 fixed parity" },
	{ DAC960_V2_RAID_Level3L, "RAID3 left symmetric parity" },
	{ DAC960_V2_RAID_Span, "Mylex SPAN" },
	{ DAC960_V2_RAID_Level5L, "RAID5 left symmetric parity" },
	{ DAC960_V2_RAID_LevelE, "RAIDE (concatenation)" },
	{ DAC960_V2_RAID_Physical, "Physical device" },
	{ 0xff, NULL }
};

static char *DAC960_V2_RAIDLevelName(DAC960_V2_RAIDLevel_T level)
{
	struct DAC960_V2_RAIDLevelTbl *entry =
		DAC960_V2_RAIDLevelNames;

	while (entry && entry->name) {
		if (entry->level == level)
			return entry->name;
		entry++;
	}
	return NULL;
}

/*
  DAC960_V2_ReportProgress prints an appropriate progress message for
  Logical Device Long Operations.
*/

static void DAC960_V2_ReportProgress(myr_hba *c,
				     unsigned short ldev_num,
				     unsigned char *msg,
				     unsigned long blocks,
				     unsigned long size)
{
	shost_printk(KERN_INFO, c->host,
		     "Logical Drive %d: %s in Progress: %ld%% completed\n",
		     ldev_num, msg, (100 * (blocks >> 7)) / (size >> 7));
}

/*
  init_dma_loaf() and slice_dma_loaf() are helper functions for
  aggregating the dma-mapped memory for a well-known collection of
  data structures that are of different lengths.

  These routines don't guarantee any alignment.  The caller must
  include any space needed for alignment in the sizes of the structures
  that are passed in.
*/

static bool init_dma_loaf(struct pci_dev *dev, struct dma_loaf *loaf,
			  size_t len)
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

static void *slice_dma_loaf(struct dma_loaf *loaf, size_t len,
			    dma_addr_t *dma_handle)
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
  DAC960_CreateAuxiliaryStructures allocates and initializes the auxiliary
  data structures for Controller.  It returns true on success and false on
  failure.
*/

static bool DAC960_CreateAuxiliaryStructures(myr_hba *c)
{
	struct pci_dev *pdev = c->PCIDevice;
	struct pci_pool *ScatterGatherPool;
	struct pci_pool *RequestSensePool = NULL;
	struct pci_pool *DCDBPool = NULL;
	size_t elem_size, elem_align;

	if (c->FirmwareType == DAC960_V1_Controller) {
		elem_align = sizeof(DAC960_V1_ScatterGatherSegment_T);
		elem_size = c->host->sg_tablesize * elem_align;
		ScatterGatherPool = pci_pool_create("DAC960_V1_ScatterGather",
						    pdev, elem_size,
						    elem_align, 0);
		if (ScatterGatherPool == NULL) {
			shost_printk(KERN_ERR, c->host,
				     "Failed to allocate SG pool\n");
			return false;
		}
		elem_size = sizeof(DAC960_V1_DCDB_T);
		elem_align = sizeof(unsigned int);
		DCDBPool = pci_pool_create("DAC960_V1_DCDB",
					   pdev, elem_size, elem_align, 0);
		if (!DCDBPool) {
			pci_pool_destroy(ScatterGatherPool);
			shost_printk(KERN_ERR, c->host,
				     "Failed to allocate DCDB pool\n");
			return false;
		}
		c->ScatterGatherPool = ScatterGatherPool;
		c->V1.DCDBPool = DCDBPool;
	} else {
		elem_align = sizeof(DAC960_V2_ScatterGatherSegment_T);
		elem_size = c->host->sg_tablesize * elem_align;
		ScatterGatherPool = pci_pool_create("DAC960_V2_ScatterGather",
						    pdev, elem_size,
						    elem_align, 0);
		if (ScatterGatherPool == NULL) {
			shost_printk(KERN_ERR, c->host,
				     "Failed to allocate SG pool\n");
			return false;
		}
		elem_size = DAC960_V2_SENSE_BUFFERSIZE;
		elem_align = sizeof(int);
		RequestSensePool = pci_pool_create("DAC960_V2_RequestSense",
						   pdev, elem_size,
						   elem_align, 0);
		if (RequestSensePool == NULL) {
			pci_pool_destroy(ScatterGatherPool);
			shost_printk(KERN_ERR, c->host,
				     "Failed to allocate sense data pool\n");
			return false;
		}
		elem_size = DAC960_V2_DCDB_SIZE;
		elem_align = sizeof(unsigned char);
		DCDBPool = pci_pool_create("DAC960_V2_DCDB",
					   pdev, elem_size, elem_align, 0);
		if (!DCDBPool) {
			pci_pool_destroy(ScatterGatherPool);
			pci_pool_destroy(RequestSensePool);
			shost_printk(KERN_ERR, c->host,
				     "Failed to allocate DCDB pool\n");
			return false;
		}
		c->ScatterGatherPool = ScatterGatherPool;
		c->V2.RequestSensePool = RequestSensePool;
		c->V2.DCDBPool = DCDBPool;
	}
	return true;
}


/*
  DAC960_DestroyAuxiliaryStructures deallocates the auxiliary data
  structures for Controller.
*/

static void DAC960_DestroyAuxiliaryStructures(myr_hba *c)
{
	if (c->ScatterGatherPool != NULL)
		pci_pool_destroy(c->ScatterGatherPool);

	if (c->FirmwareType == DAC960_V1_Controller) {
		if (c->V1.DCDBPool)
			pci_pool_destroy(c->V1.DCDBPool);
	} else {
		if (c->V2.DCDBPool)
			pci_pool_destroy(c->V2.DCDBPool);
		if (c->V2.RequestSensePool)
			pci_pool_destroy(c->V2.RequestSensePool);
	}
}


/*
  DAC960_V1_ClearCommand clears critical fields of Command for DAC960 V1
  Firmware Controllers.
*/

static inline void DAC960_V1_ClearCommand(myr_v1_cmdblk *cmd_blk)
{
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;

	memset(mbox, 0, sizeof(DAC960_V1_CommandMailbox_T));
	cmd_blk->status = 0;
}


/*
  DAC960_V2_ClearCommand clears critical fields of Command for DAC960 V2
  Firmware Controllers.
*/

static inline void DAC960_V2_ClearCommand(myr_v2_cmdblk *cmd_blk)
{
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;

	memset(mbox, 0, sizeof(DAC960_V2_CommandMailbox_T));
	cmd_blk->status = 0;
}


/*
 * DAC960_V2_QueueCommand queues Command for DAC960 V2 Series Controllers.
 */
static void DAC960_V2_QueueCommand(myr_hba *c,
				   myr_v2_cmdblk *cmd_blk)
{
	void __iomem *base = c->BaseAddress;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V2_CommandMailbox_T *next_mbox =
		c->V2.NextCommandMailbox;

	c->V2.WriteCommandMailbox(next_mbox, mbox);

	if (c->V2.PreviousCommandMailbox1->Words[0] == 0 ||
	    c->V2.PreviousCommandMailbox2->Words[0] == 0)
		c->V2.MailboxNewCommand(base);

	c->V2.PreviousCommandMailbox2 =
		c->V2.PreviousCommandMailbox1;
	c->V2.PreviousCommandMailbox1 = next_mbox;

	if (++next_mbox > c->V2.LastCommandMailbox)
		next_mbox = c->V2.FirstCommandMailbox;

	c->V2.NextCommandMailbox = next_mbox;
}

/*
 * DAC960_V1_QueueCommand queues Command for DAC960 V1 Series Controller
 */

static void DAC960_V1_QueueCommand(myr_hba *c,
				   myr_v1_cmdblk *cmd_blk)
{
	void __iomem *base = c->BaseAddress;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V1_CommandMailbox_T *next_mbox =
		c->V1.NextCommandMailbox;

	c->V1.WriteCommandMailbox(next_mbox, mbox);
	if (c->V1.PreviousCommandMailbox1->Words[0] == 0 ||
	    c->V1.PreviousCommandMailbox2->Words[0] == 0)
		c->V1.MailboxNewCommand(base);
	c->V1.PreviousCommandMailbox2 =
		c->V1.PreviousCommandMailbox1;
	c->V1.PreviousCommandMailbox1 = next_mbox;
	if (++next_mbox > c->V1.LastCommandMailbox)
		next_mbox = c->V1.FirstCommandMailbox;
	c->V1.NextCommandMailbox = next_mbox;
}

/*
  DAC960_PD_QueueCommand queues Command for DAC960 PD Series Controllers.
*/

static void DAC960_PD_QueueCommand(myr_hba *c,
				   myr_v1_cmdblk *cmd_blk)
{
	void __iomem *base = c->BaseAddress;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;

	while (DAC960_PD_MailboxFullP(base))
		udelay(1);
	DAC960_PD_WriteCommandMailbox(base, mbox);
	DAC960_PD_NewCommand(base);
}


/*
  DAC960_P_QueueCommand queues Command for DAC960 P Series Controllers.
*/

static void DAC960_P_QueueCommand(myr_hba *c,
				  myr_v1_cmdblk *cmd_blk)
{
	void __iomem *base = c->BaseAddress;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;

	switch (mbox->Common.opcode) {
	case DAC960_V1_Enquiry:
		mbox->Common.opcode = DAC960_V1_Enquiry_Old;
		break;
	case DAC960_V1_GetDeviceState:
		mbox->Common.opcode = DAC960_V1_GetDeviceState_Old;
		break;
	case DAC960_V1_Read:
		mbox->Common.opcode = DAC960_V1_Read_Old;
		DAC960_PD_To_P_TranslateReadWriteCommand(cmd_blk);
		break;
	case DAC960_V1_Write:
		mbox->Common.opcode = DAC960_V1_Write_Old;
		DAC960_PD_To_P_TranslateReadWriteCommand(cmd_blk);
		break;
	case DAC960_V1_ReadWithScatterGather:
		mbox->Common.opcode = DAC960_V1_ReadWithScatterGather_Old;
		DAC960_PD_To_P_TranslateReadWriteCommand(cmd_blk);
		break;
	case DAC960_V1_WriteWithScatterGather:
		mbox->Common.opcode = DAC960_V1_WriteWithScatterGather_Old;
		DAC960_PD_To_P_TranslateReadWriteCommand(cmd_blk);
		break;
	default:
		break;
	}
	while (DAC960_PD_MailboxFullP(base))
		udelay(1);
	DAC960_PD_WriteCommandMailbox(base, mbox);
	DAC960_PD_NewCommand(base);
}

/*
 * DAC960_V1_ExecuteCommand executes V1 Command and waits for completion.
 */

static void DAC960_V1_ExecuteCommand(myr_hba *c,
				     myr_v1_cmdblk *cmd_blk)
{
	DECLARE_COMPLETION_ONSTACK(Completion);
	unsigned long flags;

	cmd_blk->Completion = &Completion;

	spin_lock_irqsave(&c->queue_lock, flags);
	c->V1.QueueCommand(c, cmd_blk);
	spin_unlock_irqrestore(&c->queue_lock, flags);

	if (in_interrupt())
		return;
	wait_for_completion(&Completion);
}

/*
 * DAC960_V2_ExecuteCommand executes V1 Command and waits for completion.
 */

static void DAC960_V2_ExecuteCommand(myr_hba *c,
				     myr_v2_cmdblk *cmd_blk)
{
	DECLARE_COMPLETION_ONSTACK(Completion);
	unsigned long flags;

	cmd_blk->Completion = &Completion;
	spin_lock_irqsave(&c->queue_lock, flags);
	c->V2.QueueCommand(c, cmd_blk);
	spin_unlock_irqrestore(&c->queue_lock, flags);

	if (in_interrupt())
		return;
	wait_for_completion(&Completion);
}


/*
  DAC960_V1_ExecuteType3 executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short DAC960_V1_ExecuteType3(myr_hba *c,
					     myr_v1_cmd_opcode op,
					     dma_addr_t DataDMA)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.DirectCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_DirectCommandIdentifier;
	mbox->Type3.opcode = op;
	mbox->Type3.BusAddress = DataDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V1.dcmd_mutex);
	return status;
}


/*
  DAC960_V1_ExecuteTypeB executes a DAC960 V1 Firmware Controller Type 3B
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short DAC960_V1_ExecuteType3B(myr_hba *c,
					      myr_v1_cmd_opcode op,
					      unsigned char CommandOpcode2,
					      dma_addr_t DataDMA)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.DirectCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3B.id = DAC960_DirectCommandIdentifier;
	mbox->Type3B.opcode = op;
	mbox->Type3B.CommandOpcode2 = CommandOpcode2;
	mbox->Type3B.BusAddress = DataDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V1.dcmd_mutex);
	return status;
}


/*
  DAC960_V1_ExecuteType3D executes a DAC960 V1 Firmware Controller Type 3D
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short DAC960_V1_ExecuteType3D(myr_hba *c,
					      myr_v1_cmd_opcode op,
					      struct scsi_device *sdev)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.DirectCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	myr_v1_pdev_state *pdev_info = sdev->hostdata;
	unsigned short status;

	if (!pdev_info) {
		pdev_info = kzalloc(sizeof(*pdev_info), GFP_KERNEL);
		if (!pdev_info)
			return DAC960_V1_OutOfMemory;
	}
	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3D.id = DAC960_DirectCommandIdentifier;
	mbox->Type3D.opcode = op;
	mbox->Type3D.Channel = sdev->channel;
	mbox->Type3D.TargetID = sdev->id;
	mbox->Type3D.BusAddress = c->V1.NewDeviceStateDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion)
		memcpy(pdev_info, c->V1.NewDeviceState, sizeof(*pdev_info));
	else {
		kfree(pdev_info);
		pdev_info = NULL;
	}
	mutex_unlock(&c->V1.dcmd_mutex);

	if (!sdev->hostdata && pdev_info)
		sdev->hostdata = pdev_info;
	if (sdev->hostdata && !pdev_info)
		sdev->hostdata = NULL;
	return status;
}


/*
  DAC960_V1_GetEventLog executes a DAC960 V1 Firmware Controller Type 3E
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short DAC960_V1_MonitorGetEventLog(myr_hba *c,
						   unsigned int event)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.MonitoringCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;
	static char *DAC960_EventMessages[] =
		{ "killed because write recovery failed",
		  "killed because of SCSI bus reset failure",
		  "killed because of double check condition",
		  "killed because it was removed",
		  "killed because of gross error on SCSI chip",
		  "killed because of bad tag returned from drive",
		  "killed because of timeout on SCSI command",
		  "killed because of reset SCSI command issued from system",
		  "killed because busy or parity error count exceeded limit",
		  "killed because of 'kill drive' command from system",
		  "killed because of selection timeout",
		  "killed due to SCSI phase sequence error",
		  "killed due to unknown status" };

	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3E.id = DAC960_MonitoringIdentifier;
	mbox->Type3E.opcode = DAC960_V1_PerformEventLogOperation;
	mbox->Type3E.OperationType = DAC960_V1_GetEventLogEntry;
	mbox->Type3E.OperationQualifier = 1;
	mbox->Type3E.SequenceNumber = event;
	mbox->Type3E.BusAddress = c->V1.EventLogEntryDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		DAC960_V1_EventLogEntry_T *EventLogEntry =
			c->V1.EventLogEntry;
		if (EventLogEntry->SequenceNumber == event) {
			struct scsi_sense_hdr sshdr;

			memset(&sshdr, 0, sizeof(sshdr));
			scsi_normalize_sense(EventLogEntry->SenseData, 32,
					     &sshdr);

			if (sshdr.sense_key == VENDOR_SPECIFIC &&
			    sshdr.asc == 0x80 &&
			    sshdr.ascq < ARRAY_SIZE(DAC960_EventMessages)) {
				shost_printk(KERN_CRIT, c->host,
					     "Physical drive %d:%d: %s\n",
					     EventLogEntry->Channel,
					     EventLogEntry->TargetID,
					     DAC960_EventMessages[sshdr.ascq]);
			} else {
				shost_printk(KERN_CRIT, c->host,
					     "Physical drive %d:%d: "
					     "Sense: %X/%02X/%02X\n",
					     EventLogEntry->Channel,
					     EventLogEntry->TargetID,
					     sshdr.sense_key,
					     sshdr.asc, sshdr.ascq);
			}
		}
	} else
		shost_printk(KERN_INFO, c->host,
			     "Failed to get event log %d, status %04x\n",
			     event, status);

	return status;
}

/*
  DAC960_V1_GetErrorTable executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static void DAC960_V1_MonitorGetErrorTable(myr_hba *c)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.MonitoringCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetErrorTable;
	mbox->Type3.BusAddress = c->V1.NewErrorTableDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		DAC960_V1_ErrorTable_T *old_table = &c->V1.ErrorTable;
		DAC960_V1_ErrorTable_T *new_table = c->V1.NewErrorTable;
		DAC960_V1_ErrorTableEntry_T *new_entry, *old_entry;
		struct scsi_device *sdev;

		shost_for_each_device(sdev, c->host) {
			if (sdev->channel >= c->PhysicalChannelCount)
				continue;
			new_entry =
				&new_table->ErrorTableEntries[sdev->channel][sdev->id];
			old_entry =
				&old_table->ErrorTableEntries[sdev->channel][sdev->id];
			if ((new_entry->ParityErrorCount !=
			     old_entry->ParityErrorCount) ||
			    (new_entry->SoftErrorCount !=
			     old_entry->SoftErrorCount) ||
			    (new_entry->HardErrorCount !=
			     old_entry->HardErrorCount) ||
			    (new_entry->MiscErrorCount !=
			     old_entry->MiscErrorCount))
				sdev_printk(KERN_CRIT, sdev,
					    "Errors: "
					    "Parity = %d, Soft = %d, "
					    "Hard = %d, Misc = %d\n",
					    new_entry->ParityErrorCount,
					    new_entry->SoftErrorCount,
					    new_entry->HardErrorCount,
					    new_entry->MiscErrorCount);
		}
		memcpy(&c->V1.ErrorTable, c->V1.NewErrorTable,
		       sizeof(DAC960_V1_ErrorTable_T));
	}
}

/*
  DAC960_V1_GetLogicalDriveInfo executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short DAC960_V1_GetLogicalDriveInfo(myr_hba *c)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.DirectCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_DirectCommandIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetLogicalDeviceInfo;
	mbox->Type3.BusAddress = c->V1.LogicalDeviceInfoDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V1.dcmd_mutex);
	if (status == DAC960_V1_NormalCompletion) {
		int ldev_num;
		for (ldev_num = 0; ldev_num < c->LogicalDriveCount; ldev_num++) {
			DAC960_V1_LogicalDeviceInfo_T *old = NULL;
			DAC960_V1_LogicalDeviceInfo_T *new =
				c->V1.LogicalDeviceInfo[ldev_num];
			struct scsi_device *sdev;
			unsigned short ldev_num;
			myr_v1_devstate old_state =
				DAC960_V1_Device_Offline;

			sdev = scsi_device_lookup(c->host,
						  c->PhysicalChannelCount,
						  ldev_num, 0);
			if (sdev && sdev->hostdata)
				old = sdev->hostdata;
			else if (new->State == DAC960_V1_Device_Online) {
				shost_printk(KERN_INFO, c->host,
					     "Logical Drive %d is now Online\n",
					     ldev_num);
				scsi_add_device(c->host,
						c->PhysicalChannelCount,
						ldev_num, 0);
				break;
			}
			if (old)
				old_state = old->State;
			if (new->State != old_state)
				shost_printk(KERN_INFO, c->host,
					 "Logical Drive %d is now %s\n",
					 ldev_num,
					 DAC960_V1_DriveStateName(new->State));
			if (old && new->WriteBack != old->WriteBack)
				sdev_printk(KERN_INFO, sdev,
					 "Logical Drive is now %s\n",
					 (new->WriteBack
					  ? "WRITE BACK" : "WRITE THRU"));
			if (old)
				memcpy(old, new, sizeof(*new));
		}
	}
	return status;
}


/*
  DAC960_V1_RebuildProgress executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static void DAC960_V1_MonitorRebuildProgress(myr_hba *c)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.MonitoringCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetRebuildProgress;
	mbox->Type3.BusAddress = c->V1.RebuildProgressDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		unsigned int ldev_num =
			c->V1.RebuildProgress->LogicalDriveNumber;
		unsigned int LogicalDriveSize =
			c->V1.RebuildProgress->LogicalDriveSize;
		unsigned int BlocksCompleted =
			LogicalDriveSize - c->V1.RebuildProgress->RemainingBlocks;
		struct scsi_device *sdev;

		sdev = scsi_device_lookup(c->host,
					  c->PhysicalChannelCount,
					  ldev_num, 0);
		if (status == DAC960_V1_NoRebuildOrCheckInProgress &&
		    c->V1.LastRebuildStatus == DAC960_V1_NormalCompletion)
			status = DAC960_V1_RebuildSuccessful;
		switch (status) {
		case DAC960_V1_NormalCompletion:
			sdev_printk(KERN_INFO, sdev,
				     "Rebuild in Progress, "
				     "%d%% completed\n",
				     (100 * (BlocksCompleted >> 7))
				     / (LogicalDriveSize >> 7));
			break;
		case DAC960_V1_RebuildFailed_LogicalDriveFailure:
			sdev_printk(KERN_INFO, sdev,
				    "Rebuild Failed due to "
				    "Logical Drive Failure\n");
			break;
		case DAC960_V1_RebuildFailed_BadBlocksOnOther:
			sdev_printk(KERN_INFO, sdev,
				    "Rebuild Failed due to "
				    "Bad Blocks on Other Drives\n");
			break;
		case DAC960_V1_RebuildFailed_NewDriveFailed:
			sdev_printk(KERN_INFO, sdev,
				    "Rebuild Failed due to "
				    "Failure of Drive Being Rebuilt\n");
			break;
		case DAC960_V1_NoRebuildOrCheckInProgress:
			break;
		case DAC960_V1_RebuildSuccessful:
			sdev_printk(KERN_INFO, sdev,
				    "Rebuild Completed Successfully\n");
			break;
		case DAC960_V1_RebuildSuccessfullyTerminated:
			sdev_printk(KERN_INFO, sdev,
				     "Rebuild Successfully Terminated\n");
			break;
		}
		c->V1.LastRebuildStatus = status;
	}
}


/*
  DAC960_V1_ConsistencyCheckProgress executes a DAC960 V1 Firmware Controller
  Type 3 Command and waits for completion.
*/

static void DAC960_V1_ConsistencyCheckProgress(myr_hba *c)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.MonitoringCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_RebuildStat;
	mbox->Type3.BusAddress = c->V1.RebuildProgressDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		unsigned int ldev_num =
			c->V1.RebuildProgress->LogicalDriveNumber;
		unsigned int LogicalDriveSize =
			c->V1.RebuildProgress->LogicalDriveSize;
		unsigned int BlocksCompleted =
			LogicalDriveSize - c->V1.RebuildProgress->RemainingBlocks;
		struct scsi_device *sdev;

		sdev = scsi_device_lookup(c->host, c->PhysicalChannelCount,
					  ldev_num, 0);
		sdev_printk(KERN_INFO, sdev,
			    "Consistency Check in Progress: %d%% completed\n",
			    (100 * (BlocksCompleted >> 7))
			    / (LogicalDriveSize >> 7));
	}
}


/*
  DAC960_V1_BackgroundInitialization executes a DAC960 V1 Firmware Controller
  Type 3B Command and waits for completion.
*/

static void DAC960_V1_BackgroundInitialization(myr_hba *c)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.MonitoringCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V1_BackgroundInitializationStatus_T *bgi, *last_bgi;
	struct scsi_device *sdev;
	unsigned short status;

	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3B.id = DAC960_DirectCommandIdentifier;
	mbox->Type3B.opcode = DAC960_V1_BackgroundInitializationControl;
	mbox->Type3B.CommandOpcode2 = 0x20;
	mbox->Type3B.BusAddress = c->V1.BackgroundInitializationStatusDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	bgi = c->V1.BackgroundInitializationStatus;
	last_bgi = &c->V1.LastBackgroundInitializationStatus;
	sdev = scsi_device_lookup(c->host, c->PhysicalChannelCount,
				  bgi->LogicalDriveNumber, 0);
	switch (status) {
	case DAC960_V1_NormalCompletion:
		switch (bgi->Status) {
		case DAC960_V1_BackgroundInitializationInvalid:
			break;
		case DAC960_V1_BackgroundInitializationStarted:
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Started\n");
			break;
		case DAC960_V1_BackgroundInitializationInProgress:
			if (bgi->BlocksCompleted ==
			    last_bgi->BlocksCompleted &&
			    bgi->LogicalDriveNumber ==
			    last_bgi->LogicalDriveNumber)
				break;
			sdev_printk(KERN_INFO, sdev,
				 "Background Initialization in Progress: "
				 "%d%% completed\n",
				 (100 * (bgi->BlocksCompleted >> 7))
				 / (bgi->LogicalDriveSize >> 7));
			break;
		case DAC960_V1_BackgroundInitializationSuspended:
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Suspended\n");
			break;
		case DAC960_V1_BackgroundInitializationCancelled:
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Cancelled\n");
			break;
		}
		memcpy(&c->V1.LastBackgroundInitializationStatus,
		       c->V1.BackgroundInitializationStatus,
		       sizeof(DAC960_V1_BackgroundInitializationStatus_T));
		break;
	case DAC960_V1_BackgroundInitSuccessful:
		if (bgi->Status ==
		    DAC960_V1_BackgroundInitializationInProgress)
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization "
				    "Completed Successfully\n");
		bgi->Status = DAC960_V1_BackgroundInitializationInvalid;
		break;
	case DAC960_V1_BackgroundInitAborted:
		if (bgi->Status ==
		    DAC960_V1_BackgroundInitializationInProgress)
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Aborted\n");
		bgi->Status = DAC960_V1_BackgroundInitializationInvalid;
		break;
	case DAC960_V1_NoBackgroundInitInProgress:
		break;
	}
}

/*
  DAC960_V1_ConsistencyCheckProgress executes a DAC960 V1 Firmware Controller
  Type 3 Command and waits for completion.
*/

static unsigned short DAC960_V1_NewEnquiry(myr_hba *c)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.DirectCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_DirectCommandIdentifier;
	mbox->Type3.opcode = DAC960_V1_Enquiry;
	mbox->Type3.BusAddress = c->V1.NewEnquiryDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V1.dcmd_mutex);
	if (status == DAC960_V1_NormalCompletion) {
		DAC960_V1_Enquiry_T *old = &c->V1.Enquiry;
		DAC960_V1_Enquiry_T *new = c->V1.NewEnquiry;
		if (new->NumberOfLogicalDrives > c->LogicalDriveCount) {
			int ldev_num = c->LogicalDriveCount - 1;
			while (++ldev_num < new->NumberOfLogicalDrives)
				shost_printk(KERN_CRIT, c->host,
					"Logical Drive %d Now Exists\n",
					 ldev_num);
			c->LogicalDriveCount = new->NumberOfLogicalDrives;
		}
		if (new->NumberOfLogicalDrives < c->LogicalDriveCount) {
			int ldev_num = new->NumberOfLogicalDrives - 1;
			while (++ldev_num < c->LogicalDriveCount)
				shost_printk(KERN_CRIT, c->host,
					 "Logical Drive %d No Longer Exists\n",
					 ldev_num);
			c->LogicalDriveCount = new->NumberOfLogicalDrives;
		}
		if (new->StatusFlags.DeferredWriteError !=
		    old->StatusFlags.DeferredWriteError)
			shost_printk(KERN_CRIT, c->host,
				 "Deferred Write Error Flag is now %s\n",
				 (new->StatusFlags.DeferredWriteError
				  ? "TRUE" : "FALSE"));
		if (new->EventLogSequenceNumber !=
		    old->EventLogSequenceNumber) {
			c->V1.NewEventLogSequenceNumber =
				new->EventLogSequenceNumber;
			c->V1.NeedErrorTableInformation = true;
			shost_printk(KERN_INFO, c->host,
				     "Event log %d/%d (%d/%d) available\n",
				     c->V1.OldEventLogSequenceNumber,
				     c->V1.NewEventLogSequenceNumber,
				     old->EventLogSequenceNumber,
				     new->EventLogSequenceNumber);
		}
		if ((new->CriticalLogicalDriveCount > 0 ||
		     new->CriticalLogicalDriveCount !=
		     old->CriticalLogicalDriveCount) ||
		    (new->OfflineLogicalDriveCount > 0 ||
		     new->OfflineLogicalDriveCount !=
		     old->OfflineLogicalDriveCount) ||
		    (new->NumberOfLogicalDrives !=
		     old->NumberOfLogicalDrives)) {
			shost_printk(KERN_INFO, c->host,
				     "Logical drive count changed (%d/%d/%d)\n",
				     new->CriticalLogicalDriveCount,
				     new->OfflineLogicalDriveCount,
				     new->NumberOfLogicalDrives);
			c->V1.NeedLogicalDeviceInfo = true;
		}
		if ((new->DeadDriveCount > 0 ||
		     new->DeadDriveCount != old->DeadDriveCount) ||
		    time_after_eq(jiffies, c->SecondaryMonitoringTime
				  + DAC960_SecondaryMonitoringInterval)) {
			c->V1.NeedBackgroundInitializationStatus =
				c->V1.BackgroundInitializationStatusSupported;
			c->SecondaryMonitoringTime = jiffies;
		}
		if (new->RebuildFlag == DAC960_V1_StandbyRebuildInProgress ||
		    new->RebuildFlag
		    == DAC960_V1_BackgroundRebuildInProgress ||
		    old->RebuildFlag == DAC960_V1_StandbyRebuildInProgress ||
		    old->RebuildFlag == DAC960_V1_BackgroundRebuildInProgress) {
			c->V1.NeedRebuildProgress = true;
			c->V1.RebuildProgressFirst =
				(new->CriticalLogicalDriveCount <
				 old->CriticalLogicalDriveCount);
		}
		if (old->RebuildFlag == DAC960_V1_BackgroundCheckInProgress)
			switch (new->RebuildFlag) {
			case DAC960_V1_NoStandbyRebuildOrCheckInProgress:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Completed Successfully\n");
				break;
			case DAC960_V1_StandbyRebuildInProgress:
			case DAC960_V1_BackgroundRebuildInProgress:
				break;
			case DAC960_V1_BackgroundCheckInProgress:
				c->V1.NeedConsistencyCheckProgress = true;
				break;
			case DAC960_V1_StandbyRebuildCompletedWithError:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Completed with Error\n");
				break;
			case DAC960_V1_BackgroundRebuildOrCheckFailed_DriveFailed:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Failed - "
					 "Physical Device Failed\n");
				break;
			case DAC960_V1_BackgroundRebuildOrCheckFailed_LogicalDriveFailed:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Failed - "
					 "Logical Drive Failed\n");
				break;
			case DAC960_V1_BackgroundRebuildOrCheckFailed_OtherCauses:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Failed - Other Causes\n");
				break;
			case DAC960_V1_BackgroundRebuildOrCheckSuccessfullyTerminated:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Successfully Terminated\n");
				break;
			}
		else if (new->RebuildFlag
			 == DAC960_V1_BackgroundCheckInProgress)
			c->V1.NeedConsistencyCheckProgress = true;
		if (new->RebuildFlag > DAC960_V1_BackgroundCheckInProgress) {
			c->V1.PendingRebuildFlag = new->RebuildFlag;
			c->V1.RebuildFlagPending = true;
		}
		memcpy(old, new, sizeof(DAC960_V1_Enquiry_T));
	}
	return status;
}

/*
  DAC960_V1_SetDeviceState sets the Device State for a Physical Device for
  DAC960 V1 Firmware Controllers.
*/

static unsigned short DAC960_V1_SetDeviceState(myr_hba *c,
					       struct scsi_device *sdev,
					       myr_v1_devstate State)
{
	myr_v1_cmdblk *cmd_blk = &c->V1.DirectCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&c->V1.dcmd_mutex);
	mbox->Type3D.opcode = DAC960_V1_StartDevice;
	mbox->Type3D.id = DAC960_DirectCommandIdentifier;
	mbox->Type3D.Channel = sdev->channel;
	mbox->Type3D.TargetID = sdev->id;
	mbox->Type3D.State = State & 0x1F;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V1.dcmd_mutex);

	return status;
}

/*
  DAC960_V2_ControllerInfo executes a DAC960 V2 Firmware Controller
  Information Reading IOCTL Command and waits for completion.  It returns
  true on success and false on failure.

  Data is returned in the controller's V2.NewControllerInformation dma-able
  memory buffer.
*/

static unsigned char DAC960_V2_NewControllerInfo(myr_hba *c)
{
	myr_v2_cmdblk *cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	unsigned char status;

	mutex_lock(&c->V2.dcmd_mutex);
	DAC960_V2_ClearCommand(cmd_blk);
	mbox->ControllerInfo.id = DAC960_DirectCommandIdentifier;
	mbox->ControllerInfo.opcode = DAC960_V2_IOCTL;
	mbox->ControllerInfo.control.DataTransferControllerToHost = true;
	mbox->ControllerInfo.control.NoAutoRequestSense = true;
	mbox->ControllerInfo.dma_size =
		sizeof(DAC960_V2_ControllerInfo_T);
	mbox->ControllerInfo.ControllerNumber = 0;
	mbox->ControllerInfo.IOCTL_Opcode = DAC960_V2_GetControllerInfo;
	dma_addr = &mbox->ControllerInfo.dma_addr;
	dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
		c->V2.NewControllerInformationDMA;
	dma_addr->ScatterGatherSegments[0].SegmentByteCount =
		mbox->ControllerInfo.dma_size;
	dev_dbg(&c->host->shost_gendev,
		"Sending GetControllerInfo\n");
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	if (status == DAC960_V2_NormalCompletion) {
		DAC960_V2_ControllerInfo_T *new =
			c->V2.NewControllerInformation;
		DAC960_V2_ControllerInfo_T *old =
			&c->V2.ControllerInformation;
		if (new->BackgroundInitializationsActive +
		    new->LogicalDeviceInitializationsActive +
		    new->PhysicalDeviceInitializationsActive +
		    new->ConsistencyChecksActive +
		    new->RebuildsActive +
		    new->OnlineExpansionsActive != 0)
			c->V2.NeedControllerInformation = true;
		if (new->LogicalDevicesPresent != old->LogicalDevicesPresent ||
		    new->LogicalDevicesCritical != old->LogicalDevicesCritical ||
		    new->LogicalDevicesOffline != old->LogicalDevicesOffline)
			shost_printk(KERN_INFO, c->host,
				     "Logical drive count changes (%d/%d/%d)\n",
				     new->LogicalDevicesCritical,
				     new->LogicalDevicesOffline,
				     new->LogicalDevicesPresent);
		c->LogicalDriveCount = new->LogicalDevicesPresent;
		memcpy(old, new,
		       sizeof(DAC960_V2_ControllerInfo_T));
	}

	return status;
}


/*
  DAC960_V2_LogicalDeviceInfo executes a DAC960 V2 Firmware Controller Logical
  Device Information Reading IOCTL Command and waits for completion.  It
  returns true on success and false on failure.

  Data is returned in the controller's V2.NewLogicalDeviceInformation
*/

static unsigned char
DAC960_V2_NewLogicalDeviceInfo(myr_hba *c,
			       unsigned short ldev_num,
			       DAC960_V2_LogicalDeviceInfo_T *ldev_info)
{
	myr_v2_cmdblk *cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	unsigned char status;

	mutex_lock(&c->V2.dcmd_mutex);
	DAC960_V2_ClearCommand(cmd_blk);
	mbox->LogicalDeviceInfo.id = DAC960_DirectCommandIdentifier;
	mbox->LogicalDeviceInfo.opcode = DAC960_V2_IOCTL;
	mbox->LogicalDeviceInfo.control.DataTransferControllerToHost = true;
	mbox->LogicalDeviceInfo.control.NoAutoRequestSense = true;
	mbox->LogicalDeviceInfo.dma_size =
		sizeof(DAC960_V2_LogicalDeviceInfo_T);
	mbox->LogicalDeviceInfo.LogicalDevice.LogicalDeviceNumber = ldev_num;
	mbox->LogicalDeviceInfo.IOCTL_Opcode =
		DAC960_V2_GetLogicalDeviceInfoValid;
	dma_addr = &mbox->LogicalDeviceInfo.dma_addr;
	dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
		c->V2.NewLogicalDeviceInformationDMA;
	dma_addr->ScatterGatherSegments[0].SegmentByteCount =
		mbox->LogicalDeviceInfo.dma_size;
	dev_dbg(&c->host->shost_gendev,
		"Sending GetLogicalDeviceInfoValid for ldev %d\n", ldev_num);
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V2_NormalCompletion) {
		unsigned short ldev_num = ldev_info->LogicalDeviceNumber;
		DAC960_V2_LogicalDeviceInfo_T *new =
			c->V2.NewLogicalDeviceInformation;
		DAC960_V2_LogicalDeviceInfo_T *old = ldev_info;

		if (old != NULL) {
			unsigned long ldev_size =
				new->ConfigurableDeviceSize;

			if (new->State != old->State) {
				const char *name;

				name = DAC960_V2_DriveStateName(new->State);
				shost_printk(KERN_INFO, c->host,
					 "Logical Drive %d is now %s\n",
					 ldev_num, name ? name : "Invalid");
			}
			if ((new->SoftErrors != old->SoftErrors) ||
			    (new->CommandsFailed != old->CommandsFailed) ||
			    (new->DeferredWriteErrors !=
			     old->DeferredWriteErrors))
				shost_printk(KERN_INFO, c->host,
					    "Logical Drive %d Errors: "
					    "Soft = %d, Failed = %d, Deferred Write = %d\n",
					    ldev_num,
					    new->SoftErrors,
					    new->CommandsFailed,
					    new->DeferredWriteErrors);
			if (new->BackgroundInitializationInProgress)
				DAC960_V2_ReportProgress(c, ldev_num,
					"Background Initialization",
					new->BackgroundInitializationBlockNumber,
					ldev_size);
			else if (new->ForegroundInitializationInProgress)
				DAC960_V2_ReportProgress(c, ldev_num,
					"Foreground Initialization",
					new->ForegroundInitializationBlockNumber,
					ldev_size);
			else if (new->DataMigrationInProgress)
				DAC960_V2_ReportProgress(c, ldev_num,
					"Data Migration",
					new->DataMigrationBlockNumber,
					ldev_size);
			else if (new->PatrolOperationInProgress)
				DAC960_V2_ReportProgress(c, ldev_num,
					"Patrol Operation",
					new->PatrolOperationBlockNumber,
					ldev_size);
			if (old->BackgroundInitializationInProgress &&
			    !new->BackgroundInitializationInProgress)
				shost_printk(KERN_INFO, c->host,
					    "Logical Drive %d: "
					    "Background Initialization %s\n",
					    ldev_num,
					    (new->LogicalDeviceControl
						 .LogicalDeviceInitialized
						 ? "Completed" : "Failed"));
			memcpy(ldev_info, c->V2.NewLogicalDeviceInformation,
			       sizeof(*ldev_info));
		}
	}
	mutex_unlock(&c->V2.dcmd_mutex);
	return status;
}


/*
  DAC960_V2_PhysicalDeviceInfo executes a DAC960 V2 Firmware Controller "Read
  Physical Device Information" IOCTL Command and waits for completion.  It
  returns true on success and false on failure.

  The Channel, TargetID, LogicalUnit arguments should be 0 the first time
  this function is called for a given controller.  This will return data
  for the "first" device on that controller.  The returned data includes a
  Channel, TargetID, LogicalUnit that can be passed in to this routine to
  get data for the NEXT device on that controller.

  Data is stored in the controller's V2.NewPhysicalDeviceInfo dma-able
  memory buffer.

*/

static unsigned char
DAC960_V2_NewPhysicalDeviceInfo(myr_hba *c,
				unsigned char Channel,
				unsigned char TargetID,
				unsigned char LogicalUnit,
				DAC960_V2_PhysicalDeviceInfo_T *pdev_info)
{
	myr_v2_cmdblk *cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	unsigned char status;

	mutex_lock(&c->V2.dcmd_mutex);
	DAC960_V2_ClearCommand(cmd_blk);
	mbox->PhysicalDeviceInfo.opcode = DAC960_V2_IOCTL;
	mbox->PhysicalDeviceInfo.id = DAC960_DirectCommandIdentifier;
	mbox->PhysicalDeviceInfo.control.DataTransferControllerToHost = true;
	mbox->PhysicalDeviceInfo.control.NoAutoRequestSense = true;
	mbox->PhysicalDeviceInfo.dma_size =
		sizeof(DAC960_V2_PhysicalDeviceInfo_T);
	mbox->PhysicalDeviceInfo.PhysicalDevice.LogicalUnit = LogicalUnit;
	mbox->PhysicalDeviceInfo.PhysicalDevice.TargetID = TargetID;
	mbox->PhysicalDeviceInfo.PhysicalDevice.Channel = Channel;
	mbox->PhysicalDeviceInfo.IOCTL_Opcode =
		DAC960_V2_GetPhysicalDeviceInfoValid;
	dma_addr = &mbox->PhysicalDeviceInfo.dma_addr;
	dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
		c->V2.NewPhysicalDeviceInformationDMA;
	dma_addr->ScatterGatherSegments[0].SegmentByteCount =
		mbox->PhysicalDeviceInfo.dma_size;
	dev_dbg(&c->host->shost_gendev,
		"Sending GetPhysicalDeviceInfoValid for pdev %d:%d:%d\n",
		Channel, TargetID, LogicalUnit);
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V2_NormalCompletion)
		memcpy(pdev_info, &c->V2.NewPhysicalDeviceInformation,
		       sizeof(*pdev_info));
	mutex_unlock(&c->V2.dcmd_mutex);
	return status;
}

/*
  DAC960_V2_DeviceOperation executes a DAC960 V2 Firmware Controller Device
  Operation IOCTL Command and waits for completion.  It returns true on
  success and false on failure.
*/

static unsigned char
DAC960_V2_DeviceOperation(myr_hba *c,
			  DAC960_V2_IOCTL_Opcode_T opcode,
			  DAC960_V2_OperationDevice_T opdev)
{
	myr_v2_cmdblk *cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned char status;

	mutex_lock(&c->V2.dcmd_mutex);
	DAC960_V2_ClearCommand(cmd_blk);
	mbox->DeviceOperation.opcode = DAC960_V2_IOCTL;
	mbox->DeviceOperation.id = DAC960_DirectCommandIdentifier;
	mbox->DeviceOperation.control.DataTransferControllerToHost = true;
	mbox->DeviceOperation.control.NoAutoRequestSense = true;
	mbox->DeviceOperation.IOCTL_Opcode = opcode;
	mbox->DeviceOperation.OperationDevice = opdev;
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	return status;
}


/*
  DAC960_V2_TranslatePhysicalDevice translates a Physical Device Channel and
  TargetID into a Logical Device.
*/

static unsigned char
DAC960_V2_TranslatePhysicalDevice(myr_hba *c,
				  unsigned char Channel,
				  unsigned char TargetID,
				  unsigned char LogicalUnit,
				  unsigned short *ldev_num)
{
	myr_v2_cmdblk *cmd_blk;
	DAC960_V2_CommandMailbox_T *mbox;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	unsigned char status;

	mutex_lock(&c->V2.dcmd_mutex);
	cmd_blk = &c->V2.DirectCommandBlock;
	mbox = &cmd_blk->mbox;
	mbox->PhysicalDeviceInfo.opcode = DAC960_V2_IOCTL;
	mbox->PhysicalDeviceInfo.control.DataTransferControllerToHost = true;
	mbox->PhysicalDeviceInfo.control.NoAutoRequestSense = true;
	mbox->PhysicalDeviceInfo.dma_size =
		sizeof(DAC960_V2_PhysicalToLogicalDevice_T);
	mbox->PhysicalDeviceInfo.PhysicalDevice.TargetID = TargetID;
	mbox->PhysicalDeviceInfo.PhysicalDevice.Channel = Channel;
	mbox->PhysicalDeviceInfo.PhysicalDevice.LogicalUnit = LogicalUnit;
	mbox->PhysicalDeviceInfo.IOCTL_Opcode =
		DAC960_V2_TranslatePhysicalToLogicalDevice;
	dma_addr = &mbox->PhysicalDeviceInfo.dma_addr;
	dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
		c->V2.PhysicalToLogicalDeviceDMA;
	dma_addr->ScatterGatherSegments[0].SegmentByteCount =
		mbox->PhysicalDeviceInfo.dma_size;

	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	if (status == DAC960_V2_NormalCompletion)
		*ldev_num = c->V2.PhysicalToLogicalDevice->LogicalDeviceNumber;

	return status;
}


static unsigned char DAC960_V2_MonitorGetEvent(myr_hba *c)
{
	myr_v2_cmdblk *cmd_blk = &c->V2.MonitoringCommandBlock;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	unsigned char status;

	mbox->GetEvent.opcode = DAC960_V2_IOCTL;
	mbox->GetEvent.dma_size = sizeof(DAC960_V2_Event_T);
	mbox->GetEvent.EventSequenceNumberHigh16 =
		c->V2.NextEventSequenceNumber >> 16;
	mbox->GetEvent.ControllerNumber = 0;
	mbox->GetEvent.IOCTL_Opcode = DAC960_V2_GetEvent;
	mbox->GetEvent.EventSequenceNumberLow16 =
		c->V2.NextEventSequenceNumber & 0xFFFF;
	dma_addr = &mbox->GetEvent.dma_addr;
	dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
		c->V2.EventDMA;
	dma_addr->ScatterGatherSegments[0].SegmentByteCount =
		mbox->GetEvent.dma_size;
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;

	return status;
}

/*
  DAC960_V1_EnableMemoryMailboxInterface enables the Memory Mailbox Interface
  for DAC960 V1 Firmware Controllers.

  PD and P controller types have no memory mailbox, but still need the
  other dma mapped memory.
*/

static bool DAC960_V1_EnableMemoryMailboxInterface(myr_hba *c)
{
	void __iomem *base = c->BaseAddress;
	DAC960_HardwareType_T hw_type = c->HardwareType;
	struct pci_dev *pdev = c->PCIDevice;
	struct dma_loaf *DmaPages = &c->DmaPages;
	size_t DmaPagesSize;
	size_t CommandMailboxesSize;
	size_t StatusMailboxesSize;

	DAC960_V1_CommandMailbox_T *CommandMailboxesMemory;
	dma_addr_t CommandMailboxesMemoryDMA;

	DAC960_V1_StatusMailbox_T *StatusMailboxesMemory;
	dma_addr_t StatusMailboxesMemoryDMA;

	DAC960_V1_CommandMailbox_T mbox;
	unsigned short status;
	int timeout = 0;
	int i;

	memset(&mbox, 0, sizeof(DAC960_V1_CommandMailbox_T));

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		dev_err(&pdev->dev, "DMA mask out of range\n");
		return false;
	}
	c->BounceBufferLimit = DMA_BIT_MASK(32);

	if ((hw_type == DAC960_PD_Controller) || (hw_type == DAC960_P_Controller)) {
		CommandMailboxesSize =  0;
		StatusMailboxesSize = 0;
	} else {
		CommandMailboxesSize =  DAC960_V1_CommandMailboxCount * sizeof(DAC960_V1_CommandMailbox_T);
		StatusMailboxesSize = DAC960_V1_StatusMailboxCount * sizeof(DAC960_V1_StatusMailbox_T);
	}
	DmaPagesSize = CommandMailboxesSize + StatusMailboxesSize +
		sizeof(DAC960_V1_DCDB_T) + sizeof(DAC960_V1_Enquiry_T) +
		sizeof(DAC960_V1_ErrorTable_T) + sizeof(DAC960_V1_EventLogEntry_T) +
		sizeof(DAC960_V1_RebuildProgress_T) +
		sizeof(DAC960_V1_LogicalDeviceInfoArray_T) +
		sizeof(DAC960_V1_BackgroundInitializationStatus_T) +
		sizeof(myr_v1_pdev_state);

	if (!init_dma_loaf(pdev, DmaPages, DmaPagesSize))
		return false;


	if ((hw_type == DAC960_PD_Controller) || (hw_type == DAC960_P_Controller))
		goto skip_mailboxes;

	CommandMailboxesMemory = slice_dma_loaf(DmaPages,
						CommandMailboxesSize, &CommandMailboxesMemoryDMA);

	/* These are the base addresses for the command memory mailbox array */
	c->V1.FirstCommandMailbox = CommandMailboxesMemory;
	c->V1.FirstCommandMailboxDMA = CommandMailboxesMemoryDMA;

	CommandMailboxesMemory += DAC960_V1_CommandMailboxCount - 1;
	c->V1.LastCommandMailbox = CommandMailboxesMemory;
	c->V1.NextCommandMailbox = c->V1.FirstCommandMailbox;
	c->V1.PreviousCommandMailbox1 = c->V1.LastCommandMailbox;
	c->V1.PreviousCommandMailbox2 = c->V1.LastCommandMailbox - 1;

	/* These are the base addresses for the status memory mailbox array */
	StatusMailboxesMemory = slice_dma_loaf(DmaPages,
					       StatusMailboxesSize, &StatusMailboxesMemoryDMA);

	c->V1.FirstStatusMailbox = StatusMailboxesMemory;
	c->V1.FirstStatusMailboxDMA = StatusMailboxesMemoryDMA;
	StatusMailboxesMemory += DAC960_V1_StatusMailboxCount - 1;
	c->V1.LastStatusMailbox = StatusMailboxesMemory;
	c->V1.NextStatusMailbox = c->V1.FirstStatusMailbox;

skip_mailboxes:
	c->V1.NewEnquiry = slice_dma_loaf(DmaPages,
					  sizeof(DAC960_V1_Enquiry_T),
					  &c->V1.NewEnquiryDMA);

	c->V1.NewErrorTable = slice_dma_loaf(DmaPages,
					     sizeof(DAC960_V1_ErrorTable_T),
					     &c->V1.NewErrorTableDMA);

	c->V1.EventLogEntry = slice_dma_loaf(DmaPages,
					     sizeof(DAC960_V1_EventLogEntry_T),
					     &c->V1.EventLogEntryDMA);

	c->V1.RebuildProgress = slice_dma_loaf(DmaPages,
					       sizeof(DAC960_V1_RebuildProgress_T),
					       &c->V1.RebuildProgressDMA);

	c->V1.LogicalDeviceInfo = slice_dma_loaf(DmaPages,
						       sizeof(DAC960_V1_LogicalDeviceInfoArray_T),
						       &c->V1.LogicalDeviceInfoDMA);

	c->V1.BackgroundInitializationStatus = slice_dma_loaf(DmaPages,
							      sizeof(DAC960_V1_BackgroundInitializationStatus_T),
							      &c->V1.BackgroundInitializationStatusDMA);

	c->V1.NewDeviceState = slice_dma_loaf(DmaPages,
					      sizeof(myr_v1_pdev_state),
					      &c->V1.NewDeviceStateDMA);

	if ((hw_type == DAC960_PD_Controller) || (hw_type == DAC960_P_Controller))
		return true;

	/* Enable the Memory Mailbox Interface. */
	c->V1.DualModeMemoryMailboxInterface = true;
	mbox.TypeX.opcode = 0x2B;
	mbox.TypeX.id = 0;
	mbox.TypeX.CommandOpcode2 = 0x14;
	mbox.TypeX.CommandMailboxesBusAddress = c->V1.FirstCommandMailboxDMA;
	mbox.TypeX.StatusMailboxesBusAddress = c->V1.FirstStatusMailboxDMA;

	for (i = 0; i < 2; i++)
		switch (c->HardwareType) {
		case DAC960_LA_Controller:
			timeout = 0;
			while (timeout < DAC960_MAILBOX_TIMEOUT) {
				if (!DAC960_LA_HardwareMailboxFullP(base))
					break;
				udelay(10);
				timeout++;
			}
			if (DAC960_LA_HardwareMailboxFullP(base)) {
				dev_err(&pdev->dev,
					"Timeout waiting for empty mailbox\n");
				return false;
			}
			DAC960_LA_WriteHardwareMailbox(base, &mbox);
			DAC960_LA_HardwareMailboxNewCommand(base);
			timeout = 0;
			while (timeout < DAC960_MAILBOX_TIMEOUT) {
				if (DAC960_LA_HardwareMailboxStatusAvailableP(
					    base))
					break;
				udelay(10);
				timeout++;
			}
			if (!DAC960_LA_HardwareMailboxStatusAvailableP(base)) {
				dev_err(&pdev->dev,
					"Timeout waiting for mailbox status\n");
				return false;
			}
			status = DAC960_LA_ReadStatusRegister(base);
			DAC960_LA_AcknowledgeHardwareMailboxInterrupt(base);
			DAC960_LA_AcknowledgeHardwareMailboxStatus(base);
			if (status == DAC960_V1_NormalCompletion)
				return true;
			c->V1.DualModeMemoryMailboxInterface = false;
			mbox.TypeX.CommandOpcode2 = 0x10;
			break;
		case DAC960_PG_Controller:
			timeout = 0;
			while (timeout < DAC960_MAILBOX_TIMEOUT) {
				if (!DAC960_PG_HardwareMailboxFullP(base))
					break;
				udelay(10);
				timeout++;
			}
			if (DAC960_PG_HardwareMailboxFullP(base)) {
				dev_err(&pdev->dev,
					"Timeout waiting for empty mailbox\n");
				return false;
			}
			DAC960_PG_WriteHardwareMailbox(base, &mbox);
			DAC960_PG_HardwareMailboxNewCommand(base);

			timeout = 0;
			while (timeout < DAC960_MAILBOX_TIMEOUT) {
				if (DAC960_PG_HardwareMailboxStatusAvailableP(
					    base))
					break;
				udelay(10);
				timeout++;
			}
			if (!DAC960_PG_HardwareMailboxStatusAvailableP(base)) {
				dev_err(&pdev->dev,
					"Timeout waiting for mailbox status\n");
				return false;
			}
			status = DAC960_PG_ReadStatusRegister(base);
			DAC960_PG_AcknowledgeHardwareMailboxInterrupt(base);
			DAC960_PG_AcknowledgeHardwareMailboxStatus(base);
			if (status == DAC960_V1_NormalCompletion)
				return true;
			c->V1.DualModeMemoryMailboxInterface = false;
			mbox.TypeX.CommandOpcode2 = 0x10;
			break;
		default:
			dev_err(&pdev->dev,
				"Unknown Controller Type %X\n",
				c->HardwareType);
			return false;
			break;
		}
	dev_err(&pdev->dev,
		"Failed to enable mailbox, statux %02X\n",
		status);
	return false;
}


/*
  DAC960_V2_EnableMemoryMailboxInterface enables the Memory Mailbox Interface
  for DAC960 V2 Firmware Controllers.

  Aggregate the space needed for the controller's memory mailbox and
  the other data structures that will be targets of dma transfers with
  the controller.  Allocate a dma-mapped region of memory to hold these
  structures.  Then, save CPU pointers and dma_addr_t values to reference
  the structures that are contained in that region.
*/

static bool DAC960_V2_EnableMemoryMailboxInterface(myr_hba *c)
{
	void __iomem *base = c->BaseAddress;
	struct pci_dev *pdev = c->PCIDevice;
	struct dma_loaf *DmaPages = &c->DmaPages;
	size_t DmaPagesSize;
	size_t CommandMailboxesSize;
	size_t StatusMailboxesSize;

	DAC960_V2_CommandMailbox_T *CommandMailboxesMemory;
	dma_addr_t CommandMailboxesMemoryDMA;

	DAC960_V2_StatusMailbox_T *StatusMailboxesMemory;
	dma_addr_t StatusMailboxesMemoryDMA;

	DAC960_V2_CommandMailbox_T *mbox;
	dma_addr_t	CommandMailboxDMA;
	unsigned char status;

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64)))
		c->BounceBufferLimit = DMA_BIT_MASK(64);
	else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32)))
		c->BounceBufferLimit = DMA_BIT_MASK(32);
	else {
		dev_err(&pdev->dev, "DMA mask out of range\n");
		return false;
	}

	/* This is a temporary dma mapping, used only in the scope of this function */
	mbox = pci_alloc_consistent(pdev,
				    sizeof(DAC960_V2_CommandMailbox_T),
				    &CommandMailboxDMA);
	if (mbox == NULL)
		return false;

	CommandMailboxesSize = DAC960_V2_CommandMailboxCount * sizeof(DAC960_V2_CommandMailbox_T);
	StatusMailboxesSize = DAC960_V2_StatusMailboxCount * sizeof(DAC960_V2_StatusMailbox_T);
	DmaPagesSize =
		CommandMailboxesSize + StatusMailboxesSize +
		sizeof(DAC960_V2_HealthStatusBuffer_T) +
		sizeof(DAC960_V2_ControllerInfo_T) +
		sizeof(DAC960_V2_LogicalDeviceInfo_T) +
		sizeof(DAC960_V2_PhysicalDeviceInfo_T) +
		sizeof(DAC960_V2_Event_T) +
		sizeof(DAC960_V2_PhysicalToLogicalDevice_T);

	if (!init_dma_loaf(pdev, DmaPages, DmaPagesSize)) {
		pci_free_consistent(pdev, sizeof(DAC960_V2_CommandMailbox_T),
				    mbox, CommandMailboxDMA);
		return false;
	}

	CommandMailboxesMemory = slice_dma_loaf(DmaPages,
						CommandMailboxesSize, &CommandMailboxesMemoryDMA);

	/* These are the base addresses for the command memory mailbox array */
	c->V2.FirstCommandMailbox = CommandMailboxesMemory;
	c->V2.FirstCommandMailboxDMA = CommandMailboxesMemoryDMA;

	CommandMailboxesMemory += DAC960_V2_CommandMailboxCount - 1;
	c->V2.LastCommandMailbox = CommandMailboxesMemory;
	c->V2.NextCommandMailbox = c->V2.FirstCommandMailbox;
	c->V2.PreviousCommandMailbox1 = c->V2.LastCommandMailbox;
	c->V2.PreviousCommandMailbox2 = c->V2.LastCommandMailbox - 1;

	/* These are the base addresses for the status memory mailbox array */
	StatusMailboxesMemory = slice_dma_loaf(DmaPages,
					       StatusMailboxesSize, &StatusMailboxesMemoryDMA);

	c->V2.FirstStatusMailbox = StatusMailboxesMemory;
	c->V2.FirstStatusMailboxDMA = StatusMailboxesMemoryDMA;
	StatusMailboxesMemory += DAC960_V2_StatusMailboxCount - 1;
	c->V2.LastStatusMailbox = StatusMailboxesMemory;
	c->V2.NextStatusMailbox = c->V2.FirstStatusMailbox;

	c->V2.HealthStatusBuffer = slice_dma_loaf(DmaPages,
							   sizeof(DAC960_V2_HealthStatusBuffer_T),
							   &c->V2.HealthStatusBufferDMA);

	c->V2.NewControllerInformation = slice_dma_loaf(DmaPages,
								 sizeof(DAC960_V2_ControllerInfo_T),
								 &c->V2.NewControllerInformationDMA);

	c->V2.NewLogicalDeviceInformation =  slice_dma_loaf(DmaPages,
								     sizeof(DAC960_V2_LogicalDeviceInfo_T),
								     &c->V2.NewLogicalDeviceInformationDMA);

	c->V2.NewPhysicalDeviceInformation = slice_dma_loaf(DmaPages,
								     sizeof(DAC960_V2_PhysicalDeviceInfo_T),
								     &c->V2.NewPhysicalDeviceInformationDMA);

	c->V2.Event = slice_dma_loaf(DmaPages,
					      sizeof(DAC960_V2_Event_T),
					      &c->V2.EventDMA);

	c->V2.PhysicalToLogicalDevice = slice_dma_loaf(DmaPages,
								sizeof(DAC960_V2_PhysicalToLogicalDevice_T),
								&c->V2.PhysicalToLogicalDeviceDMA);

	/*
	  Enable the Memory Mailbox Interface.

	  I don't know why we can't just use one of the memory mailboxes
	  we just allocated to do this, instead of using this temporary one.
	  Try this change later.
	*/
	memset(mbox, 0, sizeof(DAC960_V2_CommandMailbox_T));
	mbox->SetMemoryMailbox.id = 1;
	mbox->SetMemoryMailbox.opcode = DAC960_V2_IOCTL;
	mbox->SetMemoryMailbox.control.NoAutoRequestSense = true;
	mbox->SetMemoryMailbox.FirstCommandMailboxSizeKB =
		(DAC960_V2_CommandMailboxCount * sizeof(DAC960_V2_CommandMailbox_T)) >> 10;
	mbox->SetMemoryMailbox.FirstStatusMailboxSizeKB =
		(DAC960_V2_StatusMailboxCount * sizeof(DAC960_V2_StatusMailbox_T)) >> 10;
	mbox->SetMemoryMailbox.SecondCommandMailboxSizeKB = 0;
	mbox->SetMemoryMailbox.SecondStatusMailboxSizeKB = 0;
	mbox->SetMemoryMailbox.sense_len = 0;
	mbox->SetMemoryMailbox.IOCTL_Opcode = DAC960_V2_SetMemoryMailbox;
	mbox->SetMemoryMailbox.HealthStatusBufferSizeKB = 1;
	mbox->SetMemoryMailbox.HealthStatusBufferBusAddress =
		c->V2.HealthStatusBufferDMA;
	mbox->SetMemoryMailbox.FirstCommandMailboxBusAddress =
		c->V2.FirstCommandMailboxDMA;
	mbox->SetMemoryMailbox.FirstStatusMailboxBusAddress =
		c->V2.FirstStatusMailboxDMA;
	switch (c->HardwareType) {
	case DAC960_GEM_Controller:
		while (DAC960_GEM_HardwareMailboxFullP(base))
			udelay(1);
		DAC960_GEM_WriteHardwareMailbox(base, CommandMailboxDMA);
		DAC960_GEM_HardwareMailboxNewCommand(base);
		while (!DAC960_GEM_HardwareMailboxStatusAvailableP(base))
			udelay(1);
		status = DAC960_GEM_ReadCommandStatus(base);
		DAC960_GEM_AcknowledgeHardwareMailboxInterrupt(base);
		DAC960_GEM_AcknowledgeHardwareMailboxStatus(base);
		break;
	case DAC960_BA_Controller:
		while (DAC960_BA_HardwareMailboxFullP(base))
			udelay(1);
		DAC960_BA_WriteHardwareMailbox(base, CommandMailboxDMA);
		DAC960_BA_HardwareMailboxNewCommand(base);
		while (!DAC960_BA_HardwareMailboxStatusAvailableP(base))
			udelay(1);
		status = DAC960_BA_ReadCommandStatus(base);
		DAC960_BA_AcknowledgeHardwareMailboxInterrupt(base);
		DAC960_BA_AcknowledgeHardwareMailboxStatus(base);
		break;
	case DAC960_LP_Controller:
		while (DAC960_LP_HardwareMailboxFullP(base))
			udelay(1);
		DAC960_LP_WriteHardwareMailbox(base, CommandMailboxDMA);
		DAC960_LP_HardwareMailboxNewCommand(base);
		while (!DAC960_LP_HardwareMailboxStatusAvailableP(base))
			udelay(1);
		status = DAC960_LP_ReadCommandStatus(base);
		DAC960_LP_AcknowledgeHardwareMailboxInterrupt(base);
		DAC960_LP_AcknowledgeHardwareMailboxStatus(base);
		break;
	default:
		dev_err(&pdev->dev, "Unknown Controller Type %X\n",
			c->HardwareType);
		return false;
	}
	pci_free_consistent(pdev, sizeof(DAC960_V2_CommandMailbox_T),
			    mbox, CommandMailboxDMA);
	if (status != DAC960_V2_NormalCompletion)
		dev_err(&pdev->dev, "Failed to enable mailbox, status %X\n",
			status);
	return (status == DAC960_V2_NormalCompletion);
}


/*
  DAC960_V1_ReadControllerConfiguration reads the Configuration Information
  from DAC960 V1 Firmware Controllers and initializes the Controller structure.
*/

static int DAC960_V1_ReadControllerConfiguration(myr_hba *c)
{
	DAC960_V1_Enquiry2_T *Enquiry2;
	dma_addr_t Enquiry2DMA;
	DAC960_V1_Config2_T *Config2;
	dma_addr_t Config2DMA;
	struct Scsi_Host *shost = c->host;
	struct pci_dev *pdev = c->PCIDevice;
	unsigned short status;
	int ret = -ENODEV;

	Enquiry2 = pci_zalloc_consistent(pdev, sizeof(DAC960_V1_Enquiry2_T),
					 &Enquiry2DMA);
	if (!Enquiry2) {
		shost_printk(KERN_ERR, c->host,
			     "Failed to allocated V1 Enquiry2 memory\n");
		return -ENOMEM;
	}
	Config2 = pci_zalloc_consistent(pdev, sizeof(DAC960_V1_Config2_T),
					&Config2DMA);
	if (!Config2) {
		shost_printk(KERN_ERR, c->host,
			     "Failed to allocate V1 Config2 memory\n");
		pci_free_consistent(pdev, sizeof(DAC960_V1_Enquiry2_T),
				    Enquiry2, Enquiry2DMA);
		return -ENOMEM;
	}
	mutex_lock(&c->V1.dma_mutex);
	status = DAC960_V1_NewEnquiry(c);
	mutex_unlock(&c->V1.dma_mutex);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed it issue V1 Enquiry\n");
		goto out;
	}

	status = DAC960_V1_ExecuteType3(c, DAC960_V1_Enquiry2, Enquiry2DMA);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed to issue V1 Enquiry2\n");
		goto out;
	}

	status = DAC960_V1_ExecuteType3(c, DAC960_V1_ReadConfig2, Config2DMA);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed to issue ReadConfig2\n");
		goto out;
	}

	status = DAC960_V1_GetLogicalDriveInfo(c);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed to get logical drive information\n");
		goto out;
	}

	/*
	  Initialize the Controller Model Name and Full Model Name fields.
	*/
	switch (Enquiry2->HardwareID.SubModel) {
	case DAC960_V1_P_PD_PU:
		if (Enquiry2->SCSICapability.BusSpeed == DAC960_V1_Ultra)
			strcpy(c->ModelName, "DAC960PU");
		else
			strcpy(c->ModelName, "DAC960PD");
		break;
	case DAC960_V1_PL:
		strcpy(c->ModelName, "DAC960PL");
		break;
	case DAC960_V1_PG:
		strcpy(c->ModelName, "DAC960PG");
		break;
	case DAC960_V1_PJ:
		strcpy(c->ModelName, "DAC960PJ");
		break;
	case DAC960_V1_PR:
		strcpy(c->ModelName, "DAC960PR");
		break;
	case DAC960_V1_PT:
		strcpy(c->ModelName, "DAC960PT");
		break;
	case DAC960_V1_PTL0:
		strcpy(c->ModelName, "DAC960PTL0");
		break;
	case DAC960_V1_PRL:
		strcpy(c->ModelName, "DAC960PRL");
		break;
	case DAC960_V1_PTL1:
		strcpy(c->ModelName, "DAC960PTL1");
		break;
	case DAC960_V1_1164P:
		strcpy(c->ModelName, "eXtremeRAID 1100");
		break;
	default:
		shost_printk(KERN_WARNING, c->host,
			     "Unknown Model %X\n",
			     Enquiry2->HardwareID.SubModel);
		goto out;
	}
	strcpy(c->FullModelName, DAC960_DriverName);
	strcat(c->FullModelName, " ");
	strcat(c->FullModelName, c->ModelName);
	/*
	  Initialize the Controller Firmware Version field and verify that it
	  is a supported firmware version.  The supported firmware versions are:

	  DAC1164P		    5.06 and above
	  DAC960PTL/PRL/PJ/PG	    4.06 and above
	  DAC960PU/PD/PL	    3.51 and above
	  DAC960PU/PD/PL/P	    2.73 and above
	*/
#if defined(CONFIG_ALPHA)
	/*
	  DEC Alpha machines were often equipped with DAC960 cards that were
	  OEMed from Mylex, and had their own custom firmware. Version 2.70,
	  the last custom FW revision to be released by DEC for these older
	  controllers, appears to work quite well with this driver.

	  Cards tested successfully were several versions each of the PD and
	  PU, called by DEC the KZPSC and KZPAC, respectively, and having
	  the Manufacturer Numbers (from Mylex), usually on a sticker on the
	  back of the board, of:

	  KZPSC:  D040347 (1-channel) or D040348 (2-channel) or D040349 (3-channel)
	  KZPAC:  D040395 (1-channel) or D040396 (2-channel) or D040397 (3-channel)
	*/
# define FIRMWARE_27X	"2.70"
#else
# define FIRMWARE_27X	"2.73"
#endif

	if (Enquiry2->FirmwareID.MajorVersion == 0) {
		Enquiry2->FirmwareID.MajorVersion =
			c->V1.Enquiry.MajorFirmwareVersion;
		Enquiry2->FirmwareID.MinorVersion =
			c->V1.Enquiry.MinorFirmwareVersion;
		Enquiry2->FirmwareID.FirmwareType = '0';
		Enquiry2->FirmwareID.TurnID = 0;
	}
	sprintf(c->FirmwareVersion, "%d.%02d-%c-%02d",
		Enquiry2->FirmwareID.MajorVersion,
		Enquiry2->FirmwareID.MinorVersion,
		Enquiry2->FirmwareID.FirmwareType,
		Enquiry2->FirmwareID.TurnID);
	if (!((c->FirmwareVersion[0] == '5' &&
	       strcmp(c->FirmwareVersion, "5.06") >= 0) ||
	      (c->FirmwareVersion[0] == '4' &&
	       strcmp(c->FirmwareVersion, "4.06") >= 0) ||
	      (c->FirmwareVersion[0] == '3' &&
	       strcmp(c->FirmwareVersion, "3.51") >= 0) ||
	      (c->FirmwareVersion[0] == '2' &&
	       strcmp(c->FirmwareVersion, FIRMWARE_27X) >= 0))) {
		shost_printk(KERN_WARNING, c->host,
			"Firmware Version '%s' unsupported\n",
			c->FirmwareVersion);
		goto out;
	}
	/*
	  Initialize the c Channels, Targets, Memory Size, and SAF-TE
	  Enclosure Management Enabled fields.
	*/
	switch (Enquiry2->HardwareID.Model) {
	case DAC960_V1_FiveChannelBoard:
		c->PhysicalChannelMax = 5;
		break;
	case DAC960_V1_ThreeChannelBoard:
	case DAC960_V1_ThreeChannelASIC_DAC:
		c->PhysicalChannelMax = 3;
		break;
	case DAC960_V1_TwoChannelBoard:
		c->PhysicalChannelMax = 2;
		break;
	default:
		c->PhysicalChannelMax = Enquiry2->ActualChannels;
		break;
	}
	c->PhysicalChannelCount = Enquiry2->ActualChannels;
	c->LogicalChannelCount = 1;
	c->LogicalChannelMax = 1;
	if (Enquiry2->SCSICapability.BusWidth == DAC960_V1_Wide_32bit)
		c->V1.BusWidth = 32;
	else if (Enquiry2->SCSICapability.BusWidth == DAC960_V1_Wide_16bit)
		c->V1.BusWidth = 16;
	else
		c->V1.BusWidth = 8;
	c->V1.LogicalBlockSize = Enquiry2->LogicalDriveBlockSize;
	shost->max_channel = c->PhysicalChannelCount + c->LogicalChannelCount;
	shost->max_id = Enquiry2->MaxTargets;
	if (Enquiry2->MaxLogicalDrives > shost->max_id) {
		int channels;

		channels = Enquiry2->MaxLogicalDrives / shost->max_id;
		c->LogicalChannelCount = c->LogicalChannelMax = channels;
	}
	c->MemorySize = Enquiry2->MemorySize >> 20;
	c->V1.SAFTE_EnclosureManagementEnabled =
		(Enquiry2->FaultManagementType == DAC960_V1_SAFTE);
	/*
	  Initialize the Controller Queue Depth, Driver Queue Depth, Logical Drive
	  Count, Maximum Blocks per Command, Controller Scatter/Gather Limit, and
	  Driver Scatter/Gather Limit.  The Driver Queue Depth must be at most one
	  less than the Controller Queue Depth to allow for an automatic drive
	  rebuild operation.
	*/
	c->ControllerQueueDepth = c->V1.Enquiry.MaxCommands;
	if (c->ControllerQueueDepth < 3)
		c->ControllerQueueDepth = Enquiry2->MaxCommands;
	if (c->ControllerQueueDepth < 3)
		/* Play safe and disable TCQ */
		c->ControllerQueueDepth = 3;
	shost->can_queue = c->ControllerQueueDepth - 2;
	if (shost->can_queue > DAC960_MaxDriverQueueDepth)
		shost->can_queue = DAC960_MaxDriverQueueDepth;
	c->LogicalDriveCount = c->V1.Enquiry.NumberOfLogicalDrives;
	shost->max_sectors = Enquiry2->MaxBlocksPerCommand;
	c->ControllerScatterGatherLimit = Enquiry2->MaxScatterGatherEntries;
	shost->sg_tablesize = c->ControllerScatterGatherLimit;
	if (shost->sg_tablesize > DAC960_V1_ScatterGatherLimit)
		shost->sg_tablesize = DAC960_V1_ScatterGatherLimit;
	/*
	  Initialize the Stripe Size, Segment Size, and Geometry Translation.
	*/
	c->V1.StripeSize = Config2->BlocksPerStripe * Config2->BlockFactor
		>> (10 - DAC960_BlockSizeBits);
	c->V1.SegmentSize = Config2->BlocksPerCacheLine * Config2->BlockFactor
		>> (10 - DAC960_BlockSizeBits);
	switch (Config2->DriveGeometry) {
	case DAC960_V1_Geometry_128_32:
		c->V1.GeometryTranslationHeads = 128;
		c->V1.GeometryTranslationSectors = 32;
		break;
	case DAC960_V1_Geometry_255_63:
		c->V1.GeometryTranslationHeads = 255;
		c->V1.GeometryTranslationSectors = 63;
		break;
	default:
		shost_printk(KERN_WARNING, c->host,
			     "Invalid config2 drive geometry %x\n",
			     Config2->DriveGeometry);
		goto out;
	}
	/*
	  Initialize the Background Initialization Status.
	*/
	if ((c->FirmwareVersion[0] == '4' &&
	     strcmp(c->FirmwareVersion, "4.08") >= 0) ||
	    (c->FirmwareVersion[0] == '5' &&
	     strcmp(c->FirmwareVersion, "5.08") >= 0)) {
		c->V1.BackgroundInitializationStatusSupported = true;
		DAC960_V1_ExecuteType3B(c,
					DAC960_V1_BackgroundInitializationControl, 0x20,
					c->
					V1.BackgroundInitializationStatusDMA);
		memcpy(&c->V1.LastBackgroundInitializationStatus,
		       c->V1.BackgroundInitializationStatus,
		       sizeof(DAC960_V1_BackgroundInitializationStatus_T));
	}
	c->V1.LastRebuildStatus = DAC960_V1_NoRebuildOrCheckInProgress;
	ret = 0;

out:
	pci_free_consistent(pdev, sizeof(DAC960_V1_Enquiry2_T),
			    Enquiry2, Enquiry2DMA);
	pci_free_consistent(pdev, sizeof(DAC960_V1_Config2_T),
			    Config2, Config2DMA);
	return ret;
}


/*
  DAC960_V2_ReadControllerConfiguration reads the Configuration Information
  from DAC960 V2 Firmware Controllers and initializes the Controller structure.
*/

static int DAC960_V2_ReadControllerConfiguration(myr_hba *c)
{
	DAC960_V2_ControllerInfo_T *info = &c->V2.ControllerInformation;
	struct Scsi_Host *shost = c->host;
	unsigned char status;
	int i, ModelNameLength;

	/* Get data into dma-able area, then copy into permanent location */
	mutex_lock(&c->V2.cinfo_mutex);
	status = DAC960_V2_NewControllerInfo(c);
	mutex_unlock(&c->V2.cinfo_mutex);
	if (status != DAC960_V2_NormalCompletion) {
		shost_printk(KERN_ERR, shost,
			     "Failed to get controller information\n");
		return -ENODEV;
	}

	/*
	  Initialize the Controller Model Name and Full Model Name fields.
	*/
	ModelNameLength = sizeof(info->ControllerName);
	if (ModelNameLength > sizeof(c->ModelName)-1)
		ModelNameLength = sizeof(c->ModelName)-1;
	memcpy(c->ModelName, info->ControllerName,
	       ModelNameLength);
	ModelNameLength--;
	while (c->ModelName[ModelNameLength] == ' ' ||
	       c->ModelName[ModelNameLength] == '\0')
		ModelNameLength--;
	c->ModelName[++ModelNameLength] = '\0';
	strcpy(c->FullModelName, DAC960_DriverName);
	strcat(c->FullModelName, " ");
	strcat(c->FullModelName, c->ModelName);
	/*
	  Initialize the Controller Firmware Version field.
	*/
	sprintf(c->FirmwareVersion, "%d.%02d-%02d",
		info->FirmwareMajorVersion,
		info->FirmwareMinorVersion,
		info->FirmwareTurnNumber);
	if (info->FirmwareMajorVersion == 6 &&
	    info->FirmwareMinorVersion == 0 &&
	    info->FirmwareTurnNumber < 1) {
		shost_printk(KERN_WARNING, shost,
			"FIRMWARE VERSION %s DOES NOT PROVIDE THE CONTROLLER\n"
			"STATUS MONITORING FUNCTIONALITY NEEDED BY THIS DRIVER.\n"
			"PLEASE UPGRADE TO VERSION 6.00-01 OR ABOVE.\n",
			c->FirmwareVersion);
	}
	/*
	  Initialize the Controller Channels, Targets, and Memory Size.
	*/
	c->PhysicalChannelMax = info->NumberOfPhysicalChannelsPossible;
	c->PhysicalChannelCount = info->NumberOfPhysicalChannelsPresent;
	c->LogicalChannelMax = info->NumberOfVirtualChannelsPossible;
	c->LogicalChannelCount = info->NumberOfVirtualChannelsPresent;
	shost->max_channel = c->PhysicalChannelCount + c->LogicalChannelCount;
	shost->max_id = info->MaximumTargetsPerChannel[0];
	for (i = 1; i < 16; i++) {
		if (!info->MaximumTargetsPerChannel[i])
			continue;
		if (shost->max_id < info->MaximumTargetsPerChannel[i])
			shost->max_id = info->MaximumTargetsPerChannel[i];
	}
	c->MemorySize = info->MemorySizeMB;
	/*
	 * Initialize the Controller Queue Depth, Driver Queue Depth,
	 * Logical Drive Count, Maximum Blocks per Command, Controller
	 * Scatter/Gather Limit, and Driver Scatter/Gather Limit.
	 * The Driver Queue Depth must be at most three less than
	 * the Controller Queue Depth; tag '1' is reserved for
	 * direct commands, and tag '2' for monitoring commands.
	 */
	c->ControllerQueueDepth = info->MaximumParallelCommands;
	shost->can_queue = c->ControllerQueueDepth - 3;
	if (shost->can_queue > DAC960_MaxDriverQueueDepth)
		shost->can_queue = DAC960_MaxDriverQueueDepth;
	c->LogicalDriveCount = info->LogicalDevicesPresent;
	shost->max_sectors =
		info->MaximumDataTransferSizeInBlocks;
	c->ControllerScatterGatherLimit =
		info->MaximumScatterGatherEntries;
	shost->sg_tablesize = c->ControllerScatterGatherLimit;
	if (shost->sg_tablesize > DAC960_V2_ScatterGatherLimit)
		shost->sg_tablesize = DAC960_V2_ScatterGatherLimit;
	return 0;
}


/*
  DAC960_ReportControllerConfiguration reports the Configuration Information
  for Controller.
*/

static void DAC960_ReportControllerConfiguration(myr_hba *c)
{
	shost_printk(KERN_INFO, c->host,
		"Configuring %s PCI RAID Controller\n", c->ModelName);
	shost_printk(KERN_INFO, c->host,
		"  Firmware Version: %s, Channels: %d, Memory Size: %dMB\n",
		c->FirmwareVersion, c->PhysicalChannelCount, c->MemorySize);
	if (c->IO_Address == 0)
		shost_printk(KERN_INFO, c->host,
			"  I/O Address: n/a, PCI Address: 0x%lX, IRQ Channel: %d\n",
			(unsigned long)c->PCI_Address, c->IRQ_Channel);
	else
		shost_printk(KERN_INFO, c->host,
			"  I/O Address: 0x%lX, PCI Address: 0x%lX, IRQ Channel: %d\n",
			(unsigned long)c->IO_Address,
			(unsigned long)c->PCI_Address,
			c->IRQ_Channel);
	shost_printk(KERN_INFO, c->host,
		"  Controller Queue Depth: %d, Maximum Blocks per Command: %d\n",
		c->ControllerQueueDepth, c->host->max_sectors);
	shost_printk(KERN_INFO, c->host,
		"  Driver Queue Depth: %d, Scatter/Gather Limit: %d of %d Segments\n",
		c->host->can_queue, c->host->sg_tablesize,
		c->ControllerScatterGatherLimit);
	if (c->FirmwareType == DAC960_V1_Controller) {
		shost_printk(KERN_INFO, c->host,
			"  Stripe Size: %dKB, Segment Size: %dKB, "
			"BIOS Geometry: %d/%d%s\n",
			c->V1.StripeSize,
			c->V1.SegmentSize,
			c->V1.GeometryTranslationHeads,
			c->V1.GeometryTranslationSectors,
			c->V1.SAFTE_EnclosureManagementEnabled ?
			     "  SAF-TE Enclosure Management Enabled" : "");
		shost_printk(KERN_INFO, c->host,
			"  Physical: %d/%d channels\n",
			c->PhysicalChannelCount, c->PhysicalChannelMax);
	} else {
		int i;
		DAC960_V2_ControllerInfo_T *info;

		info = &c->V2.ControllerInformation;
		for (i = 0; i < c->PhysicalChannelMax; i++) {
			if (!info->MaximumTargetsPerChannel[i])
				continue;
			shost_printk(KERN_INFO, c->host,
				     "  Device Channel %d: max %d devices\n",
				     i, info->MaximumTargetsPerChannel[i]);
		}
		shost_printk(KERN_INFO, c->host,
			"  Physical: %d/%d channels, %d disks, %d devices\n",
			c->PhysicalChannelCount, c->PhysicalChannelMax,
			info->PhysicalDisksPresent,
			info->PhysicalDevicesPresent);
	}
	shost_printk(KERN_INFO, c->host,
		     "  Logical: %d/%d channels, %d disks\n",
		     c->LogicalChannelCount, c->LogicalChannelMax,
		     c->LogicalDriveCount);
}

/*
  DAC960_ReportErrorStatus reports Controller BIOS Messages passed through
  the Error Status Register when the driver performs the BIOS handshaking.
  It returns true for fatal errors and false otherwise.
*/

static bool DAC960_ReportErrorStatus(myr_hba *c,
				     unsigned char ErrorStatus,
				     unsigned char Parameter0,
				     unsigned char Parameter1)
{
	struct pci_dev *pdev = c->PCIDevice;

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
	struct pci_dev *pdev = c->PCIDevice;

	/* Free the memory mailbox, status, and related structures */
	free_dma_loaf(pdev, &c->DmaPages);
	if (c->MemoryMappedAddress) {
		DAC960_DisableInterrupts(c);
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

int DAC960_host_reset(struct scsi_cmnd *scmd)
{
	struct Scsi_Host *shost = scmd->device->host;
	myr_hba *c =
		(myr_hba *)shost->hostdata;

	c->Reset(c->BaseAddress);
	return SUCCESS;
}

static int mylex_v1_pthru_queuecommand(struct Scsi_Host *shost,
					struct scsi_cmnd *scmd)
{
	myr_hba *c = (myr_hba *)shost->hostdata;
	myr_v1_cmdblk *cmd_blk = scsi_cmd_priv(scmd);
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V1_DCDB_T *DCDB;
	dma_addr_t DCDB_dma;
	struct scsi_device *sdev = scmd->device;
	struct scatterlist *sgl;
	unsigned long flags;
	int nsge;

	DAC960_V1_ClearCommand(cmd_blk);
	DCDB = pci_pool_alloc(c->V1.DCDBPool, GFP_ATOMIC, &DCDB_dma);
	if (!DCDB)
		return SCSI_MLQUEUE_HOST_BUSY;
	nsge = scsi_dma_map(scmd);
	if (nsge > 1) {
		pci_pool_free(c->V1.DCDBPool, DCDB, DCDB_dma);
		cmd_blk->DCDB = NULL;
		scmd->result = (DID_ERROR << 16);
		scmd->scsi_done(scmd);
		return 0;
	}

	cmd_blk->DCDB = DCDB;
	cmd_blk->DCDB_dma = DCDB_dma;
	mbox->Type3.opcode = DAC960_V1_DCDB;
	mbox->Type3.id = scmd->request->tag + 3;
	mbox->Type3.BusAddress = DCDB_dma;
	DCDB->Channel = sdev->channel;
	DCDB->TargetID = sdev->id;
	switch (scmd->sc_data_direction) {
	case DMA_NONE:
		DCDB->Direction = DAC960_V1_DCDB_NoDataTransfer;
		break;
	case DMA_TO_DEVICE:
		DCDB->Direction = DAC960_V1_DCDB_DataTransferSystemToDevice;
		break;
	case DMA_FROM_DEVICE:
		DCDB->Direction = DAC960_V1_DCDB_DataTransferDeviceToSystem;
		break;
	default:
		DCDB->Direction = DAC960_V1_DCDB_IllegalDataTransfer;
		break;
	}
	DCDB->EarlyStatus = false;
	if (scmd->request->timeout <= 10)
		DCDB->Timeout = DAC960_V1_DCDB_Timeout_10_seconds;
	else if (scmd->request->timeout <= 60)
		DCDB->Timeout = DAC960_V1_DCDB_Timeout_60_seconds;
	else if (scmd->request->timeout <= 600)
		DCDB->Timeout = DAC960_V1_DCDB_Timeout_10_minutes;
	else
		DCDB->Timeout = DAC960_V1_DCDB_Timeout_24_hours;
	DCDB->NoAutomaticRequestSense = false;
	DCDB->DisconnectPermitted = true;
	sgl = scsi_sglist(scmd);
	DCDB->BusAddress = sg_dma_address(sgl);
	if (sg_dma_len(sgl) > USHRT_MAX) {
		DCDB->TransferLength = sg_dma_len(sgl) & 0xffff;
		DCDB->TransferLengthHigh4 = sg_dma_len(sgl) >> 16;
	} else {
		DCDB->TransferLength = sg_dma_len(sgl);
		DCDB->TransferLengthHigh4 = 0;
	}
	DCDB->CDBLength = scmd->cmd_len;
	DCDB->SenseLength = sizeof(DCDB->SenseData);
	memcpy(&DCDB->CDB, scmd->cmnd, scmd->cmd_len);

	spin_lock_irqsave(&c->queue_lock, flags);
	c->V1.QueueCommand(c, cmd_blk);
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return 0;
}

static void mylex_v1_inquiry(myr_hba *c,
			     struct scsi_cmnd *scmd)
{
	unsigned char inq[36] = {
		0x00, 0x00, 0x03, 0x02, 0x20, 0x00, 0x01, 0x00,
		0x4d, 0x59, 0x4c, 0x45, 0x58, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20,
	};

	if (c->V1.BusWidth > 16)
		inq[7] |= 1 << 6;
	if (c->V1.BusWidth > 8)
		inq[7] |= 1 << 5;
	memcpy(&inq[16], c->ModelName, 16);
	memcpy(&inq[32], c->FirmwareVersion, 4);

	scsi_sg_copy_from_buffer(scmd, (void *)inq, 36);
}

static void
mylex_v1_mode_sense(myr_hba *c,
		    struct scsi_cmnd *scmd,
		    DAC960_V1_LogicalDeviceInfo_T *ldev_info)
{
	unsigned char modes[32], *mode_pg;
	bool dbd;
	size_t mode_len;

	dbd = (scmd->cmnd[1] & 0x08) == 0x08;
	if (dbd) {
		mode_len = 24;
		mode_pg = &modes[4];
	} else {
		mode_len = 32;
		mode_pg = &modes[12];
	}
	memset(modes, 0, sizeof(modes));
	modes[0] = mode_len - 1;
	if (!dbd) {
		unsigned char *block_desc = &modes[4];
		modes[3] = 8;
		put_unaligned_be32(ldev_info->Size, &block_desc[0]);
		put_unaligned_be32(c->V1.LogicalBlockSize, &block_desc[5]);
	}
	mode_pg[0] = 0x08;
	mode_pg[1] = 0x12;
	if (ldev_info->WriteBack)
		mode_pg[2] |= 0x04;
	if (c->V1.SegmentSize) {
		mode_pg[2] |= 0x08;
		put_unaligned_be16(c->V1.SegmentSize, &mode_pg[14]);
	}

	scsi_sg_copy_from_buffer(scmd, modes, mode_len);
}

static void mylex_v1_request_sense(myr_hba *c,
				   struct scsi_cmnd *scmd)
{
	scsi_build_sense_buffer(0, scmd->sense_buffer,
				NO_SENSE, 0, 0);
	scsi_sg_copy_from_buffer(scmd, scmd->sense_buffer,
				 SCSI_SENSE_BUFFERSIZE);
}

static void
mylex_v1_read_capacity(myr_hba *c,
		       struct scsi_cmnd *scmd,
		       DAC960_V1_LogicalDeviceInfo_T *ldev_info)
{
	unsigned char data[8];

	dev_dbg(&scmd->device->sdev_gendev,
		"Capacity %u, blocksize %u\n",
		ldev_info->Size, c->V1.LogicalBlockSize);
	put_unaligned_be32(ldev_info->Size - 1, &data[0]);
	put_unaligned_be32(c->V1.LogicalBlockSize, &data[4]);
	scsi_sg_copy_from_buffer(scmd, data, 8);
}

static int mylex_v1_ldev_queuecommand(struct Scsi_Host *shost,
				       struct scsi_cmnd *scmd)
{
	myr_hba *c = (myr_hba *)shost->hostdata;
	myr_v1_cmdblk *cmd_blk = scsi_cmd_priv(scmd);
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V1_LogicalDeviceInfo_T *ldev_info;
	struct scsi_device *sdev = scmd->device;
	struct scatterlist *sgl;
	unsigned long flags;
	u64 lba;
	u32 block_cnt;
	int nsge;

	ldev_info = sdev->hostdata;
	if (!ldev_info || ldev_info->State != DAC960_V1_Device_Online) {
		scmd->result = (DID_BAD_TARGET << 16);
		scmd->scsi_done(scmd);
		return 0;
	}
	switch (scmd->cmnd[0]) {
	case TEST_UNIT_READY:
		scmd->result = (DID_OK << 16);
		scmd->scsi_done(scmd);
		return 0;
	case INQUIRY:
		if (scmd->cmnd[1] & 1) {
			/* Illegal request, invalid field in CDB */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						ILLEGAL_REQUEST, 0x24, 0);
			scmd->result = (DRIVER_SENSE << 24) |
				SAM_STAT_CHECK_CONDITION;
		} else {
			mylex_v1_inquiry(c, scmd);
			scmd->result = (DID_OK << 16);
		}
		scmd->scsi_done(scmd);
		return 0;
		break;
	case MODE_SENSE:
		if ((scmd->cmnd[2] & 0x3F) != 0x3F &&
		    (scmd->cmnd[2] & 0x3F) != 0x08) {
			/* Illegal request, invalid field in CDB */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						ILLEGAL_REQUEST, 0x24, 0);
			scmd->result = (DRIVER_SENSE << 24) |
				SAM_STAT_CHECK_CONDITION;
		} else {
			mylex_v1_mode_sense(c, scmd, ldev_info);
			scmd->result = (DID_OK << 16);
		}
		scmd->scsi_done(scmd);
		return 0;
		break;
	case READ_CAPACITY:
		if ((scmd->cmnd[1] & 1) ||
		    (scmd->cmnd[8] & 1)) {
			/* Illegal request, invalid field in CDB */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						ILLEGAL_REQUEST, 0x24, 0);
			scmd->result = (DRIVER_SENSE << 24) |
				SAM_STAT_CHECK_CONDITION;
			scmd->scsi_done(scmd);
			return 0;
		}
		lba = get_unaligned_be32(&scmd->cmnd[2]);
		if (lba) {
			/* Illegal request, invalid field in CDB */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						ILLEGAL_REQUEST, 0x24, 0);
			scmd->result = (DRIVER_SENSE << 24) |
				SAM_STAT_CHECK_CONDITION;
			scmd->scsi_done(scmd);
			return 0;
		}
		mylex_v1_read_capacity(c, scmd, ldev_info);
		scmd->scsi_done(scmd);
		return 0;
	case REQUEST_SENSE:
		mylex_v1_request_sense(c, scmd);
		scmd->result = (DID_OK << 16);
		return 0;
		break;
	case SEND_DIAGNOSTIC:
		if (scmd->cmnd[1] != 0x04) {
			/* Illegal request, invalid field in CDB */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						ILLEGAL_REQUEST, 0x24, 0);
			scmd->result = (DRIVER_SENSE << 24) |
				SAM_STAT_CHECK_CONDITION;
		} else {
			/* Assume good status */
			scmd->result = (DID_OK << 16);
		}
		scmd->scsi_done(scmd);
		return 0;
		break;
	case READ_6:
	case WRITE_6:
		lba = (((scmd->cmnd[1] & 0x1F) << 16) |
		       (scmd->cmnd[2] << 8) |
		       scmd->cmnd[3]);
		block_cnt = scmd->cmnd[4];
		break;
	case READ_10:
	case WRITE_10:
	case VERIFY:		/* 0x2F */
	case WRITE_VERIFY:	/* 0x2E */
		lba = get_unaligned_be32(&scmd->cmnd[2]);
		block_cnt = get_unaligned_be16(&scmd->cmnd[7]);
		break;
	case READ_12:
	case WRITE_12:
	case VERIFY_12: /* 0xAF */
	case WRITE_VERIFY_12:	/* 0xAE */
		lba = get_unaligned_be32(&scmd->cmnd[2]);
		block_cnt = get_unaligned_be32(&scmd->cmnd[6]);
		break;
	default:
		/* Illegal request, invalid opcode */
		scsi_build_sense_buffer(0, scmd->sense_buffer,
					ILLEGAL_REQUEST, 0x20, 0);
		scmd->result = (DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;
		scmd->scsi_done(scmd);
		return 0;
	}

	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type5.id = scmd->request->tag + 3;
	if (scmd->sc_data_direction == DMA_NONE)
		goto submit;
	nsge = scsi_dma_map(scmd);
	if (nsge == 1) {
		sgl = scsi_sglist(scmd);
		if (scmd->sc_data_direction == DMA_FROM_DEVICE)
			mbox->Type5.opcode = DAC960_V1_Read;
		else
			mbox->Type5.opcode = DAC960_V1_Write;

		mbox->Type5.LD.TransferLength = block_cnt;
		mbox->Type5.LD.LogicalDriveNumber = sdev->id;
		mbox->Type5.LogicalBlockAddress = lba;
		mbox->Type5.BusAddress = (u32)sg_dma_address(sgl);
	} else {
		DAC960_V1_ScatterGatherSegment_T *hw_sgl;
		dma_addr_t hw_sgl_addr;
		int i;

		hw_sgl = pci_pool_alloc(c->ScatterGatherPool,
					GFP_ATOMIC, &hw_sgl_addr);
		if (!hw_sgl)
			return SCSI_MLQUEUE_HOST_BUSY;

		cmd_blk->sgl = hw_sgl;
		cmd_blk->sgl_addr = hw_sgl_addr;

		if (scmd->sc_data_direction == DMA_FROM_DEVICE)
			mbox->Type5.opcode = DAC960_V1_ReadWithScatterGather;
		else
			mbox->Type5.opcode = DAC960_V1_WriteWithScatterGather;

		mbox->Type5.LD.TransferLength = block_cnt;
		mbox->Type5.LD.LogicalDriveNumber = sdev->id;
		mbox->Type5.LogicalBlockAddress = lba;
		mbox->Type5.BusAddress = hw_sgl_addr;
		mbox->Type5.ScatterGatherCount = nsge;

		scsi_for_each_sg(scmd, sgl, nsge, i) {
			hw_sgl->SegmentDataPointer = (u32)sg_dma_address(sgl);
			hw_sgl->SegmentByteCount = (u32)sg_dma_len(sgl);
			hw_sgl++;
		}
	}
submit:
	spin_lock_irqsave(&c->queue_lock, flags);
	c->V1.QueueCommand(c, cmd_blk);
	spin_unlock_irqrestore(&c->queue_lock, flags);

	return 0;
}

static int mylex_v1_queuecommand(struct Scsi_Host *shost,
				  struct scsi_cmnd *scmd)
{
	myr_hba *c =
		(myr_hba *)shost->hostdata;
	struct scsi_device *sdev = scmd->device;

	if (sdev->channel > c->host->max_channel) {
		scmd->result = (DID_BAD_TARGET << 16);
		scmd->scsi_done(scmd);
		return 0;
	}
	if (sdev->channel >= c->PhysicalChannelCount)
		return mylex_v1_ldev_queuecommand(shost, scmd);

	return mylex_v1_pthru_queuecommand(shost, scmd);
}

static int mylex_v1_slave_alloc(struct scsi_device *sdev)
{
	myr_hba *c =
		(myr_hba *)sdev->host->hostdata;
	unsigned short status;

	if (sdev->channel > c->host->max_channel)
		return -ENXIO;

	if (sdev->lun > 0)
		return -ENXIO;

	if (sdev->channel >= c->PhysicalChannelCount) {
		DAC960_V1_LogicalDeviceInfo_T *ldev_info;
		unsigned short ldev_num;

		ldev_num = mylex_translate_ldev(c, sdev);
		ldev_info = c->V1.LogicalDeviceInfo[ldev_num];
		if (ldev_info) {
			enum raid_level level;

			sdev->hostdata = kzalloc(sizeof(*ldev_info),
						 GFP_KERNEL);
			if (!sdev->hostdata)
				return -ENOMEM;
			memcpy(sdev->hostdata, ldev_info,
			       sizeof(*ldev_info));
			switch (ldev_info->RAIDLevel) {
			case DAC960_V1_RAID_Level0:
				level = RAID_LEVEL_LINEAR;
				break;
			case DAC960_V1_RAID_Level1:
				level = RAID_LEVEL_1;
				break;
			case DAC960_V1_RAID_Level3:
				level = RAID_LEVEL_3;
				break;
			case DAC960_V1_RAID_Level5:
				level = RAID_LEVEL_5;
				break;
			case DAC960_V1_RAID_Level6:
				level = RAID_LEVEL_6;
				break;
			case DAC960_V1_RAID_JBOD:
				level = RAID_LEVEL_JBOD;
				break;
			default:
				level = RAID_LEVEL_UNKNOWN;
				break;
			}
			raid_set_level(mylex_v1_raid_template,
				       &sdev->sdev_gendev, level);
		}
		return 0;
	}

	status = DAC960_V1_ExecuteType3D(c, DAC960_V1_GetDeviceState, sdev);
	if (status != DAC960_V1_NormalCompletion) {
		dev_dbg(&sdev->sdev_gendev,
			"Failed to get device state, status %x\n", status);
	}
	return 0;
}

int mylex_v1_slave_configure(struct scsi_device *sdev)
{
	myr_hba *c =
		(myr_hba *)sdev->host->hostdata;
	DAC960_V1_LogicalDeviceInfo_T *ldev_info;

	if (sdev->channel > c->host->max_id)
		return -ENXIO;

	if (sdev->channel < c->PhysicalChannelCount) {
		sdev->no_uld_attach = 1;
		return 0;
	}
	if (sdev->lun != 0)
		return -ENXIO;

	ldev_info = sdev->hostdata;
	if (!ldev_info)
		return -ENXIO;
	if (ldev_info->State != DAC960_V1_Device_Online)
		sdev_printk(KERN_INFO, sdev,
			    "Logical drive is %s\n",
			    DAC960_V1_DriveStateName(ldev_info->State));

	sdev->tagged_supported = 1;
	return 0;
}

static void mylex_v1_slave_destroy(struct scsi_device *sdev)
{
	void *hostdata = sdev->hostdata;

	if (hostdata) {
		kfree(hostdata);
		sdev->hostdata = NULL;
	}
}

static ssize_t mylex_v1_show_dev_state(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	int ret;

	if (!sdev->hostdata)
		return snprintf(buf, 16, "Unknown\n");

	if (sdev->channel >= c->PhysicalChannelCount) {
		DAC960_V1_LogicalDeviceInfo_T *ldev_info =
			sdev->hostdata;
		const char *name;

		name = DAC960_V1_DriveStateName(ldev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       ldev_info->State);
	} else {
		myr_v1_pdev_state *pdev_info = sdev->hostdata;
		unsigned short status;
		const char *name;

		status = DAC960_V1_ExecuteType3D(c, DAC960_V1_GetDeviceState,
						 sdev);
		if (status != DAC960_V1_NormalCompletion)
			sdev_printk(KERN_INFO, sdev,
				    "Failed to get device state, status %x\n",
				    status);

		if (!pdev_info->Present)
			name = "Removed";
		else
			name = DAC960_V1_DriveStateName(pdev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       pdev_info->State);
	}
	return ret;
}

static ssize_t mylex_v1_store_dev_state(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	myr_v1_pdev_state *pdev_info;
	myr_v1_devstate new_state;
	unsigned short status;

	if (!strncmp(buf, "kill", 4) ||
	    !strncmp(buf, "offline", 7))
		new_state = DAC960_V1_Device_Dead;
	else if (!strncmp(buf, "online", 6))
		new_state = DAC960_V1_Device_Online;
	else if (!strncmp(buf, "standby", 7))
		new_state = DAC960_V1_Device_Standby;
	else
		return -EINVAL;

	pdev_info = sdev->hostdata;
	if (!pdev_info) {
		sdev_printk(KERN_INFO, sdev,
			    "Failed - no physical device information\n");
		return -ENXIO;
	}
	if (!pdev_info->Present) {
		sdev_printk(KERN_INFO, sdev,
			    "Failed - device not present\n");
		return -ENXIO;
	}

	if (pdev_info->State == new_state)
		return count;

	status = DAC960_V1_SetDeviceState(c, sdev, new_state);
	switch (status) {
	case DAC960_V1_NormalCompletion:
		break;
	case DAC960_V1_UnableToStartDevice:
		sdev_printk(KERN_INFO, sdev,
			     "Failed - Unable to Start Device\n");
		count = -EAGAIN;
		break;
	case DAC960_V1_NoDeviceAtAddress:
		sdev_printk(KERN_INFO, sdev,
			    "Failed - No Device at Address\n");
		count = -ENODEV;
		break;
	case DAC960_V1_InvalidChannelOrTargetOrModifier:
		sdev_printk(KERN_INFO, sdev,
			 "Failed - Invalid Channel or Target or Modifier\n");
		count = -EINVAL;
		break;
	case DAC960_V1_ChannelBusy:
		sdev_printk(KERN_INFO, sdev,
			 "Failed - Channel Busy\n");
		count = -EBUSY;
		break;
	default:
		sdev_printk(KERN_INFO, sdev,
			 "Failed - Unexpected Status %04X\n", status);
		count = -EIO;
		break;
	}
	return count;
}

static ssize_t mylex_v2_show_dev_state(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	int ret;

	if (!sdev->hostdata)
		return snprintf(buf, 16, "Unknown\n");

	if (sdev->channel >= c->PhysicalChannelCount) {
		DAC960_V2_LogicalDeviceInfo_T *ldev_info = sdev->hostdata;
		const char *name;

		name = DAC960_V2_DriveStateName(ldev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       ldev_info->State);
	} else {
		DAC960_V2_PhysicalDeviceInfo_T *pdev_info;
		const char *name;

		pdev_info = sdev->hostdata;
		name = DAC960_V2_DriveStateName(pdev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       pdev_info->State);
	}
	return ret;
}

static ssize_t mylex_v2_store_dev_state(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	myr_v2_cmdblk *cmd_blk;
	DAC960_V2_CommandMailbox_T *mbox;
	DAC960_V2_DriveState_T new_state;
	unsigned short ldev_num;
	unsigned char status;

	if (!strncmp(buf, "offline", 7) ||
	    !strncmp(buf, "kill", 4))
		new_state = DAC960_V2_Device_Offline;
	else if (!strncmp(buf, "online", 6))
		new_state = DAC960_V2_Device_Online;
	else if (!strncmp(buf, "standby", 7))
		new_state = DAC960_V2_Device_Standby;
	else
		return -EINVAL;

	if (sdev->channel < c->PhysicalChannelCount) {
		DAC960_V2_PhysicalDeviceInfo_T *pdev_info = sdev->hostdata;

		if (pdev_info->State == new_state) {
			sdev_printk(KERN_INFO, sdev,
				    "Device already in %s\n",
				    DAC960_V2_DriveStateName(new_state));
			return count;
		}
		status = DAC960_V2_TranslatePhysicalDevice(c, sdev->channel,
							   sdev->id, sdev->lun,
							   &ldev_num);
		if (status != DAC960_V2_NormalCompletion)
			return -ENXIO;
	} else {
		DAC960_V2_LogicalDeviceInfo_T *ldev_info = sdev->hostdata;

		if (ldev_info->State == new_state) {
			sdev_printk(KERN_INFO, sdev,
				    "Device already in %s\n",
				    DAC960_V2_DriveStateName(new_state));
			return count;
		}
		ldev_num = ldev_info->LogicalDeviceNumber;
	}
	mutex_lock(&c->V2.dcmd_mutex);
	cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_ClearCommand(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	mbox->SetDeviceState.IOCTL_Opcode = DAC960_V2_SetDeviceState;
	mbox->SetDeviceState.State = new_state;
	mbox->SetDeviceState.LogicalDevice.LogicalDeviceNumber = ldev_num;
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	if (status == DAC960_V2_NormalCompletion) {
		if (sdev->channel < c->PhysicalChannelCount) {
			DAC960_V2_PhysicalDeviceInfo_T *pdev_info =
				sdev->hostdata;

			pdev_info->State = new_state;
		} else {
			DAC960_V2_LogicalDeviceInfo_T *ldev_info =
				sdev->hostdata;

			ldev_info->State = new_state;
		}
		sdev_printk(KERN_INFO, sdev,
			    "Set device state to %s\n",
			    DAC960_V2_DriveStateName(new_state));
		return count;
	}
	sdev_printk(KERN_INFO, sdev,
		    "Failed to set device state to %s, status 0x%02x\n",
		    DAC960_V2_DriveStateName(new_state),
		    status);
	return -EINVAL;
}

static ssize_t mylex_show_dev_state(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_show_dev_state(dev, attr, buf);
	else
		return mylex_v2_show_dev_state(dev, attr, buf);
}

static ssize_t mylex_store_dev_state(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_store_dev_state(dev, attr, buf, count);
	else
		return mylex_v2_store_dev_state(dev, attr, buf, count);
}

static DEVICE_ATTR(raid_state, S_IRUGO | S_IWUSR, mylex_show_dev_state,
		   mylex_store_dev_state);

static ssize_t mylex_v1_show_dev_level(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (sdev->channel >= c->PhysicalChannelCount) {
		DAC960_V1_LogicalDeviceInfo_T *ldev_info = sdev->hostdata;
		const char *name;

		if (!ldev_info)
			return -ENXIO;

		name = DAC960_V1_RAIDLevelName(ldev_info->RAIDLevel);
		if (!name)
			return snprintf(buf, 32, "Invalid (%02X)\n",
					ldev_info->State);
		return snprintf(buf,32, "%s\n", name);
	}
	return snprintf(buf, 32, "Physical Drive\n");
}

static ssize_t mylex_v2_show_dev_level(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	const char *name = NULL;

	if (!sdev->hostdata)
		return snprintf(buf, 16, "Unknown\n");

	if (sdev->channel >= c->PhysicalChannelCount) {
		DAC960_V2_LogicalDeviceInfo_T *ldev_info;

		ldev_info = sdev->hostdata;
		name = DAC960_V2_RAIDLevelName(ldev_info->RAIDLevel);
		if (!name)
			return snprintf(buf, 32, "Invalid (%02X)\n",
					ldev_info->State);

	} else
		name = DAC960_V2_RAIDLevelName(DAC960_V2_RAID_Physical);

	return snprintf(buf, 32, "%s\n", name);
}

static ssize_t mylex_show_dev_level(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_show_dev_level(dev, attr, buf);
	else
		return mylex_v2_show_dev_level(dev, attr, buf);
}
static DEVICE_ATTR(raid_level, S_IRUGO, mylex_show_dev_level, NULL);

static ssize_t mylex_show_dev_rebuild(struct device *,
				      struct device_attribute *, char *);
static ssize_t mylex_store_dev_rebuild(struct device *,
				       struct device_attribute *,
				       const char *, size_t);
static DEVICE_ATTR(rebuild, S_IRUGO | S_IWUSR, mylex_show_dev_rebuild,
		   mylex_store_dev_rebuild);

static ssize_t mylex_v1_show_dev_rebuild(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	myr_v1_cmdblk *cmd_blk = &c->V1.MonitoringCommandBlock;
	DAC960_V1_CommandMailbox_T *mbox = &cmd_blk->mbox;
	unsigned short ldev_num = 0xffff;
	unsigned char status;
	bool rebuild = false;
	ssize_t ldev_size, remaining;

	if (sdev->channel < c->PhysicalChannelCount)
		return snprintf(buf, 32, "physical device - not rebuilding\n");

	if (attr == &dev_attr_rebuild)
		rebuild = true;

	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetRebuildProgress;
	mbox->Type3.BusAddress = c->V1.RebuildProgressDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		ldev_num = c->V1.RebuildProgress->LogicalDriveNumber;
		ldev_size = c->V1.RebuildProgress->LogicalDriveSize;
		remaining = c->V1.RebuildProgress->RemainingBlocks;
	}
	mutex_unlock(&c->V1.dcmd_mutex);

	if (ldev_num != mylex_translate_ldev(c, sdev) ||
	    status != DAC960_V1_NormalCompletion)
		return snprintf(buf, 32, "not %s\n",
				rebuild ? "rebuilding" : "checking");

	if (c->V1.Enquiry.RebuildFlag == DAC960_V1_BackgroundCheckInProgress &&
	    rebuild)
		return snprintf(buf, 32, "not rebuilding\n");
	else if (!rebuild &&
		 c->V1.Enquiry.RebuildFlag ==
		 DAC960_V1_BackgroundRebuildInProgress)
		return snprintf(buf, 32, "not checking\n");

	return snprintf(buf, 32, "%s block %zu of %zu\n",
			rebuild ? "rebuilding" : "checking",
			ldev_size - remaining, ldev_size);
}

static ssize_t mylex_v2_show_dev_rebuild(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info;
	unsigned short ldev_num;
	unsigned char status;

	if (sdev->channel < c->PhysicalChannelCount)
		return snprintf(buf, 32, "physical device - not rebuilding\n");

	ldev_info = sdev->hostdata;
	ldev_num = ldev_info->LogicalDeviceNumber;
	status = DAC960_V2_NewLogicalDeviceInfo(c, ldev_num, ldev_info);
	if (ldev_info->RebuildInProgress) {
		return snprintf(buf, 32, "rebuilding block %zu of %zu\n",
				(size_t)ldev_info->RebuildBlockNumber,
				(size_t)ldev_info->ConfigurableDeviceSize);
	} else
		return snprintf(buf, 32, "not rebuilding\n");
}

static ssize_t mylex_v1_store_dev_rebuild(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	myr_v1_cmdblk *cmd_blk;
	DAC960_V1_CommandMailbox_T *mbox;
	char tmpbuf[8];
	ssize_t len;
	unsigned short ldev_num = 0xFFFF;
	unsigned short status;
	int start;
	bool rebuild = false;
	const char *msg;

	if (attr == &dev_attr_rebuild)
		rebuild = true;

	len = count > sizeof(tmpbuf) - 1 ? sizeof(tmpbuf) - 1 : count;
	strncpy(tmpbuf, buf, len);
	tmpbuf[len] = '\0';
	if (sscanf(tmpbuf, "%d", &start) != 1)
		return -EINVAL;

	if (rebuild && start && sdev->channel >= c->PhysicalChannelCount)
		return -ENXIO;
	else if (sdev->channel < c->PhysicalChannelCount)
		return -ENXIO;
	mutex_lock(&c->V1.dcmd_mutex);
	DAC960_V1_ClearCommand(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetRebuildProgress;
	mbox->Type3.BusAddress = c->V1.RebuildProgressDMA;
	DAC960_V1_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion)
		ldev_num = c->V1.RebuildProgress->LogicalDriveNumber;
	mutex_unlock(&c->V1.dcmd_mutex);

	if (start) {
		if (status != DAC960_V1_NormalCompletion) {
			sdev_printk(KERN_INFO, sdev,
				    "%s Not Initiated; already in progress\n",
				    rebuild ? "Rebuild" : "Check Consistency");
			return -EALREADY;
		}
		mutex_lock(&c->V1.dcmd_mutex);
		cmd_blk = &c->V1.DirectCommandBlock;
		DAC960_V1_ClearCommand(cmd_blk);
		mbox = &cmd_blk->mbox;
		if (rebuild) {
			mbox->Type3D.opcode = DAC960_V1_RebuildAsync;
			mbox->Type3D.id = DAC960_DirectCommandIdentifier;
			mbox->Type3D.Channel = sdev->channel;
			mbox->Type3D.TargetID = sdev->id;
		} else {
			ldev_num = mylex_translate_ldev(c, sdev);
			mbox->Type3C.opcode = DAC960_V1_CheckConsistencyAsync;
			mbox->Type3C.id = DAC960_DirectCommandIdentifier;
			mbox->Type3C.LogicalDriveNumber = ldev_num;
			mbox->Type3C.AutoRestore = true;
		}
		DAC960_V1_ExecuteCommand(c, cmd_blk);
		status = cmd_blk->status;
		mutex_unlock(&c->V1.dcmd_mutex);
	} else {
		struct pci_dev *pdev = c->PCIDevice;
		unsigned char *rate;
		dma_addr_t rate_addr;

		if (ldev_num != mylex_translate_ldev(c, sdev)) {
			sdev_printk(KERN_INFO, sdev,
				    "%s Not Cancelled; not in progress\n",
				    rebuild ? "Rebuild" : "Check Consistency");
			return 0;
		}
		rate = pci_alloc_consistent(pdev, sizeof(char), &rate_addr);
		if (rate == NULL) {
			sdev_printk(KERN_INFO, sdev,
				    "Cancellation of %s Failed - "
				    "Out of Memory\n",
				    rebuild ? "Rebuild" : "Check Consistency");
			return -ENOMEM;
		}
		mutex_lock(&c->V1.dcmd_mutex);
		cmd_blk = &c->V1.DirectCommandBlock;
		DAC960_V1_ClearCommand(cmd_blk);
		mbox = &cmd_blk->mbox;
		mbox->Type3R.opcode = DAC960_V1_RebuildControl;
		mbox->Type3R.id = DAC960_DirectCommandIdentifier;
		mbox->Type3R.RebuildRateConstant = 0xFF;
		mbox->Type3R.BusAddress = rate_addr;
		DAC960_V1_ExecuteCommand(c, cmd_blk);
		status = cmd_blk->status;
		pci_free_consistent(pdev, sizeof(char), rate, rate_addr);
		mutex_unlock(&c->V1.dcmd_mutex);
	}
	if (status == DAC960_V1_NormalCompletion) {
		sdev_printk(KERN_INFO, sdev, "%s %s\n",
			    rebuild ? "Rebuild" : "Check Consistency",
			    start ? "Initiated" : "Cancelled");
		return count;
	}
	if (!start) {
		sdev_printk(KERN_INFO, sdev,
			    "%s Not Cancelled, status 0x%x\n",
			    rebuild ? "Rebuild" : "Check Consistency",
			    status);
		return -EIO;
	}

	switch (status) {
	case DAC960_V1_AttemptToRebuildOnlineDrive:
		if (rebuild)
			msg = "Attempt to Rebuild Online or Unresponsive Drive";
		else
			msg = "Dependent Physical Device is DEAD";
		sdev_printk(KERN_INFO, sdev,
			    "%s Failed - %s\n",
			    rebuild ? "Rebuild" : "Check Consistency", msg);
		break;
	case DAC960_V1_NewDiskFailedDuringRebuild:
		sdev_printk(KERN_INFO, sdev,
			    "Rebuild Failed - "
			    "New Disk Failed During Rebuild\n");
		break;
	case DAC960_V1_InvalidDeviceAddress:
		if (rebuild)
			msg = "Invalid Device Address";
		else
			msg = "Invalid or Nonredundant Logical Drive";
		sdev_printk(KERN_INFO, sdev,
			    "%s Failed - %s\n",
			    rebuild ? "Rebuild" : "Check Consistency", msg);
		break;
	case DAC960_V1_RebuildOrCheckAlreadyInProgress:
		sdev_printk(KERN_INFO, sdev,
			    "%s Failed - Already in Progress\n",
			    rebuild ? "Rebuild" : "Check Consistency");
		break;
	default:
		sdev_printk(KERN_INFO, sdev,
			    "%s Failed, status 0x%x\n",
			    rebuild ? "Rebuild" : "Check Consistency", status);
	}
	return -EIO;
}

static ssize_t mylex_v2_store_dev_rebuild(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info;
	myr_v2_cmdblk *cmd_blk;
	DAC960_V2_CommandMailbox_T *mbox;
	char tmpbuf[8];
	ssize_t len;
	unsigned short ldev_num;
	unsigned char status;
	int rebuild;
	int ret = count;

	if (sdev->channel < c->PhysicalChannelCount)
		return -EINVAL;

	ldev_info = sdev->hostdata;
	if (!ldev_info)
		return -ENXIO;
	ldev_num = ldev_info->LogicalDeviceNumber;

	len = count > sizeof(tmpbuf) - 1 ? sizeof(tmpbuf) - 1 : count;
	strncpy(tmpbuf, buf, len);
	tmpbuf[len] = '\0';
	if (sscanf(tmpbuf, "%d", &rebuild) != 1)
		return -EINVAL;

	status = DAC960_V2_NewLogicalDeviceInfo(c, ldev_num, ldev_info);
	if (status != DAC960_V2_NormalCompletion) {
		sdev_printk(KERN_INFO, sdev,
			    "Failed to get device information, status 0x%02x\n",
			    status);
		return -EIO;
	}

	if (rebuild && ldev_info->RebuildInProgress) {
		sdev_printk(KERN_INFO, sdev,
			    "Rebuild Not Initiated; already in progress\n");
		return -EALREADY;
	}
	if (!rebuild && !ldev_info->RebuildInProgress) {
		sdev_printk(KERN_INFO, sdev,
			    "Rebuild Not Cancelled; no rebuild in progress\n");
		return ret;
	}

	mutex_lock(&c->V2.dcmd_mutex);
	cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_ClearCommand(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	if (rebuild) {
		mbox->LogicalDeviceInfo.LogicalDevice.LogicalDeviceNumber =
			ldev_num;
		mbox->LogicalDeviceInfo.IOCTL_Opcode =
			DAC960_V2_RebuildDeviceStart;
	} else {
		mbox->LogicalDeviceInfo.LogicalDevice.LogicalDeviceNumber =
			ldev_num;
		mbox->LogicalDeviceInfo.IOCTL_Opcode =
			DAC960_V2_RebuildDeviceStop;
	}
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	if (status) {
		sdev_printk(KERN_INFO, sdev,
			    "Rebuild Not %s, status 0x%02x\n",
			    rebuild ? "Initiated" : "Cancelled", status);
		ret = -EIO;
	} else
		sdev_printk(KERN_INFO, sdev, "Rebuild %s\n",
			    rebuild ? "Initiated" : "Cancelled");

	return ret;
}

static ssize_t mylex_show_dev_rebuild(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_show_dev_rebuild(dev, attr, buf);
	else
		return mylex_v2_show_dev_rebuild(dev, attr, buf);
}

static ssize_t mylex_store_dev_rebuild(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_store_dev_rebuild(dev, attr, buf, count);
	else
		return mylex_v2_store_dev_rebuild(dev, attr, buf, count);
}

static ssize_t mylex_v2_show_consistency_check(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info;
	unsigned short ldev_num;
	unsigned char status;

	if (sdev->channel < c->PhysicalChannelCount)
		return snprintf(buf, 32, "physical device - not checking\n");

	ldev_info = sdev->hostdata;
	if (!ldev_info)
		return -ENXIO;
	ldev_num = ldev_info->LogicalDeviceNumber;
	status = DAC960_V2_NewLogicalDeviceInfo(c, ldev_num, ldev_info);
	if (ldev_info->ConsistencyCheckInProgress)
		return snprintf(buf, 32, "checking block %zu of %zu\n",
				(size_t)ldev_info->ConsistencyCheckBlockNumber,
				(size_t)ldev_info->ConfigurableDeviceSize);
	else
		return snprintf(buf, 32, "not checking\n");
}

static ssize_t mylex_v2_store_consistency_check(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info;
	myr_v2_cmdblk *cmd_blk;
	DAC960_V2_CommandMailbox_T *mbox;
	char tmpbuf[8];
	ssize_t len;
	unsigned short ldev_num;
	unsigned char status;
	int check;
	int ret = count;

	if (sdev->channel < c->PhysicalChannelCount)
		return -EINVAL;

	ldev_info = sdev->hostdata;
	if (!ldev_info)
		return -ENXIO;
	ldev_num = ldev_info->LogicalDeviceNumber;

	len = count > sizeof(tmpbuf) - 1 ? sizeof(tmpbuf) - 1 : count;
	strncpy(tmpbuf, buf, len);
	tmpbuf[len] = '\0';
	if (sscanf(tmpbuf, "%d", &check) != 1)
		return -EINVAL;

	status = DAC960_V2_NewLogicalDeviceInfo(c, ldev_num, ldev_info);
	if (status != DAC960_V2_NormalCompletion) {
		sdev_printk(KERN_INFO, sdev,
			    "Failed to get device information, status 0x%02x\n",
			    status);
		return -EIO;
	}
	if (check && ldev_info->ConsistencyCheckInProgress) {
		sdev_printk(KERN_INFO, sdev,
			    "Consistency Check Not Initiated; "
			    "already in progress\n");
		return -EALREADY;
	}
	if (!check && !ldev_info->ConsistencyCheckInProgress) {
		sdev_printk(KERN_INFO, sdev,
			    "Consistency Check Not Cancelled; "
			    "check not in progress\n");
		return ret;
	}

	mutex_lock(&c->V2.dcmd_mutex);
	cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_ClearCommand(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	if (check) {
		mbox->LogicalDeviceInfo.LogicalDevice.LogicalDeviceNumber =
			ldev_num;
		mbox->ConsistencyCheck.IOCTL_Opcode =
			DAC960_V2_ConsistencyCheckStart;
		mbox->ConsistencyCheck.RestoreConsistency = true;
		mbox->ConsistencyCheck.InitializedAreaOnly = false;
	} else {
		mbox->LogicalDeviceInfo.LogicalDevice.LogicalDeviceNumber =
			ldev_num;
		mbox->ConsistencyCheck.IOCTL_Opcode =
			DAC960_V2_ConsistencyCheckStop;
	}
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	if (status != DAC960_V2_NormalCompletion) {
		sdev_printk(KERN_INFO, sdev,
			    "Consistency Check Not %s, status 0x%02x\n",
			    check ? "Initiated" : "Cancelled", status);
		ret = -EIO;
	} else
		sdev_printk(KERN_INFO, sdev, "Consistency Check %s\n",
			    check ? "Initiated" : "Cancelled");

	return ret;
}

static ssize_t mylex_show_dev_consistency_check(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_show_dev_rebuild(dev, attr, buf);
	else
		return mylex_v2_show_consistency_check(dev, attr, buf);
}

static ssize_t mylex_store_dev_consistency_check(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_store_dev_rebuild(dev, attr, buf, count);
	else
		return mylex_v2_store_consistency_check(dev, attr, buf, count);
}
static DEVICE_ATTR(consistency_check, S_IRUGO | S_IWUSR,
		   mylex_show_dev_consistency_check,
		   mylex_store_dev_consistency_check);

static ssize_t mylex_show_ctlr_num(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;

	return snprintf(buf, 20, "%d\n", c->ControllerNumber);
}
static DEVICE_ATTR(mylex_num, S_IRUGO, mylex_show_ctlr_num, NULL);

static ssize_t mylex_show_firmware_version(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;

	return snprintf(buf, 16, "%s\n", c->FirmwareVersion);
}
static DEVICE_ATTR(firmware, S_IRUGO, mylex_show_firmware_version, NULL);

static ssize_t mylex_v1_store_flush_cache(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;
	unsigned short status;

	status = DAC960_V1_ExecuteType3(c, DAC960_V1_Flush, 0);
	if (status == DAC960_V1_NormalCompletion) {
		shost_printk(KERN_INFO, c->host,
			     "Cache Flush Completed\n");
		return count;
	}
	shost_printk(KERN_INFO, c->host,
		     "Cache Flush Failed, status %x\n", status);
	return -EIO;
}

static ssize_t mylex_v2_store_flush_cache(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;
	unsigned char status;

	status = DAC960_V2_DeviceOperation(c, DAC960_V2_PauseDevice,
					   DAC960_V2_RAID_Controller);
	if (status == DAC960_V2_NormalCompletion) {
		shost_printk(KERN_INFO, c->host,
			     "Cache Flush Completed\n");
		return count;
	}
	shost_printk(KERN_INFO, c->host,
		     "Cashe Flush failed, status 0x%02x\n",
		     status);
	return -EIO;
}

static ssize_t mylex_store_flush_cache(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;

	if (c->FirmwareType == DAC960_V1_Controller)
		return mylex_v1_store_flush_cache(dev, attr, buf, count);
	else
		return mylex_v2_store_flush_cache(dev, attr, buf, count);
}
static DEVICE_ATTR(flush_cache, S_IWUSR, NULL, mylex_store_flush_cache);

static struct device_attribute *mylex_v1_sdev_attrs[] = {
	&dev_attr_rebuild,
	&dev_attr_consistency_check,
	&dev_attr_raid_state,
	&dev_attr_raid_level,
	NULL,
};

static struct device_attribute *mylex_v1_shost_attrs[] = {
	&dev_attr_mylex_num,
	&dev_attr_firmware,
	&dev_attr_flush_cache,
	NULL,
};

struct scsi_host_template mylex_v1_template = {
	.module = THIS_MODULE,
	.name = DAC960_DriverName,
	.proc_name = "mylex",
	.queuecommand = mylex_v1_queuecommand,
	.eh_host_reset_handler = DAC960_host_reset,
	.slave_alloc = mylex_v1_slave_alloc,
	.slave_configure = mylex_v1_slave_configure,
	.slave_destroy = mylex_v1_slave_destroy,
	.cmd_size = sizeof(myr_v1_cmdblk),
	.shost_attrs = mylex_v1_shost_attrs,
	.sdev_attrs = mylex_v1_sdev_attrs,
	.this_id = -1,
};

static int mylex_v2_queuecommand(struct Scsi_Host *shost,
				  struct scsi_cmnd *scmd)
{
	myr_hba *c = (myr_hba *)shost->hostdata;
	myr_v2_cmdblk *cmd_blk = scsi_cmd_priv(scmd);
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	struct scsi_device *sdev = scmd->device;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	dma_addr_t sense_addr;
	struct scatterlist *sgl;
	unsigned long flags, timeout;
	int nsge;

	if (!scmd->device->hostdata) {
		scmd->result = (DID_NO_CONNECT << 16);
		scmd->scsi_done(scmd);
		return 0;
	}

	if (scmd->cmnd[0] == REPORT_LUNS) {
		scsi_build_sense_buffer(0, scmd->sense_buffer, ILLEGAL_REQUEST,
					0x20, 0x0);
		scmd->result = (DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;
		scmd->scsi_done(scmd);
		return 0;
	}

	DAC960_V2_ClearCommand(cmd_blk);
	cmd_blk->sense = pci_pool_alloc(c->V2.RequestSensePool, GFP_ATOMIC,
					&sense_addr);
	if (!cmd_blk->sense)
		return SCSI_MLQUEUE_HOST_BUSY;
	cmd_blk->sense_addr = sense_addr;

	timeout = scmd->request->timeout;
	if (scmd->cmd_len <= 10) {
		if (scmd->device->channel >= c->PhysicalChannelCount) {
			DAC960_V2_LogicalDeviceInfo_T *ldev_info =
				sdev->hostdata;

			mbox->SCSI_10.opcode = DAC960_V2_SCSI_10;
			mbox->SCSI_10.PhysicalDevice.LogicalUnit =
				ldev_info->LogicalUnit;
			mbox->SCSI_10.PhysicalDevice.TargetID =
				ldev_info->TargetID;
			mbox->SCSI_10.PhysicalDevice.Channel =
				ldev_info->Channel;
			mbox->SCSI_10.PhysicalDevice.Controller = 0;
		} else {
			mbox->SCSI_10.opcode =
				DAC960_V2_SCSI_10_Passthru;
			mbox->SCSI_10.PhysicalDevice.LogicalUnit = sdev->lun;
			mbox->SCSI_10.PhysicalDevice.TargetID = sdev->id;
			mbox->SCSI_10.PhysicalDevice.Channel = sdev->channel;
		}
		mbox->SCSI_10.id = scmd->request->tag + 3;
		mbox->SCSI_10.control.DataTransferControllerToHost =
			(scmd->sc_data_direction == DMA_FROM_DEVICE);
		mbox->SCSI_10.dma_size = scsi_bufflen(scmd);
		mbox->SCSI_10.sense_addr = cmd_blk->sense_addr;
		mbox->SCSI_10.sense_len = DAC960_V2_SENSE_BUFFERSIZE;
		mbox->SCSI_10.CDBLength = scmd->cmd_len;
		if (timeout > 60) {
			mbox->SCSI_10.tmo.TimeoutScale =
				DAC960_V2_TimeoutScale_Minutes;
			mbox->SCSI_10.tmo.TimeoutValue = timeout / 60;
		} else {
			mbox->SCSI_10.tmo.TimeoutScale =
				DAC960_V2_TimeoutScale_Seconds;
			mbox->SCSI_10.tmo.TimeoutValue = timeout;
		}
		memcpy(&mbox->SCSI_10.SCSI_CDB, scmd->cmnd, scmd->cmd_len);
		dma_addr = &mbox->SCSI_10.dma_addr;
		cmd_blk->DCDB = NULL;
	} else {
		dma_addr_t DCDB_dma;

		cmd_blk->DCDB = pci_pool_alloc(c->V2.DCDBPool, GFP_ATOMIC,
					       &DCDB_dma);
		if (!cmd_blk->DCDB) {
			pci_pool_free(c->V2.RequestSensePool, cmd_blk->sense,
				      cmd_blk->sense_addr);
			cmd_blk->sense = NULL;
			cmd_blk->sense_addr = 0;
			return SCSI_MLQUEUE_HOST_BUSY;
		}
		cmd_blk->DCDB_dma = DCDB_dma;
		if (scmd->device->channel >= c->PhysicalChannelCount) {
			DAC960_V2_LogicalDeviceInfo_T *ldev_info =
				sdev->hostdata;

			mbox->SCSI_255.opcode = DAC960_V2_SCSI_256;
			mbox->SCSI_255.PhysicalDevice.LogicalUnit =
				ldev_info->LogicalUnit;
			mbox->SCSI_255.PhysicalDevice.TargetID =
				ldev_info->TargetID;
			mbox->SCSI_255.PhysicalDevice.Channel =
				ldev_info->Channel;
			mbox->SCSI_255.PhysicalDevice.Controller = 0;
		} else {
			mbox->SCSI_255.opcode =
				DAC960_V2_SCSI_255_Passthru;
			mbox->SCSI_255.PhysicalDevice.LogicalUnit = sdev->lun;
			mbox->SCSI_255.PhysicalDevice.TargetID = sdev->id;
			mbox->SCSI_255.PhysicalDevice.Channel = sdev->channel;
		}
		mbox->SCSI_255.id = scmd->request->tag + 3;
		mbox->SCSI_255.control.DataTransferControllerToHost =
			(scmd->sc_data_direction == DMA_FROM_DEVICE);
		mbox->SCSI_255.dma_size = scsi_bufflen(scmd);
		mbox->SCSI_255.sense_addr = cmd_blk->sense_addr;
		mbox->SCSI_255.sense_len = DAC960_V2_SENSE_BUFFERSIZE;
		mbox->SCSI_255.CDBLength = scmd->cmd_len;
		mbox->SCSI_255.SCSI_CDB_BusAddress = cmd_blk->DCDB_dma;
		if (timeout > 60) {
			mbox->SCSI_255.tmo.TimeoutScale =
				DAC960_V2_TimeoutScale_Minutes;
			mbox->SCSI_255.tmo.TimeoutValue = timeout / 60;
		} else {
			mbox->SCSI_255.tmo.TimeoutScale =
				DAC960_V2_TimeoutScale_Seconds;
			mbox->SCSI_255.tmo.TimeoutValue = timeout;
		}
		memcpy(cmd_blk->DCDB, scmd->cmnd, scmd->cmd_len);
		dma_addr = &mbox->SCSI_255.dma_addr;
	}
	if (scmd->sc_data_direction == DMA_NONE)
		goto submit;
	nsge = scsi_dma_map(scmd);
	if (nsge == 1) {
		sgl = scsi_sglist(scmd);
		dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
			(u64)sg_dma_address(sgl);
		dma_addr->ScatterGatherSegments[0].SegmentByteCount =
			(u64)sg_dma_len(sgl);
	} else {
		DAC960_V2_ScatterGatherSegment_T *hw_sgl;
		dma_addr_t hw_sgl_addr;
		int i;

		if (nsge > 2) {
			hw_sgl = pci_pool_alloc(c->ScatterGatherPool,
						GFP_ATOMIC, &hw_sgl_addr);
			if (WARN_ON(!hw_sgl)) {
				if (cmd_blk->DCDB) {
					pci_pool_free(c->V2.DCDBPool,
						      cmd_blk->DCDB,
						      cmd_blk->DCDB_dma);
					cmd_blk->DCDB = NULL;
					cmd_blk->DCDB_dma = 0;
				}
				pci_pool_free(c->V2.RequestSensePool,
					      cmd_blk->sense,
					      cmd_blk->sense_addr);
				cmd_blk->sense = NULL;
				cmd_blk->sense_addr = 0;
				return SCSI_MLQUEUE_HOST_BUSY;
			}
			cmd_blk->sgl = hw_sgl;
			cmd_blk->sgl_addr = hw_sgl_addr;
			if (scmd->cmd_len <= 10)
				mbox->SCSI_10.control
					.AdditionalScatterGatherListMemory = true;
			else
				mbox->SCSI_255.control
					.AdditionalScatterGatherListMemory = true;
			dma_addr->ExtendedScatterGather.ScatterGatherList0Length = nsge;
			dma_addr->ExtendedScatterGather.ScatterGatherList0Address =
				cmd_blk->sgl_addr;
		} else
			hw_sgl = dma_addr->ScatterGatherSegments;

		scsi_for_each_sg(scmd, sgl, nsge, i) {
			if (WARN_ON(!hw_sgl)) {
				scsi_dma_unmap(scmd);
				scmd->result = (DID_ERROR << 16);
				scmd->scsi_done(scmd);
				return 0;
			}
			hw_sgl->SegmentDataPointer = (u64)sg_dma_address(sgl);
			hw_sgl->SegmentByteCount = (u64)sg_dma_len(sgl);
			hw_sgl++;
		}
	}
submit:
	spin_lock_irqsave(&c->queue_lock, flags);
	c->V2.QueueCommand(c, cmd_blk);
	spin_unlock_irqrestore(&c->queue_lock, flags);

	return 0;
}

static int mylex_v2_slave_alloc(struct scsi_device *sdev)
{
	myr_hba *c =
		(myr_hba *)sdev->host->hostdata;
	unsigned char status;

	if (sdev->channel > c->host->max_channel)
		return 0;

	if (sdev->channel >= c->PhysicalChannelCount) {
		DAC960_V2_LogicalDeviceInfo_T *ldev_info;
		unsigned short ldev_num;

		if (sdev->lun > 0)
			return -ENXIO;

		ldev_num = mylex_translate_ldev(c, sdev);
		if (ldev_num >= c->LogicalDriveCount)
			return -ENXIO;

		ldev_info = kzalloc(sizeof(*ldev_info), GFP_KERNEL);
		if (!ldev_info)
			return -ENOMEM;

		status = DAC960_V2_NewLogicalDeviceInfo(c, ldev_num,
							ldev_info);
		if (status != DAC960_V2_NormalCompletion) {
			sdev->hostdata = NULL;
			kfree(ldev_info);
		} else {
			enum raid_level level;

			dev_dbg(&sdev->sdev_gendev,
				"Logical device mapping %d:%d:%d -> %d\n",
				ldev_info->Channel, ldev_info->TargetID,
				ldev_info->LogicalUnit,
				ldev_info->LogicalDeviceNumber);

			sdev->hostdata = ldev_info;
			switch (ldev_info->RAIDLevel) {
			case DAC960_V2_RAID_Level0:
				level = RAID_LEVEL_LINEAR;
				break;
			case DAC960_V2_RAID_Level1:
				level = RAID_LEVEL_1;
				break;
			case DAC960_V2_RAID_Level3:
			case DAC960_V2_RAID_Level3F:
			case DAC960_V2_RAID_Level3L:
				level = RAID_LEVEL_3;
				break;
			case DAC960_V2_RAID_Level5:
			case DAC960_V2_RAID_Level5L:
				level = RAID_LEVEL_5;
				break;
			case DAC960_V2_RAID_Level6:
				level = RAID_LEVEL_6;
				break;
			case DAC960_V2_RAID_LevelE:
			case DAC960_V2_RAID_NewSpan:
			case DAC960_V2_RAID_Span:
				level = RAID_LEVEL_LINEAR;
				break;
			case DAC960_V2_RAID_JBOD:
				level = RAID_LEVEL_JBOD;
				break;
			default:
				level = RAID_LEVEL_UNKNOWN;
				break;
			}
			raid_set_level(mylex_v2_raid_template,
				       &sdev->sdev_gendev, level);
			if (ldev_info->State != DAC960_V2_Device_Online) {
				const char *name;

				name = DAC960_V2_DriveStateName(ldev_info->State);
				sdev_printk(KERN_DEBUG, sdev,
					    "logical device in state %s\n",
					    name ? name : "Invalid");
			}
		}
	} else {
		DAC960_V2_PhysicalDeviceInfo_T *pdev_info;

		pdev_info = kzalloc(sizeof(*pdev_info), GFP_KERNEL);
		if (!pdev_info)
			return -ENOMEM;

		status = DAC960_V2_NewPhysicalDeviceInfo(c, sdev->channel,
							 sdev->id, sdev->lun,
							 pdev_info);
		if (status != DAC960_V2_NormalCompletion) {
			sdev->hostdata = NULL;
			kfree(pdev_info);
			return -ENXIO;
		}
		sdev->hostdata = pdev_info;
	}
	return 0;
}

static int mylex_v2_slave_configure(struct scsi_device *sdev)
{
	myr_hba *c =
		(myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info;

	if (sdev->channel > c->host->max_channel)
		return -ENXIO;

	if (sdev->channel < c->PhysicalChannelCount) {
		/* Skip HBA device */
		if (sdev->type == TYPE_RAID)
			return -ENXIO;
		sdev->no_uld_attach = 1;
		return 0;
	}
	if (sdev->lun != 0)
		return -ENXIO;

	ldev_info = sdev->hostdata;
	if (!ldev_info)
		return -ENXIO;
	if (ldev_info->LogicalDeviceControl.WriteCache ==
	    DAC960_V2_WriteCacheEnabled ||
	    ldev_info->LogicalDeviceControl.WriteCache ==
	    DAC960_V2_IntelligentWriteCacheEnabled)
		sdev->wce_default_on = 1;
	sdev->tagged_supported = 1;
	return 0;
}

static void mylex_v2_slave_destroy(struct scsi_device *sdev)
{
	void *hostdata = sdev->hostdata;

	if (hostdata) {
		kfree(hostdata);
		sdev->hostdata = NULL;
	}
}

static struct device_attribute *mylex_sdev_attrs[] = {
	&dev_attr_consistency_check,
	&dev_attr_rebuild,
	&dev_attr_raid_state,
	&dev_attr_raid_level,
	NULL,
};

static ssize_t mylex_v2_show_ctlr_serial(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;
	char serial[17];

	memcpy(serial, c->V2.ControllerInformation.ControllerSerialNumber, 16);
	serial[16] = '\0';
	return snprintf(buf, 16, "%s\n", serial);
}
static DEVICE_ATTR(serial, S_IRUGO, mylex_v2_show_ctlr_serial, NULL);

static struct DAC960_V2_ProcessorTypeTbl {
	DAC960_V2_ProcessorType_T type;
	char *name;
} DAC960_V2_ProcessorTypeNames[] = {
	{ DAC960_V2_ProcessorType_i960CA, "i960CA" },
	{ DAC960_V2_ProcessorType_i960RD, "i960RD" },
	{ DAC960_V2_ProcessorType_i960RN, "i960RN" },
	{ DAC960_V2_ProcessorType_i960RP, "i960RP" },
	{ DAC960_V2_ProcessorType_NorthBay, "NorthBay" },
	{ DAC960_V2_ProcessorType_StrongArm, "StrongARM" },
	{ DAC960_V2_ProcessorType_i960RM, "i960RM" },
	{ 0xff, NULL },
};

static ssize_t mylex_v2_show_processor(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;
	struct DAC960_V2_ProcessorTypeTbl *tbl = DAC960_V2_ProcessorTypeNames;
	const char *first_processor = NULL;
	const char *second_processor = NULL;
	DAC960_V2_ControllerInfo_T *info = &c->V2.ControllerInformation;
	ssize_t ret;

	if (info->FirstProcessorCount) {
		while (tbl && tbl->name) {
			if (tbl->type == info->FirstProcessorType) {
				first_processor = tbl->name;
				break;
			}
			tbl++;
		}
	}
	if (info->SecondProcessorCount) {
		tbl = DAC960_V2_ProcessorTypeNames;
		while (tbl && tbl->name) {
			if (tbl->type == info->SecondProcessorType) {
				second_processor = tbl->name;
				break;
			}
			tbl++;
		}
	}
	if (first_processor && second_processor)
		ret = snprintf(buf, 64, "1: %s (%s, %d cpus)\n"
			       "2: %s (%s, %d cpus)\n",
			       info->FirstProcessorName,
			       first_processor, info->FirstProcessorCount,
			       info->SecondProcessorName,
			       second_processor, info->SecondProcessorCount);
	else if (!second_processor)
		ret = snprintf(buf, 64, "1: %s (%s, %d cpus)\n2: absent\n",
			       info->FirstProcessorName,
			       first_processor, info->FirstProcessorCount );
	else if (!first_processor)
		ret = snprintf(buf, 64, "1: absent\n2: %s (%s, %d cpus)\n",
			       info->SecondProcessorName,
			       second_processor, info->SecondProcessorCount);
	else
		ret = snprintf(buf, 64, "1: absent\n2: absent\n");

	return ret;
}
static DEVICE_ATTR(processor, S_IRUGO, mylex_v2_show_processor, NULL);

static ssize_t mylex_v2_store_discovery_command(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;
	myr_v2_cmdblk *cmd_blk;
	DAC960_V2_CommandMailbox_T *mbox;
	unsigned char status;

	mutex_lock(&c->V2.dcmd_mutex);
	cmd_blk = &c->V2.DirectCommandBlock;
	DAC960_V2_ClearCommand(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	mbox->Common.IOCTL_Opcode = DAC960_V2_StartDiscovery;
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&c->V2.dcmd_mutex);
	if (status != DAC960_V2_NormalCompletion) {
		shost_printk(KERN_INFO, c->host,
			     "Discovery Not Initiated, status %02X\n",
			     status);
		return -EINVAL;
	}
	shost_printk(KERN_INFO, c->host, "Discovery Initiated\n");
	c->V2.NextEventSequenceNumber = 0;
	c->V2.NeedControllerInformation = true;
	queue_delayed_work(c->work_q, &c->monitor_work, 1);
	flush_delayed_work(&c->monitor_work);
	shost_printk(KERN_INFO, c->host, "Discovery Completed\n");

	return count;
}
static DEVICE_ATTR(discovery, S_IWUSR, NULL, mylex_v2_store_discovery_command);

static ssize_t mylex_v2_show_suppress_enclosure_messages(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myr_hba *c = (myr_hba *)shost->hostdata;

	return snprintf(buf, 3, "%d\n", c->SuppressEnclosureMessages);
}

static ssize_t mylex_v2_store_suppress_enclosure_messages(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	char tmpbuf[8];
	ssize_t len;
	int value;

	len = count > sizeof(tmpbuf) - 1 ? sizeof(tmpbuf) - 1 : count;
	strncpy(tmpbuf, buf, len);
	tmpbuf[len] = '\0';
	if (sscanf(tmpbuf, "%d", &value) != 1 || value > 2)
		return -EINVAL;

	c->SuppressEnclosureMessages = value;
	return count;
}
static DEVICE_ATTR(disable_enclosure_messages, S_IRUGO | S_IWUSR,
		   mylex_v2_show_suppress_enclosure_messages,
		   mylex_v2_store_suppress_enclosure_messages);

static struct device_attribute *mylex_v2_shost_attrs[] = {
	&dev_attr_serial,
	&dev_attr_mylex_num,
	&dev_attr_processor,
	&dev_attr_firmware,
	&dev_attr_discovery,
	&dev_attr_flush_cache,
	&dev_attr_disable_enclosure_messages,
	NULL,
};

struct scsi_host_template mylex_v2_template = {
	.module = THIS_MODULE,
	.name = DAC960_DriverName,
	.proc_name = "mylex",
	.queuecommand = mylex_v2_queuecommand,
	.eh_host_reset_handler = DAC960_host_reset,
	.slave_alloc = mylex_v2_slave_alloc,
	.slave_configure = mylex_v2_slave_configure,
	.slave_destroy = mylex_v2_slave_destroy,
	.cmd_size = sizeof(myr_v2_cmdblk),
	.shost_attrs = mylex_v2_shost_attrs,
	.sdev_attrs = mylex_sdev_attrs,
	.this_id = -1,
};

/**
 * mylex_is_raid - return boolean indicating device is raid volume
 * @dev the device struct object
 */
static int
mylex_is_raid(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;

	return (sdev->channel >= c->PhysicalChannelCount) ? 1 : 0;
}

/**
 * mylex_v1_get_resync - get raid volume resync percent complete
 * @dev the device struct object
 */
static void
mylex_v1_get_resync(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	unsigned int percent_complete = 0;
	unsigned short ldev_num;
	unsigned int ldev_size = 0, remaining = 0;

	if (sdev->channel < c->PhysicalChannelCount)
		return;
	if (DAC960_V1_ControllerIsRebuilding(c)) {
		ldev_num = c->V1.RebuildProgress->LogicalDriveNumber;
		if (ldev_num == mylex_translate_ldev(c, sdev)) {
			ldev_size =
				c->V1.RebuildProgress->LogicalDriveSize;
			remaining =
				c->V1.RebuildProgress->RemainingBlocks;
		}
	}
	if (remaining && ldev_size)
		percent_complete = (ldev_size - remaining) * 100 / ldev_size;
	raid_set_resync(mylex_v1_raid_template, dev, percent_complete);
}

/**
 * mylex_v1_get_state - get raid volume status
 * @dev the device struct object
 */
static void
mylex_v1_get_state(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V1_LogicalDeviceInfo_T *ldev_info = sdev->hostdata;
	enum raid_state state = RAID_STATE_UNKNOWN;

	if (sdev->channel < c->PhysicalChannelCount || !ldev_info)
		state = RAID_STATE_UNKNOWN;
	else if (DAC960_V1_ControllerIsRebuilding(c))
		 state = RAID_STATE_RESYNCING;
	else {
		switch (ldev_info->State) {
		case DAC960_V1_Device_Online:
			state = RAID_STATE_ACTIVE;
			break;
		case DAC960_V1_Device_WriteOnly:
		case DAC960_V1_Device_Critical:
			state = RAID_STATE_DEGRADED;
			break;
		default:
			state = RAID_STATE_OFFLINE;
		}
	}
	raid_set_state(mylex_v1_raid_template, dev, state);
}

static struct raid_function_template mylex_v1_raid_functions = {
	.cookie		= &mylex_v1_template,
	.is_raid	= mylex_is_raid,
	.get_resync	= mylex_v1_get_resync,
	.get_state	= mylex_v1_get_state,
};

/**
 * mylex_v2_get_resync - get raid volume resync percent complete
 * @dev the device struct object
 */
static void
mylex_v2_get_resync(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info = sdev->hostdata;
	u8 percent_complete = 0, status;

	if (sdev->channel < c->PhysicalChannelCount || !ldev_info)
		return;
	if (ldev_info->RebuildInProgress) {
		unsigned short ldev_num = ldev_info->LogicalDeviceNumber;

		status = DAC960_V2_NewLogicalDeviceInfo(c, ldev_num,
							ldev_info);
		percent_complete = ldev_info->RebuildBlockNumber * 100 /
			ldev_info->ConfigurableDeviceSize;
	}
	raid_set_resync(mylex_v2_raid_template, dev, percent_complete);
}

/**
 * mylex_v2_get_state - get raid volume status
 * @dev the device struct object
 */
static void
mylex_v2_get_state(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myr_hba *c = (myr_hba *)sdev->host->hostdata;
	DAC960_V2_LogicalDeviceInfo_T *ldev_info = sdev->hostdata;
	enum raid_state state = RAID_STATE_UNKNOWN;

	if (sdev->channel < c->PhysicalChannelCount || !ldev_info)
		state = RAID_STATE_UNKNOWN;
	else {
		switch (ldev_info->State) {
		case DAC960_V2_Device_Online:
			state = RAID_STATE_ACTIVE;
			break;
		case DAC960_V2_Device_SuspectedCritical:
		case DAC960_V2_Device_Critical:
			state = RAID_STATE_DEGRADED;
			break;
		case DAC960_V2_Device_Rebuild:
			state = RAID_STATE_RESYNCING;
			break;
		case DAC960_V2_Device_Unconfigured:
		case DAC960_V2_Device_InvalidState:
			state = RAID_STATE_UNKNOWN;
			break;
		default:
			state = RAID_STATE_OFFLINE;
		}
	}
	raid_set_state(mylex_v2_raid_template, dev, state);
}

static struct raid_function_template mylex_v2_raid_functions = {
	.cookie		= &mylex_v2_template,
	.is_raid	= mylex_is_raid,
	.get_resync	= mylex_v2_get_resync,
	.get_state	= mylex_v2_get_state,
};

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
	struct Scsi_Host *shost;
	myr_hba *c = NULL;
	unsigned char DeviceFunction = pdev->devfn;
	void __iomem *base;

	if (privdata->FirmwareType == DAC960_V1_Controller)
		shost = scsi_host_alloc(&mylex_v1_template,
					sizeof(myr_hba));
	else
		shost = scsi_host_alloc(&mylex_v2_template,
					sizeof(myr_hba));
	if (!shost) {
		dev_err(&pdev->dev, "Unable to allocate Controller\n");
		return NULL;
	}
	c = (myr_hba *)shost->hostdata;
	c->host = shost;
	c->ControllerNumber = DAC960_ControllerCount++;
	c->Bus = pdev->bus->number;
	c->FirmwareType = privdata->FirmwareType;
	c->HardwareType = privdata->HardwareType;
	c->Device = DeviceFunction >> 3;
	c->Function = DeviceFunction & 0x7;
	c->PCIDevice = pdev;
	strcpy(c->FullModelName, "DAC960");
	shost->max_lun = 256;
	if (c->FirmwareType == DAC960_V1_Controller) {
		shost->max_cmd_len = 12;
		mutex_init(&c->V1.dcmd_mutex);
		mutex_init(&c->V1.dma_mutex);
	} else {
		shost->max_cmd_len = 16;
		mutex_init(&c->V2.dcmd_mutex);
		mutex_init(&c->V2.cinfo_mutex);
	}

	snprintf(c->work_q_name, sizeof(c->work_q_name),
		 "mylex_wq_%d", shost->host_no);
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
	c->BaseAddress =
		c->MemoryMappedAddress + (c->PCI_Address & ~PAGE_MASK);
	if (c->MemoryMappedAddress == NULL) {
		dev_err(&pdev->dev,
			"Unable to map Controller Register Window\n");
		goto Failure;
	}
	base = c->BaseAddress;

	if (privdata->HardwareInit(pdev, c, base))
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

	ret = DAC960_ReadControllerConfiguration(c);
	if (ret < 0) {
		DAC960_DetectCleanup(c);
		return ret;
	}
	DAC960_ReportControllerConfiguration(c);

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
  DAC960_Finalize finalizes the DAC960 Driver.
*/

static void DAC960_Remove(struct pci_dev *pdev)
{
	myr_hba *c = pci_get_drvdata(pdev);

	if (c == NULL)
		return;

	cancel_delayed_work_sync(&c->monitor_work);
	if (c->FirmwareType == DAC960_V1_Controller) {
		shost_printk(KERN_NOTICE, c->host, "Flushing Cache...");
		DAC960_V1_ExecuteType3(c, DAC960_V1_Flush, 0);
	} else {
		shost_printk(KERN_NOTICE, c->host, "Flushing Cache...");
		DAC960_V2_DeviceOperation(c, DAC960_V2_PauseDevice,
					  DAC960_V2_RAID_Controller);
	}
	DAC960_DestroyAuxiliaryStructures(c);
	DAC960_DetectCleanup(c);
}


/*
  DAC960_V1_HandleSCSI performs completion processing for Command
  for DAC960 V1 Firmware Controllers.
*/

static void DAC960_V1_HandleSCSI(myr_hba *c,
				 myr_v1_cmdblk *cmd_blk,
				 struct scsi_cmnd *scmd)
{
	unsigned short status;

	if (!cmd_blk)
		return;

	BUG_ON(!scmd);
	scsi_dma_unmap(scmd);

	if (cmd_blk->DCDB) {
		memcpy(scmd->sense_buffer, &cmd_blk->DCDB->SenseData, 64);
		pci_pool_free(c->V1.DCDBPool, cmd_blk->DCDB,
			      cmd_blk->DCDB_dma);
		cmd_blk->DCDB = NULL;
	}
	if (cmd_blk->sgl) {
		pci_pool_free(c->ScatterGatherPool, cmd_blk->sgl,
			      cmd_blk->sgl_addr);
		cmd_blk->sgl = NULL;
		cmd_blk->sgl_addr = 0;
	}
	status = cmd_blk->status;
	switch (status) {
	case DAC960_V1_NormalCompletion:
	case DAC960_V1_DeviceBusy:
		scmd->result = (DID_OK << 16) | status;
		break;
	case DAC960_V1_BadDataEncountered:
		dev_dbg(&scmd->device->sdev_gendev,
			"Bad Data Encountered\n");
		if (scmd->sc_data_direction == DMA_FROM_DEVICE)
			/* Unrecovered read error */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						MEDIUM_ERROR, 0x11, 0);
		else
			/* Write error */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						MEDIUM_ERROR, 0x0C, 0);
		scmd->result = (DID_OK << 16) | SAM_STAT_CHECK_CONDITION;
		break;
	case DAC960_V1_IrrecoverableDataError:
		scmd_printk(KERN_ERR, scmd, "Irrecoverable Data Error\n");
		if (scmd->sc_data_direction == DMA_FROM_DEVICE)
			/* Unrecovered read error, auto-reallocation failed */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						MEDIUM_ERROR, 0x11, 0x04);
		else
			/* Write error, auto-reallocation failed */
			scsi_build_sense_buffer(0, scmd->sense_buffer,
						MEDIUM_ERROR, 0x0C, 0x02);
		scmd->result = (DID_OK << 16) | SAM_STAT_CHECK_CONDITION;
		break;
	case DAC960_V1_LogicalDriveNonexistentOrOffline:
		dev_dbg(&scmd->device->sdev_gendev,
			    "Logical Drive Nonexistent or Offline");
		scmd->result = (DID_BAD_TARGET << 16);
		break;
	case DAC960_V1_AccessBeyondEndOfLogicalDrive:
		dev_dbg(&scmd->device->sdev_gendev,
			    "Attempt to Access Beyond End of Logical Drive");
		/* Logical block address out of range */
		scsi_build_sense_buffer(0, scmd->sense_buffer,
					NOT_READY, 0x21, 0);
		break;
	case DAC960_V1_DeviceNonresponsive:
		dev_dbg(&scmd->device->sdev_gendev, "Device nonresponsive\n");
		scmd->result = (DID_BAD_TARGET << 16);
		break;
	default:
		scmd_printk(KERN_ERR, scmd,
			    "Unexpected Error Status %04X", status);
		scmd->result = (DID_ERROR << 16);
		break;
	}
	scmd->scsi_done(scmd);
}

static void DAC960_V1_HandleCommandBlock(myr_hba *c,
					 myr_v1_cmdblk *cmd_blk)
{
	if (!cmd_blk)
		return;

	if (cmd_blk->Completion) {
		complete(cmd_blk->Completion);
		cmd_blk->Completion = NULL;
	}
}


/*
  DAC960_V2_ReportEvent prints an appropriate message when a Controller Event
  occurs.
*/

static struct {
	int EventCode;
	unsigned char *EventMessage;
} EventList[] =
{ /* Physical Device Events (0x0000 - 0x007F) */
	{ 0x0001, "P Online" },
	{ 0x0002, "P Standby" },
	{ 0x0005, "P Automatic Rebuild Started" },
	{ 0x0006, "P Manual Rebuild Started" },
	{ 0x0007, "P Rebuild Completed" },
	{ 0x0008, "P Rebuild Cancelled" },
	{ 0x0009, "P Rebuild Failed for Unknown Reasons" },
	{ 0x000A, "P Rebuild Failed due to New Physical Device" },
	{ 0x000B, "P Rebuild Failed due to Logical Drive Failure" },
	{ 0x000C, "S Offline" },
	{ 0x000D, "P Found" },
	{ 0x000E, "P Removed" },
	{ 0x000F, "P Unconfigured" },
	{ 0x0010, "P Expand Capacity Started" },
	{ 0x0011, "P Expand Capacity Completed" },
	{ 0x0012, "P Expand Capacity Failed" },
	{ 0x0013, "P Command Timed Out" },
	{ 0x0014, "P Command Aborted" },
	{ 0x0015, "P Command Retried" },
	{ 0x0016, "P Parity Error" },
	{ 0x0017, "P Soft Error" },
	{ 0x0018, "P Miscellaneous Error" },
	{ 0x0019, "P Reset" },
	{ 0x001A, "P Active Spare Found" },
	{ 0x001B, "P Warm Spare Found" },
	{ 0x001C, "S Sense Data Received" },
	{ 0x001D, "P Initialization Started" },
	{ 0x001E, "P Initialization Completed" },
	{ 0x001F, "P Initialization Failed" },
	{ 0x0020, "P Initialization Cancelled" },
	{ 0x0021, "P Failed because Write Recovery Failed" },
	{ 0x0022, "P Failed because SCSI Bus Reset Failed" },
	{ 0x0023, "P Failed because of Double Check Condition" },
	{ 0x0024, "P Failed because Device Cannot Be Accessed" },
	{ 0x0025, "P Failed because of Gross Error on SCSI Processor" },
	{ 0x0026, "P Failed because of Bad Tag from Device" },
	{ 0x0027, "P Failed because of Command Timeout" },
	{ 0x0028, "P Failed because of System Reset" },
	{ 0x0029, "P Failed because of Busy Status or Parity Error" },
	{ 0x002A, "P Failed because Host Set Device to Failed State" },
	{ 0x002B, "P Failed because of Selection Timeout" },
	{ 0x002C, "P Failed because of SCSI Bus Phase Error" },
	{ 0x002D, "P Failed because Device Returned Unknown Status" },
	{ 0x002E, "P Failed because Device Not Ready" },
	{ 0x002F, "P Failed because Device Not Found at Startup" },
	{ 0x0030, "P Failed because COD Write Operation Failed" },
	{ 0x0031, "P Failed because BDT Write Operation Failed" },
	{ 0x0039, "P Missing at Startup" },
	{ 0x003A, "P Start Rebuild Failed due to Physical Drive Too Small" },
	{ 0x003C, "P Temporarily Offline Device Automatically Made Online" },
	{ 0x003D, "P Standby Rebuild Started" },
	/* Logical Device Events (0x0080 - 0x00FF) */
	{ 0x0080, "M Consistency Check Started" },
	{ 0x0081, "M Consistency Check Completed" },
	{ 0x0082, "M Consistency Check Cancelled" },
	{ 0x0083, "M Consistency Check Completed With Errors" },
	{ 0x0084, "M Consistency Check Failed due to Logical Drive Failure" },
	{ 0x0085, "M Consistency Check Failed due to Physical Device Failure" },
	{ 0x0086, "L Offline" },
	{ 0x0087, "L Critical" },
	{ 0x0088, "L Online" },
	{ 0x0089, "M Automatic Rebuild Started" },
	{ 0x008A, "M Manual Rebuild Started" },
	{ 0x008B, "M Rebuild Completed" },
	{ 0x008C, "M Rebuild Cancelled" },
	{ 0x008D, "M Rebuild Failed for Unknown Reasons" },
	{ 0x008E, "M Rebuild Failed due to New Physical Device" },
	{ 0x008F, "M Rebuild Failed due to Logical Drive Failure" },
	{ 0x0090, "M Initialization Started" },
	{ 0x0091, "M Initialization Completed" },
	{ 0x0092, "M Initialization Cancelled" },
	{ 0x0093, "M Initialization Failed" },
	{ 0x0094, "L Found" },
	{ 0x0095, "L Deleted" },
	{ 0x0096, "M Expand Capacity Started" },
	{ 0x0097, "M Expand Capacity Completed" },
	{ 0x0098, "M Expand Capacity Failed" },
	{ 0x0099, "L Bad Block Found" },
	{ 0x009A, "L Size Changed" },
	{ 0x009B, "L Type Changed" },
	{ 0x009C, "L Bad Data Block Found" },
	{ 0x009E, "L Read of Data Block in BDT" },
	{ 0x009F, "L Write Back Data for Disk Block Lost" },
	{ 0x00A0, "L Temporarily Offline RAID-5/3 Drive Made Online" },
	{ 0x00A1, "L Temporarily Offline RAID-6/1/0/7 Drive Made Online" },
	{ 0x00A2, "L Standby Rebuild Started" },
	/* Fault Management Events (0x0100 - 0x017F) */
	{ 0x0140, "E Fan %d Failed" },
	{ 0x0141, "E Fan %d OK" },
	{ 0x0142, "E Fan %d Not Present" },
	{ 0x0143, "E Power Supply %d Failed" },
	{ 0x0144, "E Power Supply %d OK" },
	{ 0x0145, "E Power Supply %d Not Present" },
	{ 0x0146, "E Temperature Sensor %d Temperature Exceeds Safe Limit" },
	{ 0x0147, "E Temperature Sensor %d Temperature Exceeds Working Limit" },
	{ 0x0148, "E Temperature Sensor %d Temperature Normal" },
	{ 0x0149, "E Temperature Sensor %d Not Present" },
	{ 0x014A, "E Enclosure Management Unit %d Access Critical" },
	{ 0x014B, "E Enclosure Management Unit %d Access OK" },
	{ 0x014C, "E Enclosure Management Unit %d Access Offline" },
	/* Controller Events (0x0180 - 0x01FF) */
	{ 0x0181, "C Cache Write Back Error" },
	{ 0x0188, "C Battery Backup Unit Found" },
	{ 0x0189, "C Battery Backup Unit Charge Level Low" },
	{ 0x018A, "C Battery Backup Unit Charge Level OK" },
	{ 0x0193, "C Installation Aborted" },
	{ 0x0195, "C Battery Backup Unit Physically Removed" },
	{ 0x0196, "C Memory Error During Warm Boot" },
	{ 0x019E, "C Memory Soft ECC Error Corrected" },
	{ 0x019F, "C Memory Hard ECC Error Corrected" },
	{ 0x01A2, "C Battery Backup Unit Failed" },
	{ 0x01AB, "C Mirror Race Recovery Failed" },
	{ 0x01AC, "C Mirror Race on Critical Drive" },
	/* Controller Internal Processor Events */
	{ 0x0380, "C Internal Controller Hung" },
	{ 0x0381, "C Internal Controller Firmware Breakpoint" },
	{ 0x0390, "C Internal Controller i960 Processor Specific Error" },
	{ 0x03A0, "C Internal Controller StrongARM Processor Specific Error" },
	{ 0, "" }
};

static void DAC960_V2_ReportEvent(myr_hba *c,
				  DAC960_V2_Event_T *Event)
{
	unsigned char MessageBuffer[DAC960_LineBufferSize];
	int EventListIndex = 0, EventCode;
	unsigned char EventType, *EventMessage;
	struct scsi_device *sdev;
	struct scsi_sense_hdr sshdr;
	unsigned char *sense_info;
	unsigned char *cmd_specific;

	if (Event->EventCode == 0x1C) {
		if (!scsi_normalize_sense(Event->RequestSenseData,
					  40, &sshdr))
			memset(&sshdr, 0x0, sizeof(sshdr));
		else {
			sense_info = &Event->RequestSenseData[3];
			cmd_specific = &Event->RequestSenseData[7];
		}
	}
	if (sshdr.sense_key == VENDOR_SPECIFIC &&
	    (sshdr.asc == 0x80 || sshdr.asc == 0x81))
		Event->EventCode = ((sshdr.asc - 0x80) << 8 || sshdr.ascq);
	while (true) {
		EventCode = EventList[EventListIndex].EventCode;
		if (EventCode == Event->EventCode || EventCode == 0)
			break;
		EventListIndex++;
	}
	EventType = EventList[EventListIndex].EventMessage[0];
	EventMessage = &EventList[EventListIndex].EventMessage[2];
	if (EventCode == 0) {
		shost_printk(KERN_WARNING, c->host,
			     "Unknown Controller Event Code %04X\n",
			     Event->EventCode);
		return;
	}
	switch (EventType) {
	case 'P':
		sdev = scsi_device_lookup(c->host, Event->Channel,
					  Event->TargetID, 0);
		sdev_printk(KERN_INFO, sdev, "%s\n", EventMessage);
		if (sdev && sdev->hostdata &&
		    sdev->channel < c->PhysicalChannelCount) {
			if (c->FirmwareType == DAC960_V2_Controller) {
				DAC960_V2_PhysicalDeviceInfo_T *pdev_info =
					sdev->hostdata;
				switch (Event->EventCode) {
				case 0x0001:
				case 0x0007:
					pdev_info->State =
						DAC960_V2_Device_Online;
					break;
				case 0x0002:
					pdev_info->State =
						DAC960_V2_Device_Standby;
					break;
				case 0x000C:
					pdev_info->State =
						DAC960_V2_Device_Offline;
					break;
				case 0x000E:
					pdev_info->State =
						DAC960_V2_Device_Missing;
					break;
				case 0x000F:
					pdev_info->State =
						DAC960_V2_Device_Unconfigured;
					break;
				}
			}
		}
		break;
	case 'L':
		shost_printk(KERN_INFO, c->host, "Logical Drive %d %s\n",
			 Event->LogicalUnit, EventMessage);
		c->V2.NeedControllerInformation = true;
		break;
	case 'M':
		shost_printk(KERN_INFO, c->host, "Logical Drive %d %s\n",
			 Event->LogicalUnit, EventMessage);
		c->V2.NeedControllerInformation = true;
		break;
	case 'S':
		if (sshdr.sense_key == NO_SENSE ||
		    (sshdr.sense_key == NOT_READY &&
		     sshdr.asc == 0x04 && (sshdr.ascq == 0x01 ||
					    sshdr.ascq == 0x02)))
			break;
		shost_printk(KERN_INFO, c->host, "Physical Device %d:%d %s\n",
			 Event->Channel, Event->TargetID, EventMessage);
		shost_printk(KERN_INFO, c->host,
			 "Physical Device %d:%d Request Sense: "
			 "Sense Key = %X, ASC = %02X, ASCQ = %02X\n",
			 Event->Channel, Event->TargetID,
			 sshdr.sense_key, sshdr.asc, sshdr.ascq);
		shost_printk(KERN_INFO, c->host,
			 "Physical Device %d:%d Request Sense: "
			 "Information = %02X%02X%02X%02X "
			 "%02X%02X%02X%02X\n",
			 Event->Channel, Event->TargetID,
			 sense_info[0], sense_info[1],
			 sense_info[2], sense_info[3],
			 cmd_specific[0], cmd_specific[1],
			 cmd_specific[2], cmd_specific[3]);
		break;
	case 'E':
		if (c->SuppressEnclosureMessages)
			break;
		sprintf(MessageBuffer, EventMessage, Event->LogicalUnit);
		shost_printk(KERN_INFO, c->host, "Enclosure %d %s\n",
			 Event->TargetID, MessageBuffer);
		break;
	case 'C':
		shost_printk(KERN_INFO, c->host, "Controller %s\n", EventMessage);
		break;
	default:
		shost_printk(KERN_INFO, c->host, "Unknown Controller Event Code %04X\n",
			 Event->EventCode);
		break;
	}
}


/*
  DAC960_V2_ProcessCompletedCommand performs completion processing for Command
  for DAC960 V2 Firmware Controllers.
*/

static void DAC960_V2_HandleSCSI(myr_hba *c,
				 myr_v2_cmdblk *cmd_blk,
				 struct scsi_cmnd *scmd)
{
	unsigned char status;

	if (!cmd_blk)
		return;

	BUG_ON(!scmd);
	scsi_dma_unmap(scmd);

	if (cmd_blk->sense) {
		if (status == DAC960_V2_AbnormalCompletion &&
		    cmd_blk->sense_len) {
			unsigned int sense_len = SCSI_SENSE_BUFFERSIZE;

			if (sense_len > cmd_blk->sense_len)
				sense_len = cmd_blk->sense_len;
			memcpy(scmd->sense_buffer, cmd_blk->sense, sense_len);
		}
		pci_pool_free(c->V2.RequestSensePool, cmd_blk->sense,
			      cmd_blk->sense_addr);
		cmd_blk->sense = NULL;
		cmd_blk->sense_addr = 0;
	}
	if (cmd_blk->DCDB) {
		pci_pool_free(c->V2.DCDBPool, cmd_blk->DCDB,
			      cmd_blk->DCDB_dma);
		cmd_blk->DCDB = NULL;
		cmd_blk->DCDB_dma = 0;
	}
	if (cmd_blk->sgl) {
		pci_pool_free(c->ScatterGatherPool, cmd_blk->sgl,
			      cmd_blk->sgl_addr);
		cmd_blk->sgl = NULL;
		cmd_blk->sgl_addr = 0;
	}
	if (cmd_blk->residual)
		scsi_set_resid(scmd, cmd_blk->residual);
	status = cmd_blk->status;
	if (status == DAC960_V2_DeviceNonresponsive ||
	    status == DAC960_V2_DeviceNonresponsive2)
		scmd->result = (DID_BAD_TARGET << 16);
	else
		scmd->result = (DID_OK << 16) || status;
	scmd->scsi_done(scmd);
}

static void DAC960_V2_HandleCommandBlock(myr_hba *c,
					 myr_v2_cmdblk *cmd_blk)
{
	if (!cmd_blk)
		return;

	if (cmd_blk->Completion) {
		complete(cmd_blk->Completion);
		cmd_blk->Completion = NULL;
	}
}


/*
  DAC960_GEM_HardwareInit initializes the hardware for DAC960 GEM Series
  Controllers.
*/

static int DAC960_GEM_HardwareInit(struct pci_dev *pdev,
				   myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_GEM_DisableInterrupts(base);
	DAC960_GEM_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_GEM_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_GEM_ReadErrorStatus(base, &ErrorStatus,
					       &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V2_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_GEM_ControllerReset(base);
		return -EAGAIN;
	}
	DAC960_GEM_EnableInterrupts(base);
	c->V2.QueueCommand = DAC960_V2_QueueCommand;
	c->V2.WriteCommandMailbox = DAC960_GEM_WriteCommandMailbox;
	c->V2.MailboxNewCommand = DAC960_GEM_MemoryMailboxNewCommand;
	c->ReadControllerConfiguration =
		DAC960_V2_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_GEM_DisableInterrupts;
	c->Reset = DAC960_GEM_ControllerReset;
	return 0;
}

/*
  DAC960_GEM_InterruptHandler handles hardware interrupts from DAC960 GEM Series
  Controllers.
*/

static irqreturn_t DAC960_GEM_InterruptHandler(int IRQ_Channel,
					       void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	DAC960_V2_StatusMailbox_T *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_GEM_AcknowledgeInterrupt(base);
	NextStatusMailbox = c->V2.NextStatusMailbox;
	while (NextStatusMailbox->id > 0) {
		unsigned short id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myr_v2_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V2.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V2.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk) {
			cmd_blk->status = NextStatusMailbox->status;
			cmd_blk->sense_len = NextStatusMailbox->sense_len;
			cmd_blk->residual = NextStatusMailbox->residual;
		} else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(DAC960_V2_StatusMailbox_T));
		if (++NextStatusMailbox > c->V2.LastStatusMailbox)
			NextStatusMailbox = c->V2.FirstStatusMailbox;

		if (id < 3)
			DAC960_V2_HandleCommandBlock(c, cmd_blk);
		else
			DAC960_V2_HandleSCSI(c, cmd_blk, scmd);
	}
	c->V2.NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_BA_HardwareInit initializes the hardware for DAC960 BA Series
  Controllers.
*/

static int DAC960_BA_HardwareInit(struct pci_dev *pdev,
				   myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_BA_DisableInterrupts(base);
	DAC960_BA_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_BA_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_BA_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V2_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_BA_ControllerReset(base);
		return -EAGAIN;
	}
	DAC960_BA_EnableInterrupts(base);
	c->V2.QueueCommand = DAC960_V2_QueueCommand;
	c->V2.WriteCommandMailbox = DAC960_BA_WriteCommandMailbox;
	c->V2.MailboxNewCommand = DAC960_BA_MemoryMailboxNewCommand;
	c->ReadControllerConfiguration =
		DAC960_V2_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_BA_DisableInterrupts;
	c->Reset = DAC960_BA_ControllerReset;
	return 0;
}


/*
  DAC960_BA_InterruptHandler handles hardware interrupts from DAC960 BA Series
  Controllers.
*/

static irqreturn_t DAC960_BA_InterruptHandler(int IRQ_Channel,
					      void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	DAC960_V2_StatusMailbox_T *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_BA_AcknowledgeInterrupt(base);
	NextStatusMailbox = c->V2.NextStatusMailbox;
	while (NextStatusMailbox->id > 0) {
		unsigned short id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myr_v2_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V2.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V2.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk) {
			cmd_blk->status = NextStatusMailbox->status;
			cmd_blk->sense_len = NextStatusMailbox->sense_len;
			cmd_blk->residual = NextStatusMailbox->residual;
		} else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(DAC960_V2_StatusMailbox_T));
		if (++NextStatusMailbox > c->V2.LastStatusMailbox)
			NextStatusMailbox = c->V2.FirstStatusMailbox;

		if (id < 3)
			DAC960_V2_HandleCommandBlock(c, cmd_blk);
		else
			DAC960_V2_HandleSCSI(c, cmd_blk, scmd);
	}
	c->V2.NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_LP_HardwareInit initializes the hardware for DAC960 LP Series
  Controllers.
*/

static int DAC960_LP_HardwareInit(struct pci_dev *pdev,
				  myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_LP_DisableInterrupts(base);
	DAC960_LP_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_LP_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_LP_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V2_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_LP_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_LP_EnableInterrupts(base);
	c->V2.QueueCommand = DAC960_V2_QueueCommand;
	c->V2.WriteCommandMailbox = DAC960_LP_WriteCommandMailbox;
	c->V2.MailboxNewCommand = DAC960_LP_MemoryMailboxNewCommand;
	c->ReadControllerConfiguration =
		DAC960_V2_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_LP_DisableInterrupts;
	c->Reset = DAC960_LP_ControllerReset;

	return 0;
}

/*
  DAC960_LP_InterruptHandler handles hardware interrupts from DAC960 LP Series
  Controllers.
*/

static irqreturn_t DAC960_LP_InterruptHandler(int IRQ_Channel,
					      void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	DAC960_V2_StatusMailbox_T *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_LP_AcknowledgeInterrupt(base);
	NextStatusMailbox = c->V2.NextStatusMailbox;
	while (NextStatusMailbox->id > 0) {
		unsigned short id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myr_v2_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V2.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V2.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk) {
			cmd_blk->status = NextStatusMailbox->status;
			cmd_blk->sense_len = NextStatusMailbox->sense_len;
			cmd_blk->residual = NextStatusMailbox->residual;
		} else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(DAC960_V2_StatusMailbox_T));
		if (++NextStatusMailbox > c->V2.LastStatusMailbox)
			NextStatusMailbox = c->V2.FirstStatusMailbox;

		if (id < 3)
			DAC960_V2_HandleCommandBlock(c, cmd_blk);
		else
			DAC960_V2_HandleSCSI(c, cmd_blk, scmd);
	}
	c->V2.NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_LA_HardwareInit initializes the hardware for DAC960 LA Series
  Controllers.
*/

static int DAC960_LA_HardwareInit(struct pci_dev *pdev,
				   myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_LA_DisableInterrupts(base);
	timeout = 0;
	while (DAC960_LA_HardwareMailboxStatusAvailableP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		DAC960_LA_AcknowledgeHardwareMailboxStatus(base);
		udelay(10);
		timeout++;
	}
	if (DAC960_LA_HardwareMailboxStatusAvailableP(base)) {
		dev_err(&pdev->dev,
			"Hardware Mailbox status still not cleared\n");
		DAC960_LA_ControllerReset(base);
	} else if (timeout)
		dev_info(&pdev->dev,
			 "Hardware Mailbox status cleared, %d attempts\n",
			 timeout);

	udelay(1000);
	timeout = 0;
	while (DAC960_LA_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_LA_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -ENODEV;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_LA_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_LA_EnableInterrupts(base);
	c->V1.QueueCommand = DAC960_V1_QueueCommand;
	c->V1.WriteCommandMailbox = DAC960_LA_WriteCommandMailbox;
	if (c->V1.DualModeMemoryMailboxInterface)
		c->V1.MailboxNewCommand =
			DAC960_LA_MemoryMailboxNewCommand;
	else
		c->V1.MailboxNewCommand =
			DAC960_LA_HardwareMailboxNewCommand;
	c->ReadControllerConfiguration =
		DAC960_V1_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_LA_DisableInterrupts;
	c->Reset = DAC960_LA_ControllerReset;

	return 0;
}


/*
  DAC960_LA_InterruptHandler handles hardware interrupts from DAC960 LA Series
  Controllers.
*/

static irqreturn_t DAC960_LA_InterruptHandler(int IRQ_Channel,
					      void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	DAC960_V1_StatusMailbox_T *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_LA_AcknowledgeInterrupt(base);
	NextStatusMailbox = c->V1.NextStatusMailbox;
	while (NextStatusMailbox->valid) {
		unsigned char id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myr_v1_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V1.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V1.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status = NextStatusMailbox->status;
		else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(DAC960_V1_StatusMailbox_T));
		if (++NextStatusMailbox > c->V1.LastStatusMailbox)
			NextStatusMailbox = c->V1.FirstStatusMailbox;

		if (id < 3)
			DAC960_V1_HandleCommandBlock(c, cmd_blk);
		else
			DAC960_V1_HandleSCSI(c, cmd_blk, scmd);
	}
	c->V1.NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_PG_HardwareInit initializes the hardware for DAC960 PG Series
  Controllers.
*/

static int DAC960_PG_HardwareInit(struct pci_dev *pdev,
				  myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_PG_DisableInterrupts(base);
	DAC960_PG_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_PG_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_PG_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_PG_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_PG_EnableInterrupts(base);
	c->V1.QueueCommand = DAC960_V1_QueueCommand;
	c->V1.WriteCommandMailbox = DAC960_PG_WriteCommandMailbox;
	if (c->V1.DualModeMemoryMailboxInterface)
		c->V1.MailboxNewCommand =
			DAC960_PG_MemoryMailboxNewCommand;
	else
		c->V1.MailboxNewCommand =
			DAC960_PG_HardwareMailboxNewCommand;
	c->ReadControllerConfiguration =
		DAC960_V1_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_PG_DisableInterrupts;
	c->Reset = DAC960_PG_ControllerReset;

	return 0;
}

/*
  DAC960_PG_InterruptHandler handles hardware interrupts from DAC960 PG Series
  Controllers.
*/

static irqreturn_t DAC960_PG_InterruptHandler(int IRQ_Channel,
					      void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	DAC960_V1_StatusMailbox_T *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_PG_AcknowledgeInterrupt(base);
	NextStatusMailbox = c->V1.NextStatusMailbox;
	while (NextStatusMailbox->valid) {
		unsigned char id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myr_v1_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V1.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V1.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status = NextStatusMailbox->status;
		else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(DAC960_V1_StatusMailbox_T));
		if (++NextStatusMailbox > c->V1.LastStatusMailbox)
			NextStatusMailbox = c->V1.FirstStatusMailbox;

		if (id < 3)
			DAC960_V1_HandleCommandBlock(c, cmd_blk);
		else
			DAC960_V1_HandleSCSI(c, cmd_blk, scmd);
	}
	c->V1.NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_PD_HardwareInit initializes the hardware for DAC960 P Series
  Controllers.
*/

static int DAC960_PD_HardwareInit(struct pci_dev *pdev,
				  myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	if (!request_region(c->IO_Address, 0x80,
			    c->FullModelName)) {
		dev_err(&pdev->dev, "IO port 0x%lx busy\n",
			(unsigned long)c->IO_Address);
		return -EBUSY;
	}
	DAC960_PD_DisableInterrupts(base);
	DAC960_PD_AcknowledgeStatus(base);
	udelay(1000);
	while (DAC960_PD_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_PD_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_PD_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_PD_EnableInterrupts(base);
	c->V1.QueueCommand = DAC960_PD_QueueCommand;
	c->ReadControllerConfiguration =
		DAC960_V1_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_PD_DisableInterrupts;
	c->Reset = DAC960_PD_ControllerReset;

	return 0;
}


/*
  DAC960_PD_InterruptHandler handles hardware interrupts from DAC960 PD Series
  Controllers.
*/

static irqreturn_t DAC960_PD_InterruptHandler(int IRQ_Channel,
					      void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	while (DAC960_PD_StatusAvailableP(base)) {
		unsigned char id = DAC960_PD_ReadStatusCommandIdentifier(base);
		struct scsi_cmnd *scmd = NULL;
		myr_v1_cmdblk *cmd_blk;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V1.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V1.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status =
				DAC960_PD_ReadStatusRegister(base);
		else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		DAC960_PD_AcknowledgeInterrupt(base);
		DAC960_PD_AcknowledgeStatus(base);

		if (id < 3)
			DAC960_V1_HandleCommandBlock(c, cmd_blk);
		else
			DAC960_V1_HandleSCSI(c, cmd_blk, scmd);
	}
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_P_HardwareInit initializes the hardware for DAC960 P Series
  Controllers.
*/

static int DAC960_P_HardwareInit(struct pci_dev *pdev,
				 myr_hba *c, void __iomem *base)
{
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	if (!request_region(c->IO_Address, 0x80, c->FullModelName)){
		dev_err(&pdev->dev, "IO port 0x%lx busy\n",
			(unsigned long)c->IO_Address);
		return -EBUSY;
	}
	DAC960_PD_DisableInterrupts(base);
	DAC960_PD_AcknowledgeStatus(base);
	udelay(1000);
	while (DAC960_PD_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_PD_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    DAC960_ReportErrorStatus(c, ErrorStatus,
					     Parameter0, Parameter1))
			return -EAGAIN;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(c)) {
		dev_err(&pdev->dev,
			"Unable to allocate DMA mapped memory\n");
		DAC960_PD_ControllerReset(base);
		return -ETIMEDOUT;
	}
	DAC960_PD_EnableInterrupts(base);
	c->V1.QueueCommand = DAC960_P_QueueCommand;
	c->ReadControllerConfiguration =
		DAC960_V1_ReadControllerConfiguration;
	c->DisableInterrupts = DAC960_PD_DisableInterrupts;
	c->Reset = DAC960_PD_ControllerReset;

	return 0;
}

/*
  DAC960_P_InterruptHandler handles hardware interrupts from DAC960 P Series
  Controllers.

  Translations of DAC960_V1_Enquiry and DAC960_V1_GetDeviceState rely
  on the data having been placed into myr_hba, rather than
  an arbitrary buffer.
*/

static irqreturn_t DAC960_P_InterruptHandler(int IRQ_Channel,
					     void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	void __iomem *base = c->BaseAddress;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	while (DAC960_PD_StatusAvailableP(base)) {
		unsigned char id = DAC960_PD_ReadStatusCommandIdentifier(base);
		struct scsi_cmnd *scmd = NULL;
		myr_v1_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &c->V1.DirectCommandBlock;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &c->V1.MonitoringCommandBlock;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status
				= DAC960_PD_ReadStatusRegister(base);
		else
			dev_err(&c->PCIDevice->dev,
				"Unhandled command completion %d\n", id);

		DAC960_PD_AcknowledgeInterrupt(base);
		DAC960_PD_AcknowledgeStatus(base);

		if (cmd_blk) {
			DAC960_V1_CommandMailbox_T *mbox;
			myr_v1_cmd_opcode op;

			mbox = &cmd_blk->mbox;
			op = mbox->Common.opcode;
			switch (op) {
			case DAC960_V1_Enquiry_Old:
				mbox->Common.opcode = DAC960_V1_Enquiry;
				DAC960_P_To_PD_TranslateEnquiry(c->V1.NewEnquiry);
				break;
			case DAC960_V1_GetDeviceState_Old:
				mbox->Common.opcode = DAC960_V1_GetDeviceState;
				DAC960_P_To_PD_TranslateDeviceState(c->V1.NewDeviceState);
				break;
			case DAC960_V1_Read_Old:
				mbox->Common.opcode = DAC960_V1_Read;
				DAC960_P_To_PD_TranslateReadWriteCommand(cmd_blk);
				break;
			case DAC960_V1_Write_Old:
				mbox->Common.opcode = DAC960_V1_Write;
				DAC960_P_To_PD_TranslateReadWriteCommand(cmd_blk);
				break;
			case DAC960_V1_ReadWithScatterGather_Old:
				mbox->Common.opcode = DAC960_V1_ReadWithScatterGather;
				DAC960_P_To_PD_TranslateReadWriteCommand(cmd_blk);
				break;
			case DAC960_V1_WriteWithScatterGather_Old:
				mbox->Common.opcode = DAC960_V1_WriteWithScatterGather;
				DAC960_P_To_PD_TranslateReadWriteCommand(cmd_blk);
				break;
			default:
				break;
			}
			if (id < 3)
				DAC960_V1_HandleCommandBlock(c, cmd_blk);
			else
				DAC960_V1_HandleSCSI(c, cmd_blk, scmd);
		}
	}
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_V2_MonitoringGetHealthStatus queues a Get Health Status Command
  to DAC960 V2 Firmware Controllers.
*/

static unsigned char DAC960_V2_MonitoringGetHealthStatus(myr_hba *c)
{
	myr_v2_cmdblk *cmd_blk = &c->V2.MonitoringCommandBlock;
	DAC960_V2_CommandMailbox_T *mbox = &cmd_blk->mbox;
	DAC960_V2_DataTransferMemoryAddress_T *dma_addr;
	unsigned char status = cmd_blk->status;

	DAC960_V2_ClearCommand(cmd_blk);
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_MonitoringIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	mbox->Common.dma_size = sizeof(DAC960_V2_HealthStatusBuffer_T);
	mbox->Common.IOCTL_Opcode = DAC960_V2_GetHealthStatus;
	dma_addr = &mbox->Common.dma_addr;
	dma_addr->ScatterGatherSegments[0].SegmentDataPointer =
		c->V2.HealthStatusBufferDMA;
	dma_addr->ScatterGatherSegments[0].SegmentByteCount =
		mbox->ControllerInfo.dma_size;
	dev_dbg(&c->host->shost_gendev, "Sending GetHealthStatus\n");
	DAC960_V2_ExecuteCommand(c, cmd_blk);
	status = cmd_blk->status;

	return status;
}

/*
  DAC960_MonitoringTimerFunction is the timer function for monitoring
  the status of DAC960 Controllers.
*/

static void DAC960_MonitoringWork(struct work_struct *work)
{
	myr_hba *c =
		container_of(work, myr_hba, monitor_work.work);
	unsigned long interval = DAC960_MonitoringTimerInterval;
	unsigned char status;

	dev_dbg(&c->host->shost_gendev, "monitor tick\n");
	if (c->FirmwareType == DAC960_V1_Controller) {
		if (c->V1.NewEventLogSequenceNumber
		    > c->V1.OldEventLogSequenceNumber) {
			int event = c->V1.OldEventLogSequenceNumber;
			dev_dbg(&c->host->shost_gendev,
				"get event log no %d/%d\n",
				c->V1.NewEventLogSequenceNumber, event);
			DAC960_V1_MonitorGetEventLog(c, event);
			c->V1.OldEventLogSequenceNumber = event + 1;
			interval = 10;
		} else if (c->V1.NeedErrorTableInformation) {
			c->V1.NeedErrorTableInformation = false;
			dev_dbg(&c->host->shost_gendev, "get error table\n");
			DAC960_V1_MonitorGetErrorTable(c);
			interval = 10;
		} else if (c->V1.NeedRebuildProgress &&
			   c->V1.RebuildProgressFirst) {
			c->V1.NeedRebuildProgress = false;
			dev_dbg(&c->host->shost_gendev,
				"get rebuild progress\n");
			DAC960_V1_MonitorRebuildProgress(c);
			interval = 10;
		} else if (c->V1.NeedLogicalDeviceInfo) {
			c->V1.NeedLogicalDeviceInfo = false;
			dev_dbg(&c->host->shost_gendev,
				"get logical drive info\n");
			DAC960_V1_GetLogicalDriveInfo(c);
			interval = 10;
		} else if (c->V1.NeedRebuildProgress) {
			c->V1.NeedRebuildProgress = false;
			dev_dbg(&c->host->shost_gendev,
				"get rebuild progress\n");
			DAC960_V1_MonitorRebuildProgress(c);
			interval = 10;
		} else if (c->V1.NeedConsistencyCheckProgress) {
			c->V1.NeedConsistencyCheckProgress = false;
			dev_dbg(&c->host->shost_gendev,
				"get consistency check progress\n");
			DAC960_V1_ConsistencyCheckProgress(c);
			interval = 10;
		} else if (c->V1.NeedBackgroundInitializationStatus) {
			c->V1.NeedBackgroundInitializationStatus = false;
			dev_dbg(&c->host->shost_gendev,
				"get background init status\n");
			DAC960_V1_BackgroundInitialization(c);
			interval = 10;
		} else {
			dev_dbg(&c->host->shost_gendev, "new enquiry\n");
			mutex_lock(&c->V1.dma_mutex);
			DAC960_V1_NewEnquiry(c);
			mutex_unlock(&c->V1.dma_mutex);
			if ((c->V1.NewEventLogSequenceNumber
			     - c->V1.OldEventLogSequenceNumber > 0) ||
			    c->V1.NeedErrorTableInformation ||
			    c->V1.NeedRebuildProgress ||
			    c->V1.NeedLogicalDeviceInfo ||
			    c->V1.NeedRebuildProgress ||
			    c->V1.NeedConsistencyCheckProgress ||
			    c->V1.NeedBackgroundInitializationStatus)
				dev_dbg(&c->host->shost_gendev,
					"reschedule monitor\n");
		}
	} else {
		DAC960_V2_ControllerInfo_T *info =
			&c->V2.ControllerInformation;
		unsigned int StatusChangeCounter =
			c->V2.HealthStatusBuffer->StatusChangeCounter;

		status = DAC960_V2_MonitoringGetHealthStatus(c);

		if (c->V2.NeedControllerInformation) {
			c->V2.NeedControllerInformation = false;
			mutex_lock(&c->V2.cinfo_mutex);
			status = DAC960_V2_NewControllerInfo(c);
			mutex_unlock(&c->V2.cinfo_mutex);
		}
		if (c->V2.HealthStatusBuffer->NextEventSequenceNumber
		    - c->V2.NextEventSequenceNumber > 0) {
			status = DAC960_V2_MonitorGetEvent(c);
			if (status == DAC960_V2_NormalCompletion) {
				DAC960_V2_ReportEvent(c, c->V2.Event);
				c->V2.NextEventSequenceNumber++;
				interval = 1;
			}
		}

		if (time_after(jiffies, c->SecondaryMonitoringTime
			       + DAC960_SecondaryMonitoringInterval))
			c->SecondaryMonitoringTime = jiffies;

		if (info->BackgroundInitializationsActive +
		    info->LogicalDeviceInitializationsActive +
		    info->PhysicalDeviceInitializationsActive +
		    info->ConsistencyChecksActive +
		    info->RebuildsActive +
		    info->OnlineExpansionsActive != 0) {
			struct scsi_device *sdev;
			shost_for_each_device(sdev, c->host) {
				DAC960_V2_LogicalDeviceInfo_T *ldev_info;
				if (sdev->channel < c->PhysicalChannelCount)
					continue;
				ldev_info = sdev->hostdata;
				if (!ldev_info)
					continue;
				status = DAC960_V2_NewLogicalDeviceInfo(c,
					ldev_info->LogicalDeviceNumber,
					ldev_info);
			}
			c->V2.NeedControllerInformation = true;
		}
		if (StatusChangeCounter == c->V2.StatusChangeCounter &&
		    c->V2.HealthStatusBuffer->NextEventSequenceNumber
		    == c->V2.NextEventSequenceNumber &&
		    (c->V2.NeedControllerInformation == false ||
		     time_before(jiffies, c->PrimaryMonitoringTime
				 + DAC960_MonitoringTimerInterval))) {
			interval = DAC960_SecondaryMonitoringInterval;
		}
	}
	if (interval > 1)
		c->PrimaryMonitoringTime = jiffies;
	queue_delayed_work(c->work_q, &c->monitor_work, interval);
}

static struct DAC960_privdata DAC960_GEM_privdata = {
	.HardwareType =		DAC960_GEM_Controller,
	.FirmwareType =		DAC960_V2_Controller,
	.HardwareInit =		DAC960_GEM_HardwareInit,
	.InterruptHandler =	DAC960_GEM_InterruptHandler,
	.MemoryWindowSize =	DAC960_GEM_RegisterWindowSize,
};


static struct DAC960_privdata DAC960_BA_privdata = {
	.HardwareType =		DAC960_BA_Controller,
	.FirmwareType =		DAC960_V2_Controller,
	.HardwareInit =		DAC960_BA_HardwareInit,
	.InterruptHandler =	DAC960_BA_InterruptHandler,
	.MemoryWindowSize =	DAC960_BA_RegisterWindowSize,
};

static struct DAC960_privdata DAC960_LP_privdata = {
	.HardwareType =		DAC960_LP_Controller,
	.FirmwareType =		DAC960_V2_Controller,
	.HardwareInit =		DAC960_LP_HardwareInit,
	.InterruptHandler =	DAC960_LP_InterruptHandler,
	.MemoryWindowSize =	DAC960_LP_RegisterWindowSize,
};

static struct DAC960_privdata DAC960_LA_privdata = {
	.HardwareType =		DAC960_LA_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_LA_HardwareInit,
	.InterruptHandler =	DAC960_LA_InterruptHandler,
	.MemoryWindowSize =	DAC960_LA_RegisterWindowSize,
};

static struct DAC960_privdata DAC960_PG_privdata = {
	.HardwareType =		DAC960_PG_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_PG_HardwareInit,
	.InterruptHandler =	DAC960_PG_InterruptHandler,
	.MemoryWindowSize =	DAC960_PG_RegisterWindowSize,
};

static struct DAC960_privdata DAC960_PD_privdata = {
	.HardwareType =		DAC960_PD_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_PD_HardwareInit,
	.InterruptHandler =	DAC960_PD_InterruptHandler,
	.MemoryWindowSize =	DAC960_PD_RegisterWindowSize,
};

static struct DAC960_privdata DAC960_P_privdata = {
	.HardwareType =		DAC960_P_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_P_HardwareInit,
	.InterruptHandler =	DAC960_P_InterruptHandler,
	.MemoryWindowSize =	DAC960_PD_RegisterWindowSize,
};

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

	mylex_v1_raid_template = raid_class_attach(&mylex_v1_raid_functions);
	if (!mylex_v1_raid_template)
		return -ENODEV;
	mylex_v2_raid_template = raid_class_attach(&mylex_v2_raid_functions);
	if (!mylex_v2_raid_template) {
		raid_class_release(mylex_v1_raid_template);
		return -ENODEV;
	}

	ret = pci_register_driver(&DAC960_pci_driver);
	if (ret) {
		raid_class_release(mylex_v2_raid_template);
		raid_class_release(mylex_v1_raid_template);
	}
	return ret;
}

static void __exit DAC960_cleanup_module(void)
{
	pci_unregister_driver(&DAC960_pci_driver);
	raid_class_release(mylex_v2_raid_template);
	raid_class_release(mylex_v1_raid_template);
}

module_init(DAC960_init_module);
module_exit(DAC960_cleanup_module);

MODULE_DESCRIPTION("Mylex DAC960/AcceleRAID/eXtremeRAID driver");
MODULE_AUTHOR("Hannes Reinecke <hare@suse.com>");
MODULE_LICENSE("GPL");
