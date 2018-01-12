/*
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


#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/raid_class.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_tcq.h>
#include "mylex.h"
#include "myrs.h"

static struct myrs_devstate_name_entry {
	myrs_devstate state;
	char *name;
} myrs_devstate_name_list[] = {
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

static char *myrs_devstate_name(myrs_devstate state)
{
	struct myrs_devstate_name_entry *entry = myrs_devstate_name_list;

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

bool myrs_create_mempools(struct pci_dev *pdev, myr_hba *c)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);
	struct pci_pool *ScatterGatherPool;
	struct pci_pool *RequestSensePool = NULL;
	struct pci_pool *DCDBPool = NULL;
	size_t elem_size, elem_align;

	elem_align = sizeof(myrs_sge);
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
	cs->RequestSensePool = RequestSensePool;
	cs->DCDBPool = DCDBPool;

	return true;
}

void myrs_destroy_mempools(myr_hba *c)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);

	if (cs->DCDBPool) {
		pci_pool_destroy(cs->DCDBPool);
		cs->DCDBPool = NULL;
	}
	if (cs->RequestSensePool) {
		pci_pool_destroy(cs->RequestSensePool);
		cs->RequestSensePool = NULL;
	}
}

/*
  myrs_reset_cmd clears critical fields of Command for DAC960 V2
  Firmware Controllers.
*/

static inline void myrs_reset_cmd(myrs_cmdblk *cmd_blk)
{
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;

	memset(mbox, 0, sizeof(myrs_cmd_mbox));
	cmd_blk->status = 0;
}


/*
 * DAC960_V2_qcmd queues Command for DAC960 V2 Series Controllers.
 */
static void myrs_qcmd(myrs_hba *cs, myrs_cmdblk *cmd_blk)
{
	void __iomem *base = cs->common.io_addr;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	myrs_cmd_mbox *next_mbox = cs->NextCommandMailbox;

	cs->WriteCommandMailbox(next_mbox, mbox);

	if (cs->PreviousCommandMailbox1->Words[0] == 0 ||
	    cs->PreviousCommandMailbox2->Words[0] == 0)
		cs->MailboxNewCommand(base);

	cs->PreviousCommandMailbox2 = cs->PreviousCommandMailbox1;
	cs->PreviousCommandMailbox1 = next_mbox;

	if (++next_mbox > cs->LastCommandMailbox)
		next_mbox = cs->FirstCommandMailbox;

	cs->NextCommandMailbox = next_mbox;
}

/*
 * DAC960_V2_ExecuteCommand executes V2 Command and waits for completion.
 */

static void DAC960_V2_ExecuteCommand(myrs_hba *cs,
				     myrs_cmdblk *cmd_blk)
{
	DECLARE_COMPLETION_ONSTACK(Completion);
	unsigned long flags;

	cmd_blk->Completion = &Completion;
	spin_lock_irqsave(&cs->common.queue_lock, flags);
	myrs_qcmd(cs, cmd_blk);
	spin_unlock_irqrestore(&cs->common.queue_lock, flags);

	if (in_interrupt())
		return;
	wait_for_completion(&Completion);
}


/*
  DAC960_V2_ControllerInfo executes a DAC960 V2 Firmware Controller
  Information Reading IOCTL Command and waits for completion.  It returns
  true on success and false on failure.

  Data is returned in the controller's V2.ctlr_info_buf dma-able
  memory buffer.
*/

static unsigned char DAC960_V2_NewControllerInfo(myrs_hba *cs)
{
	myr_hba *c = &cs->common;
	myrs_cmdblk *cmd_blk = &cs->dcmd_blk;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	myrs_sgl *sgl;
	unsigned char status;

	mutex_lock(&cs->dcmd_mutex);
	myrs_reset_cmd(cmd_blk);
	mbox->ControllerInfo.id = DAC960_DirectCommandIdentifier;
	mbox->ControllerInfo.opcode = DAC960_V2_IOCTL;
	mbox->ControllerInfo.control.DataTransferControllerToHost = true;
	mbox->ControllerInfo.control.NoAutoRequestSense = true;
	mbox->ControllerInfo.dma_size = sizeof(myrs_ctlr_info);
	mbox->ControllerInfo.ctlr_num = 0;
	mbox->ControllerInfo.ioctl_opcode = DAC960_V2_GetControllerInfo;
	sgl = &mbox->ControllerInfo.dma_addr;
	sgl->sge[0].sge_addr = cs->ctlr_info_addr;
	sgl->sge[0].sge_count = mbox->ControllerInfo.dma_size;
	dev_dbg(&c->host->shost_gendev,
		"Sending GetControllerInfo\n");
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
	if (status == DAC960_V2_NormalCompletion) {
		myrs_ctlr_info *new = cs->ctlr_info_buf;
		myrs_ctlr_info *old = &cs->ctlr_info;
		if (new->BackgroundInitializationsActive +
		    new->LogicalDeviceInitializationsActive +
		    new->PhysicalDeviceInitializationsActive +
		    new->ConsistencyChecksActive +
		    new->RebuildsActive +
		    new->OnlineExpansionsActive != 0)
			cs->NeedControllerInformation = true;
		if (new->LogicalDevicesPresent != old->LogicalDevicesPresent ||
		    new->LogicalDevicesCritical != old->LogicalDevicesCritical ||
		    new->LogicalDevicesOffline != old->LogicalDevicesOffline)
			shost_printk(KERN_INFO, c->host,
				     "Logical drive count changes (%d/%d/%d)\n",
				     new->LogicalDevicesCritical,
				     new->LogicalDevicesOffline,
				     new->LogicalDevicesPresent);
		c->LogicalDriveCount = new->LogicalDevicesPresent;
		memcpy(old, new, sizeof(myrs_ctlr_info));
	}

	return status;
}


/*
  DAC960_V2_LogicalDeviceInfo executes a DAC960 V2 Firmware Controller Logical
  Device Information Reading IOCTL Command and waits for completion.  It
  returns true on success and false on failure.

  Data is returned in the controller's V2.ldev_info_buf
*/

static unsigned char
DAC960_V2_NewLogicalDeviceInfo(myrs_hba *cs,
			       unsigned short ldev_num,
			       myrs_ldev_info *ldev_info)
{
	myr_hba *c = &cs->common;
	myrs_cmdblk *cmd_blk = &cs->dcmd_blk;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	myrs_sgl *sgl;
	unsigned char status;

	mutex_lock(&cs->dcmd_mutex);
	myrs_reset_cmd(cmd_blk);
	mbox->LogicalDeviceInfo.id = DAC960_DirectCommandIdentifier;
	mbox->LogicalDeviceInfo.opcode = DAC960_V2_IOCTL;
	mbox->LogicalDeviceInfo.control.DataTransferControllerToHost = true;
	mbox->LogicalDeviceInfo.control.NoAutoRequestSense = true;
	mbox->LogicalDeviceInfo.dma_size =
		sizeof(myrs_ldev_info);
	mbox->LogicalDeviceInfo.ldev.LogicalDeviceNumber = ldev_num;
	mbox->LogicalDeviceInfo.ioctl_opcode =
		DAC960_V2_GetLogicalDeviceInfoValid;
	sgl = &mbox->LogicalDeviceInfo.dma_addr;
	sgl->sge[0].sge_addr = cs->ldev_info_addr;
	sgl->sge[0].sge_count = mbox->LogicalDeviceInfo.dma_size;
	dev_dbg(&c->host->shost_gendev,
		"Sending GetLogicalDeviceInfoValid for ldev %d\n", ldev_num);
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V2_NormalCompletion) {
		unsigned short ldev_num = ldev_info->LogicalDeviceNumber;
		myrs_ldev_info *new = cs->ldev_info_buf;
		myrs_ldev_info *old = ldev_info;

		if (old != NULL) {
			unsigned long ldev_size = new->ConfigurableDeviceSize;

			if (new->State != old->State) {
				const char *name;

				name = myrs_devstate_name(new->State);
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
			memcpy(ldev_info, cs->ldev_info_buf,
			       sizeof(*ldev_info));
		}
	}
	mutex_unlock(&cs->dcmd_mutex);
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
DAC960_V2_NewPhysicalDeviceInfo(myrs_hba *cs,
				unsigned char Channel,
				unsigned char TargetID,
				unsigned char LogicalUnit,
				myrs_pdev_info *pdev_info)
{
	myr_hba *c = &cs->common;
	myrs_cmdblk *cmd_blk = &cs->dcmd_blk;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	myrs_sgl *sgl;
	unsigned char status;

	mutex_lock(&cs->dcmd_mutex);
	myrs_reset_cmd(cmd_blk);
	mbox->PhysicalDeviceInfo.opcode = DAC960_V2_IOCTL;
	mbox->PhysicalDeviceInfo.id = DAC960_DirectCommandIdentifier;
	mbox->PhysicalDeviceInfo.control.DataTransferControllerToHost = true;
	mbox->PhysicalDeviceInfo.control.NoAutoRequestSense = true;
	mbox->PhysicalDeviceInfo.dma_size =
		sizeof(myrs_pdev_info);
	mbox->PhysicalDeviceInfo.pdev.LogicalUnit = LogicalUnit;
	mbox->PhysicalDeviceInfo.pdev.TargetID = TargetID;
	mbox->PhysicalDeviceInfo.pdev.Channel = Channel;
	mbox->PhysicalDeviceInfo.ioctl_opcode =
		DAC960_V2_GetPhysicalDeviceInfoValid;
	sgl = &mbox->PhysicalDeviceInfo.dma_addr;
	sgl->sge[0].sge_addr = cs->pdev_info_addr;
	sgl->sge[0].sge_count = mbox->PhysicalDeviceInfo.dma_size;
	dev_dbg(&c->host->shost_gendev,
		"Sending GetPhysicalDeviceInfoValid for pdev %d:%d:%d\n",
		Channel, TargetID, LogicalUnit);
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V2_NormalCompletion)
		memcpy(pdev_info, &cs->pdev_info_buf, sizeof(*pdev_info));
	mutex_unlock(&cs->dcmd_mutex);
	return status;
}

/*
  DAC960_V2_DeviceOperation executes a DAC960 V2 Firmware Controller Device
  Operation IOCTL Command and waits for completion.  It returns true on
  success and false on failure.
*/

static unsigned char
DAC960_V2_DeviceOperation(myrs_hba *cs,
			  myrs_ioctl_opcode opcode,
			  myrs_opdev opdev)
{
	myrs_cmdblk *cmd_blk = &cs->dcmd_blk;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned char status;

	mutex_lock(&cs->dcmd_mutex);
	myrs_reset_cmd(cmd_blk);
	mbox->DeviceOperation.opcode = DAC960_V2_IOCTL;
	mbox->DeviceOperation.id = DAC960_DirectCommandIdentifier;
	mbox->DeviceOperation.control.DataTransferControllerToHost = true;
	mbox->DeviceOperation.control.NoAutoRequestSense = true;
	mbox->DeviceOperation.ioctl_opcode = opcode;
	mbox->DeviceOperation.opdev = opdev;
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
	return status;
}


/*
  DAC960_V2_TranslatePhysicalDevice translates a Physical Device Channel and
  TargetID into a Logical Device.
*/

static unsigned char
DAC960_V2_TranslatePhysicalDevice(myrs_hba *cs,
				  unsigned char Channel,
				  unsigned char TargetID,
				  unsigned char LogicalUnit,
				  unsigned short *ldev_num)
{
	myrs_cmdblk *cmd_blk;
	myrs_cmd_mbox *mbox;
	myrs_sgl *sgl;
	unsigned char status;

	mutex_lock(&cs->dcmd_mutex);
	cmd_blk = &cs->dcmd_blk;
	mbox = &cmd_blk->mbox;
	mbox->PhysicalDeviceInfo.opcode = DAC960_V2_IOCTL;
	mbox->PhysicalDeviceInfo.control.DataTransferControllerToHost = true;
	mbox->PhysicalDeviceInfo.control.NoAutoRequestSense = true;
	mbox->PhysicalDeviceInfo.dma_size = sizeof(myrs_devmap);
	mbox->PhysicalDeviceInfo.pdev.TargetID = TargetID;
	mbox->PhysicalDeviceInfo.pdev.Channel = Channel;
	mbox->PhysicalDeviceInfo.pdev.LogicalUnit = LogicalUnit;
	mbox->PhysicalDeviceInfo.ioctl_opcode =
		DAC960_V2_TranslatePhysicalToLogicalDevice;
	sgl = &mbox->PhysicalDeviceInfo.dma_addr;
	sgl->sge[0].sge_addr = cs->devmap_addr;
	sgl->sge[0].sge_addr = mbox->PhysicalDeviceInfo.dma_size;

	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
	if (status == DAC960_V2_NormalCompletion)
		*ldev_num = cs->devmap_buf->LogicalDeviceNumber;

	return status;
}


static unsigned char DAC960_V2_MonitorGetEvent(myrs_hba *cs)
{
	myrs_cmdblk *cmd_blk = &cs->mcmd_blk;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	myrs_sgl *sgl;
	unsigned char status;

	mbox->GetEvent.opcode = DAC960_V2_IOCTL;
	mbox->GetEvent.dma_size = sizeof(myrs_event);
	mbox->GetEvent.evnum_upper = cs->NextEventSequenceNumber >> 16;
	mbox->GetEvent.ctlr_num = 0;
	mbox->GetEvent.ioctl_opcode = DAC960_V2_GetEvent;
	mbox->GetEvent.evnum_lower = cs->NextEventSequenceNumber & 0xFFFF;
	sgl = &mbox->GetEvent.dma_addr;
	sgl->sge[0].sge_addr = cs->event_addr;
	sgl->sge[0].sge_count = mbox->GetEvent.dma_size;
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;

	return status;
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

static bool DAC960_V2_EnableMemoryMailboxInterface(myrs_hba *cs)
{
	myr_hba *c = &cs->common;
	void __iomem *base = c->io_addr;
	struct pci_dev *pdev = c->PCIDevice;
	struct dma_loaf *DmaPages = &c->DmaPages;
	size_t DmaPagesSize;
	size_t CommandMailboxesSize;
	size_t StatusMailboxesSize;

	myrs_cmd_mbox *CommandMailboxesMemory;
	dma_addr_t CommandMailboxesMemoryDMA;

	myrs_stat_mbox *StatusMailboxesMemory;
	dma_addr_t StatusMailboxesMemoryDMA;

	myrs_cmd_mbox *mbox;
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
				    sizeof(myrs_cmd_mbox),
				    &CommandMailboxDMA);
	if (mbox == NULL)
		return false;

	CommandMailboxesSize = DAC960_V2_CommandMailboxCount * sizeof(myrs_cmd_mbox);
	StatusMailboxesSize = DAC960_V2_StatusMailboxCount * sizeof(myrs_stat_mbox);
	DmaPagesSize =
		CommandMailboxesSize + StatusMailboxesSize +
		sizeof(myrs_fwstat) +
		sizeof(myrs_ctlr_info) +
		sizeof(myrs_ldev_info) +
		sizeof(myrs_pdev_info) +
		sizeof(myrs_event) +
		sizeof(myrs_devmap);

	if (!init_dma_loaf(pdev, DmaPages, DmaPagesSize)) {
		pci_free_consistent(pdev, sizeof(myrs_cmd_mbox),
				    mbox, CommandMailboxDMA);
		return false;
	}

	CommandMailboxesMemory = slice_dma_loaf(DmaPages,
						CommandMailboxesSize, &CommandMailboxesMemoryDMA);

	/* These are the base addresses for the command memory mailbox array */
	cs->FirstCommandMailbox = CommandMailboxesMemory;
	cs->FirstCommandMailboxDMA = CommandMailboxesMemoryDMA;

	CommandMailboxesMemory += DAC960_V2_CommandMailboxCount - 1;
	cs->LastCommandMailbox = CommandMailboxesMemory;
	cs->NextCommandMailbox = cs->FirstCommandMailbox;
	cs->PreviousCommandMailbox1 = cs->LastCommandMailbox;
	cs->PreviousCommandMailbox2 = cs->LastCommandMailbox - 1;

	/* These are the base addresses for the status memory mailbox array */
	StatusMailboxesMemory = slice_dma_loaf(DmaPages,
					       StatusMailboxesSize, &StatusMailboxesMemoryDMA);

	cs->FirstStatusMailbox = StatusMailboxesMemory;
	cs->FirstStatusMailboxDMA = StatusMailboxesMemoryDMA;
	StatusMailboxesMemory += DAC960_V2_StatusMailboxCount - 1;
	cs->LastStatusMailbox = StatusMailboxesMemory;
	cs->NextStatusMailbox = cs->FirstStatusMailbox;

	cs->fwstat_buf = slice_dma_loaf(DmaPages, sizeof(myrs_fwstat),
					  &cs->fwstat_addr);

	cs->ctlr_info_buf = slice_dma_loaf(DmaPages, sizeof(myrs_ctlr_info),
					     &cs->ctlr_info_addr);

	cs->ldev_info_buf = slice_dma_loaf(DmaPages, sizeof(myrs_ldev_info),
					     &cs->ldev_info_addr);

	cs->pdev_info_buf = slice_dma_loaf(DmaPages, sizeof(myrs_pdev_info),
					     &cs->pdev_info_addr);

	cs->event_buf = slice_dma_loaf(DmaPages, sizeof(myrs_event),
					 &cs->event_addr);

	cs->devmap_buf = slice_dma_loaf(DmaPages, sizeof(myrs_devmap),
					  &cs->devmap_addr);

	/*
	  Enable the Memory Mailbox Interface.

	  I don't know why we can't just use one of the memory mailboxes
	  we just allocated to do this, instead of using this temporary one.
	  Try this change later.
	*/
	memset(mbox, 0, sizeof(myrs_cmd_mbox));
	mbox->SetMemoryMailbox.id = 1;
	mbox->SetMemoryMailbox.opcode = DAC960_V2_IOCTL;
	mbox->SetMemoryMailbox.control.NoAutoRequestSense = true;
	mbox->SetMemoryMailbox.FirstCommandMailboxSizeKB =
		(DAC960_V2_CommandMailboxCount * sizeof(myrs_cmd_mbox)) >> 10;
	mbox->SetMemoryMailbox.FirstStatusMailboxSizeKB =
		(DAC960_V2_StatusMailboxCount * sizeof(myrs_stat_mbox)) >> 10;
	mbox->SetMemoryMailbox.SecondCommandMailboxSizeKB = 0;
	mbox->SetMemoryMailbox.SecondStatusMailboxSizeKB = 0;
	mbox->SetMemoryMailbox.sense_len = 0;
	mbox->SetMemoryMailbox.ioctl_opcode = DAC960_V2_SetMemoryMailbox;
	mbox->SetMemoryMailbox.HealthStatusBufferSizeKB = 1;
	mbox->SetMemoryMailbox.HealthStatusBufferBusAddress =
		cs->fwstat_addr;
	mbox->SetMemoryMailbox.FirstCommandMailboxBusAddress =
		cs->FirstCommandMailboxDMA;
	mbox->SetMemoryMailbox.FirstStatusMailboxBusAddress =
		cs->FirstStatusMailboxDMA;
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
	pci_free_consistent(pdev, sizeof(myrs_cmd_mbox),
			    mbox, CommandMailboxDMA);
	if (status != DAC960_V2_NormalCompletion)
		dev_err(&pdev->dev, "Failed to enable mailbox, status %X\n",
			status);
	return (status == DAC960_V2_NormalCompletion);
}


/*
  DAC960_V2_ReadControllerConfiguration reads the Configuration Information
  from DAC960 V2 Firmware Controllers and initializes the Controller structure.
*/

int DAC960_V2_ReadControllerConfiguration(myr_hba *c)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);
	myrs_ctlr_info *info = &cs->ctlr_info;
	struct Scsi_Host *shost = c->host;
	unsigned char status;
	int i, ModelNameLength;

	/* Get data into dma-able area, then copy into permanent location */
	mutex_lock(&cs->cinfo_mutex);
	status = DAC960_V2_NewControllerInfo(cs);
	mutex_unlock(&cs->cinfo_mutex);
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
	strcpy(c->FullModelName, "DAC960 ");
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
  DAC960_V2_ReportEvent prints an appropriate message when a Controller Event
  occurs.
*/

static struct {
	int ev_code;
	unsigned char *ev_msg;
} myrs_ev_list[] =
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

static void DAC960_V2_ReportEvent(myrs_hba *cs, myrs_event *ev)
{
	unsigned char MessageBuffer[DAC960_LineBufferSize];
	int ev_idx = 0, ev_code;
	unsigned char ev_type, *ev_msg;
	struct Scsi_Host *shost = cs->common.host;
	struct scsi_device *sdev;
	struct scsi_sense_hdr sshdr;
	unsigned char *sense_info;
	unsigned char *cmd_specific;

	if (ev->ev_code == 0x1C) {
		if (!scsi_normalize_sense(ev->sense_data, 40, &sshdr))
			memset(&sshdr, 0x0, sizeof(sshdr));
		else {
			sense_info = &ev->sense_data[3];
			cmd_specific = &ev->sense_data[7];
		}
	}
	if (sshdr.sense_key == VENDOR_SPECIFIC &&
	    (sshdr.asc == 0x80 || sshdr.asc == 0x81))
		ev->ev_code = ((sshdr.asc - 0x80) << 8 || sshdr.ascq);
	while (true) {
		ev_code = myrs_ev_list[ev_idx].ev_code;
		if (ev_code == ev->ev_code || ev_code == 0)
			break;
		ev_idx++;
	}
	ev_type = myrs_ev_list[ev_idx].ev_msg[0];
	ev_msg = &myrs_ev_list[ev_idx].ev_msg[2];
	if (ev_code == 0) {
		shost_printk(KERN_WARNING, shost,
			     "Unknown Controller Event Code %04X\n",
			     ev->ev_code);
		return;
	}
	switch (ev_type) {
	case 'P':
		sdev = scsi_device_lookup(shost, ev->channel,
					  ev->target, 0);
		sdev_printk(KERN_INFO, sdev, "%s\n", ev_msg);
		if (sdev && sdev->hostdata &&
		    sdev->channel < cs->common.PhysicalChannelCount) {
			myrs_pdev_info *pdev_info = sdev->hostdata;
			switch (ev->ev_code) {
			case 0x0001:
			case 0x0007:
				pdev_info->State = DAC960_V2_Device_Online;
				break;
			case 0x0002:
				pdev_info->State = DAC960_V2_Device_Standby;
				break;
			case 0x000C:
				pdev_info->State = DAC960_V2_Device_Offline;
				break;
			case 0x000E:
				pdev_info->State = DAC960_V2_Device_Missing;
				break;
			case 0x000F:
				pdev_info->State =
					DAC960_V2_Device_Unconfigured;
				break;
			}
		}
		break;
	case 'L':
		shost_printk(KERN_INFO, shost, "Logical Drive %d %s\n",
			     ev->lun, ev_msg);
		cs->NeedControllerInformation = true;
		break;
	case 'M':
		shost_printk(KERN_INFO, shost, "Logical Drive %d %s\n",
			     ev->lun, ev_msg);
		cs->NeedControllerInformation = true;
		break;
	case 'S':
		if (sshdr.sense_key == NO_SENSE ||
		    (sshdr.sense_key == NOT_READY &&
		     sshdr.asc == 0x04 && (sshdr.ascq == 0x01 ||
					    sshdr.ascq == 0x02)))
			break;
		shost_printk(KERN_INFO, shost, "Physical Device %d:%d %s\n",
			     ev->channel, ev->target, ev_msg);
		shost_printk(KERN_INFO, shost,
			     "Physical Device %d:%d Request Sense: "
			     "Sense Key = %X, ASC = %02X, ASCQ = %02X\n",
			     ev->channel, ev->target,
			     sshdr.sense_key, sshdr.asc, sshdr.ascq);
		shost_printk(KERN_INFO, shost,
			     "Physical Device %d:%d Request Sense: "
			     "Information = %02X%02X%02X%02X "
			     "%02X%02X%02X%02X\n",
			     ev->channel, ev->target,
			     sense_info[0], sense_info[1],
			     sense_info[2], sense_info[3],
			     cmd_specific[0], cmd_specific[1],
			     cmd_specific[2], cmd_specific[3]);
		break;
	case 'E':
		if (cs->common.SuppressEnclosureMessages)
			break;
		sprintf(MessageBuffer, ev_msg, ev->lun);
		shost_printk(KERN_INFO, shost, "Enclosure %d %s\n",
			     ev->target, MessageBuffer);
		break;
	case 'C':
		shost_printk(KERN_INFO, shost, "Controller %s\n", ev_msg);
		break;
	default:
		shost_printk(KERN_INFO, shost,
			     "Unknown Controller Event Code %04X\n",
			     ev->ev_code);
		break;
	}
}

void myrs_get_ctlr_info(myr_hba *c)
{
	int i;
	myrs_hba *cs = container_of(c, myrs_hba, common);
	myrs_ctlr_info *info = &cs->ctlr_info;

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

static ssize_t myrs_show_dev_state(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	int ret;

	if (!sdev->hostdata)
		return snprintf(buf, 16, "Unknown\n");

	if (sdev->channel >= cs->common.PhysicalChannelCount) {
		myrs_ldev_info *ldev_info = sdev->hostdata;
		const char *name;

		name = myrs_devstate_name(ldev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       ldev_info->State);
	} else {
		myrs_pdev_info *pdev_info;
		const char *name;

		pdev_info = sdev->hostdata;
		name = myrs_devstate_name(pdev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       pdev_info->State);
	}
	return ret;
}

static ssize_t myrs_store_dev_state(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_cmdblk *cmd_blk;
	myrs_cmd_mbox *mbox;
	myrs_devstate new_state;
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

	if (sdev->channel < cs->common.PhysicalChannelCount) {
		myrs_pdev_info *pdev_info = sdev->hostdata;

		if (pdev_info->State == new_state) {
			sdev_printk(KERN_INFO, sdev,
				    "Device already in %s\n",
				    myrs_devstate_name(new_state));
			return count;
		}
		status = DAC960_V2_TranslatePhysicalDevice(cs, sdev->channel,
							   sdev->id, sdev->lun,
							   &ldev_num);
		if (status != DAC960_V2_NormalCompletion)
			return -ENXIO;
	} else {
		myrs_ldev_info *ldev_info = sdev->hostdata;

		if (ldev_info->State == new_state) {
			sdev_printk(KERN_INFO, sdev,
				    "Device already in %s\n",
				    myrs_devstate_name(new_state));
			return count;
		}
		ldev_num = ldev_info->LogicalDeviceNumber;
	}
	mutex_lock(&cs->dcmd_mutex);
	cmd_blk = &cs->dcmd_blk;
	myrs_reset_cmd(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	mbox->SetDeviceState.ioctl_opcode = DAC960_V2_SetDeviceState;
	mbox->SetDeviceState.state = new_state;
	mbox->SetDeviceState.ldev.LogicalDeviceNumber = ldev_num;
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
	if (status == DAC960_V2_NormalCompletion) {
		if (sdev->channel < cs->common.PhysicalChannelCount) {
			myrs_pdev_info *pdev_info = sdev->hostdata;

			pdev_info->State = new_state;
		} else {
			myrs_ldev_info *ldev_info = sdev->hostdata;

			ldev_info->State = new_state;
		}
		sdev_printk(KERN_INFO, sdev,
			    "Set device state to %s\n",
			    myrs_devstate_name(new_state));
		return count;
	}
	sdev_printk(KERN_INFO, sdev,
		    "Failed to set device state to %s, status 0x%02x\n",
		    myrs_devstate_name(new_state), status);
	return -EINVAL;
}

static DEVICE_ATTR(raid_state, S_IRUGO | S_IWUSR, myrs_show_dev_state,
		   myrs_store_dev_state);

static ssize_t myrs_show_dev_level(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	const char *name = NULL;

	if (!sdev->hostdata)
		return snprintf(buf, 16, "Unknown\n");

	if (sdev->channel >= cs->common.PhysicalChannelCount) {
		myrs_ldev_info *ldev_info;

		ldev_info = sdev->hostdata;
		name = DAC960_V2_RAIDLevelName(ldev_info->RAIDLevel);
		if (!name)
			return snprintf(buf, 32, "Invalid (%02X)\n",
					ldev_info->State);

	} else
		name = DAC960_V2_RAIDLevelName(DAC960_V2_RAID_Physical);

	return snprintf(buf, 32, "%s\n", name);
}
static DEVICE_ATTR(raid_level, S_IRUGO, myrs_show_dev_level, NULL);

static ssize_t myrs_show_dev_rebuild(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info;
	unsigned short ldev_num;
	unsigned char status;

	if (sdev->channel < cs->common.PhysicalChannelCount)
		return snprintf(buf, 32, "physical device - not rebuilding\n");

	ldev_info = sdev->hostdata;
	ldev_num = ldev_info->LogicalDeviceNumber;
	status = DAC960_V2_NewLogicalDeviceInfo(cs, ldev_num, ldev_info);
	if (ldev_info->RebuildInProgress) {
		return snprintf(buf, 32, "rebuilding block %zu of %zu\n",
				(size_t)ldev_info->RebuildBlockNumber,
				(size_t)ldev_info->ConfigurableDeviceSize);
	} else
		return snprintf(buf, 32, "not rebuilding\n");
}

static ssize_t myrs_store_dev_rebuild(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info;
	myrs_cmdblk *cmd_blk;
	myrs_cmd_mbox *mbox;
	char tmpbuf[8];
	ssize_t len;
	unsigned short ldev_num;
	unsigned char status;
	int rebuild;
	int ret = count;

	if (sdev->channel < cs->common.PhysicalChannelCount)
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

	status = DAC960_V2_NewLogicalDeviceInfo(cs, ldev_num, ldev_info);
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

	mutex_lock(&cs->dcmd_mutex);
	cmd_blk = &cs->dcmd_blk;
	myrs_reset_cmd(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	if (rebuild) {
		mbox->LogicalDeviceInfo.ldev.LogicalDeviceNumber = ldev_num;
		mbox->LogicalDeviceInfo.ioctl_opcode =
			DAC960_V2_RebuildDeviceStart;
	} else {
		mbox->LogicalDeviceInfo.ldev.LogicalDeviceNumber = ldev_num;
		mbox->LogicalDeviceInfo.ioctl_opcode =
			DAC960_V2_RebuildDeviceStop;
	}
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
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
static DEVICE_ATTR(rebuild, S_IRUGO | S_IWUSR, myrs_show_dev_rebuild,
		   myrs_store_dev_rebuild);


static ssize_t myrs_show_consistency_check(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info;
	unsigned short ldev_num;
	unsigned char status;

	if (sdev->channel < cs->common.PhysicalChannelCount)
		return snprintf(buf, 32, "physical device - not checking\n");

	ldev_info = sdev->hostdata;
	if (!ldev_info)
		return -ENXIO;
	ldev_num = ldev_info->LogicalDeviceNumber;
	status = DAC960_V2_NewLogicalDeviceInfo(cs, ldev_num, ldev_info);
	if (ldev_info->ConsistencyCheckInProgress)
		return snprintf(buf, 32, "checking block %zu of %zu\n",
				(size_t)ldev_info->ConsistencyCheckBlockNumber,
				(size_t)ldev_info->ConfigurableDeviceSize);
	else
		return snprintf(buf, 32, "not checking\n");
}

static ssize_t myrs_store_consistency_check(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info;
	myrs_cmdblk *cmd_blk;
	myrs_cmd_mbox *mbox;
	char tmpbuf[8];
	ssize_t len;
	unsigned short ldev_num;
	unsigned char status;
	int check;
	int ret = count;

	if (sdev->channel < cs->common.PhysicalChannelCount)
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

	status = DAC960_V2_NewLogicalDeviceInfo(cs, ldev_num, ldev_info);
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

	mutex_lock(&cs->dcmd_mutex);
	cmd_blk = &cs->dcmd_blk;
	myrs_reset_cmd(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	if (check) {
		mbox->ConsistencyCheck.ldev.LogicalDeviceNumber = ldev_num;
		mbox->ConsistencyCheck.ioctl_opcode =
			DAC960_V2_ConsistencyCheckStart;
		mbox->ConsistencyCheck.RestoreConsistency = true;
		mbox->ConsistencyCheck.InitializedAreaOnly = false;
	} else {
		mbox->ConsistencyCheck.ldev.LogicalDeviceNumber = ldev_num;
		mbox->ConsistencyCheck.ioctl_opcode =
			DAC960_V2_ConsistencyCheckStop;
	}
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
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
static DEVICE_ATTR(consistency_check, S_IRUGO | S_IWUSR,
		   myrs_show_consistency_check,
		   myrs_store_consistency_check);

static ssize_t myr_show_ctlr_num(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;

	return snprintf(buf, 20, "%d\n", cs->common.ControllerNumber);
}
static DEVICE_ATTR(myr_num, S_IRUGO, myr_show_ctlr_num, NULL);

static ssize_t myr_show_firmware_version(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;

	return snprintf(buf, 16, "%s\n", cs->common.FirmwareVersion);
}
static DEVICE_ATTR(firmware, S_IRUGO, myr_show_firmware_version, NULL);

static ssize_t myrs_store_flush_cache(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;
	unsigned char status;

	status = DAC960_V2_DeviceOperation(cs, DAC960_V2_PauseDevice,
					   DAC960_V2_RAID_Controller);
	if (status == DAC960_V2_NormalCompletion) {
		shost_printk(KERN_INFO, shost, "Cache Flush Completed\n");
		return count;
	}
	shost_printk(KERN_INFO, shost,
		     "Cashe Flush failed, status 0x%02x\n", status);
	return -EIO;
}
static DEVICE_ATTR(flush_cache, S_IWUSR, NULL, myrs_store_flush_cache);

int myrs_host_reset(struct scsi_cmnd *scmd)
{
	struct Scsi_Host *shost = scmd->device->host;
	myrs_hba *cs = (myrs_hba *)shost->hostdata;

	cs->common.Reset(cs->common.io_addr);
	return SUCCESS;
}

static int myrs_queuecommand(struct Scsi_Host *shost,
			     struct scsi_cmnd *scmd)
{
	myrs_hba *cs = (myrs_hba *)shost->hostdata;
	myrs_cmdblk *cmd_blk = scsi_cmd_priv(scmd);
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	struct scsi_device *sdev = scmd->device;
	myrs_sgl *hw_sge;
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

	myrs_reset_cmd(cmd_blk);
	cmd_blk->sense = pci_pool_alloc(cs->RequestSensePool, GFP_ATOMIC,
					&sense_addr);
	if (!cmd_blk->sense)
		return SCSI_MLQUEUE_HOST_BUSY;
	cmd_blk->sense_addr = sense_addr;

	timeout = scmd->request->timeout;
	if (scmd->cmd_len <= 10) {
		if (scmd->device->channel >= cs->common.PhysicalChannelCount) {
			myrs_ldev_info *ldev_info = sdev->hostdata;

			mbox->SCSI_10.opcode = DAC960_V2_SCSI_10;
			mbox->SCSI_10.pdev.LogicalUnit =
				ldev_info->LogicalUnit;
			mbox->SCSI_10.pdev.TargetID = ldev_info->TargetID;
			mbox->SCSI_10.pdev.Channel = ldev_info->Channel;
			mbox->SCSI_10.pdev.Controller = 0;
		} else {
			mbox->SCSI_10.opcode =
				DAC960_V2_SCSI_10_Passthru;
			mbox->SCSI_10.pdev.LogicalUnit = sdev->lun;
			mbox->SCSI_10.pdev.TargetID = sdev->id;
			mbox->SCSI_10.pdev.Channel = sdev->channel;
		}
		mbox->SCSI_10.id = scmd->request->tag + 3;
		mbox->SCSI_10.control.DataTransferControllerToHost =
			(scmd->sc_data_direction == DMA_FROM_DEVICE);
		mbox->SCSI_10.dma_size = scsi_bufflen(scmd);
		mbox->SCSI_10.sense_addr = cmd_blk->sense_addr;
		mbox->SCSI_10.sense_len = DAC960_V2_SENSE_BUFFERSIZE;
		mbox->SCSI_10.cdb_len = scmd->cmd_len;
		if (timeout > 60) {
			mbox->SCSI_10.tmo.TimeoutScale =
				DAC960_V2_TimeoutScale_Minutes;
			mbox->SCSI_10.tmo.TimeoutValue = timeout / 60;
		} else {
			mbox->SCSI_10.tmo.TimeoutScale =
				DAC960_V2_TimeoutScale_Seconds;
			mbox->SCSI_10.tmo.TimeoutValue = timeout;
		}
		memcpy(&mbox->SCSI_10.cdb, scmd->cmnd, scmd->cmd_len);
		hw_sge = &mbox->SCSI_10.dma_addr;
		cmd_blk->DCDB = NULL;
	} else {
		dma_addr_t DCDB_dma;

		cmd_blk->DCDB = pci_pool_alloc(cs->DCDBPool, GFP_ATOMIC,
					       &DCDB_dma);
		if (!cmd_blk->DCDB) {
			pci_pool_free(cs->RequestSensePool, cmd_blk->sense,
				      cmd_blk->sense_addr);
			cmd_blk->sense = NULL;
			cmd_blk->sense_addr = 0;
			return SCSI_MLQUEUE_HOST_BUSY;
		}
		cmd_blk->DCDB_dma = DCDB_dma;
		if (scmd->device->channel >= cs->common.PhysicalChannelCount) {
			myrs_ldev_info *ldev_info = sdev->hostdata;

			mbox->SCSI_255.opcode = DAC960_V2_SCSI_256;
			mbox->SCSI_255.pdev.LogicalUnit =
				ldev_info->LogicalUnit;
			mbox->SCSI_255.pdev.TargetID = ldev_info->TargetID;
			mbox->SCSI_255.pdev.Channel = ldev_info->Channel;
			mbox->SCSI_255.pdev.Controller = 0;
		} else {
			mbox->SCSI_255.opcode =
				DAC960_V2_SCSI_255_Passthru;
			mbox->SCSI_255.pdev.LogicalUnit = sdev->lun;
			mbox->SCSI_255.pdev.TargetID = sdev->id;
			mbox->SCSI_255.pdev.Channel = sdev->channel;
		}
		mbox->SCSI_255.id = scmd->request->tag + 3;
		mbox->SCSI_255.control.DataTransferControllerToHost =
			(scmd->sc_data_direction == DMA_FROM_DEVICE);
		mbox->SCSI_255.dma_size = scsi_bufflen(scmd);
		mbox->SCSI_255.sense_addr = cmd_blk->sense_addr;
		mbox->SCSI_255.sense_len = DAC960_V2_SENSE_BUFFERSIZE;
		mbox->SCSI_255.cdb_len = scmd->cmd_len;
		mbox->SCSI_255.cdb_addr = cmd_blk->DCDB_dma;
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
		hw_sge = &mbox->SCSI_255.dma_addr;
	}
	if (scmd->sc_data_direction == DMA_NONE)
		goto submit;
	nsge = scsi_dma_map(scmd);
	if (nsge == 1) {
		sgl = scsi_sglist(scmd);
		hw_sge->sge[0].sge_addr = (u64)sg_dma_address(sgl);
		hw_sge->sge[0].sge_count = (u64)sg_dma_len(sgl);
	} else {
		myrs_sge *hw_sgl;
		dma_addr_t hw_sgl_addr;
		int i;

		if (nsge > 2) {
			hw_sgl = pci_pool_alloc(cs->common.ScatterGatherPool,
						GFP_ATOMIC, &hw_sgl_addr);
			if (WARN_ON(!hw_sgl)) {
				if (cmd_blk->DCDB) {
					pci_pool_free(cs->DCDBPool,
						      cmd_blk->DCDB,
						      cmd_blk->DCDB_dma);
					cmd_blk->DCDB = NULL;
					cmd_blk->DCDB_dma = 0;
				}
				pci_pool_free(cs->RequestSensePool,
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
			hw_sge->ext.sge0_len = nsge;
			hw_sge->ext.sge0_addr = cmd_blk->sgl_addr;
		} else
			hw_sgl = hw_sge->sge;

		scsi_for_each_sg(scmd, sgl, nsge, i) {
			if (WARN_ON(!hw_sgl)) {
				scsi_dma_unmap(scmd);
				scmd->result = (DID_ERROR << 16);
				scmd->scsi_done(scmd);
				return 0;
			}
			hw_sgl->sge_addr = (u64)sg_dma_address(sgl);
			hw_sgl->sge_count = (u64)sg_dma_len(sgl);
			hw_sgl++;
		}
	}
submit:
	spin_lock_irqsave(&cs->common.queue_lock, flags);
	myrs_qcmd(cs, cmd_blk);
	spin_unlock_irqrestore(&cs->common.queue_lock, flags);

	return 0;
}

static int myrs_slave_alloc(struct scsi_device *sdev)
{
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	unsigned char status;

	if (sdev->channel > sdev->host->max_channel)
		return 0;

	if (sdev->channel >= cs->common.PhysicalChannelCount) {
		myrs_ldev_info *ldev_info;
		unsigned short ldev_num;

		if (sdev->lun > 0)
			return -ENXIO;

		ldev_num = myr_translate_ldev(&cs->common, sdev);
		if (ldev_num >= cs->common.LogicalDriveCount)
			return -ENXIO;

		ldev_info = kzalloc(sizeof(*ldev_info), GFP_KERNEL);
		if (!ldev_info)
			return -ENOMEM;

		status = DAC960_V2_NewLogicalDeviceInfo(cs, ldev_num,
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
			raid_set_level(myrs_raid_template,
				       &sdev->sdev_gendev, level);
			if (ldev_info->State != DAC960_V2_Device_Online) {
				const char *name;

				name = myrs_devstate_name(ldev_info->State);
				sdev_printk(KERN_DEBUG, sdev,
					    "logical device in state %s\n",
					    name ? name : "Invalid");
			}
		}
	} else {
		myrs_pdev_info *pdev_info;

		pdev_info = kzalloc(sizeof(*pdev_info), GFP_KERNEL);
		if (!pdev_info)
			return -ENOMEM;

		status = DAC960_V2_NewPhysicalDeviceInfo(cs, sdev->channel,
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

static int myrs_slave_configure(struct scsi_device *sdev)
{
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info;

	if (sdev->channel > sdev->host->max_channel)
		return -ENXIO;

	if (sdev->channel < cs->common.PhysicalChannelCount) {
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

static void myrs_slave_destroy(struct scsi_device *sdev)
{
	void *hostdata = sdev->hostdata;

	if (hostdata) {
		kfree(hostdata);
		sdev->hostdata = NULL;
	}
}

static struct device_attribute *myr_sdev_attrs[] = {
	&dev_attr_consistency_check,
	&dev_attr_rebuild,
	&dev_attr_raid_state,
	&dev_attr_raid_level,
	NULL,
};

static ssize_t myrs_show_ctlr_serial(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;
	char serial[17];

	memcpy(serial, cs->ctlr_info.ControllerSerialNumber, 16);
	serial[16] = '\0';
	return snprintf(buf, 16, "%s\n", serial);
}
static DEVICE_ATTR(serial, S_IRUGO, myrs_show_ctlr_serial, NULL);

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

static ssize_t myrs_show_processor(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;
	struct DAC960_V2_ProcessorTypeTbl *tbl = DAC960_V2_ProcessorTypeNames;
	const char *first_processor = NULL;
	const char *second_processor = NULL;
	myrs_ctlr_info *info = &cs->ctlr_info;
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
static DEVICE_ATTR(processor, S_IRUGO, myrs_show_processor, NULL);

static ssize_t myrs_store_discovery_command(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;
	myrs_cmdblk *cmd_blk;
	myrs_cmd_mbox *mbox;
	unsigned char status;

	mutex_lock(&cs->dcmd_mutex);
	cmd_blk = &cs->dcmd_blk;
	myrs_reset_cmd(cmd_blk);
	mbox = &cmd_blk->mbox;
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_DirectCommandIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	mbox->Common.ioctl_opcode = DAC960_V2_StartDiscovery;
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cs->dcmd_mutex);
	if (status != DAC960_V2_NormalCompletion) {
		shost_printk(KERN_INFO, shost,
			     "Discovery Not Initiated, status %02X\n",
			     status);
		return -EINVAL;
	}
	shost_printk(KERN_INFO, shost, "Discovery Initiated\n");
	cs->NextEventSequenceNumber = 0;
	cs->NeedControllerInformation = true;
	queue_delayed_work(cs->common.work_q, &cs->common.monitor_work, 1);
	flush_delayed_work(&cs->common.monitor_work);
	shost_printk(KERN_INFO, shost, "Discovery Completed\n");

	return count;
}
static DEVICE_ATTR(discovery, S_IWUSR, NULL, myrs_store_discovery_command);

static ssize_t myrs_show_suppress_enclosure_messages(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrs_hba *cs = (myrs_hba *)shost->hostdata;

	return snprintf(buf, 3, "%d\n", cs->common.SuppressEnclosureMessages);
}

static ssize_t myrs_store_suppress_enclosure_messages(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	char tmpbuf[8];
	ssize_t len;
	int value;

	len = count > sizeof(tmpbuf) - 1 ? sizeof(tmpbuf) - 1 : count;
	strncpy(tmpbuf, buf, len);
	tmpbuf[len] = '\0';
	if (sscanf(tmpbuf, "%d", &value) != 1 || value > 2)
		return -EINVAL;

	cs->common.SuppressEnclosureMessages = value;
	return count;
}
static DEVICE_ATTR(disable_enclosure_messages, S_IRUGO | S_IWUSR,
		   myrs_show_suppress_enclosure_messages,
		   myrs_store_suppress_enclosure_messages);

static struct device_attribute *myrs_shost_attrs[] = {
	&dev_attr_serial,
	&dev_attr_myr_num,
	&dev_attr_processor,
	&dev_attr_firmware,
	&dev_attr_discovery,
	&dev_attr_flush_cache,
	&dev_attr_disable_enclosure_messages,
	NULL,
};

struct scsi_host_template myrs_template = {
	.module = THIS_MODULE,
	.name = "DAC960",
	.proc_name = "myrs",
	.queuecommand = myrs_queuecommand,
	.eh_host_reset_handler = myrs_host_reset,
	.slave_alloc = myrs_slave_alloc,
	.slave_configure = myrs_slave_configure,
	.slave_destroy = myrs_slave_destroy,
	.cmd_size = sizeof(myrs_cmdblk),
	.shost_attrs = myrs_shost_attrs,
	.sdev_attrs = myr_sdev_attrs,
	.this_id = -1,
};

/**
 * myr_is_raid - return boolean indicating device is raid volume
 * @dev the device struct object
 */
static int
myr_is_raid(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;

	return (sdev->channel >= cs->common.PhysicalChannelCount) ? 1 : 0;
}

/**
 * myrs_get_resync - get raid volume resync percent complete
 * @dev the device struct object
 */
static void
myrs_get_resync(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info = sdev->hostdata;
	u8 percent_complete = 0, status;

	if (sdev->channel < cs->common.PhysicalChannelCount || !ldev_info)
		return;
	if (ldev_info->RebuildInProgress) {
		unsigned short ldev_num = ldev_info->LogicalDeviceNumber;

		status = DAC960_V2_NewLogicalDeviceInfo(cs, ldev_num,
							ldev_info);
		percent_complete = ldev_info->RebuildBlockNumber * 100 /
			ldev_info->ConfigurableDeviceSize;
	}
	raid_set_resync(myrs_raid_template, dev, percent_complete);
}

/**
 * myrs_get_state - get raid volume status
 * @dev the device struct object
 */
static void
myrs_get_state(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrs_hba *cs = (myrs_hba *)sdev->host->hostdata;
	myrs_ldev_info *ldev_info = sdev->hostdata;
	enum raid_state state = RAID_STATE_UNKNOWN;

	if (sdev->channel < cs->common.PhysicalChannelCount || !ldev_info)
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
	raid_set_state(myrs_raid_template, dev, state);
}

struct raid_function_template myrs_raid_functions = {
	.cookie		= &myrs_template,
	.is_raid	= myr_is_raid,
	.get_resync	= myrs_get_resync,
	.get_state	= myrs_get_state,
};

myr_hba *myrs_alloc_host(struct pci_dev *pdev,
			 const struct pci_device_id *entry)
{
	struct Scsi_Host *shost;
	myrs_hba *cs;
	myr_hba *c;

	shost = scsi_host_alloc(&myrs_template, sizeof(myrs_hba));
	if (!shost)
		return NULL;

	shost->max_cmd_len = 16;
	shost->max_lun = 256;
	cs = (myrs_hba *)shost->hostdata;
	mutex_init(&cs->dcmd_mutex);
	mutex_init(&cs->cinfo_mutex);

	c = &cs->common;
	c->host = shost;

	return c;
}

void myrs_flush_cache(myr_hba *c)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);

	DAC960_V2_DeviceOperation(cs, DAC960_V2_PauseDevice,
				  DAC960_V2_RAID_Controller);
}

static void myrs_handle_scsi(myrs_hba *cs, myrs_cmdblk *cmd_blk,
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
		pci_pool_free(cs->RequestSensePool, cmd_blk->sense,
			      cmd_blk->sense_addr);
		cmd_blk->sense = NULL;
		cmd_blk->sense_addr = 0;
	}
	if (cmd_blk->DCDB) {
		pci_pool_free(cs->DCDBPool, cmd_blk->DCDB,
			      cmd_blk->DCDB_dma);
		cmd_blk->DCDB = NULL;
		cmd_blk->DCDB_dma = 0;
	}
	if (cmd_blk->sgl) {
		pci_pool_free(cs->common.ScatterGatherPool, cmd_blk->sgl,
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

static void myrs_handle_cmdblk(myrs_hba *cs, myrs_cmdblk *cmd_blk)
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

int DAC960_GEM_HardwareInit(struct pci_dev *pdev,
			    myr_hba *c, void __iomem *base)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_GEM_DisableInterrupts(base);
	DAC960_GEM_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_GEM_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_GEM_ReadErrorStatus(base, &ErrorStatus,
					       &Parameter0, &Parameter1) &&
		    myr_err_status(c, ErrorStatus,
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
	if (!DAC960_V2_EnableMemoryMailboxInterface(cs)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_GEM_ControllerReset(base);
		return -EAGAIN;
	}
	DAC960_GEM_EnableInterrupts(base);
	cs->WriteCommandMailbox = DAC960_GEM_WriteCommandMailbox;
	cs->MailboxNewCommand = DAC960_GEM_MemoryMailboxNewCommand;
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

irqreturn_t DAC960_GEM_InterruptHandler(int IRQ_Channel,
					void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	myrs_hba *cs = container_of(c, myrs_hba, common);
	void __iomem *base = c->io_addr;
	myrs_stat_mbox *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_GEM_AcknowledgeInterrupt(base);
	NextStatusMailbox = cs->NextStatusMailbox;
	while (NextStatusMailbox->id > 0) {
		unsigned short id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myrs_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cs->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cs->mcmd_blk;
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

		memset(NextStatusMailbox, 0, sizeof(myrs_stat_mbox));
		if (++NextStatusMailbox > cs->LastStatusMailbox)
			NextStatusMailbox = cs->FirstStatusMailbox;

		if (id < 3)
			myrs_handle_cmdblk(cs, cmd_blk);
		else
			myrs_handle_scsi(cs, cmd_blk, scmd);
	}
	cs->NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_BA_HardwareInit initializes the hardware for DAC960 BA Series
  Controllers.
*/

int DAC960_BA_HardwareInit(struct pci_dev *pdev,
			   myr_hba *c, void __iomem *base)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_BA_DisableInterrupts(base);
	DAC960_BA_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_BA_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_BA_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    myr_err_status(c, ErrorStatus,
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
	if (!DAC960_V2_EnableMemoryMailboxInterface(cs)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_BA_ControllerReset(base);
		return -EAGAIN;
	}
	DAC960_BA_EnableInterrupts(base);
	cs->WriteCommandMailbox = DAC960_BA_WriteCommandMailbox;
	cs->MailboxNewCommand = DAC960_BA_MemoryMailboxNewCommand;
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

irqreturn_t DAC960_BA_InterruptHandler(int IRQ_Channel,
				       void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	myrs_hba *cs = container_of(c, myrs_hba, common);
	void __iomem *base = c->io_addr;
	myrs_stat_mbox *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_BA_AcknowledgeInterrupt(base);
	NextStatusMailbox = cs->NextStatusMailbox;
	while (NextStatusMailbox->id > 0) {
		unsigned short id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myrs_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cs->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cs->mcmd_blk;
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

		memset(NextStatusMailbox, 0, sizeof(myrs_stat_mbox));
		if (++NextStatusMailbox > cs->LastStatusMailbox)
			NextStatusMailbox = cs->FirstStatusMailbox;

		if (id < 3)
			myrs_handle_cmdblk(cs, cmd_blk);
		else
			myrs_handle_scsi(cs, cmd_blk, scmd);
	}
	cs->NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}


/*
  DAC960_LP_HardwareInit initializes the hardware for DAC960 LP Series
  Controllers.
*/

int DAC960_LP_HardwareInit(struct pci_dev *pdev,
			   myr_hba *c, void __iomem *base)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_LP_DisableInterrupts(base);
	DAC960_LP_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_LP_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_LP_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    myr_err_status(c, ErrorStatus,
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
	if (!DAC960_V2_EnableMemoryMailboxInterface(cs)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_LP_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_LP_EnableInterrupts(base);
	cs->WriteCommandMailbox = DAC960_LP_WriteCommandMailbox;
	cs->MailboxNewCommand = DAC960_LP_MemoryMailboxNewCommand;
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

irqreturn_t DAC960_LP_InterruptHandler(int IRQ_Channel,
				       void *DeviceIdentifier)
{
	myr_hba *c = DeviceIdentifier;
	myrs_hba *cs = container_of(c, myrs_hba, common);
	void __iomem *base = c->io_addr;
	myrs_stat_mbox *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_LP_AcknowledgeInterrupt(base);
	NextStatusMailbox = cs->NextStatusMailbox;
	while (NextStatusMailbox->id > 0) {
		unsigned short id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myrs_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cs->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cs->mcmd_blk;
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

		memset(NextStatusMailbox, 0, sizeof(myrs_stat_mbox));
		if (++NextStatusMailbox > cs->LastStatusMailbox)
			NextStatusMailbox = cs->FirstStatusMailbox;

		if (id < 3)
			myrs_handle_cmdblk(cs, cmd_blk);
		else
			myrs_handle_scsi(cs, cmd_blk, scmd);
	}
	cs->NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}

/*
  DAC960_V2_MonitoringGetHealthStatus queues a Get Health Status Command
  to DAC960 V2 Firmware Controllers.
*/

static unsigned char DAC960_V2_MonitoringGetHealthStatus(myrs_hba *cs)
{
	myrs_cmdblk *cmd_blk = &cs->mcmd_blk;
	myrs_cmd_mbox *mbox = &cmd_blk->mbox;
	myrs_sgl *sgl;
	unsigned char status = cmd_blk->status;

	myrs_reset_cmd(cmd_blk);
	mbox->Common.opcode = DAC960_V2_IOCTL;
	mbox->Common.id = DAC960_MonitoringIdentifier;
	mbox->Common.control.DataTransferControllerToHost = true;
	mbox->Common.control.NoAutoRequestSense = true;
	mbox->Common.dma_size = sizeof(myrs_fwstat);
	mbox->Common.ioctl_opcode = DAC960_V2_GetHealthStatus;
	sgl = &mbox->Common.dma_addr;
	sgl->sge[0].sge_addr = cs->fwstat_addr;
	sgl->sge[0].sge_count = mbox->ControllerInfo.dma_size;
	dev_dbg(&cs->common.host->shost_gendev, "Sending GetHealthStatus\n");
	DAC960_V2_ExecuteCommand(cs, cmd_blk);
	status = cmd_blk->status;

	return status;
}

unsigned long myrs_monitor(myr_hba *c)
{
	myrs_hba *cs = container_of(c, myrs_hba, common);
	myrs_ctlr_info *info = &cs->ctlr_info;
	unsigned int StatusChangeCounter =
		cs->fwstat_buf->StatusChangeCounter;
	unsigned long interval = DAC960_MonitoringTimerInterval;
	unsigned char status;

	status = DAC960_V2_MonitoringGetHealthStatus(cs);

	if (cs->NeedControllerInformation) {
		cs->NeedControllerInformation = false;
		mutex_lock(&cs->cinfo_mutex);
		status = DAC960_V2_NewControllerInfo(cs);
		mutex_unlock(&cs->cinfo_mutex);
	}
	if (cs->fwstat_buf->NextEventSequenceNumber
	    - cs->NextEventSequenceNumber > 0) {
		status = DAC960_V2_MonitorGetEvent(cs);
		if (status == DAC960_V2_NormalCompletion) {
			DAC960_V2_ReportEvent(cs, cs->event_buf);
			cs->NextEventSequenceNumber++;
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
			myrs_ldev_info *ldev_info;
			if (sdev->channel < c->PhysicalChannelCount)
				continue;
			ldev_info = sdev->hostdata;
			if (!ldev_info)
				continue;
			status = DAC960_V2_NewLogicalDeviceInfo(cs,
						ldev_info->LogicalDeviceNumber,
						ldev_info);
		}
		cs->NeedControllerInformation = true;
	}
	if (StatusChangeCounter == cs->StatusChangeCounter &&
	    cs->fwstat_buf->NextEventSequenceNumber
	    == cs->NextEventSequenceNumber &&
	    (cs->NeedControllerInformation == false ||
	     time_before(jiffies, c->PrimaryMonitoringTime
			 + DAC960_MonitoringTimerInterval))) {
		interval = DAC960_SecondaryMonitoringInterval;
	}
	return interval;
}
