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
#include "myr.h"
#include "myrb.h"

static void myrb_monitor(struct work_struct *work);

static struct myrb_devstate_name_entry {
	myrb_devstate state;
	char *name;
} myrb_devstate_name_list[] = {
	{ DAC960_V1_Device_Dead, "Dead" },
	{ DAC960_V1_Device_WriteOnly, "WriteOnly" },
	{ DAC960_V1_Device_Online, "Online" },
	{ DAC960_V1_Device_Critical, "Critical" },
	{ DAC960_V1_Device_Standby, "Standby" },
	{ DAC960_V1_Device_Offline, NULL },
};

static char *myrb_devstate_name(myrb_devstate state)
{
	struct myrb_devstate_name_entry *entry = myrb_devstate_name_list;

	while (entry && entry->name) {
		if (entry->state == state)
			return entry->name;
		entry++;
	}
	return (state == DAC960_V1_Device_Offline) ? "Offline" : "Unknown";
}

static struct myrb_raidlevel_name_entry {
	myrb_raidlevel level;
	char *name;
} myrb_raidlevel_name_list[] = {
	{ DAC960_V1_RAID_Level0, "RAID0" },
	{ DAC960_V1_RAID_Level1, "RAID1" },
	{ DAC960_V1_RAID_Level3, "RAID3" },
	{ DAC960_V1_RAID_Level5, "RAID5" },
	{ DAC960_V1_RAID_Level6, "RAID6" },
	{ DAC960_V1_RAID_JBOD, "JBOD" },
	{ 0xff, NULL }
};

static char *myrb_raidlevel_name(myrb_raidlevel level)
{
	struct myrb_raidlevel_name_entry *entry = myrb_raidlevel_name_list;

	while (entry && entry->name) {
		if (entry->level == level)
			return entry->name;
		entry++;
	}
	return NULL;
}

/*
  DAC960_CreateAuxiliaryStructures allocates and initializes the auxiliary
  data structures for Controller.  It returns true on success and false on
  failure.
*/

bool myrb_create_mempools(struct pci_dev *pdev, myr_hba *c)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);
	size_t elem_size, elem_align;

	elem_align = sizeof(myrb_sge);
	elem_size = c->host->sg_tablesize * elem_align;
	cb->sg_pool = pci_pool_create("myrb_sg", pdev,
				      elem_size, elem_align, 0);
	if (cb->sg_pool == NULL) {
		shost_printk(KERN_ERR, c->host,
			     "Failed to allocate SG pool\n");
		return false;
	}

	cb->dcdb_pool = pci_pool_create("myrb_dcdb", pdev,
				       sizeof(myrb_dcdb),
				       sizeof(unsigned int), 0);
	if (!cb->dcdb_pool) {
		pci_pool_destroy(cb->sg_pool);
		cb->sg_pool = NULL;
		shost_printk(KERN_ERR, c->host,
			     "Failed to allocate DCDB pool\n");
		return false;
	}

	snprintf(cb->work_q_name, sizeof(cb->work_q_name),
		 "myrs_wq_%d", c->host->host_no);
	cb->work_q = create_singlethread_workqueue(cb->work_q_name);
	if (!cb->work_q) {
		pci_pool_destroy(cb->dcdb_pool);
		cb->dcdb_pool = NULL;
		pci_pool_destroy(cb->sg_pool);
		cb->sg_pool = NULL;
		shost_printk(KERN_ERR, c->host,
			     "Failed to create workqueue\n");
		return false;
	}

	/*
	  Initialize the Monitoring Timer.
	*/
	INIT_DELAYED_WORK(&cb->monitor_work, myrb_monitor);
	queue_delayed_work(cb->work_q, &cb->monitor_work, 1);

	return true;
}

void myrb_destroy_mempools(myr_hba *c)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);

	cancel_delayed_work_sync(&cb->monitor_work);
	destroy_workqueue(cb->work_q);

	if (cb->sg_pool != NULL)
		pci_pool_destroy(cb->sg_pool);

	if (cb->dcdb_pool) {
		pci_pool_destroy(cb->dcdb_pool);
		cb->dcdb_pool = NULL;
	}
}

/*
  myrb_reset_cmd clears critical fields of Command for DAC960 V1
  Firmware Controllers.
*/

static inline void myrb_reset_cmd(myrb_cmdblk *cmd_blk)
{
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;

	memset(mbox, 0, sizeof(myrb_cmd_mbox));
	cmd_blk->status = 0;
}


/*
 * myrb_qcmd queues Command for DAC960 V1 Series Controller
 */

static void myrb_qcmd(myrb_hba *cb, myrb_cmdblk *cmd_blk)
{
	void __iomem *base = cb->common.io_addr;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	myrb_cmd_mbox *next_mbox = cb->NextCommandMailbox;

	cb->WriteCommandMailbox(next_mbox, mbox);
	if (cb->PreviousCommandMailbox1->Words[0] == 0 ||
	    cb->PreviousCommandMailbox2->Words[0] == 0)
		cb->MailboxNewCommand(base);
	cb->PreviousCommandMailbox2 = cb->PreviousCommandMailbox1;
	cb->PreviousCommandMailbox1 = next_mbox;
	if (++next_mbox > cb->LastCommandMailbox)
		next_mbox = cb->FirstCommandMailbox;
	cb->NextCommandMailbox = next_mbox;
}

/*
 * myrb_exec_cmd executes V1 Command and waits for completion.
 */

static void myrb_exec_cmd(myrb_hba *cb, myrb_cmdblk *cmd_blk)
{
	DECLARE_COMPLETION_ONSTACK(Completion);
	unsigned long flags;

	cmd_blk->Completion = &Completion;

	spin_lock_irqsave(&cb->common.queue_lock, flags);
	cb->QueueCommand(cb, cmd_blk);
	spin_unlock_irqrestore(&cb->common.queue_lock, flags);

	if (in_interrupt())
		return;
	wait_for_completion(&Completion);
}

/*
  myrb_exec_type3 executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short myrb_exec_type3(myrb_hba *cb,
				      myrb_cmd_opcode op,
				      dma_addr_t addr)
{
	myrb_cmdblk *cmd_blk = &cb->dcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&cb->dcmd_mutex);
	myrb_reset_cmd(cmd_blk);
	mbox->Type3.id = DAC960_DirectCommandIdentifier;
	mbox->Type3.opcode = op;
	mbox->Type3.addr = addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cb->dcmd_mutex);
	return status;
}


/*
  myrb_exec_type3B executes a DAC960 V1 Firmware Controller Type 3B
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short myrb_exec_type3B(myrb_hba *cb,
					      myrb_cmd_opcode op,
					      unsigned char CommandOpcode2,
					      dma_addr_t DataDMA)
{
	myrb_cmdblk *cmd_blk = &cb->dcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&cb->dcmd_mutex);
	myrb_reset_cmd(cmd_blk);
	mbox->Type3B.id = DAC960_DirectCommandIdentifier;
	mbox->Type3B.opcode = op;
	mbox->Type3B.CommandOpcode2 = CommandOpcode2;
	mbox->Type3B.addr = DataDMA;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cb->dcmd_mutex);
	return status;
}


/*
  myrb_exec_type3D executes a DAC960 V1 Firmware Controller Type 3D
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short myrb_exec_type3D(myrb_hba *cb,
				       myrb_cmd_opcode op,
				       struct scsi_device *sdev,
				       myrb_pdev_state *pdev_info)
{
	myr_hba *c = &cb->common;
	myrb_cmdblk *cmd_blk = &cb->dcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;
	dma_addr_t pdev_info_addr;

	pdev_info_addr = dma_map_single(&c->pdev->dev, pdev_info,
					sizeof(myrb_pdev_state),
					DMA_FROM_DEVICE);
	if (dma_mapping_error(&c->pdev->dev, pdev_info_addr))
		return DAC960_V1_SubsystemFailed;

	mutex_lock(&cb->dcmd_mutex);
	myrb_reset_cmd(cmd_blk);
	mbox->Type3D.id = DAC960_DirectCommandIdentifier;
	mbox->Type3D.opcode = op;
	mbox->Type3D.Channel = sdev->channel;
	mbox->Type3D.TargetID = sdev->id;
	mbox->Type3D.addr = pdev_info_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cb->dcmd_mutex);
	dma_unmap_single(&c->pdev->dev, pdev_info_addr,
			 sizeof(myrb_pdev_state), DMA_FROM_DEVICE);
	if (status == DAC960_V1_NormalCompletion &&
	    mbox->Type3D.opcode == DAC960_V1_GetDeviceState_Old)
		DAC960_P_To_PD_TranslateDeviceState(pdev_info);

	return status;
}


/*
  DAC960_V1_GetEventLog executes a DAC960 V1 Firmware Controller Type 3E
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short DAC960_V1_MonitorGetEventLog(myrb_hba *cb,
						   unsigned int event)
{
	myrb_cmdblk *cmd_blk = &cb->mcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
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

	myrb_reset_cmd(cmd_blk);
	mbox->Type3E.id = DAC960_MonitoringIdentifier;
	mbox->Type3E.opcode = DAC960_V1_PerformEventLogOperation;
	mbox->Type3E.optype = DAC960_V1_GetEventLogEntry;
	mbox->Type3E.opqual = 1;
	mbox->Type3E.ev_seq = event;
	mbox->Type3E.addr = cb->ev_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		if (cb->ev_buf->SequenceNumber == event) {
			struct scsi_sense_hdr sshdr;

			memset(&sshdr, 0, sizeof(sshdr));
			scsi_normalize_sense(cb->ev_buf->SenseData, 32,
					     &sshdr);

			if (sshdr.sense_key == VENDOR_SPECIFIC &&
			    sshdr.asc == 0x80 &&
			    sshdr.ascq < ARRAY_SIZE(DAC960_EventMessages)) {
				shost_printk(KERN_CRIT, cb->common.host,
					     "Physical drive %d:%d: %s\n",
					     cb->ev_buf->Channel,
					     cb->ev_buf->TargetID,
					     DAC960_EventMessages[sshdr.ascq]);
			} else {
				shost_printk(KERN_CRIT, cb->common.host,
					     "Physical drive %d:%d: "
					     "Sense: %X/%02X/%02X\n",
					     cb->ev_buf->Channel,
					     cb->ev_buf->TargetID,
					     sshdr.sense_key,
					     sshdr.asc, sshdr.ascq);
			}
		}
	} else
		shost_printk(KERN_INFO, cb->common.host,
			     "Failed to get event log %d, status %04x\n",
			     event, status);

	return status;
}

/*
  DAC960_V1_GetErrorTable executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static void DAC960_V1_MonitorGetErrorTable(myrb_hba *cb)
{
	myr_hba *c = &cb->common;
	myrb_cmdblk *cmd_blk = &cb->mcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;
	myrb_error_table old_table;

	memcpy(&old_table, cb->err_table, sizeof(myrb_error_table));

	myrb_reset_cmd(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetErrorTable;
	mbox->Type3.addr = cb->err_table_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		myrb_error_table *table = cb->err_table;
		myrb_error_entry *new_entry, *old_entry;
		struct scsi_device *sdev;

		shost_for_each_device(sdev, c->host) {
			if (sdev->channel >= c->PhysicalChannelCount)
				continue;
			new_entry = &table->entries[sdev->channel][sdev->id];
			old_entry = &old_table.entries[sdev->channel][sdev->id];
			if ((new_entry->parity_err != old_entry->parity_err) ||
			    (new_entry->soft_err != old_entry->soft_err) ||
			    (new_entry->hard_err != old_entry->hard_err) ||
			    (new_entry->misc_err !=
			     old_entry->misc_err))
				sdev_printk(KERN_CRIT, sdev,
					    "Errors: "
					    "Parity = %d, Soft = %d, "
					    "Hard = %d, Misc = %d\n",
					    new_entry->parity_err,
					    new_entry->soft_err,
					    new_entry->hard_err,
					    new_entry->misc_err);
		}
	}
}

/*
  myrb_get_ldev_info executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static unsigned short myrb_get_ldev_info(myrb_hba *cb)
{
	unsigned short status;
	int ldev_num, ldev_cnt = cb->enquiry->ldev_count;
	int pdev_cnt = cb->common.PhysicalChannelCount;
	struct Scsi_Host *shost = cb->common.host;

	status = myrb_exec_type3(cb, DAC960_V1_GetLogicalDeviceInfo,
				 cb->ldev_info_addr);
	if (status != DAC960_V1_NormalCompletion)
		return status;

	for (ldev_num = 0; ldev_num < ldev_cnt; ldev_num++) {
		myrb_ldev_info *old = NULL;
		myrb_ldev_info *new = cb->ldev_info_buf[ldev_num];
		struct scsi_device *sdev;
		unsigned short ldev_num;
		myrb_devstate old_state = DAC960_V1_Device_Offline;

		sdev = scsi_device_lookup(shost, pdev_cnt, ldev_num, 0);
		if (sdev && sdev->hostdata)
			old = sdev->hostdata;
		else {
			shost_printk(KERN_INFO, shost,
				     "Adding Logical Drive %d in state %s\n",
				     ldev_num, myrb_devstate_name(new->State));
			scsi_add_device(shost, pdev_cnt, ldev_num, 0);
			break;
		}
		if (old)
			old_state = old->State;
		if (new->State != old_state)
			shost_printk(KERN_INFO, shost,
				     "Logical Drive %d is now %s\n",
				     ldev_num, myrb_devstate_name(new->State));
		if (old && new->WriteBack != old->WriteBack)
			sdev_printk(KERN_INFO, sdev,
				    "Logical Drive is now WRITE %s\n",
				    (new->WriteBack ? "BACK" : "THRU"));
		if (old)
			memcpy(old, new, sizeof(*new));
	}
	return status;
}


/*
  DAC960_V1_RebuildProgress executes a DAC960 V1 Firmware Controller Type 3
  Command and waits for completion.  It returns true on success and false
  on failure.
*/

static void DAC960_V1_MonitorRebuildProgress(myrb_hba *cb)
{
	myr_hba *c = &cb->common;
	myrb_cmdblk *cmd_blk = &cb->mcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;

	myrb_reset_cmd(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetRebuildProgress;
	mbox->Type3.addr = cb->rbld_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		unsigned int ldev_num = cb->rbld->ldev_num;
		unsigned int ldev_size = cb->rbld->ldev_size;
		unsigned int blocks_done =
			ldev_size - cb->rbld->blocks_left;
		struct scsi_device *sdev;

		sdev = scsi_device_lookup(c->host,
					  c->PhysicalChannelCount,
					  ldev_num, 0);
		if (status == DAC960_V1_NoRebuildOrCheckInProgress &&
		    cb->last_rbld_status == DAC960_V1_NormalCompletion)
			status = DAC960_V1_RebuildSuccessful;
		switch (status) {
		case DAC960_V1_NormalCompletion:
			sdev_printk(KERN_INFO, sdev,
				     "Rebuild in Progress, "
				     "%d%% completed\n",
				     (100 * (blocks_done >> 7))
				     / (ldev_size >> 7));
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
		cb->last_rbld_status = status;
	}
}


/*
  DAC960_V1_ConsistencyCheckProgress executes a DAC960 V1 Firmware Controller
  Type 3 Command and waits for completion.
*/

static void DAC960_V1_ConsistencyCheckProgress(myrb_hba *cb)
{
	myr_hba *c = &cb->common;
	myrb_cmdblk *cmd_blk = &cb->mcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;

	myrb_reset_cmd(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_RebuildStat;
	mbox->Type3.addr = cb->rbld_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		unsigned int ldev_num = cb->rbld->ldev_num;
		unsigned int ldev_size = cb->rbld->ldev_size;
		unsigned int blocks_done =
			ldev_size - cb->rbld->blocks_left;
		struct scsi_device *sdev;

		sdev = scsi_device_lookup(c->host, c->PhysicalChannelCount,
					  ldev_num, 0);
		sdev_printk(KERN_INFO, sdev,
			    "Consistency Check in Progress: %d%% completed\n",
			    (100 * (blocks_done >> 7))
			    / (ldev_size >> 7));
	}
}


/*
  myrb_bgi_control executes a DAC960 V1 Firmware Controller
  Type 3B Command and waits for completion.
*/

static void myrb_bgi_control(myrb_hba *cb)
{
	myr_hba *c = &cb->common;
	myrb_cmdblk *cmd_blk = &cb->mcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	myrb_bgi_status *bgi, *last_bgi;
	struct scsi_device *sdev;
	unsigned short status;

	myrb_reset_cmd(cmd_blk);
	mbox->Type3B.id = DAC960_DirectCommandIdentifier;
	mbox->Type3B.opcode = DAC960_V1_BackgroundInitializationControl;
	mbox->Type3B.CommandOpcode2 = 0x20;
	mbox->Type3B.addr = cb->bgi_status_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	bgi = cb->bgi_status_buf;
	last_bgi = &cb->bgi_status_old;
	sdev = scsi_device_lookup(c->host, c->PhysicalChannelCount,
				  bgi->ldev_num, 0);
	switch (status) {
	case DAC960_V1_NormalCompletion:
		switch (bgi->Status) {
		case MYRB_BGI_INVALID:
			break;
		case MYRB_BGI_STARTED:
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Started\n");
			break;
		case MYRB_BGI_INPROGRESS:
			if (bgi->blocks_done == last_bgi->blocks_done &&
			    bgi->ldev_num == last_bgi->ldev_num)
				break;
			sdev_printk(KERN_INFO, sdev,
				 "Background Initialization in Progress: "
				 "%d%% completed\n",
				 (100 * (bgi->blocks_done >> 7))
				 / (bgi->ldev_size >> 7));
			break;
		case MYRB_BGI_SUSPENDED:
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Suspended\n");
			break;
		case MYRB_BGI_CANCELLED:
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Cancelled\n");
			break;
		}
		memcpy(&cb->bgi_status_old, cb->bgi_status_buf,
		       sizeof(myrb_bgi_status));
		break;
	case DAC960_V1_BackgroundInitSuccessful:
		if (bgi->Status == MYRB_BGI_INPROGRESS)
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization "
				    "Completed Successfully\n");
		bgi->Status = MYRB_BGI_INVALID;
		break;
	case DAC960_V1_BackgroundInitAborted:
		if (bgi->Status ==  MYRB_BGI_INPROGRESS)
			sdev_printk(KERN_INFO, sdev,
				    "Background Initialization Aborted\n");
		bgi->Status = MYRB_BGI_INVALID;
		break;
	case DAC960_V1_NoBackgroundInitInProgress:
		break;
	}
}

/*
  myrb_hba_enquiry executes a DAC960 V1 Firmware Controller
  Type 3 Command and waits for completion.
*/

static unsigned short myrb_hba_enquiry(myrb_hba *cb)
{
	myr_hba *c = &cb->common;
	myrb_enquiry old;
	dma_addr_t enquiry_addr;
	unsigned short status;

	memcpy(&old, cb->enquiry, sizeof(myrb_enquiry));

	enquiry_addr = dma_map_single(&c->pdev->dev, cb->enquiry,
				      sizeof(myrb_enquiry), DMA_FROM_DEVICE);
	if (dma_mapping_error(&c->pdev->dev, enquiry_addr))
		return DAC960_V1_SubsystemFailed;

	status = myrb_exec_type3(cb, DAC960_V1_Enquiry, enquiry_addr);
	if (status == DAC960_V1_NormalCompletion) {
		myrb_enquiry *new = cb->enquiry;
		if (new->ldev_count > old.ldev_count) {
			int ldev_num = old.ldev_count - 1;
			while (++ldev_num < new->ldev_count)
				shost_printk(KERN_CRIT, c->host,
					"Logical Drive %d Now Exists\n",
					 ldev_num);
		}
		if (new->ldev_count < old.ldev_count) {
			int ldev_num = new->ldev_count - 1;
			while (++ldev_num < old.ldev_count)
				shost_printk(KERN_CRIT, c->host,
					 "Logical Drive %d No Longer Exists\n",
					 ldev_num);
		}
		if (new->status.deferred != old.status.deferred)
			shost_printk(KERN_CRIT, c->host,
				 "Deferred Write Error Flag is now %s\n",
				 (new->status.deferred ? "TRUE" : "FALSE"));
		if (new->ev_seq != old.ev_seq) {
			cb->new_ev_seq = new->ev_seq;
			cb->need_err_info = true;
			shost_printk(KERN_INFO, c->host,
				     "Event log %d/%d (%d/%d) available\n",
				     cb->old_ev_seq, cb->new_ev_seq,
				     old.ev_seq, new->ev_seq);
		}
		if ((new->ldev_critical > 0 ||
		     new->ldev_critical != old.ldev_critical) ||
		    (new->ldev_offline > 0 ||
		     new->ldev_offline != old.ldev_offline) ||
		    (new->ldev_count != old.ldev_count)) {
			shost_printk(KERN_INFO, c->host,
				     "Logical drive count changed (%d/%d/%d)\n",
				     new->ldev_critical,
				     new->ldev_offline,
				     new->ldev_count);
			cb->need_ldev_info = true;
		}
		if ((new->pdev_dead > 0 ||
		     new->pdev_dead != old.pdev_dead) ||
		    time_after_eq(jiffies, cb->secondary_monitor_time
				  + DAC960_SecondaryMonitoringInterval)) {
			cb->need_bgi_status = cb->bgi_status_supported;
			cb->secondary_monitor_time = jiffies;
		}
		if (new->rbld == DAC960_V1_StandbyRebuildInProgress ||
		    new->rbld == DAC960_V1_BackgroundRebuildInProgress ||
		    old.rbld == DAC960_V1_StandbyRebuildInProgress ||
		    old.rbld == DAC960_V1_BackgroundRebuildInProgress) {
			cb->need_rbld = true;
			cb->rbld_first = (new->ldev_critical < old.ldev_critical);
		}
		if (old.rbld == DAC960_V1_BackgroundCheckInProgress)
			switch (new->rbld) {
			case DAC960_V1_NoStandbyRebuildOrCheckInProgress:
				shost_printk(KERN_INFO, c->host,
					 "Consistency Check Completed Successfully\n");
				break;
			case DAC960_V1_StandbyRebuildInProgress:
			case DAC960_V1_BackgroundRebuildInProgress:
				break;
			case DAC960_V1_BackgroundCheckInProgress:
				cb->need_cc_status = true;
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
		else if (new->rbld == DAC960_V1_BackgroundCheckInProgress)
			cb->need_cc_status = true;

	}
	return status;
}

/*
  DAC960_V1_SetDeviceState sets the Device State for a Physical Device for
  DAC960 V1 Firmware Controllers.
*/

static unsigned short DAC960_V1_SetDeviceState(myrb_hba *cb,
					       struct scsi_device *sdev,
					       myrb_devstate State)
{
	myrb_cmdblk *cmd_blk = &cb->dcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short status;

	mutex_lock(&cb->dcmd_mutex);
	mbox->Type3D.opcode = DAC960_V1_StartDevice;
	mbox->Type3D.id = DAC960_DirectCommandIdentifier;
	mbox->Type3D.Channel = sdev->channel;
	mbox->Type3D.TargetID = sdev->id;
	mbox->Type3D.State = State & 0x1F;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	mutex_unlock(&cb->dcmd_mutex);

	return status;
}

/*
  DAC960_V1_EnableMemoryMailboxInterface enables the Memory Mailbox Interface
  for DAC960 V1 Firmware Controllers.

  PD and P controller types have no memory mailbox, but still need the
  other dma mapped memory.
*/

static bool DAC960_V1_EnableMemoryMailboxInterface(myrb_hba *cb)
{
	myr_hba *c = &cb->common;
	void __iomem *base = c->io_addr;
	DAC960_HardwareType_T hw_type = c->HardwareType;
	struct pci_dev *pdev = c->pdev;
	struct dma_loaf *DmaPages = &c->DmaPages;
	size_t DmaPagesSize;
	size_t CommandMailboxesSize;
	size_t StatusMailboxesSize;

	myrb_cmd_mbox *CommandMailboxesMemory;
	dma_addr_t CommandMailboxesMemoryDMA;

	myrb_stat_mbox *StatusMailboxesMemory;
	dma_addr_t StatusMailboxesMemoryDMA;

	myrb_cmd_mbox mbox;
	unsigned short status;
	int timeout = 0;
	int i;

	memset(&mbox, 0, sizeof(myrb_cmd_mbox));

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		dev_err(&pdev->dev, "DMA mask out of range\n");
		return false;
	}

	if ((hw_type == DAC960_PD_Controller) || (hw_type == DAC960_P_Controller)) {
		CommandMailboxesSize =  0;
		StatusMailboxesSize = 0;
	} else {
		CommandMailboxesSize =  DAC960_V1_CommandMailboxCount * sizeof(myrb_cmd_mbox);
		StatusMailboxesSize = DAC960_V1_StatusMailboxCount * sizeof(myrb_stat_mbox);
	}
	DmaPagesSize = CommandMailboxesSize + StatusMailboxesSize +
		sizeof(myrb_dcdb) +
		sizeof(myrb_error_table) + sizeof(myrb_log_entry) +
		sizeof(myrb_rbld_progress) +
		sizeof(myrb_ldev_info_arr) +
		sizeof(myrb_bgi_status) +
		sizeof(myrb_pdev_state);

	if (!init_dma_loaf(pdev, DmaPages, DmaPagesSize))
		return false;


	if ((hw_type == DAC960_PD_Controller) || (hw_type == DAC960_P_Controller))
		goto skip_mailboxes;

	CommandMailboxesMemory = slice_dma_loaf(DmaPages,
						CommandMailboxesSize, &CommandMailboxesMemoryDMA);

	/* These are the base addresses for the command memory mailbox array */
	cb->FirstCommandMailbox = CommandMailboxesMemory;
	cb->FirstCommandMailboxDMA = CommandMailboxesMemoryDMA;

	CommandMailboxesMemory += DAC960_V1_CommandMailboxCount - 1;
	cb->LastCommandMailbox = CommandMailboxesMemory;
	cb->NextCommandMailbox = cb->FirstCommandMailbox;
	cb->PreviousCommandMailbox1 = cb->LastCommandMailbox;
	cb->PreviousCommandMailbox2 = cb->LastCommandMailbox - 1;

	/* These are the base addresses for the status memory mailbox array */
	StatusMailboxesMemory = slice_dma_loaf(DmaPages,
					       StatusMailboxesSize, &StatusMailboxesMemoryDMA);

	cb->FirstStatusMailbox = StatusMailboxesMemory;
	cb->FirstStatusMailboxDMA = StatusMailboxesMemoryDMA;
	StatusMailboxesMemory += DAC960_V1_StatusMailboxCount - 1;
	cb->LastStatusMailbox = StatusMailboxesMemory;
	cb->NextStatusMailbox = cb->FirstStatusMailbox;

skip_mailboxes:
	cb->enquiry = kzalloc(sizeof(myrb_enquiry), GFP_KERNEL | GFP_DMA);
	if (!cb->enquiry) {
		/* XXX error handling ! */
		return false;
	}

	cb->err_table = slice_dma_loaf(DmaPages, sizeof(myrb_error_table),
				       &cb->err_table_addr);

	cb->ev_buf = slice_dma_loaf(DmaPages, sizeof(myrb_log_entry),
				    &cb->ev_addr);

	cb->rbld = slice_dma_loaf(DmaPages, sizeof(myrb_rbld_progress),
				  &cb->rbld_addr);

	cb->ldev_info_buf = slice_dma_loaf(DmaPages, sizeof(myrb_ldev_info_arr),
					   &cb->ldev_info_addr);

	cb->bgi_status_buf = slice_dma_loaf(DmaPages, sizeof(myrb_bgi_status),
					    &cb->bgi_status_addr);

	if ((hw_type == DAC960_PD_Controller) || (hw_type == DAC960_P_Controller))
		return true;

	/* Enable the Memory Mailbox Interface. */
	cb->dual_mode_interface = true;
	mbox.TypeX.opcode = 0x2B;
	mbox.TypeX.id = 0;
	mbox.TypeX.CommandOpcode2 = 0x14;
	mbox.TypeX.CommandMailboxesBusAddress = cb->FirstCommandMailboxDMA;
	mbox.TypeX.StatusMailboxesBusAddress = cb->FirstStatusMailboxDMA;

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
			cb->dual_mode_interface = false;
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
			cb->dual_mode_interface = false;
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
  DAC960_V1_ReadControllerConfiguration reads the Configuration Information
  from DAC960 V1 Firmware Controllers and initializes the Controller structure.
*/

static int DAC960_V1_ReadControllerConfiguration(myr_hba *c)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);
	myrs_enquiry2 *enquiry2;
	dma_addr_t enquiry2_addr;
	myrb_config2 *config2;
	dma_addr_t config2_addr;
	struct Scsi_Host *shost = c->host;
	struct pci_dev *pdev = c->pdev;
	unsigned short status;
	int ret = -ENODEV, memsize;

	enquiry2 = dma_alloc_coherent(&pdev->dev, sizeof(myrs_enquiry2),
				      &enquiry2_addr, GFP_KERNEL);
	if (dma_mapping_error(&pdev->dev, enquiry2_addr)) {
		shost_printk(KERN_ERR, c->host,
			     "Failed to allocate V1 enquiry2 memory\n");
		return -ENOMEM;
	}
	config2 = dma_alloc_coherent(&pdev->dev, sizeof(myrb_config2),
				     &config2_addr, GFP_KERNEL);
	if (dma_mapping_error(&pdev->dev, config2_addr)) {
		shost_printk(KERN_ERR, c->host,
			     "Failed to allocate V1 config2 memory\n");
		dma_free_coherent(&pdev->dev, sizeof(myrs_enquiry2),
				  enquiry2, enquiry2_addr);
		return -ENOMEM;
	}
	mutex_lock(&cb->dma_mutex);
	status = myrb_hba_enquiry(cb);
	mutex_unlock(&cb->dma_mutex);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed it issue V1 Enquiry\n");
		goto out;
	}

	status = myrb_exec_type3(cb, DAC960_V1_Enquiry2, enquiry2_addr);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed to issue V1 Enquiry2\n");
		goto out;
	}

	status = myrb_exec_type3(cb, DAC960_V1_ReadConfig2, config2_addr);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed to issue ReadConfig2\n");
		goto out;
	}

	status = myrb_get_ldev_info(cb);
	if (status != DAC960_V1_NormalCompletion) {
		shost_printk(KERN_WARNING, c->host,
			     "Failed to get logical drive information\n");
		goto out;
	}

	/*
	  Initialize the Controller Model Name and Full Model Name fields.
	*/
	switch (enquiry2->hw.SubModel) {
	case DAC960_V1_P_PD_PU:
		if (enquiry2->SCSICapability.BusSpeed == DAC960_V1_Ultra)
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
			     enquiry2->hw.SubModel);
		goto out;
	}
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

	if (enquiry2->fw.MajorVersion == 0) {
		enquiry2->fw.MajorVersion = cb->enquiry->fw_major_version;
		enquiry2->fw.MinorVersion = cb->enquiry->fw_minor_version;
		enquiry2->fw.FirmwareType = '0';
		enquiry2->fw.TurnID = 0;
	}
	sprintf(c->FirmwareVersion, "%d.%02d-%c-%02d",
		enquiry2->fw.MajorVersion,
		enquiry2->fw.MinorVersion,
		enquiry2->fw.FirmwareType,
		enquiry2->fw.TurnID);
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
	switch (enquiry2->hw.Model) {
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
		c->PhysicalChannelMax = enquiry2->cfg_chan;
		break;
	}
	c->PhysicalChannelCount = enquiry2->cur_chan;
	if (enquiry2->SCSICapability.BusWidth == DAC960_V1_Wide_32bit)
		cb->BusWidth = 32;
	else if (enquiry2->SCSICapability.BusWidth == DAC960_V1_Wide_16bit)
		cb->BusWidth = 16;
	else
		cb->BusWidth = 8;
	cb->ldev_block_size = enquiry2->ldev_block_size;
	shost->max_channel = c->PhysicalChannelCount + 1;
	shost->max_id = enquiry2->max_targets;
	memsize = enquiry2->mem_size >> 20;
	cb->safte_enabled = (enquiry2->FaultManagementType == DAC960_V1_SAFTE);
	/*
	  Initialize the Controller Queue Depth, Driver Queue Depth, Logical Drive
	  Count, Maximum Blocks per Command, Controller Scatter/Gather Limit, and
	  Driver Scatter/Gather Limit.  The Driver Queue Depth must be at most one
	  less than the Controller Queue Depth to allow for an automatic drive
	  rebuild operation.
	*/
	shost->can_queue = cb->enquiry->max_tcq;
	if (shost->can_queue < 3)
		shost->can_queue = enquiry2->max_cmds;
	if (shost->can_queue < 3)
		/* Play safe and disable TCQ */
		shost->can_queue = 1;

	if (shost->can_queue > DAC960_MaxDriverQueueDepth)
		shost->can_queue = DAC960_MaxDriverQueueDepth;
	shost->max_sectors = enquiry2->max_sectors;
	shost->sg_tablesize = enquiry2->max_sge;
	if (shost->sg_tablesize > DAC960_V1_ScatterGatherLimit)
		shost->sg_tablesize = DAC960_V1_ScatterGatherLimit;
	/*
	  Initialize the Stripe Size, Segment Size, and Geometry Translation.
	*/
	cb->StripeSize = config2->BlocksPerStripe * config2->BlockFactor
		>> (10 - DAC960_BlockSizeBits);
	cb->SegmentSize = config2->BlocksPerCacheLine * config2->BlockFactor
		>> (10 - DAC960_BlockSizeBits);
	switch (config2->DriveGeometry) {
	case DAC960_V1_Geometry_128_32:
		cb->GeometryTranslationHeads = 128;
		cb->GeometryTranslationSectors = 32;
		break;
	case DAC960_V1_Geometry_255_63:
		cb->GeometryTranslationHeads = 255;
		cb->GeometryTranslationSectors = 63;
		break;
	default:
		shost_printk(KERN_WARNING, c->host,
			     "Invalid config2 drive geometry %x\n",
			     config2->DriveGeometry);
		goto out;
	}
	/*
	  Initialize the Background Initialization Status.
	*/
	if ((c->FirmwareVersion[0] == '4' &&
	     strcmp(c->FirmwareVersion, "4.08") >= 0) ||
	    (c->FirmwareVersion[0] == '5' &&
	     strcmp(c->FirmwareVersion, "5.08") >= 0)) {
		cb->bgi_status_supported = true;
		myrb_exec_type3B(cb, DAC960_V1_BackgroundInitializationControl,
				 0x20, cb->bgi_status_addr);
		memcpy(&cb->bgi_status_old, cb->bgi_status_buf,
		       sizeof(myrb_bgi_status));
	}
	cb->last_rbld_status = DAC960_V1_NoRebuildOrCheckInProgress;
	ret = 0;

out:
	dma_free_coherent(&pdev->dev, sizeof(myrs_enquiry2),
			  enquiry2, enquiry2_addr);
	dma_free_coherent(&pdev->dev, sizeof(myrb_config2),
			  config2, config2_addr);

	shost_printk(KERN_INFO, c->host,
		"Configuring %s PCI RAID Controller\n", c->ModelName);
	shost_printk(KERN_INFO, c->host,
		"  Firmware Version: %s, Channels: %d, Memory Size: %dMB\n",
		c->FirmwareVersion, c->PhysicalChannelCount, memsize);
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
		c->host->can_queue, c->host->max_sectors);
	shost_printk(KERN_INFO, c->host,
		     "  Driver Queue Depth: %d,"
		     " Scatter/Gather Limit: %d of %d Segments\n",
		     c->host->can_queue, c->host->sg_tablesize,
		     DAC960_V1_ScatterGatherLimit);
	shost_printk(KERN_INFO, c->host,
		     "  Stripe Size: %dKB, Segment Size: %dKB, "
		     "BIOS Geometry: %d/%d%s\n",
		     cb->StripeSize,
		     cb->SegmentSize,
		     cb->GeometryTranslationHeads,
		     cb->GeometryTranslationSectors,
		     cb->safte_enabled ?
		     "  SAF-TE Enclosure Management Enabled" : "");
	shost_printk(KERN_INFO, c->host,
		     "  Physical: %d/%d channels\n",
		     c->PhysicalChannelCount, c->PhysicalChannelMax);

	shost_printk(KERN_INFO, c->host,
		     "  Logical: 1/1 channels, %d disks\n",
		     cb->enquiry->ldev_count);

	return ret;
}


int myrb_host_reset(struct scsi_cmnd *scmd)
{
	struct Scsi_Host *shost = scmd->device->host;
	myrb_hba *cb = (myrb_hba *)shost->hostdata;

	cb->common.Reset(cb->common.io_addr);
	return SUCCESS;
}

static int myrb_pthru_queuecommand(struct Scsi_Host *shost,
					struct scsi_cmnd *scmd)
{
	myrb_hba *cb = (myrb_hba *)shost->hostdata;
	myrb_cmdblk *cmd_blk = scsi_cmd_priv(scmd);
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	myrb_dcdb *dcdb;
	dma_addr_t dcdb_addr;
	struct scsi_device *sdev = scmd->device;
	struct scatterlist *sgl;
	unsigned long flags;
	int nsge;

	myrb_reset_cmd(cmd_blk);
	dcdb = pci_pool_alloc(cb->dcdb_pool, GFP_ATOMIC, &dcdb_addr);
	if (!dcdb)
		return SCSI_MLQUEUE_HOST_BUSY;
	nsge = scsi_dma_map(scmd);
	if (nsge > 1) {
		pci_pool_free(cb->dcdb_pool, dcdb, dcdb_addr);
		scmd->result = (DID_ERROR << 16);
		scmd->scsi_done(scmd);
		return 0;
	}

	mbox->Type3.opcode = DAC960_V1_DCDB;
	mbox->Type3.id = scmd->request->tag + 3;
	mbox->Type3.addr = dcdb_addr;
	dcdb->Channel = sdev->channel;
	dcdb->TargetID = sdev->id;
	switch (scmd->sc_data_direction) {
	case DMA_NONE:
		dcdb->Direction = DAC960_V1_DCDB_NoDataTransfer;
		break;
	case DMA_TO_DEVICE:
		dcdb->Direction = DAC960_V1_DCDB_DataTransferSystemToDevice;
		break;
	case DMA_FROM_DEVICE:
		dcdb->Direction = DAC960_V1_DCDB_DataTransferDeviceToSystem;
		break;
	default:
		dcdb->Direction = DAC960_V1_DCDB_IllegalDataTransfer;
		break;
	}
	dcdb->EarlyStatus = false;
	if (scmd->request->timeout <= 10)
		dcdb->Timeout = DAC960_V1_DCDB_Timeout_10_seconds;
	else if (scmd->request->timeout <= 60)
		dcdb->Timeout = DAC960_V1_DCDB_Timeout_60_seconds;
	else if (scmd->request->timeout <= 600)
		dcdb->Timeout = DAC960_V1_DCDB_Timeout_10_minutes;
	else
		dcdb->Timeout = DAC960_V1_DCDB_Timeout_24_hours;
	dcdb->NoAutomaticRequestSense = false;
	dcdb->DisconnectPermitted = true;
	sgl = scsi_sglist(scmd);
	dcdb->BusAddress = sg_dma_address(sgl);
	if (sg_dma_len(sgl) > USHRT_MAX) {
		dcdb->xfer_len_lo = sg_dma_len(sgl) & 0xffff;
		dcdb->xfer_len_hi4 = sg_dma_len(sgl) >> 16;
	} else {
		dcdb->xfer_len_lo = sg_dma_len(sgl);
		dcdb->xfer_len_hi4 = 0;
	}
	dcdb->CDBLength = scmd->cmd_len;
	dcdb->SenseLength = sizeof(dcdb->SenseData);
	memcpy(&dcdb->CDB, scmd->cmnd, scmd->cmd_len);

	spin_lock_irqsave(&cb->common.queue_lock, flags);
	cb->QueueCommand(cb, cmd_blk);
	spin_unlock_irqrestore(&cb->common.queue_lock, flags);
	return 0;
}

static void myrb_inquiry(myrb_hba *cb,
			 struct scsi_cmnd *scmd)
{
	unsigned char inq[36] = {
		0x00, 0x00, 0x03, 0x02, 0x20, 0x00, 0x01, 0x00,
		0x4d, 0x59, 0x4c, 0x45, 0x58, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20,
	};

	if (cb->BusWidth > 16)
		inq[7] |= 1 << 6;
	if (cb->BusWidth > 8)
		inq[7] |= 1 << 5;
	memcpy(&inq[16], cb->common.ModelName, 16);
	memcpy(&inq[32], cb->common.FirmwareVersion, 4);

	scsi_sg_copy_from_buffer(scmd, (void *)inq, 36);
}

static void
myrb_mode_sense(myrb_hba *cb, struct scsi_cmnd *scmd,
		myrb_ldev_info *ldev_info)
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
		put_unaligned_be32(cb->ldev_block_size, &block_desc[5]);
	}
	mode_pg[0] = 0x08;
	mode_pg[1] = 0x12;
	if (ldev_info->WriteBack)
		mode_pg[2] |= 0x04;
	if (cb->SegmentSize) {
		mode_pg[2] |= 0x08;
		put_unaligned_be16(cb->SegmentSize, &mode_pg[14]);
	}

	scsi_sg_copy_from_buffer(scmd, modes, mode_len);
}

static void myrb_request_sense(myrb_hba *cb,
			       struct scsi_cmnd *scmd)
{
	scsi_build_sense_buffer(0, scmd->sense_buffer,
				NO_SENSE, 0, 0);
	scsi_sg_copy_from_buffer(scmd, scmd->sense_buffer,
				 SCSI_SENSE_BUFFERSIZE);
}

static void myrb_read_capacity(myrb_hba *cb,
			       struct scsi_cmnd *scmd,
			       myrb_ldev_info *ldev_info)
{
	unsigned char data[8];

	dev_dbg(&scmd->device->sdev_gendev,
		"Capacity %u, blocksize %u\n",
		ldev_info->Size, cb->ldev_block_size);
	put_unaligned_be32(ldev_info->Size - 1, &data[0]);
	put_unaligned_be32(cb->ldev_block_size, &data[4]);
	scsi_sg_copy_from_buffer(scmd, data, 8);
}

static int myrb_ldev_queuecommand(struct Scsi_Host *shost,
				  struct scsi_cmnd *scmd)
{
	myrb_hba *cb = (myrb_hba *)shost->hostdata;
	myrb_cmdblk *cmd_blk = scsi_cmd_priv(scmd);
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	myrb_ldev_info *ldev_info;
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
			myrb_inquiry(cb, scmd);
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
			myrb_mode_sense(cb, scmd, ldev_info);
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
		myrb_read_capacity(cb, scmd, ldev_info);
		scmd->scsi_done(scmd);
		return 0;
	case REQUEST_SENSE:
		myrb_request_sense(cb, scmd);
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

	myrb_reset_cmd(cmd_blk);
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

		mbox->Type5.LD.xfer_len = block_cnt;
		mbox->Type5.LD.ldev_num = sdev->id;
		mbox->Type5.lba = lba;
		mbox->Type5.addr = (u32)sg_dma_address(sgl);
	} else {
		myrb_sge *hw_sgl;
		dma_addr_t hw_sgl_addr;
		int i;

		hw_sgl = pci_pool_alloc(cb->sg_pool, GFP_ATOMIC, &hw_sgl_addr);
		if (!hw_sgl)
			return SCSI_MLQUEUE_HOST_BUSY;

		cmd_blk->sgl = hw_sgl;
		cmd_blk->sgl_addr = hw_sgl_addr;

		if (scmd->sc_data_direction == DMA_FROM_DEVICE)
			mbox->Type5.opcode = DAC960_V1_ReadWithScatterGather;
		else
			mbox->Type5.opcode = DAC960_V1_WriteWithScatterGather;

		mbox->Type5.LD.xfer_len = block_cnt;
		mbox->Type5.LD.ldev_num = sdev->id;
		mbox->Type5.lba = lba;
		mbox->Type5.addr = hw_sgl_addr;
		mbox->Type5.sg_count = nsge;

		scsi_for_each_sg(scmd, sgl, nsge, i) {
			hw_sgl->SegmentDataPointer = (u32)sg_dma_address(sgl);
			hw_sgl->SegmentByteCount = (u32)sg_dma_len(sgl);
			hw_sgl++;
		}
	}
submit:
	spin_lock_irqsave(&cb->common.queue_lock, flags);
	cb->QueueCommand(cb, cmd_blk);
	spin_unlock_irqrestore(&cb->common.queue_lock, flags);

	return 0;
}

static int myrb_queuecommand(struct Scsi_Host *shost,
			     struct scsi_cmnd *scmd)
{
	myrb_hba *cb = (myrb_hba *)shost->hostdata;
	struct scsi_device *sdev = scmd->device;

	if (sdev->channel > shost->max_channel) {
		scmd->result = (DID_BAD_TARGET << 16);
		scmd->scsi_done(scmd);
		return 0;
	}
	if (sdev->channel >= cb->common.PhysicalChannelCount)
		return myrb_ldev_queuecommand(shost, scmd);

	return myrb_pthru_queuecommand(shost, scmd);
}

static unsigned short myrb_translate_ldev(myr_hba *c,
					  struct scsi_device *sdev)
{
	unsigned short ldev_num;

	ldev_num = sdev->id +
		(sdev->channel - c->PhysicalChannelCount) * DAC960_V1_MaxTargets;

	return ldev_num;
}

static int myrb_slave_alloc(struct scsi_device *sdev)
{
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	unsigned short status;

	if (sdev->channel > sdev->host->max_channel)
		return -ENXIO;

	if (sdev->lun > 0)
		return -ENXIO;

	if (sdev->channel >= cb->common.PhysicalChannelCount) {
		myrb_ldev_info *ldev_info;
		unsigned short ldev_num;

		ldev_num = myrb_translate_ldev(&cb->common, sdev);
		ldev_info = cb->ldev_info_buf[ldev_num];
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
			raid_set_level(myrb_raid_template,
				       &sdev->sdev_gendev, level);
		}
		return 0;
	} else {
		myrb_pdev_state *pdev_info;

		pdev_info = kzalloc(sizeof(*pdev_info), GFP_KERNEL|GFP_DMA);
		if (!pdev_info)
			return -ENOMEM;

		status = myrb_exec_type3D(cb, DAC960_V1_GetDeviceState,
					  sdev, pdev_info);
		if (status != DAC960_V1_NormalCompletion) {
			dev_dbg(&sdev->sdev_gendev,
				"Failed to get device state, status %x\n",
				status);
			kfree(pdev_info);
			return -ENXIO;
		}
		sdev->hostdata = pdev_info;
	}
	return 0;
}

int myrb_slave_configure(struct scsi_device *sdev)
{
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	myrb_ldev_info *ldev_info;

	if (sdev->channel > sdev->host->max_channel)
		return -ENXIO;

	if (sdev->channel < cb->common.PhysicalChannelCount) {
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
			    myrb_devstate_name(ldev_info->State));

	sdev->tagged_supported = 1;
	return 0;
}

static void myrb_slave_destroy(struct scsi_device *sdev)
{
	void *hostdata = sdev->hostdata;

	if (hostdata) {
		kfree(hostdata);
		sdev->hostdata = NULL;
	}
}

static ssize_t myrb_show_dev_state(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	int ret;

	if (!sdev->hostdata)
		return snprintf(buf, 16, "Unknown\n");

	if (sdev->channel >= cb->common.PhysicalChannelCount) {
		myrb_ldev_info *ldev_info = sdev->hostdata;
		const char *name;

		name = myrb_devstate_name(ldev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       ldev_info->State);
	} else {
		myrb_pdev_state *pdev_info = sdev->hostdata;
		unsigned short status;
		const char *name;

		status = myrb_exec_type3D(cb, DAC960_V1_GetDeviceState,
					  sdev, pdev_info);
		if (status != DAC960_V1_NormalCompletion)
			sdev_printk(KERN_INFO, sdev,
				    "Failed to get device state, status %x\n",
				    status);

		if (!pdev_info->Present)
			name = "Removed";
		else
			name = myrb_devstate_name(pdev_info->State);
		if (name)
			ret = snprintf(buf, 32, "%s\n", name);
		else
			ret = snprintf(buf, 32, "Invalid (%02X)\n",
				       pdev_info->State);
	}
	return ret;
}

static ssize_t myrb_store_dev_state(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	myrb_pdev_state *pdev_info;
	myrb_devstate new_state;
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

	status = DAC960_V1_SetDeviceState(cb, sdev, new_state);
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
static DEVICE_ATTR(raid_state, S_IRUGO | S_IWUSR, myrb_show_dev_state,
		   myrb_store_dev_state);

static ssize_t myrb_show_dev_level(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;

	if (sdev->channel >= cb->common.PhysicalChannelCount) {
		myrb_ldev_info *ldev_info = sdev->hostdata;
		const char *name;

		if (!ldev_info)
			return -ENXIO;

		name = myrb_raidlevel_name(ldev_info->RAIDLevel);
		if (!name)
			return snprintf(buf, 32, "Invalid (%02X)\n",
					ldev_info->State);
		return snprintf(buf,32, "%s\n", name);
	}
	return snprintf(buf, 32, "Physical Drive\n");
}
static DEVICE_ATTR(raid_level, S_IRUGO, myrb_show_dev_level, NULL);

static ssize_t myrb_show_dev_rebuild(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	myrb_cmdblk *cmd_blk = &cb->mcmd_blk;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;
	unsigned short ldev_num = 0xffff;
	unsigned char status;
	bool rebuild = true;
	ssize_t ldev_size, remaining;

	if (sdev->channel < cb->common.PhysicalChannelCount)
		return snprintf(buf, 32, "physical device - not rebuilding\n");

	mutex_lock(&cb->dcmd_mutex);
	myrb_reset_cmd(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetRebuildProgress;
	mbox->Type3.addr = cb->rbld_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion) {
		ldev_num = cb->rbld->ldev_num;
		ldev_size = cb->rbld->ldev_size;
		remaining = cb->rbld->blocks_left;
	}
	mutex_unlock(&cb->dcmd_mutex);

	if (ldev_num != myrb_translate_ldev(&cb->common, sdev) ||
	    status != DAC960_V1_NormalCompletion)
		return snprintf(buf, 32, "not %s\n",
				rebuild ? "rebuilding" : "checking");

	if (cb->enquiry->rbld == DAC960_V1_BackgroundCheckInProgress &&
	    rebuild)
		return snprintf(buf, 32, "not rebuilding\n");
	else if (!rebuild &&
		 cb->enquiry->rbld == DAC960_V1_BackgroundRebuildInProgress)
		return snprintf(buf, 32, "not checking\n");

	return snprintf(buf, 32, "%s block %zu of %zu\n",
			rebuild ? "rebuilding" : "checking",
			ldev_size - remaining, ldev_size);
}

static ssize_t myrb_store_dev_rebuild(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	myrb_cmdblk *cmd_blk;
	myrb_cmd_mbox *mbox;
	char tmpbuf[8];
	ssize_t len;
	unsigned short ldev_num = 0xFFFF;
	unsigned short status;
	int start;
	bool rebuild = true;
	const char *msg;

	len = count > sizeof(tmpbuf) - 1 ? sizeof(tmpbuf) - 1 : count;
	strncpy(tmpbuf, buf, len);
	tmpbuf[len] = '\0';
	if (sscanf(tmpbuf, "%d", &start) != 1)
		return -EINVAL;

	if (rebuild && start &&
	    sdev->channel >= cb->common.PhysicalChannelCount)
		return -ENXIO;
	else if (sdev->channel < cb->common.PhysicalChannelCount)
		return -ENXIO;
	mutex_lock(&cb->dcmd_mutex);
	myrb_reset_cmd(cmd_blk);
	mbox->Type3.id = DAC960_MonitoringIdentifier;
	mbox->Type3.opcode = DAC960_V1_GetRebuildProgress;
	mbox->Type3.addr = cb->rbld_addr;
	myrb_exec_cmd(cb, cmd_blk);
	status = cmd_blk->status;
	if (status == DAC960_V1_NormalCompletion)
		ldev_num = cb->rbld->ldev_num;
	mutex_unlock(&cb->dcmd_mutex);

	if (start) {
		if (status != DAC960_V1_NormalCompletion) {
			sdev_printk(KERN_INFO, sdev,
				    "%s Not Initiated; already in progress\n",
				    rebuild ? "Rebuild" : "Check Consistency");
			return -EALREADY;
		}
		mutex_lock(&cb->dcmd_mutex);
		cmd_blk = &cb->dcmd_blk;
		myrb_reset_cmd(cmd_blk);
		mbox = &cmd_blk->mbox;
		if (rebuild) {
			mbox->Type3D.opcode = DAC960_V1_RebuildAsync;
			mbox->Type3D.id = DAC960_DirectCommandIdentifier;
			mbox->Type3D.Channel = sdev->channel;
			mbox->Type3D.TargetID = sdev->id;
		} else {
			ldev_num = myrb_translate_ldev(&cb->common, sdev);
			mbox->Type3C.opcode = DAC960_V1_CheckConsistencyAsync;
			mbox->Type3C.id = DAC960_DirectCommandIdentifier;
			mbox->Type3C.ldev_num = ldev_num;
			mbox->Type3C.AutoRestore = true;
		}
		myrb_exec_cmd(cb, cmd_blk);
		status = cmd_blk->status;
		mutex_unlock(&cb->dcmd_mutex);
	} else {
		struct pci_dev *pdev = cb->common.pdev;
		unsigned char *rate;
		dma_addr_t rate_addr;

		if (ldev_num != myrb_translate_ldev(&cb->common, sdev)) {
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
		mutex_lock(&cb->dcmd_mutex);
		cmd_blk = &cb->dcmd_blk;
		myrb_reset_cmd(cmd_blk);
		mbox = &cmd_blk->mbox;
		mbox->Type3R.opcode = DAC960_V1_RebuildControl;
		mbox->Type3R.id = DAC960_DirectCommandIdentifier;
		mbox->Type3R.rbld_rate = 0xFF;
		mbox->Type3R.addr = rate_addr;
		myrb_exec_cmd(cb, cmd_blk);
		status = cmd_blk->status;
		pci_free_consistent(pdev, sizeof(char), rate, rate_addr);
		mutex_unlock(&cb->dcmd_mutex);
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
static DEVICE_ATTR(rebuild, S_IRUGO | S_IWUSR, myrb_show_dev_rebuild,
		   myrb_store_dev_rebuild);

static ssize_t myrb_show_ctlr_num(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrb_hba *cb = (myrb_hba *)shost->hostdata;

	return snprintf(buf, 20, "%d\n", cb->common.ControllerNumber);
}
static DEVICE_ATTR(ctlr_num, S_IRUGO, myrb_show_ctlr_num, NULL);

static ssize_t myrb_show_firmware_version(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrb_hba *cb = (myrb_hba *)shost->hostdata;

	return snprintf(buf, 16, "%s\n", cb->common.FirmwareVersion);
}
static DEVICE_ATTR(firmware, S_IRUGO, myrb_show_firmware_version, NULL);

static ssize_t myrb_store_flush_cache(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	myrb_hba *cb = (myrb_hba *)shost->hostdata;
	unsigned short status;

	status = myrb_exec_type3(cb, DAC960_V1_Flush, 0);
	if (status == DAC960_V1_NormalCompletion) {
		shost_printk(KERN_INFO, shost,
			     "Cache Flush Completed\n");
		return count;
	}
	shost_printk(KERN_INFO, shost,
		     "Cache Flush Failed, status %x\n", status);
	return -EIO;
}
static DEVICE_ATTR(flush_cache, S_IWUSR, NULL, myrb_store_flush_cache);

static struct device_attribute *myrb_sdev_attrs[] = {
	&dev_attr_rebuild,
	&dev_attr_raid_state,
	&dev_attr_raid_level,
	NULL,
};

static struct device_attribute *myrb_shost_attrs[] = {
	&dev_attr_ctlr_num,
	&dev_attr_firmware,
	&dev_attr_flush_cache,
	NULL,
};

struct scsi_host_template myrb_template = {
	.module = THIS_MODULE,
	.name = "DAC960",
	.proc_name = "myrb",
	.queuecommand = myrb_queuecommand,
	.eh_host_reset_handler = myrb_host_reset,
	.slave_alloc = myrb_slave_alloc,
	.slave_configure = myrb_slave_configure,
	.slave_destroy = myrb_slave_destroy,
	.cmd_size = sizeof(myrb_cmdblk),
	.shost_attrs = myrb_shost_attrs,
	.sdev_attrs = myrb_sdev_attrs,
	.this_id = -1,
};

/**
 * myrb_is_raid - return boolean indicating device is raid volume
 * @dev the device struct object
 */
static int
myrb_is_raid(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;

	return (sdev->channel >= cb->common.PhysicalChannelCount) ? 1 : 0;
}

/**
 * myrb_get_resync - get raid volume resync percent complete
 * @dev the device struct object
 */
static void
myrb_get_resync(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	unsigned int percent_complete = 0;
	unsigned short ldev_num;
	unsigned int ldev_size = 0, remaining = 0;

	if (sdev->channel < cb->common.PhysicalChannelCount)
		return;
	if (DAC960_V1_ControllerIsRebuilding(cb)) {
		ldev_num = cb->rbld->ldev_num;
		if (ldev_num == myrb_translate_ldev(&cb->common, sdev)) {
			ldev_size = cb->rbld->ldev_size;
			remaining = cb->rbld->blocks_left;
		}
	}
	if (remaining && ldev_size)
		percent_complete = (ldev_size - remaining) * 100 / ldev_size;
	raid_set_resync(myrb_raid_template, dev, percent_complete);
}

/**
 * myrb_get_state - get raid volume status
 * @dev the device struct object
 */
static void
myrb_get_state(struct device *dev)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	myrb_hba *cb = (myrb_hba *)sdev->host->hostdata;
	myrb_ldev_info *ldev_info = sdev->hostdata;
	enum raid_state state = RAID_STATE_UNKNOWN;

	if (sdev->channel < cb->common.PhysicalChannelCount || !ldev_info)
		state = RAID_STATE_UNKNOWN;
	else if (DAC960_V1_ControllerIsRebuilding(cb))
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
	raid_set_state(myrb_raid_template, dev, state);
}

struct raid_function_template myrb_raid_functions = {
	.cookie		= &myrb_template,
	.is_raid	= myrb_is_raid,
	.get_resync	= myrb_get_resync,
	.get_state	= myrb_get_state,
};

static void myrb_handle_scsi(myrb_hba *cb, myrb_cmdblk *cmd_blk,
			     struct scsi_cmnd *scmd)
{
	unsigned short status;

	if (!cmd_blk)
		return;

	BUG_ON(!scmd);
	scsi_dma_unmap(scmd);

	if (cmd_blk->dcdb) {
		memcpy(scmd->sense_buffer, &cmd_blk->dcdb->SenseData, 64);
		pci_pool_free(cb->dcdb_pool, cmd_blk->dcdb,
			      cmd_blk->dcdb_addr);
		cmd_blk->dcdb = NULL;
	}
	if (cmd_blk->sgl) {
		pci_pool_free(cb->sg_pool, cmd_blk->sgl, cmd_blk->sgl_addr);
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

static void myrb_handle_cmdblk(myrb_hba *cb, myrb_cmdblk *cmd_blk)
{
	if (!cmd_blk)
		return;

	if (cmd_blk->Completion) {
		complete(cmd_blk->Completion);
		cmd_blk->Completion = NULL;
	}
}

static void myrb_monitor(struct work_struct *work)
{
	myrb_hba *cb = container_of(work, myrb_hba, monitor_work.work);
	struct Scsi_Host *shost = cb->common.host;
	unsigned long interval = DAC960_MonitoringTimerInterval;

	dev_dbg(&shost->shost_gendev, "monitor tick\n");

	if (cb->new_ev_seq > cb->old_ev_seq) {
		int event = cb->old_ev_seq;
		dev_dbg(&shost->shost_gendev,
			"get event log no %d/%d\n",
			cb->new_ev_seq, event);
		DAC960_V1_MonitorGetEventLog(cb, event);
		cb->old_ev_seq = event + 1;
		interval = 10;
	} else if (cb->need_err_info) {
		cb->need_err_info = false;
		dev_dbg(&shost->shost_gendev, "get error table\n");
		DAC960_V1_MonitorGetErrorTable(cb);
		interval = 10;
	} else if (cb->need_rbld && cb->rbld_first) {
		cb->need_rbld = false;
		dev_dbg(&shost->shost_gendev,
			"get rebuild progress\n");
		DAC960_V1_MonitorRebuildProgress(cb);
		interval = 10;
	} else if (cb->need_ldev_info) {
		cb->need_ldev_info = false;
		dev_dbg(&shost->shost_gendev,
			"get logical drive info\n");
		myrb_get_ldev_info(cb);
		interval = 10;
	} else if (cb->need_rbld) {
		cb->need_rbld = false;
		dev_dbg(&shost->shost_gendev,
			"get rebuild progress\n");
		DAC960_V1_MonitorRebuildProgress(cb);
		interval = 10;
	} else if (cb->need_cc_status) {
		cb->need_cc_status = false;
		dev_dbg(&shost->shost_gendev,
			"get consistency check progress\n");
		DAC960_V1_ConsistencyCheckProgress(cb);
		interval = 10;
	} else if (cb->need_bgi_status) {
		cb->need_bgi_status = false;
		dev_dbg(&shost->shost_gendev, "get background init status\n");
		myrb_bgi_control(cb);
		interval = 10;
	} else {
		dev_dbg(&shost->shost_gendev, "new enquiry\n");
		mutex_lock(&cb->dma_mutex);
		myrb_hba_enquiry(cb);
		mutex_unlock(&cb->dma_mutex);
		if ((cb->new_ev_seq - cb->old_ev_seq > 0) ||
		    cb->need_err_info || cb->need_rbld ||
		    cb->need_ldev_info || cb->need_cc_status ||
		    cb->need_bgi_status)
			dev_dbg(&shost->shost_gendev,
				"reschedule monitor\n");
	}
	if (interval > 1)
		cb->primary_monitor_time = jiffies;
	queue_delayed_work(cb->work_q, &cb->monitor_work, interval);
}

void myrb_flush_cache(myr_hba *c)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);

	myrb_exec_type3(cb, DAC960_V1_Flush, 0);
}

myr_hba *myrb_alloc_host(struct pci_dev *pdev,
			 const struct pci_device_id *entry)
{
	struct Scsi_Host *shost;
	myrb_hba *cb;
	myr_hba *c;

	shost = scsi_host_alloc(&myrb_template, sizeof(myrb_hba));
	if (!shost)
		return NULL;

	cb = (myrb_hba *)shost->hostdata;
	shost->max_cmd_len = 12;
	shost->max_lun = 256;
	mutex_init(&cb->dcmd_mutex);
	mutex_init(&cb->dma_mutex);
	c = &cb->common;
	c->host = shost;

	return c;
}

/*
 * Hardware-specific functions
 */

/*
  DAC960_LA_HardwareInit initializes the hardware for DAC960 LA Series
  Controllers.
*/

static int DAC960_LA_HardwareInit(struct pci_dev *pdev,
				  myr_hba *c, void __iomem *base)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);
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
		    myr_err_status(c, ErrorStatus, Parameter0, Parameter1))
			return -ENODEV;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(cb)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_LA_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_LA_EnableInterrupts(base);
	cb->QueueCommand = myrb_qcmd;
	cb->WriteCommandMailbox = DAC960_LA_WriteCommandMailbox;
	if (cb->dual_mode_interface)
		cb->MailboxNewCommand = DAC960_LA_MemoryMailboxNewCommand;
	else
		cb->MailboxNewCommand = DAC960_LA_HardwareMailboxNewCommand;
	c->ReadControllerConfiguration = DAC960_V1_ReadControllerConfiguration;
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
	myrb_hba *cb = container_of(c, myrb_hba, common);
	void __iomem *base = c->io_addr;
	myrb_stat_mbox *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_LA_AcknowledgeInterrupt(base);
	NextStatusMailbox = cb->NextStatusMailbox;
	while (NextStatusMailbox->valid) {
		unsigned char id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myrb_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cb->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cb->mcmd_blk;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status = NextStatusMailbox->status;
		else
			dev_err(&c->pdev->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(myrb_stat_mbox));
		if (++NextStatusMailbox > cb->LastStatusMailbox)
			NextStatusMailbox = cb->FirstStatusMailbox;

		if (id < 3)
			myrb_handle_cmdblk(cb, cmd_blk);
		else
			myrb_handle_scsi(cb, cmd_blk, scmd);
	}
	cb->NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}

struct DAC960_privdata DAC960_LA_privdata = {
	.HardwareType =		DAC960_LA_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_LA_HardwareInit,
	.InterruptHandler =	DAC960_LA_InterruptHandler,
	.MemoryWindowSize =	DAC960_LA_RegisterWindowSize,
};


/*
  DAC960_PG_HardwareInit initializes the hardware for DAC960 PG Series
  Controllers.
*/

static int DAC960_PG_HardwareInit(struct pci_dev *pdev,
				  myr_hba *c, void __iomem *base)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	DAC960_PG_DisableInterrupts(base);
	DAC960_PG_AcknowledgeHardwareMailboxStatus(base);
	udelay(1000);
	while (DAC960_PG_InitializationInProgressP(base) &&
	       timeout < DAC960_MAILBOX_TIMEOUT) {
		if (DAC960_PG_ReadErrorStatus(base, &ErrorStatus,
					      &Parameter0, &Parameter1) &&
		    myr_err_status(c, ErrorStatus, Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(cb)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_PG_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_PG_EnableInterrupts(base);
	cb->QueueCommand = myrb_qcmd;
	cb->WriteCommandMailbox = DAC960_PG_WriteCommandMailbox;
	if (cb->dual_mode_interface)
		cb->MailboxNewCommand = DAC960_PG_MemoryMailboxNewCommand;
	else
		cb->MailboxNewCommand = DAC960_PG_HardwareMailboxNewCommand;
	c->ReadControllerConfiguration = DAC960_V1_ReadControllerConfiguration;
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
	myrb_hba *cb = container_of(c, myrb_hba, common);
	void __iomem *base = c->io_addr;
	myrb_stat_mbox *NextStatusMailbox;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	DAC960_PG_AcknowledgeInterrupt(base);
	NextStatusMailbox = cb->NextStatusMailbox;
	while (NextStatusMailbox->valid) {
		unsigned char id = NextStatusMailbox->id;
		struct scsi_cmnd *scmd = NULL;
		myrb_cmdblk *cmd_blk = NULL;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cb->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cb->mcmd_blk;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status = NextStatusMailbox->status;
		else
			dev_err(&c->pdev->dev,
				"Unhandled command completion %d\n", id);

		memset(NextStatusMailbox, 0, sizeof(myrb_stat_mbox));
		if (++NextStatusMailbox > cb->LastStatusMailbox)
			NextStatusMailbox = cb->FirstStatusMailbox;

		if (id < 3)
			myrb_handle_cmdblk(cb, cmd_blk);
		else
			myrb_handle_scsi(cb, cmd_blk, scmd);
	}
	cb->NextStatusMailbox = NextStatusMailbox;
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}

struct DAC960_privdata DAC960_PG_privdata = {
	.HardwareType =		DAC960_PG_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_PG_HardwareInit,
	.InterruptHandler =	DAC960_PG_InterruptHandler,
	.MemoryWindowSize =	DAC960_PG_RegisterWindowSize,
};


/*
  DAC960_PD_QueueCommand queues Command for DAC960 PD Series Controllers.
*/

static void DAC960_PD_QueueCommand(myrb_hba *c, myrb_cmdblk *cmd_blk)
{
	void __iomem *base = c->common.io_addr;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;

	while (DAC960_PD_MailboxFullP(base))
		udelay(1);
	DAC960_PD_WriteCommandMailbox(base, mbox);
	DAC960_PD_NewCommand(base);
}


/*
  DAC960_PD_HardwareInit initializes the hardware for DAC960 P Series
  Controllers.
*/

static int DAC960_PD_HardwareInit(struct pci_dev *pdev,
				  myr_hba *c, void __iomem *base)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	if (!request_region(c->IO_Address, 0x80, "myrb")) {
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
		    myr_err_status(c, ErrorStatus, Parameter0, Parameter1))
			return -EIO;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(cb)) {
		dev_err(&pdev->dev,
			"Unable to Enable Memory Mailbox Interface\n");
		DAC960_PD_ControllerReset(base);
		return -ENODEV;
	}
	DAC960_PD_EnableInterrupts(base);
	cb->QueueCommand = DAC960_PD_QueueCommand;
	c->ReadControllerConfiguration = DAC960_V1_ReadControllerConfiguration;
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
	myrb_hba *cb = container_of(c, myrb_hba, common);
	void __iomem *base = c->io_addr;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	while (DAC960_PD_StatusAvailableP(base)) {
		unsigned char id = DAC960_PD_ReadStatusCommandIdentifier(base);
		struct scsi_cmnd *scmd = NULL;
		myrb_cmdblk *cmd_blk;

		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cb->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cb->mcmd_blk;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status = DAC960_PD_ReadStatusRegister(base);
		else
			dev_err(&c->pdev->dev,
				"Unhandled command completion %d\n", id);

		DAC960_PD_AcknowledgeInterrupt(base);
		DAC960_PD_AcknowledgeStatus(base);

		if (id < 3)
			myrb_handle_cmdblk(cb, cmd_blk);
		else
			myrb_handle_scsi(cb, cmd_blk, scmd);
	}
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}

struct DAC960_privdata DAC960_PD_privdata = {
	.HardwareType =		DAC960_PD_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_PD_HardwareInit,
	.InterruptHandler =	DAC960_PD_InterruptHandler,
	.MemoryWindowSize =	DAC960_PD_RegisterWindowSize,
};


/*
  DAC960_P_QueueCommand queues Command for DAC960 P Series Controllers.
*/

static void DAC960_P_QueueCommand(myrb_hba *c, myrb_cmdblk *cmd_blk)
{
	void __iomem *base = c->common.io_addr;
	myrb_cmd_mbox *mbox = &cmd_blk->mbox;

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
  DAC960_P_HardwareInit initializes the hardware for DAC960 P Series
  Controllers.
*/

static int DAC960_P_HardwareInit(struct pci_dev *pdev,
				 myr_hba *c, void __iomem *base)
{
	myrb_hba *cb = container_of(c, myrb_hba, common);
	int timeout = 0;
	unsigned char ErrorStatus, Parameter0, Parameter1;

	if (!request_region(c->IO_Address, 0x80, "myrb")){
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
		    myr_err_status(c, ErrorStatus, Parameter0, Parameter1))
			return -EAGAIN;
		udelay(10);
		timeout++;
	}
	if (timeout == DAC960_MAILBOX_TIMEOUT) {
		dev_err(&pdev->dev,
			"Timeout waiting for Controller Initialisation\n");
		return -ETIMEDOUT;
	}
	if (!DAC960_V1_EnableMemoryMailboxInterface(cb)) {
		dev_err(&pdev->dev,
			"Unable to allocate DMA mapped memory\n");
		DAC960_PD_ControllerReset(base);
		return -ETIMEDOUT;
	}
	DAC960_PD_EnableInterrupts(base);
	cb->QueueCommand = DAC960_P_QueueCommand;
	c->ReadControllerConfiguration = DAC960_V1_ReadControllerConfiguration;
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
	myrb_hba *cb = container_of(c, myrb_hba, common);
	void __iomem *base = c->io_addr;
	unsigned long flags;

	spin_lock_irqsave(&c->queue_lock, flags);
	while (DAC960_PD_StatusAvailableP(base)) {
		unsigned char id = DAC960_PD_ReadStatusCommandIdentifier(base);
		struct scsi_cmnd *scmd = NULL;
		myrb_cmdblk *cmd_blk = NULL;
		myrb_cmd_mbox *mbox;
		myrb_cmd_opcode op;


		if (id == DAC960_DirectCommandIdentifier)
			cmd_blk = &cb->dcmd_blk;
		else if (id == DAC960_MonitoringIdentifier)
			cmd_blk = &cb->mcmd_blk;
		else {
			scmd = scsi_host_find_tag(c->host, id - 3);
			if (scmd)
				cmd_blk = scsi_cmd_priv(scmd);
		}
		if (cmd_blk)
			cmd_blk->status
				= DAC960_PD_ReadStatusRegister(base);
		else
			dev_err(&c->pdev->dev,
				"Unhandled command completion %d\n", id);

		DAC960_PD_AcknowledgeInterrupt(base);
		DAC960_PD_AcknowledgeStatus(base);

		if (!cmd_blk)
			continue;

		mbox = &cmd_blk->mbox;
		op = mbox->Common.opcode;
		switch (op) {
		case DAC960_V1_Enquiry_Old:
			mbox->Common.opcode = DAC960_V1_Enquiry;
			DAC960_P_To_PD_TranslateEnquiry(cb->enquiry);
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
			myrb_handle_cmdblk(cb, cmd_blk);
		else
			myrb_handle_scsi(cb, cmd_blk, scmd);
	}
	spin_unlock_irqrestore(&c->queue_lock, flags);
	return IRQ_HANDLED;
}

struct DAC960_privdata DAC960_P_privdata = {
	.HardwareType =		DAC960_P_Controller,
	.FirmwareType =		DAC960_V1_Controller,
	.HardwareInit =		DAC960_P_HardwareInit,
	.InterruptHandler =	DAC960_P_InterruptHandler,
	.MemoryWindowSize =	DAC960_PD_RegisterWindowSize,
};
