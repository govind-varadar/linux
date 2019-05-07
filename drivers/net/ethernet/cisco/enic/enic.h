/*
 * Copyright 2008-2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2007 Nuova Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef _ENIC_H_
#define _ENIC_H_

#include "vnic_enet.h"
#include "vnic_dev.h"
#include "vnic_wq.h"
#include "vnic_rq.h"
#include "vnic_cq.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "vnic_nic.h"
#include "vnic_rss.h"
#include "enic_qp.h"
#include <linux/irq.h>

#define DRV_NAME		"enic"
#define DRV_DESCRIPTION		"Cisco VIC Ethernet NIC Driver"
#define DRV_VERSION		"2.3.0.53"
#define DRV_COPYRIGHT		"Copyright 2008-2013 Cisco Systems, Inc"

#define ENIC_BARS_MAX		6

#define ENIC_WQ_MAX		256
#define ENIC_RQ_MAX		256
#define ENIC_CQ_MAX		(ENIC_WQ_MAX + ENIC_RQ_MAX)
#define ENIC_INTR_MAX		(ENIC_WQ_MAX > ENIC_RQ_MAX ? ENIC_WQ_MAX : \
							     ENIC_RQ_MAX)

#define ENIC_NOTIFY_TIMER_PERIOD	(2 * HZ)
#define WQ_ENET_MAX_DESC_LEN		BIT(WQ_ENET_LEN_BITS)
#define MAX_TSO				BIT(16)
#define ENIC_DESC_MAX_SPLITS		(MAX_TSO / WQ_ENET_MAX_DESC_LEN + 1)

struct enic_msix_entry {
	int requested;
	char devname[IFNAMSIZ + 8];
	irqreturn_t (*isr)(int, void *);
	void *devid;
	cpumask_var_t affinity_mask;
};

struct enic_intr_mod_table {
	u32 rx_rate;
	u32 range_percent;
};

#define ENIC_AIC_TS_BREAK		100
#define ENIC_AIC_MIN_DEFAULT		3

struct enic_rx_coal {
	u16 coal_usecs;
	u16 acoal_high;
	u16 acoal_low;
	unsigned int use_adaptive_rx_coalesce : 1;
};

/* priv_flags */
#define ENIC_SRIOV_ENABLED		(1 << 0)

/* enic port profile set flags */
#define ENIC_PORT_REQUEST_APPLIED	(1 << 0)
#define ENIC_SET_REQUEST		(1 << 1)
#define ENIC_SET_NAME			(1 << 2)
#define ENIC_SET_INSTANCE		(1 << 3)
#define ENIC_SET_HOST			(1 << 4)

struct enic_port_profile {
	u32 set;
	u8 request;
	char name[PORT_PROFILE_MAX];
	u8 instance_uuid[PORT_UUID_MAX];
	u8 host_uuid[PORT_UUID_MAX];
	u8 vf_mac[ETH_ALEN];
	u8 mac_addr[ETH_ALEN];
};

/* enic_rfs_fltr_node - rfs filter node in hash table
 *	@@keys: IPv4 5 tuple
 *	@flow_id: flow_id of clsf filter provided by kernel
 *	@fltr_id: filter id of clsf filter returned by adaptor
 *	@rq_id: desired rq index
 *	@node: hlist_node
 */
struct enic_rfs_fltr_node {
	struct flow_keys keys;
	u32 flow_id;
	u16 fltr_id;
	u16 rq_id;
	struct hlist_node node;
};

/* enic_rfs_flw_tbl - rfs flow table
 *	@max: Maximum number of filters vNIC supports
 *	@free: Number of free filters available
 *	@toclean: hash table index to clean next
 *	@ht_head: hash table list head
 *	@lock: spin lock
 *	@rfs_may_expire: timer function for enic_rps_may_expire_flow
 */
struct enic_rfs_flw_tbl {
	u16 max;
	int free;

#define ENIC_RFS_FLW_BITSHIFT	(10)
#define ENIC_RFS_FLW_MASK	((1 << ENIC_RFS_FLW_BITSHIFT) - 1)
	u16 toclean:ENIC_RFS_FLW_BITSHIFT;
	struct hlist_head ht_head[1 << ENIC_RFS_FLW_BITSHIFT];
	spinlock_t lock;
	struct timer_list rfs_may_expire;
};

struct vxlan_offload {
	u16 vxlan_udp_port_number;
	u8 patch_level;
	u8 flags;
};

/* Per-instance private data structure */
struct enic {
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct vnic_enet_config config;
	struct vnic_dev_bar bar[ENIC_BARS_MAX];
	struct vnic_dev *vdev;
	struct timer_list notify_timer;
	struct work_struct reset;
	struct work_struct tx_hang_reset;
	struct work_struct change_mtu_work;
	struct msix_entry msix_entry[ENIC_INTR_MAX];
	struct enic_msix_entry msix[ENIC_INTR_MAX];
	u32 msg_enable;
	spinlock_t devcmd_lock;
	u8 mac_addr[ETH_ALEN];
	unsigned int ext_cq : 1;
	unsigned int flags;
	unsigned int priv_flags;
	unsigned int mc_count;
	unsigned int uc_count;
	u32 port_mtu;
	struct enic_rx_coal rx_coal;
#ifdef CONFIG_PCI_IOV
	u16 num_vfs;
#endif
	spinlock_t enic_api_lock;
	struct enic_port_profile *pp;

	unsigned int wq_count;
	u16 loop_enable;
	u16 loop_tag;

	struct enic_qp *qp;
	struct enic_qp_ring *qp_ring;
	unsigned int qp_count;
	struct vnic_intr_ctrl __iomem *err_ctrl;
	struct vnic_intr_ctrl __iomem *notify_ctrl;

	unsigned int rq_count;
	struct vxlan_offload vxlan;
	u64 rq_truncated_pkts;
	u64 rq_bad_fcs;
	unsigned int intr_count;
	u32 __iomem *legacy_pba;		/* memory-mapped */

	unsigned int cq_count;
	struct enic_rfs_flw_tbl rfs_h;
	u32 rx_copybreak;
	u8 rss_key[ENIC_RSS_LEN];
	struct vnic_gen_stats gen_stats;
};

static inline struct net_device *vnic_get_netdev(struct vnic_dev *vdev)
{
	struct enic *enic = vdev->priv;

	return enic->netdev;
}

/* wrappers function for kernel log
 */
#define vdev_err(vdev, fmt, ...)					\
	dev_err(&(vdev)->pdev->dev, fmt, ##__VA_ARGS__)
#define vdev_warn(vdev, fmt, ...)					\
	dev_warn(&(vdev)->pdev->dev, fmt, ##__VA_ARGS__)
#define vdev_info(vdev, fmt, ...)					\
	dev_info(&(vdev)->pdev->dev, fmt, ##__VA_ARGS__)

#define vdev_neterr(vdev, fmt, ...)					\
	netdev_err(vnic_get_netdev(vdev), fmt, ##__VA_ARGS__)
#define vdev_netwarn(vdev, fmt, ...)					\
	netdev_warn(vnic_get_netdev(vdev), fmt, ##__VA_ARGS__)
#define vdev_netinfo(vdev, fmt, ...)					\
	netdev_info(vnic_get_netdev(vdev), fmt, ##__VA_ARGS__)

static inline struct device *enic_get_dev(struct enic *enic)
{
	return &(enic->pdev->dev);
}

#define ENIC_LEGACY_IO_INTR	0
#define ENIC_LEGACY_ERR_INTR	1
#define ENIC_LEGACY_NOTIFY_INTR	2

static inline unsigned int enic_msix_notify_intr(struct enic *enic)
{
	return enic->qp_count + 1;
}

static inline unsigned int enic_msix_error_intr(struct enic *enic)
{
	return enic->qp_count;
}

static inline void enic_intr_return_credits(struct vnic_intr_ctrl *ctrl,
					    unsigned int credits,
					    int unmask, int reset_timer)
{
	u32 value = (credits & 0xffff) |
		    (unmask ? (1 << VNIC_INTR_UNMASK_SHIFT) : 0) |
		    (reset_timer ? (1 << VNIC_INTR_RESET_TIMER_SHIFT) : 0);
	iowrite32(value, &ctrl->int_credit_return);
}

static inline void enic_intr_return_all_credits(struct vnic_intr_ctrl *ctrl)
{
	unsigned int credits;
	int unmask = 1;
	int reset_timer = 1;

	credits = ioread32(&ctrl->int_credits);
	enic_intr_return_credits(ctrl, credits, unmask, reset_timer);
}

void enic_reset_addr_lists(struct enic *enic);
int enic_sriov_enabled(struct enic *enic);
int enic_is_valid_vf(struct enic *enic, int vf);
int enic_is_dynamic(struct enic *enic);
void enic_set_ethtool_ops(struct net_device *netdev);
int __enic_set_rsskey(struct enic *enic);
void enic_intr_ctrl_init(struct vnic_intr_ctrl __iomem *ctrl,
			 u32 coalescing_timer, u32 coalescing_type,
			 u32 mask_on_assertion, u32 int_credits);

#endif /* _ENIC_H_ */
