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
#define ENIC_INTR_MAX		(256 + 2)

#define ENIC_WQ_NAPI_BUDGET	256

#define ENIC_AIC_LARGE_PKT_DIFF	3

#define ENIC_NOTIFY_TIMER_PERIOD	(2 * HZ)
#define WQ_ENET_MAX_DESC_LEN		(1 << WQ_ENET_LEN_BITS)
#define MAX_TSO				(1 << 16)
#define ENIC_DESC_MAX_SPLITS		(MAX_TSO / WQ_ENET_MAX_DESC_LEN + 1)

struct enic_msix_entry {
	int requested;
	char devname[IFNAMSIZ + 8];
	irqreturn_t (*isr)(int, void *);
	void *devid;
	cpumask_var_t affinity_mask;
};

/* Store only the lower range.  Higher range is given by fw. */
struct enic_intr_mod_range {
	u32 small_pkt_range_start;
	u32 large_pkt_range_start;
};

struct enic_intr_mod_table {
	u32 rx_rate;
	u32 range_percent;
};

#define ENIC_MAX_LINK_SPEEDS		3
#define ENIC_LINK_SPEED_10G		10000
#define ENIC_LINK_SPEED_4G		4000
#define ENIC_LINK_40G_INDEX		2
#define ENIC_LINK_10G_INDEX		1
#define ENIC_LINK_4G_INDEX		0
#define ENIC_RX_COALESCE_RANGE_END	125
#define ENIC_AIC_TS_BREAK		100

struct enic_rx_coal {
	u32 small_pkt_range_start;
	u32 large_pkt_range_start;
	u32 range_end;
	u32 use_adaptive_rx_coalesce;
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
	unsigned int flags;
	unsigned int priv_flags;
	unsigned int mc_count;
	unsigned int uc_count;
	u32 port_mtu;
	struct enic_rx_coal rx_coalesce_setting;
	u32 rx_coalesce_usecs;
	u32 tx_coalesce_usecs;
#ifdef CONFIG_PCI_IOV
	u16 num_vfs;
#endif
	spinlock_t enic_api_lock;
	struct enic_port_profile *pp;

	/* work queue cache line section */
	unsigned int wq_count;
	u16 loop_enable;
	u16 loop_tag;

	struct enic_qp *qp;
	struct enic_qp_ring *qp_ring;
	unsigned int qp_count;
	unsigned int intr_count;
	struct vnic_intr_ctrl __iomem *err_ctrl;
	struct vnic_intr_ctrl __iomem *notify_ctrl;

	struct kmem_cache *wq_buf_cache;
	struct kmem_cache *rq_buf_cache;

	unsigned int rq_count;
	struct vxlan_offload vxlan;
	u64 rq_truncated_pkts;
	u64 rq_bad_fcs;

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

static inline unsigned int enic_cq_rq(struct enic *enic, unsigned int rq)
{
	return rq;
}

static inline unsigned int enic_cq_wq(struct enic *enic, unsigned int wq)
{
	return enic->rq_count + wq;
}

#define ENIC_LEGACY_IO_INTR	0
#define ENIC_LEGACY_ERR_INTR	1
#define ENIC_LEGACY_NOTIFY_INTR	3

static inline unsigned int enic_msix_wq_intr(struct enic *enic,
	unsigned int wq)
{
	return wq;
}

static inline unsigned int enic_msix_err_intr(struct enic *enic)
{
	return enic->qp_count;
}

static inline unsigned int enic_msix_notify_intr(struct enic *enic)
{
	return enic->qp_count + 1;
}

static inline bool enic_is_err_intr(struct enic *enic, int intr)
{
	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_INTX:
		return intr == ENIC_LEGACY_ERR_INTR;
	case VNIC_DEV_INTR_MODE_MSIX:
		return intr == enic_msix_err_intr(enic);
	case VNIC_DEV_INTR_MODE_MSI:
	default:
		return false;
	}
}

static inline bool enic_is_notify_intr(struct enic *enic, int intr)
{
	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_INTX:
		return intr == ENIC_LEGACY_NOTIFY_INTR;
	case VNIC_DEV_INTR_MODE_MSIX:
		return intr == enic_msix_notify_intr(enic);
	case VNIC_DEV_INTR_MODE_MSI:
	default:
		return false;
	}
}

static inline int enic_dma_map_check(struct enic *enic, dma_addr_t dma_addr)
{
	if (unlikely(pci_dma_mapping_error(enic->pdev, dma_addr))) {
		net_warn_ratelimited("%s: PCI dma mapping failed!\n",
				     enic->netdev->name);
		enic->gen_stats.dma_map_error++;

		return -ENOMEM;
	}

	return 0;
}

static inline void enic_err_intr_mask(struct enic *enic)
{
	iowrite32(1, &enic->err_ctrl->mask);
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
void enic_preload_tcp_csum_encap(struct sk_buff *skb);
void enic_preload_tcp_csum(struct sk_buff *skb);
void enic_intr_ctrl_init(struct vnic_intr_ctrl __iomem *ctrl,
				       u32 coalescing_timer,
				       u32 coalescing_type,
				       u32 mask_on_assertion, u32 int_credits);

#endif /* _ENIC_H_ */
