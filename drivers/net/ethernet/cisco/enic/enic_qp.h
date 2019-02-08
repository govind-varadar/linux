/* SPDX-License-Identifier: GPL-2.0+ */

/* Copyright 2008-2010 Cisco Systems, Inc.  All rights reserved.
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

#ifndef _ENIC_QP_H_
#define _ENIC_QP_H_

#include <linux/netdevice.h>
#include <linux/pci.h>

#include "wq_enet_desc.h"
#include "vnic_wq.h"
#include "vnic_cq.h"
#include "vnic_rq.h"
#include "vnic_dev.h"
#include "vnic_intr.h"

struct enic_wq_buf {
	struct enic_wq_buf *next;
	dma_addr_t dma_addr;
	struct sk_buff *skb;
	u32 len;
	u16 index;
	unsigned int  sop : 1;
};

struct enic_wq {
	atomic_t desc_avail;
	u16 cq_to_clean;
	u16 cq_desc_count;
	unsigned int last_color : 1;
	struct cq_desc *cq_base;
	struct wq_enet_desc *wq_base;
	struct enic_wq_buf *to_use;
	struct enic_wq_buf *to_clean;
	struct vnic_wq_ctrl __iomem *ctrl;
};

struct enic_rq_buf {
	struct enic_rq_buf *next;
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	u32 len;
	u16 index;
};

struct enic_rq {
	u16 cq_to_clean;
	u16 cq_desc_count;
	u8 vxlan_patch_level;
	unsigned int vxlan_offload	: 1;
	unsigned int last_color		: 1;
	unsigned int adaptive_coal	: 1;
	struct cq_enet_rq_desc *cq_base;
	struct rq_enet_desc *rq_base;
	struct enic_rq_buf *to_use;
	struct enic_rq_buf *to_clean;
	struct vnic_rq_ctrl __iomem *ctrl;
	ktime_t prev_ts;
	u64 bytes;
	u64 bytes_delta;
	u32 coal_timer;
	u16 acoal_low;
	u16 acoal_high;
	u16 timer_mul;
	u16 timer_div;
};

struct enic_qp {
	struct device *dev;
	struct net_device *netdev;
	struct enic_wq wq;
	struct enic_rq rq;
	struct vnic_intr_ctrl __iomem *ctrl;
	u16 index;
	struct enic *enic;
	struct napi_struct napi;
} ____cacheline_aligned;

struct enic_qp_ring {
	struct vnic_dev_ring wq_ring;
	struct vnic_dev_ring wcq_ring;
	struct vnic_dev_ring rq_ring;
	struct vnic_dev_ring rcq_ring;
	struct vnic_cq_ctrl __iomem *wcq_ctrl;
	struct vnic_cq_ctrl __iomem *rcq_ctrl;
};

static inline unsigned int enic_wq_desc_avail(struct enic_qp *qp)
{
	return atomic_read(&qp->wq.desc_avail);
}

static inline void _enic_intr_unmask(struct vnic_intr_ctrl __iomem *ctrl)
{
	iowrite32(0, &ctrl->mask);
}

static inline void enic_intr_unmask(struct enic_qp *qp)
{
	_enic_intr_unmask(qp->ctrl);
}

static inline void enic_qp_doorbell(struct enic_qp *qp)
{
	/* Write desc before ringing doorbell.
	 */
	wmb();
	iowrite32(qp->wq.to_use->index, &qp->wq.ctrl->posted_index);
}

static inline void _enic_intr_mask(struct vnic_intr_ctrl __iomem *ctrl)
{
	iowrite32(1, &ctrl->mask);
}

static inline void enic_intr_mask(struct enic_qp *qp)
{
	_enic_intr_mask(qp->ctrl);
}

static inline int _enic_intr_masked(struct vnic_intr_ctrl __iomem *ctrl)
{
	return ioread32(&ctrl->mask);
}

static inline int enic_intr_masked(struct enic_qp *qp)
{
	return _enic_intr_masked(qp->ctrl);
}

static inline unsigned int enic_rq_error_status(struct enic_qp *qp)
{
	if (!qp->rq.ctrl)
		return 0;
	return ioread32(&qp->rq.ctrl->error_status);
}

static inline unsigned int enic_wq_error_status(struct enic_qp *qp)
{
	if (!qp->wq.ctrl)
		return 0;
	return ioread32(&qp->wq.ctrl->error_status);
}

int enic_alloc_qp(struct enic *enic);
int enic_napi_poll(struct napi_struct *napi, int budget);
void enic_free_qp(struct enic *enic);
netdev_tx_t enic_hard_start_xmit(struct sk_buff *skb,
				 struct net_device *netdev);
#endif /* _ENIC_QP_H_ */
