// SPDX-License-Identifier: GPL-2.0+

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

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#ifdef CONFIG_NET_RX_BUSY_POLL
#include <net/busy_poll.h>
#endif
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ip6_checksum.h>

#include "enic_qp.h"
#include "enic.h"
#include "cq_enet_desc.h"
#include "rq_enet_desc.h"
#include "enic_res.h"

struct enic_qp qp_test;
struct enic_qp_ring qp_ring_test;
struct enic enic_test;

#define ENIC_MAX_COALESCE_TIMERS        10
/*  Interrupt moderation table, which will be used to decide the
 *  coalescing timer values
 *  {rx_rate in Mbps, mapping percentage of the range}
 */
static struct enic_intr_mod_table mod_table[ENIC_MAX_COALESCE_TIMERS + 1] = {
	{4000,  0},
	{4400, 10},
	{5060, 20},
	{5230, 30},
	{5540, 40},
	{5820, 50},
	{6120, 60},
	{6435, 70},
	{6745, 80},
	{7000, 90},
	{0xFFFFFFFF, 100}
};

static void enic_wq_enable(struct enic_qp *qp)
{
	struct enic_wq *wq = &qp->wq;

	if (!wq->ctrl)
		return;
	iowrite32(1, &wq->ctrl->enable);
}

static int enic_wq_disable(struct enic_qp *qp)
{
	struct enic_wq *wq = &qp->wq;
	int i;

	if (!wq->ctrl)
		return 0;
	iowrite32(0, &wq->ctrl->enable);

	/* Wait for HW to ACK disable request */
	for (i = 0; i < 1000; i++) {
		if (!ioread32(&wq->ctrl->running))
			return 0;
		usleep_range(10, 20);
	}

	netdev_err(qp->netdev, "Failed to disable WQ[%d]", qp->index);

	return -ETIMEDOUT;
}

static void enic_rq_enable(struct enic_qp *qp)
{
	struct enic_rq *rq = &qp->rq;

	if (!rq->ctrl)
		return;
	iowrite32(1, &rq->ctrl->enable);
}

static int enic_rq_disable(struct enic_qp *qp)
{
	unsigned int wait;
	struct enic_rq *rq = &qp->rq;
	int i;

	if (!rq->ctrl)
		return 0;
	/* Due to a race condition with clearing RQ "mini-cache" in hw, we need
	 * to disable the RQ twice to guarantee that stale descriptors are not
	 * used when this RQ is re-enabled.
	 */
	for (i = 0; i < 2; i++) {
		iowrite32(0, &rq->ctrl->enable);

		/* Wait for HW to ACK disable request */
		for (wait = 20000; wait > 0; wait--) {
			if (!ioread32(&rq->ctrl->running))
				break;
			if (!wait) {
				netdev_err(qp->netdev, "Failed to disable RQ[%d]",
					   i);
				return -ETIMEDOUT;
			}
		}
	}

	return 0;
}

static void enic_wq_free_bufs(struct enic_qp *qp)
{
	struct enic_wq_buf *buf, *end, *next;

	buf = qp->wq.to_use;
	end = qp->wq.to_use;

	if (!buf)
		return;

	do {
		next = buf->next;
		if (buf->sop)
			dma_unmap_single(qp->dev, buf->dma_addr, buf->len,
					 DMA_TO_DEVICE);
		else if (buf->dma_addr)
			dma_unmap_page(qp->dev, buf->dma_addr, buf->len,
				       DMA_TO_DEVICE);
		dev_kfree_skb(buf->skb);
		kfree(buf);
		buf = next;
	} while (buf && buf != end);

	qp->wq.to_clean = NULL;
	qp->wq.to_use = NULL;
}

static int enic_wq_alloc_bufs(struct enic_qp *qp)
{
	struct enic_wq_buf *buf;
	struct enic *enic = qp->enic;
	struct enic_qp_ring *qp_ring = &enic->qp_ring[qp->index];
	int i;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	qp->wq.to_clean = buf;
	qp->wq.to_use = buf;
	buf->next = buf;

	for (i = 1; i < qp_ring->wq_ring.desc_count; i++) {
		buf->next = kzalloc(sizeof(*buf), GFP_KERNEL);
		if (!buf->next) {
			enic_wq_free_bufs(qp);
			return -ENOMEM;
		}
		buf = buf->next;
		buf->index = i;
	}
	buf->next = qp->wq.to_clean;

	return 0;
}

static void enic_rq_free_bufs(struct enic_qp *qp)
{
	struct enic_rq_buf *buf, *end, *next;

	buf = qp->rq.to_clean;
	end = qp->rq.to_clean;

	if (!buf)
		return;

	do {
		next = buf->next;
		if (buf->dma_addr)
			dma_unmap_single(qp->dev, buf->dma_addr, buf->len,
					 DMA_FROM_DEVICE);
		dev_kfree_skb_any(buf->skb);
		kfree(buf);
		buf = next;
	} while (buf && buf != end);

	qp->rq.to_clean = NULL;
	qp->rq.to_use = NULL;
}

static int enic_rq_alloc_bufs(struct enic_qp *qp)
{
	struct enic_rq_buf *buf;
	struct enic *enic = qp->enic;
	struct enic_qp_ring *qp_ring = &enic->qp_ring[qp->index];
	int i;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	qp->rq.to_clean = buf;
	qp->rq.to_use = buf;

	for (i = 1; i < qp_ring->rq_ring.desc_count; i++) {
		buf->next = kzalloc(sizeof(*buf), GFP_KERNEL);
		if (!buf->next)
			goto out;
		buf = buf->next;
		buf->index = i;
	}
	buf->next = qp->rq.to_clean;

	return 0;
out:
	enic_rq_free_bufs(qp);
	return -ENOMEM;
}

void enic_free_qp(struct enic *enic)
{
	struct enic_qp_ring *qp_ring;
	struct enic_qp *qp;
	int i;

	for (i = 0; i < enic->wq_count; i++) {
		qp = &enic->qp[i];
		qp_ring = &enic->qp_ring[i];

		enic_wq_disable(qp);
		enic_wq_free_bufs(qp);
		vnic_dev_free_desc_ring(enic->vdev, &qp_ring->wq_ring);
		vnic_dev_free_desc_ring(enic->vdev, &qp_ring->wcq_ring);
	}
	for (i = 0; i < enic->rq_count; i++) {
		qp = &enic->qp[i];
		qp_ring = &enic->qp_ring[i];

		enic_rq_disable(qp);
		enic_rq_free_bufs(qp);
		vnic_dev_free_desc_ring(enic->vdev, &qp_ring->rq_ring);
		vnic_dev_free_desc_ring(enic->vdev, &qp_ring->rcq_ring);
	}

	for (i = 0; i < enic->qp_count; i++)
		iowrite32(0, &enic->qp[i].ctrl->int_credits);

	kfree(enic->qp_ring);
	enic->qp_ring = NULL;
	kfree(enic->qp);
	enic->qp = NULL;
	enic->notify_ctrl = NULL;
	enic->err_ctrl = NULL;
}

static void enic_wq_init_ctrl(struct vnic_wq_ctrl __iomem *ctrl, u64 paddr,
			      u32 count, u32 cq_index,
			      u32 error_interrupt_enable,
			      u32 error_interrupt_offset, u32 error_status,
			      u32 fetch_index, u32 posted_index)
{
	writeq(paddr, &ctrl->ring_base);
	iowrite32(count, &ctrl->ring_size);
	iowrite32(cq_index, &ctrl->cq_index);
	iowrite32(error_interrupt_enable, &ctrl->error_interrupt_enable);
	iowrite32(error_interrupt_offset, &ctrl->error_interrupt_offset);
	iowrite32(error_status, &ctrl->error_status);
	iowrite32(fetch_index, &ctrl->fetch_index);
	iowrite32(posted_index, &ctrl->posted_index);
}

static void enic_wq_init(struct enic_qp *qp)
{
	u64 paddr;
	struct enic_qp_ring *qp_ring = &qp->enic->qp_ring[qp->index];
	unsigned int count = qp_ring->wq_ring.desc_count;
	struct vnic_wq_ctrl __iomem *ctrl = qp->wq.ctrl;
	unsigned int error_interrupt_offset;
	unsigned int error_interrupt_enable;

	if (!ctrl)
		return;

	switch (vnic_dev_get_intr_mode(qp->enic->vdev)) {
	case VNIC_DEV_INTR_MODE_INTX:
		error_interrupt_offset = 0;
		error_interrupt_enable = 1;
		break;
	case VNIC_DEV_INTR_MODE_MSIX:
		error_interrupt_offset = qp->enic->intr_count - 2;
		error_interrupt_enable = 1;
		break;
	default:
		error_interrupt_offset = 0;
		error_interrupt_enable = 0;
		break;
	}
	paddr = (u64)qp_ring->wq_ring.base_addr | VNIC_PADDR_TARGET;
	enic_wq_init_ctrl(ctrl, paddr, count, qp->index,
			  error_interrupt_enable, error_interrupt_offset,
			  0,	/* error_status */
			  0,	/* fetch index */
			  0	/* posted_index */);
	/* fetch_index and posted_index are initialized to 0 here.
	 * enic_wq_alloc_bufs should make sure wq->to_clean and wq->to_use
	 * should point to buf with index 0;
	 */
}

static void enic_rq_init_ctrl(struct vnic_rq_ctrl __iomem *ctrl, u64 paddr,
			      u32 count, u32 cq_index,
			      u32 error_interrupt_enable,
			      u32 error_interrupt_offset,
			      u32 error_status, u32 fetch_index,
			      u32 posted_index)
{
	writeq(paddr, &ctrl->ring_base);
	iowrite32(count, &ctrl->ring_size);
	iowrite32(cq_index, &ctrl->cq_index);
	iowrite32(error_interrupt_enable, &ctrl->error_interrupt_enable);
	iowrite32(error_interrupt_offset, &ctrl->error_interrupt_offset);
	iowrite32(error_status, &ctrl->error_status);
	iowrite32(fetch_index, &ctrl->fetch_index);
	iowrite32(posted_index, &ctrl->posted_index);
}

static void enic_rq_init(struct enic_qp *qp)
{
	u64 paddr;
	struct enic_qp_ring *qp_ring = &qp->enic->qp_ring[qp->index];
	unsigned int count = qp_ring->rq_ring.desc_count;
	struct vnic_rq_ctrl __iomem *ctrl = qp->rq.ctrl;
	unsigned int error_interrupt_offset;
	unsigned int error_interrupt_enable;

	if (!ctrl)
		return;

	switch (vnic_dev_get_intr_mode(qp->enic->vdev)) {
	case VNIC_DEV_INTR_MODE_INTX:
		error_interrupt_offset = 0;
		error_interrupt_enable = 1;
		break;
	case VNIC_DEV_INTR_MODE_MSIX:
		error_interrupt_offset = qp->enic->intr_count - 2;
		error_interrupt_enable = 1;
		break;
	default:
		error_interrupt_offset = 0;
		error_interrupt_enable = 0;
		break;
	}
	paddr = (u64)qp_ring->rq_ring.base_addr | VNIC_PADDR_TARGET;
	enic_rq_init_ctrl(ctrl, paddr, count, (qp->index + qp->enic->wq_count),
			  error_interrupt_enable, error_interrupt_offset,
			  0,	/* error_status */
			  0,	/* fetch_index */
			  0	/* posted_index */);
	/* fetch_index and posted_index are initialized before rq bufs are
	 * allocated. While rq bufs are allocated, we should make sure
	 * rq->to_use and rq->to_clean points to buf with index 0, later
	 * enic_rq_alloc_bufs will set posted_index to correct value.
	 */
}

static void enic_cq_init(struct vnic_cq_ctrl __iomem *ctrl, u64 paddr,
			 u32 desc_count, u32 flow_control_enable,
			 u32 color_enable, u32 cq_head, u32 cq_tail,
			 u32 cq_tail_color, u32 interrupt_enable,
			 u32 cq_entry_enable, u32 cq_message_enable,
			 u32 interrupt_offset, u64 cq_message_addr)
{
	writeq(paddr, &ctrl->ring_base);
	iowrite32(desc_count, &ctrl->ring_size);
	iowrite32(flow_control_enable, &ctrl->flow_control_enable);
	iowrite32(color_enable, &ctrl->color_enable);
	iowrite32(cq_head, &ctrl->cq_head);
	iowrite32(cq_tail, &ctrl->cq_tail);
	iowrite32(cq_tail_color, &ctrl->cq_tail_color);
	iowrite32(interrupt_enable, &ctrl->interrupt_enable);
	iowrite32(cq_entry_enable, &ctrl->cq_entry_enable);
	iowrite32(cq_message_enable, &ctrl->cq_message_enable);
	iowrite32(interrupt_offset, &ctrl->interrupt_offset);
	writeq(cq_message_addr, &ctrl->cq_message_addr);
}

static void enic_rcq_init(struct enic_qp *qp)
{
	struct enic_qp_ring *qp_ring = &qp->enic->qp_ring[qp->index];

	enic_cq_init(qp_ring->rcq_ctrl,
		     qp_ring->rcq_ring.base_addr | VNIC_PADDR_TARGET,
		     qp_ring->rcq_ring.desc_count,
		     0, /* flow_control_enable */
		     1, /* color_enable */
		     0, /* cq_head */
		     0, /* cq_tail */
		     1, /* cq_tail_color */
		     1, /* interrupt_enable */
		     1, /* cq_entry_enable */
		     0, /* cq_message_enable */
		     qp->index, /* interrupt offset */
		     0 /*cq_message_addr */);
}

static void enic_wcq_init(struct enic_qp *qp)
{
	struct enic_qp_ring *qp_ring = &qp->enic->qp_ring[qp->index];

	enic_cq_init(qp_ring->wcq_ctrl,
		     qp_ring->wcq_ring.base_addr | VNIC_PADDR_TARGET,
		     qp_ring->wcq_ring.desc_count,
		     0, /* flow_control_enable */
		     1, /* color_enable */
		     0, /* cq_head */
		     0, /* cq_tail */
		     1, /* cq_tail_color */
		     1, /* interrupt_enable */
		     1, /* cq_entry_enable */
		     0, /* cq_message_enable */
		     qp->index, /* interrupt offset */
		     0 /*cq_message_addr */);
}

void enic_intr_ctrl_init(struct vnic_intr_ctrl __iomem *ctrl,
			 u32 coalescing_timer, u32 coalescing_type,
			 u32 mask_on_assertion, u32 int_credits)
{
	iowrite32(coalescing_timer, &ctrl->coalescing_timer);
	iowrite32(coalescing_type, &ctrl->coalescing_type);
	iowrite32(mask_on_assertion, &ctrl->mask_on_assertion);
	iowrite32(int_credits, &ctrl->int_credits);
}

static void enic_qp_ctrl_init(struct enic_qp *qp)
{
	struct enic *enic = qp->enic;
	struct enic_rx_coal *rxcoal = &enic->rx_coal;
	struct vnic_intr_ctrl __iomem *ctrl = qp->ctrl;
	u32 coal_timer_hw;
	u32 coal_timer_usec = rxcoal->coal_usecs;
	u32 mask_on_assertion = 0;

	coal_timer_hw = vnic_dev_intr_coal_timer_usec_to_hw(enic->vdev,
							    coal_timer_usec);
	qp->rq.adaptive_coal = rxcoal->use_adaptive_rx_coalesce;
	qp->rq.acoal_low = rxcoal->acoal_low;
	qp->rq.acoal_high = rxcoal->acoal_high;
	qp->rq.timer_mul = vnic_dev_get_coal_timer_mul(enic->vdev);
	qp->rq.timer_div = vnic_dev_get_coal_timer_div(enic->vdev);

	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_MSI:
	case VNIC_DEV_INTR_MODE_MSIX:
		mask_on_assertion = 1;
		break;
	case VNIC_DEV_INTR_MODE_INTX:
		mask_on_assertion = 0;
		break;
	default:
		netdev_err(qp->netdev, "interrupt type unknown");
		break;
	}

	enic_intr_ctrl_init(ctrl, coal_timer_hw, enic->config.intr_timer_type,
			    mask_on_assertion, 0);
}

static inline int enic_rq_fill_bufs(struct enic_qp *qp)
{
	struct net_device *netdev = qp->netdev;
	unsigned int len = netdev->mtu + VLAN_ETH_HLEN;
	dma_addr_t dma_addr;
	struct enic_rq_buf *buf;
	int ret = 0;

	buf = qp->rq.to_use;

	if (unlikely(!qp->rq.ctrl))
		return 0;
	while (buf->next != qp->rq.to_clean) {
		buf->skb = netdev_alloc_skb_ip_align(netdev, len);
		if (unlikely(!buf->skb)) {
			ret = -ENOMEM;
			break;
		}
		dma_addr = dma_map_single(qp->dev, buf->skb->data, len,
					  DMA_FROM_DEVICE);
		if (unlikely(dma_mapping_error(qp->dev, dma_addr))) {
			net_warn_ratelimited("%s: DMA mapping failed for rq[%d], desc[%d]",
					     qp->netdev->name, qp->index,
					     buf->index);
			qp->enic->gen_stats.dma_map_error++;
			dev_kfree_skb(buf->skb);
			buf->skb = NULL;
			ret = -ENOMEM;
			break;
		}
		rq_enet_desc_enc(&qp->rq.rq_base[buf->index],
				 (u64)dma_addr | VNIC_PADDR_TARGET,
				 RQ_ENET_TYPE_ONLY_SOP, len);
		buf->dma_addr = dma_addr;
		buf->len = len;
		buf = buf->next;
	}
	qp->rq.to_use = buf;
	/* desc should be written before posting posted_index to hw
	 */
	wmb();
	iowrite32(buf->index, &qp->rq.ctrl->posted_index);
	return ret;
}

static int enic_alloc_wq(struct enic_qp *qp)
{
	struct enic *enic = qp->enic;
	int index = qp->index;
	struct enic_qp_ring *qp_ring = &enic->qp_ring[index];
	int ret;

	qp->wq.ctrl = vnic_dev_get_res(enic->vdev, RES_TYPE_WQ, index);
	if (!qp->wq.ctrl) {
		netdev_err(qp->netdev, "WQ[%d] ctrl not found", index);
		return -ENODEV;
	}

	qp_ring->wcq_ctrl = vnic_dev_get_res(enic->vdev, RES_TYPE_CQ,
					     index);
	if (!qp_ring->wcq_ctrl) {
		netdev_err(qp->netdev, "WCQ[%d] ctrl not found", index);
		return -ENODEV;
	}
	ret = enic_wq_disable(qp);
	if (ret)
		return ret;
	ret = vnic_dev_alloc_desc_ring(enic->vdev, &qp_ring->wq_ring,
				       enic->config.wq_desc_count,
				       sizeof(struct wq_enet_desc));
	if (ret)
		return ret;
	enic_wq_init(qp);
	ret = vnic_dev_alloc_desc_ring(enic->vdev,
				       &qp_ring->wcq_ring,
				       enic->config.wq_desc_count,
				       sizeof(struct cq_enet_wq_desc));
	if (ret)
		return ret;
	qp->wq.cq_base = qp_ring->wcq_ring.descs;
	qp->wq.wq_base = qp_ring->wq_ring.descs;
	atomic_set(&qp->wq.desc_avail, qp_ring->wq_ring.desc_count - 1);
	qp->wq.cq_desc_count = qp_ring->wcq_ring.desc_count;
	enic_wcq_init(qp);
	ret = enic_wq_alloc_bufs(qp);
	if (ret)
		return ret;
	enic_wq_enable(qp);

	return 0;
}

static int enic_alloc_rq(struct enic_qp *qp)
{
	struct enic *enic = qp->enic;
	int index = qp->index;
	int ret;
	struct enic_qp_ring *qp_ring = &enic->qp_ring[index];

	qp->rq.ctrl = vnic_dev_get_res(enic->vdev, RES_TYPE_RQ, index);
	if (!qp->rq.ctrl) {
		netdev_err(qp->netdev, "RQ[%d] ctrl not found", index);
		return -ENODEV;
	}

	qp_ring->rcq_ctrl = vnic_dev_get_res(enic->vdev, RES_TYPE_CQ,
					     enic->wq_count + index);
	if (!qp_ring->rcq_ctrl) {
		netdev_err(qp->netdev, "RCQ[%d] ctrl not found", index);
		return -ENODEV;
	}
	ret = enic_rq_disable(qp);
	if (ret)
		return ret;
	ret = vnic_dev_alloc_desc_ring(enic->vdev, &qp_ring->rq_ring,
				       enic->config.rq_desc_count,
				       sizeof(struct rq_enet_desc));
	if (ret)
		return ret;
	enic_rq_init(qp);
	ret = vnic_dev_alloc_desc_ring(enic->vdev, &qp_ring->rcq_ring,
				       enic->config.rq_desc_count,
				       sizeof(struct cq_enet_rq_desc));
	if (ret)
		return ret;
	qp->rq.cq_base = qp_ring->rcq_ring.descs;
	qp->rq.rq_base = qp_ring->rq_ring.descs;
	qp->rq.cq_desc_count = qp_ring->rcq_ring.desc_count;

	enic_rcq_init(qp);
	/* RQ should be enabled before posting to RQ desc
	 */
	enic_rq_enable(qp);
	ret = enic_rq_alloc_bufs(qp);
	if (ret)
		return ret;
	ret = enic_rq_fill_bufs(qp);
	if (ret)
		return ret;

	return 0;
}

int enic_alloc_qp(struct enic *enic)
{
	int qp_num = max_t(unsigned int, enic->rq_count, enic->wq_count);
	int ret = 0;
	int i;

	enic->qp_count = qp_num;
	enic->qp = kcalloc(qp_num, sizeof(struct enic_qp), GFP_KERNEL);
	if (!enic->qp) {
		ret = -ENOMEM;
		goto out;
	}

	enic->qp_ring = kcalloc(qp_num, sizeof(struct enic_qp_ring),
				GFP_KERNEL);
	if (!enic->qp_ring) {
		ret = -ENOMEM;
		goto kvfree_qp;
	}

	for (i = 0; i < enic->qp_count; i++) {
		struct enic_qp *qp = &enic->qp[i];

		qp->dev = &enic->pdev->dev;
		qp->netdev = enic->netdev;
		qp->ctrl = vnic_dev_get_res(enic->vdev, RES_TYPE_INTR_CTRL, i);
		if (!qp->ctrl) {
			ret = -ENODEV;
			netdev_err(qp->netdev, "Intr[%d] ctrl not found", i);
			goto kvfree_qp_ring;
		}
		qp->index = i;
		qp->enic = enic;
		enic_qp_ctrl_init(qp);
		qp->rq.vxlan_patch_level = enic->vxlan.patch_level;
	}
	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_MSIX:
	case VNIC_DEV_INTR_MODE_INTX:
		enic->err_ctrl = vnic_dev_get_res(enic->vdev,
						  RES_TYPE_INTR_CTRL,
						  enic->qp_count);
		enic->notify_ctrl = vnic_dev_get_res(enic->vdev,
						     RES_TYPE_INTR_CTRL,
						     enic->qp_count + 1);
		if (!enic->err_ctrl || !enic->notify_ctrl) {
			ret = -ENODEV;
			goto free_qp;
		}
		break;
	case VNIC_DEV_INTR_MODE_MSI:
		break;
	default:
		netdev_err(enic->netdev, "Unknown interrupt type");
		break;
	}

	enic->legacy_pba = vnic_dev_get_res(enic->vdev,
					    RES_TYPE_INTR_PBA_LEGACY, 0);
	if (!enic->legacy_pba && (vnic_dev_get_intr_mode(enic->vdev) ==
				  VNIC_DEV_INTR_MODE_INTX)) {
		ret = -ENODEV;
		goto free_qp;
	}
	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_MSI:
		break;
	case VNIC_DEV_INTR_MODE_MSIX:
		enic_intr_ctrl_init(enic->err_ctrl, 0, 0, 1, 0);
		enic_intr_ctrl_init(enic->notify_ctrl, 0, 0, 1, 0);
		break;
	case VNIC_DEV_INTR_MODE_INTX:
		enic_intr_ctrl_init(enic->err_ctrl, 0, 0, 0, 0);
		enic_intr_ctrl_init(enic->notify_ctrl, 0, 0, 0, 0);
		break;
	default:
		netdev_err(enic->netdev, "interrupt mode unknown");
		break;
	}

	for (i = 0; i < enic->wq_count; i++) {
		ret = enic_alloc_wq(&enic->qp[i]);
		if (ret)
			goto free_qp;
	}

	for (i = 0; i < enic->rq_count; i++) {
		ret = enic_alloc_rq(&enic->qp[i]);
		if (ret)
			goto free_qp;
	}

	return 0;

free_qp:
	enic_free_qp(enic);
	return ret;
kvfree_qp_ring:
	kfree(enic->qp_ring);
	enic->qp_ring = NULL;
kvfree_qp:
	kfree(enic->qp);
	enic->qp = NULL;
out:
	return ret;
}

static inline void enic_wq_service(struct enic_qp *qp, int budget)
{
	struct netdev_queue *txq;
	struct cq_desc *cq_desc;
	struct enic_wq_buf *buf;
	u16 work = 0;
	u16 toclean;

	if (unlikely(!qp->wq.ctrl))
		return;
again:
	cq_desc = &qp->wq.cq_base[qp->wq.cq_to_clean];
	if (CQ_DESC_COLOR(cq_desc) != qp->wq.last_color) {
		toclean = CQ_DESC_INDEX(cq_desc);
		qp->wq.cq_to_clean++;
		if (qp->wq.cq_to_clean == qp->wq.cq_desc_count) {
			qp->wq.cq_to_clean = 0;
			qp->wq.last_color = qp->wq.last_color ? 0 : 1;
		}
		work++;
		goto again;
	} else if (work) {
		buf = qp->wq.to_clean;

		toclean++;
		toclean = (toclean == qp->wq.cq_desc_count) ? 0 : toclean;
		/* clean until (toclean - 1) index
		 */
		while (buf->index != toclean) {
			if (buf->sop)
				dma_unmap_single(qp->dev, buf->dma_addr,
						 buf->len,
						 DMA_TO_DEVICE);
			else if (buf->dma_addr)
				dma_unmap_page(qp->dev, buf->dma_addr, buf->len,
					       DMA_TO_DEVICE);

			napi_consume_skb(buf->skb, budget);
			buf->skb = NULL;
			buf->dma_addr = 0;
			buf->sop = false;
			atomic_inc(&qp->wq.desc_avail);
			buf = buf->next;
		}
		qp->wq.to_clean = buf;
		txq = netdev_get_tx_queue(qp->enic->netdev, qp->index);
		if (netif_tx_queue_stopped(txq) &&
		    (enic_wq_desc_avail(qp) >=
		     (MAX_SKB_FRAGS + ENIC_DESC_MAX_SPLITS)))
			netif_tx_wake_queue(txq);
	}
}

static inline int enic_rq_service(struct enic_qp *qp, u16 budget)
{
	struct net_device *netdev = qp->netdev;
	struct cq_enet_rq_desc *cq_desc;
	struct enic_rq_buf *buf;
	struct sk_buff *skb;
	u32 rss_hash;
	u32 pkt_len;
	u8 rss_type;
	u8 type;
	u16 work = 0;
	bool encap = false;
	bool outer_csum_ok = true;

	if (unlikely(!qp->rq.ctrl))
		return 0;

next_cq_desc:
	cq_desc = &qp->rq.cq_base[qp->rq.cq_to_clean];
	if (CQ_DESC_COLOR(cq_desc) == qp->rq.last_color)
		return work;

	qp->rq.cq_to_clean++;
	if (qp->rq.cq_to_clean == qp->rq.cq_desc_count) {
		qp->rq.cq_to_clean = 0;
		qp->rq.last_color = qp->rq.last_color ? 0 : 1;
	}
next_buf:
	buf = qp->rq.to_clean;
	skb = buf->skb;
	buf->skb = NULL;
	qp->rq.to_clean = buf->next;
	dma_unmap_single(qp->dev, buf->dma_addr, buf->len,
			 DMA_FROM_DEVICE);
	buf->dma_addr = 0;
	if (unlikely(buf->index != CQ_DESC_INDEX(cq_desc))) {
		napi_consume_skb(skb, budget);
		goto next_buf;
	}
	if (unlikely(CQ_DESC_PKT_ERR(cq_desc))) {
		napi_consume_skb(skb, budget);
		if (!CQ_DESC_FCS_OK(cq_desc)) {
			if (CQ_DESC_PKT_LEN(cq_desc) > 0)
				qp->enic->rq_bad_fcs++;
			else if (CQ_DESC_PKT_LEN(cq_desc) == 0)
				qp->enic->rq_truncated_pkts++;
		}

		goto next_cq_desc;
	}
	rss_hash = CQ_DESC_RSS_HASH(cq_desc);
	rss_type = CQ_DESC_RSS_TYPE(cq_desc);
	pkt_len = CQ_DESC_PKT_LEN(cq_desc);
	type = CQ_DESC_TYPE(cq_desc);
	work++;
	prefetch(skb->data - NET_IP_ALIGN);
	skb_put(skb, pkt_len);
	skb->protocol = eth_type_trans(skb, netdev);
	skb_record_rx_queue(skb, qp->index);
	if ((netdev->features & NETIF_F_RXHASH) && rss_hash && type == 3) {
		switch (rss_type) {
		case CQ_ENET_RQ_DESC_RSS_TYPE_TCP_IPv4:
		case CQ_ENET_RQ_DESC_RSS_TYPE_TCP_IPv6:
		case CQ_ENET_RQ_DESC_RSS_TYPE_TCP_IPv6_EX:
			skb_set_hash(skb, rss_hash, PKT_HASH_TYPE_L4);
			break;
		case CQ_ENET_RQ_DESC_RSS_TYPE_IPv4:
		case CQ_ENET_RQ_DESC_RSS_TYPE_IPv6:
		case CQ_ENET_RQ_DESC_RSS_TYPE_IPv6_EX:
			skb_set_hash(skb, rss_hash, PKT_HASH_TYPE_L3);
			break;
		}
	}
	if (qp->rq.vxlan_offload) {
		switch (qp->rq.vxlan_patch_level) {
		case 0:
			if (CQ_DESC_FCOE(cq_desc)) {
				encap = true;
				outer_csum_ok = CQ_DESC_FC_CRC_OK(cq_desc);
			}
			break;
		case 2:
			if (type == 7 && (rss_hash & BIT(0))) {
				encap = true;
				outer_csum_ok = (rss_hash & BIT(0)) &&
						(rss_hash & BIT(2));
			}
			break;
		}
	}
	if ((netdev->features & NETIF_F_RXCSUM) &&
	    !CQ_DESC_CSUM_NOT_CALC(cq_desc)	&&
	    CQ_DESC_TCP_UDP_CSUM_OK(cq_desc)	&&
	    (CQ_DESC_IPV6(cq_desc) || CQ_DESC_IPV4_CSUM_OK(cq_desc)) &&
	    outer_csum_ok) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_level = encap;
	}
	if (CQ_DESC_VLAN_STRIPPED(cq_desc))
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       CQ_DESC_VLAN_TCI(cq_desc));
	skb_mark_napi_id(skb, &qp->napi);
	if (!(netdev->features & NETIF_F_GRO))
		netif_receive_skb(skb);
	else
		napi_gro_receive(&qp->napi, skb);
	qp->rq.bytes += pkt_len;
	if (work >= budget)
		return work;
	goto next_cq_desc;
}

void enic_adaptive_coal(struct enic_qp *qp)
{
	ktime_t now = ktime_get();
	u32 timer;
	u64 delta;
	u64 traffic;
	int i;

	if (!qp->rq.adaptive_coal)
		return;
	delta = ktime_us_delta(now, qp->rq.prev_ts);
	if (unlikely(delta < ENIC_AIC_TS_BREAK))
		return;
	qp->rq.prev_ts = now;
	traffic = qp->rq.bytes - qp->rq.bytes_delta;
	qp->rq.bytes_delta = qp->rq.bytes;

	/* The table takes Mbps
	 * traffic *= 8		=> bits
	 * traffic *= (10^6 / delta)	=> bps
	 * traffic /= 10^6	=>Mbps
	 *
	 * Combining, traffic *=(8/delta)
	 */
	traffic <<= 3;
	do_div(traffic, delta);

	for (i = 0; i < ENIC_MAX_COALESCE_TIMERS; i++)
		if (traffic < mod_table[i].rx_rate)
			break;
	timer = qp->rq.acoal_low + ((qp->rq.acoal_high - qp->rq.acoal_low) *
				    mod_table[i].range_percent) / 100;
	timer = (timer + qp->rq.coal_timer) >> 1;
	if (timer != qp->rq.coal_timer) {
		u32 timer_hw;

		timer_hw = timer * qp->rq.timer_mul;
		do_div(timer_hw, qp->rq.timer_div);
		qp->rq.coal_timer = timer;
		iowrite32(timer_hw, &qp->ctrl->coalescing_timer);
	}
}

int enic_napi_poll(struct napi_struct *napi, int budget)
{
	struct enic_qp *qp = container_of(napi, struct enic_qp, napi);
	int rq_work = 0;
	int ret = 0;

	enic_wq_service(qp, budget);
	if (budget > 0) {
		rq_work = enic_rq_service(qp, budget);
		ret = enic_rq_fill_bufs(qp);
	}

	/* If buffer allocation failed, stay in polling mode so we can try to
	 * fill the ring again. If ret is true and rq_work is 0, that means
	 * second try of refill the ring failed. We exit here.
	 */
	if (rq_work < budget && napi_complete_done(napi, rq_work) &&
	    !(ret && !rq_work)) {
		enic_adaptive_coal(qp);
		enic_intr_unmask(qp);

		return rq_work;
	}

	return budget;
}

static inline void enic_enc_wq_desc(struct wq_enet_desc *desc,
				    dma_addr_t dma_addr,
				    u16 length,
				    u16 mss,
				    u16 header_length,
				    u8 offload_mode,
				    bool eop,
				    bool cq_entry,
				    u16 vlan_tag)
{
	u16 hlf = 0;

	desc->address = cpu_to_le64(dma_addr);
	desc->length = cpu_to_le16(length & WQ_ENET_LEN_MASK);
	/* loopback is always 0 */
	desc->mss_loopback = cpu_to_le16((mss & WQ_ENET_MSS_MASK) <<
					 WQ_ENET_MSS_SHIFT);
	desc->vlan_tag = cpu_to_le16(vlan_tag);

	hlf = (header_length & WQ_ENET_HDRLEN_MASK) |
	      ((offload_mode & WQ_ENET_FLAGS_OM_MASK) << WQ_ENET_HDRLEN_BITS) |
	      (eop ? (1 << WQ_ENET_FLAGS_EOP_SHIFT) : 0) |
	      (cq_entry ? (1 << WQ_ENET_FLAGS_CQ_ENTRY_SHIFT) : 0) |
	      /* skipping fcoe_encap, it's 0 for ethernet frames */
	      (vlan_tag ? (1 << WQ_ENET_FLAGS_VLAN_TAG_INSERT_SHIFT) : 0);
	desc->header_length_flags = cpu_to_le16(hlf);
}

static inline void enic_preload_tcp_csum_encap(struct sk_buff *skb)
{
	const struct ethhdr *eth = (struct ethhdr *)skb_inner_mac_header(skb);

	switch (eth->h_proto) {
	case ntohs(ETH_P_IP):
		inner_ip_hdr(skb)->check = 0;
		inner_tcp_hdr(skb)->check =
			~csum_tcpudp_magic(inner_ip_hdr(skb)->saddr,
					   inner_ip_hdr(skb)->daddr, 0,
					   IPPROTO_TCP, 0);
		break;
	case ntohs(ETH_P_IPV6):
		inner_tcp_hdr(skb)->check =
			~csum_ipv6_magic(&inner_ipv6_hdr(skb)->saddr,
					 &inner_ipv6_hdr(skb)->daddr, 0,
					 IPPROTO_TCP, 0);
		break;
	default:
		WARN_ONCE(1, "Non ipv4/ipv6 inner pkt for encap offload");
		break;
	}
}

static inline void enic_preload_tcp_csum(struct sk_buff *skb)
{
	/* Preload TCP csum field with IP pseudo hdr calculated
	 * with IP length set to zero.  HW will later add in length
	 * to each TCP segment resulting from the TSO.
	 */

	if (skb->protocol == cpu_to_be16(ETH_P_IP)) {
		ip_hdr(skb)->check = 0;
		tcp_hdr(skb)->check = ~csum_tcpudp_magic(ip_hdr(skb)->saddr,
							 ip_hdr(skb)->daddr, 0,
							 IPPROTO_TCP, 0);
	} else if (skb->protocol == cpu_to_be16(ETH_P_IPV6)) {
		tcp_hdr(skb)->check = ~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						       &ipv6_hdr(skb)->daddr, 0,
						       IPPROTO_TCP, 0);
	}
}

static inline void enic_post_xmit_skb(struct enic_qp *qp, struct sk_buff *skb)
{
	dma_addr_t dma_addr;
	skb_frag_t *frag;
	struct enic_wq_buf *buf, *backup;
	unsigned int length;
	unsigned int mss;
	unsigned int header_length = 0;
	unsigned int skb_head_len;
	unsigned int skb_data_len;
	unsigned int offset = 0;
	u8 offload_mode = WQ_ENET_OFFLOAD_MODE_CSUM;
	bool eop;
	bool cq_entry;
	u16 vlan_tag = 0;

	backup = qp->wq.to_use;
	buf = qp->wq.to_use;
	mss = skb_shinfo(skb)->gso_size;
	if (skb_vlan_tag_present(skb))
		vlan_tag = skb_vlan_tag_get(skb);

	if (mss) {
		offload_mode = WQ_ENET_OFFLOAD_MODE_TSO;
		/* For offload mode TSO, mss is max segment size. Adapter will
		 * do the csum of each packet.
		 */
		if (skb->encapsulation) {
			header_length = skb_inner_transport_header(skb) -
					skb->data;
			header_length += inner_tcp_hdrlen(skb);
			enic_preload_tcp_csum_encap(skb);
		} else {
			header_length = skb_transport_offset(skb) +
					tcp_hdrlen(skb);
			enic_preload_tcp_csum(skb);
		}
	} else if (skb->encapsulation) {
		/* Offload mode WQ_ENET_OFFLOAD_MODE_CSUM:
		 * For csum offload mode, mss is 0 means csum on
		 * outer/non-encap pkt.
		 *
		 * For encap pkt, BIT(0), BIT(1) and BIT(2) should be set.
		 */
		mss = 7;
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		/* For offload mode WQ_ENET_OFFLOAD_MODE_CSUM_L4:
		 * mms is checksum field offset from beginning of packet.
		 */
		header_length = skb_checksum_start_offset(skb);
		mss = header_length + skb->csum_offset;
		offload_mode = WQ_ENET_OFFLOAD_MODE_CSUM_L4;
	}

	skb_head_len = skb_headlen(skb);
	skb_data_len = skb->data_len;
	/* sop is 1: buf->dma_addr = dma_map_single
	 * sop is 0: buf->dma_addr = dma_map_page
	 * Used in wq cleanup
	 */
	buf->sop = true;
	dma_addr = dma_map_single(qp->dev, skb->data, skb_head_len,
				  DMA_TO_DEVICE);
	frag = &skb_shinfo(skb)->frags[0];
again:
	if (unlikely(dma_mapping_error(qp->dev, dma_addr))) {
		qp->enic->gen_stats.dma_map_error++;
		goto dma_error;
	}
	offset = 0;
	/* Hw only supports max of WQ_ENET_MAX_DESC_LEN len data per desc.
	 * Post the remaining in next desc.
	 */
	while (skb_head_len) {
		if (!offset) {
			buf->dma_addr = dma_addr;
			buf->len = skb_head_len;
		}
		length = min(skb_head_len, (unsigned int)WQ_ENET_MAX_DESC_LEN);
		skb_head_len -= length;
		eop = !skb_head_len && !skb_data_len;
		buf->skb = eop ? skb : NULL;
		cq_entry = eop;
		enic_enc_wq_desc(&qp->wq.wq_base[buf->index],
				 dma_addr + offset, length, mss, header_length,
				 offload_mode, eop, cq_entry, vlan_tag);
		atomic_dec(&qp->wq.desc_avail);
		offset += length;
		buf = buf->next;
	}

	if (!skb_data_len) {
		qp->wq.to_use = buf;
		return;
	}
	skb_head_len = skb_frag_size(frag);
	skb_data_len -= skb_head_len;
	dma_addr = skb_frag_dma_map(qp->dev, frag, 0, skb_head_len,
				    DMA_TO_DEVICE);
	frag++;
	goto again;

dma_error:
	qp->wq.to_use = backup;
	while (backup != buf) {
		if (backup->sop)
			dma_unmap_single(qp->dev, backup->dma_addr,
					 backup->len, DMA_TO_DEVICE);
		else if (backup->dma_addr)
			dma_unmap_page(qp->dev, backup->dma_addr,
				       backup->len, DMA_TO_DEVICE);
		dev_kfree_skb_any(backup->skb);
		backup->skb = NULL;
		backup->dma_addr = 0;
		atomic_inc(&qp->wq.desc_avail);
		backup = backup->next;
	}
	dev_kfree_skb_any(skb);
}

