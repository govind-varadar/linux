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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/netdevice.h>

#include "wq_enet_desc.h"
#include "rq_enet_desc.h"
#include "cq_enet_desc.h"
#include "vnic_resource.h"
#include "vnic_enet.h"
#include "vnic_dev.h"
#include "vnic_wq.h"
#include "vnic_rq.h"
#include "vnic_cq.h"
#include "vnic_intr.h"
#include "vnic_stats.h"
#include "vnic_nic.h"
#include "vnic_rss.h"
#include "enic_res.h"
#include "enic.h"

int enic_get_vnic_config(struct enic *enic)
{
	struct vnic_enet_config *c = &enic->config;
	int err;

	err = vnic_dev_get_mac_addr(enic->vdev, enic->mac_addr);
	if (err) {
		dev_err(enic_get_dev(enic),
			"Error getting MAC addr, %d\n", err);
		return err;
	}

#define GET_CONFIG(m) \
	do { \
		err = vnic_dev_spec(enic->vdev, \
			offsetof(struct vnic_enet_config, m), \
			sizeof(c->m), &c->m); \
		if (err) { \
			dev_err(enic_get_dev(enic), \
				"Error getting %s, %d\n", #m, err); \
			return err; \
		} \
	} while (0)

	GET_CONFIG(flags);
	GET_CONFIG(wq_desc_count);
	GET_CONFIG(rq_desc_count);
	GET_CONFIG(mtu);
	GET_CONFIG(intr_timer_type);
	GET_CONFIG(intr_mode);
	GET_CONFIG(intr_timer_usec);
	GET_CONFIG(loop_tag);
	GET_CONFIG(num_arfs);

	c->wq_desc_count =
		min_t(u32, ENIC_MAX_WQ_DESCS,
		max_t(u32, ENIC_MIN_WQ_DESCS,
		c->wq_desc_count));
	c->wq_desc_count &= 0xffffffe0; /* must be aligned to groups of 32 */

	c->rq_desc_count =
		min_t(u32, ENIC_MAX_RQ_DESCS,
		max_t(u32, ENIC_MIN_RQ_DESCS,
		c->rq_desc_count));
	c->rq_desc_count &= 0xffffffe0; /* must be aligned to groups of 32 */

	if (c->mtu == 0)
		c->mtu = 1500;
	c->mtu = min_t(u16, ENIC_MAX_MTU,
		max_t(u16, ENIC_MIN_MTU,
		c->mtu));

	c->intr_timer_usec = min_t(u32, c->intr_timer_usec,
		vnic_dev_get_intr_coal_timer_max(enic->vdev));

	dev_info(enic_get_dev(enic),
		"vNIC MAC addr %pM wq/rq %d/%d mtu %d\n",
		enic->mac_addr, c->wq_desc_count, c->rq_desc_count, c->mtu);

	dev_info(enic_get_dev(enic), "vNIC csum tx/rx %s/%s "
		"tso/lro %s/%s rss %s intr mode %s type %s timer %d usec "
		"loopback tag 0x%04x\n",
		ENIC_SETTING(enic, TXCSUM) ? "yes" : "no",
		ENIC_SETTING(enic, RXCSUM) ? "yes" : "no",
		ENIC_SETTING(enic, TSO) ? "yes" : "no",
		ENIC_SETTING(enic, LRO) ? "yes" : "no",
		ENIC_SETTING(enic, RSS) ? "yes" : "no",
		c->intr_mode == VENET_INTR_MODE_INTX ? "INTx" :
		c->intr_mode == VENET_INTR_MODE_MSI ? "MSI" :
		c->intr_mode == VENET_INTR_MODE_ANY ? "any" :
		"unknown",
		c->intr_timer_type == VENET_INTR_TYPE_MIN ? "min" :
		c->intr_timer_type == VENET_INTR_TYPE_IDLE ? "idle" :
		"unknown",
		c->intr_timer_usec,
		c->loop_tag);

	return 0;
}

int enic_add_vlan(struct enic *enic, u16 vlanid)
{
	u64 a0 = vlanid, a1 = 0;
	int wait = 1000;
	int err;

	err = vnic_dev_cmd(enic->vdev, CMD_VLAN_ADD, &a0, &a1, wait);
	if (err)
		dev_err(enic_get_dev(enic), "Can't add vlan id, %d\n", err);

	return err;
}

int enic_del_vlan(struct enic *enic, u16 vlanid)
{
	u64 a0 = vlanid, a1 = 0;
	int wait = 1000;
	int err;

	err = vnic_dev_cmd(enic->vdev, CMD_VLAN_DEL, &a0, &a1, wait);
	if (err)
		dev_err(enic_get_dev(enic), "Can't delete vlan id, %d\n", err);

	return err;
}

int enic_set_nic_cfg(struct enic *enic, u8 rss_default_cpu, u8 rss_hash_type,
	u8 rss_hash_bits, u8 rss_base_cpu, u8 rss_enable, u8 tso_ipid_split_en,
	u8 ig_vlan_strip_en)
{
	enum vnic_devcmd_cmd cmd = CMD_NIC_CFG;
	u64 a0, a1;
	u32 nic_cfg;
	int wait = 1000;

	vnic_set_nic_cfg(&nic_cfg, rss_default_cpu,
		rss_hash_type, rss_hash_bits, rss_base_cpu,
		rss_enable, tso_ipid_split_en, ig_vlan_strip_en);

	a0 = nic_cfg;
	a1 = 0;

	if (rss_hash_type & (NIC_CFG_RSS_HASH_TYPE_UDP_IPV4 |
			     NIC_CFG_RSS_HASH_TYPE_UDP_IPV6))
		cmd = CMD_NIC_CFG_CHK;

	return vnic_dev_cmd(enic->vdev, cmd, &a0, &a1, wait);
}

int enic_set_rss_key(struct enic *enic, dma_addr_t key_pa, u64 len)
{
	u64 a0 = (u64)key_pa, a1 = len;
	int wait = 1000;

	return vnic_dev_cmd(enic->vdev, CMD_RSS_KEY, &a0, &a1, wait);
}

int enic_set_rss_cpu(struct enic *enic, dma_addr_t cpu_pa, u64 len)
{
	u64 a0 = (u64)cpu_pa, a1 = len;
	int wait = 1000;

	return vnic_dev_cmd(enic->vdev, CMD_RSS_CPU, &a0, &a1, wait);
}

void enic_get_res_counts(struct enic *enic)
{
	enic->wq_count = vnic_dev_get_res_count(enic->vdev, RES_TYPE_WQ);
	enic->rq_count = vnic_dev_get_res_count(enic->vdev, RES_TYPE_RQ);
	enic->cq_count = vnic_dev_get_res_count(enic->vdev, RES_TYPE_CQ);
	enic->intr_count = vnic_dev_get_res_count(enic->vdev,
		RES_TYPE_INTR_CTRL);

	dev_info(enic_get_dev(enic),
		"vNIC resources avail: wq %d rq %d cq %d intr %d\n",
		enic->wq_count, enic->rq_count,
		enic->cq_count, enic->intr_count);
}

void enic_print_resources(struct enic *enic)
{
	char *intr_mode;

	switch (vnic_dev_get_intr_mode(enic->vdev)) {
	case VNIC_DEV_INTR_MODE_INTX:
		intr_mode = "legacy PCI INTx";
		break;
	case VNIC_DEV_INTR_MODE_MSI:
		intr_mode = "MSI";
		break;
	case VNIC_DEV_INTR_MODE_MSIX:
		intr_mode = "MSIX";
		break;
	default:
		intr_mode = "Unknown";
	}

	netdev_info(enic->netdev, "vNIC resources used: wq %d rq %d cq %d qp %d intr %d rq_desc %d wq_desc %d intr mode %s\n",
		    enic->wq_count, enic->rq_count, enic->cq_count,
		    enic->qp_count, enic->intr_count,
		    enic->config.rq_desc_count, enic->config.wq_desc_count,
		    intr_mode);
}

