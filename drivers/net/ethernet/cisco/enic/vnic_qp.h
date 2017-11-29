#ifndef _VNIC_QP_H_
#define _VNIC_QP_H_

#include <linux/irq.h>

#include "vnic_wq.h"
#include "vnic_cq.h"

struct enic_msix_entry {
	int requested;
	char devname[IFNAMSIZ + 8];
	irqreturn_t (*isr)(int, void *);
	void *devid;
	cpumask_var_t affinity_mask;
};

struct vnic_qp {
	struct vnic_rq rq;
	struct vnic_cq cqr;

	struct vnic_wq wq;
	struct vnic_cq cqw;
	struct vnic_intr_ctrl __iomem *intr_ctrl;
	struct enic_msix_entry msix;

	struct napi_struct napi;
	u16 index;
	struct vnic_dev *vdev;
} ____cacheline_aligned_in_smp;

#endif /* _VNIC_QP_H_ */
