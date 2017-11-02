#ifndef _VNIC_QP_H_
#define _VNIC_QP_H_

#include "vnic_wq.h"
#include "vnic_cq.h"

struct vnic_qp {
	struct vnic_rq rq;

	struct vnic_wq wq;

	u32 index;
} ____cacheline_aligned_in_smp;

#endif /* _VNIC_QP_H_ */
