// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe over Fabrics DH-HMAC-CHAP authentication command handling.
 * Copyright (c) 2020 Hannes Reinecke, SUSE Software Solutions.
 * All rights reserved.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/blkdev.h>
#include <linux/random.h>
#include <crypto/kpp.h>
#include "nvmet.h"

static u16 nvmet_auth_negotiate(struct nvmet_req *req, void *d)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvmf_auth_dhchap_negotiate_data *data = d;
	int i, hash_id, null_dh = -1;
	unsigned int hash_len;

	pr_debug("%s: ctrl %d qid %d: data sc_d %d napd %d authid %d halen %d dhlen %d\n",
		 __func__, ctrl->cntlid, req->sq->qid,
		 data->sc_c, data->napd, data->auth_protocol[0].dhchap.authid,
		 data->auth_protocol[0].dhchap.halen,
		 data->auth_protocol[0].dhchap.dhlen);
	req->sq->dhchap_transaction = le16_to_cpu(data->t_id);
	if (data->sc_c)
		return NVME_AUTH_DHCHAP_FAILURE_CONCAT_MISMATCH;

	if (data->napd != 1)
		return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;

	if (data->auth_protocol[0].dhchap.authid != 0x01)
		return NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;

	hash_id = nvmet_auth_get_hash(ctrl, &hash_len);
	for (i = 0; i < data->auth_protocol[0].dhchap.halen; i++) {
		pr_debug("%s: ctrl %d qid %d checking hash %d for %d\n",
			 __func__, ctrl->cntlid, req->sq->qid,
			 data->auth_protocol[0].dhchap.idlist[i], hash_id);
		if (hash_id != data->auth_protocol[0].dhchap.idlist[i])
			continue;
		req->sq->dhchap_response = kmalloc(hash_len, GFP_KERNEL);
		if (req->sq->dhchap_response) {
			req->sq->dhchap_hash_id = hash_id;
			req->sq->dhchap_hash_len = hash_len;
			break;
		}
	}
	if (req->sq->dhchap_hash_id == 0) {
		pr_debug("%s: ctrl %d qid %d: no usable hash found\n",
			 __func__, ctrl->cntlid, req->sq->qid);
		return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
	}

	for (i = data->auth_protocol[0].dhchap.halen;
	     i < data->auth_protocol[0].dhchap.halen +
		     data->auth_protocol[0].dhchap.dhlen; i++) {
		int dhgid = data->auth_protocol[0].dhchap.idlist[i];

		if (dhgid == NVME_AUTH_DHCHAP_DHGROUP_NULL) {
			null_dh = dhgid;
			continue;
		}
		if (nvmet_setup_dhgroup(ctrl, dhgid) == 0) {
			break;
		}
	}
	if (!ctrl->dh_tfm && null_dh < 0) {
		pr_debug("%s: ctrl %d qid %d: no DH group selected\n",
			 __func__, ctrl->cntlid, req->sq->qid);
		kfree(req->sq->dhchap_response);
		req->sq->dhchap_response = NULL;
		return NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}
	if (ctrl->dh_gid == -1) {
		ctrl->dh_gid = null_dh;
		ctrl->dh_tfm = NULL;
	}
	pr_debug("%s: ctrl %d qid %d: DH group %s (%d)\n",
		 __func__, ctrl->cntlid, req->sq->qid,
		 nvmet_dhchap_dhgroup_name(ctrl->dh_gid), ctrl->dh_gid);
	return 0;
}

static u16 nvmet_auth_reply(struct nvmet_req *req, void *d)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvmf_auth_dhchap_reply_data *data = d;

	if (data->hl != req->sq->dhchap_hash_len)
		return NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;

	if (data->dhvlen) {
		if (!ctrl->dh_tfm)
			return NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
		if (nvmet_auth_ctrl_sesskey(req, data->rval + 2 * data->hl,
					    data->dhvlen) < 0)
			return NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}

	if (memcmp(data->rval, req->sq->dhchap_response, data->hl)) {
		pr_info("ctrl %d qid %d DH-HMAC-CHAP response mismatch\n",
			ctrl->cntlid, req->sq->qid);
		kfree(req->sq->dhchap_response);
		req->sq->dhchap_response = NULL;
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}
	pr_info("ctrl %d qid %d DH-HMAC-CHAP host authenticated\n",
		ctrl->cntlid, req->sq->qid);
	if (data->cvalid) {
		u8 *challenge = data->rval + data->hl;

		pr_debug("ctrl %d qid %d challenge %*ph\n",
			 ctrl->cntlid, req->sq->qid, data->hl, challenge);
		if (nvmet_auth_controller_hash(ctrl, data->hl, challenge,
				req->sq->dhchap_response,
				le32_to_cpu(data->seqnum),
				req->sq->dhchap_transaction))
			return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
		pr_debug("ctrl %d qid %d response %*ph\n",
			 ctrl->cntlid, req->sq->qid, data->hl,
			 req->sq->dhchap_response);
	} else {
		kfree(req->sq->dhchap_response);
		req->sq->dhchap_response = NULL;
	}

	return 0;
}

static u16 nvmet_auth_failure2(struct nvmet_req *req, void *d)
{
	struct nvmf_auth_dhchap_failure_data *data = d;

	return data->reason_code_explanation;
}

void nvmet_execute_auth_send(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvmf_auth_dhchap_success2_data *data;
	void *d;
	u32 tl;
	u16 status = 0;

	if (req->cmd->auth_send.secp != NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_send_command, secp);
		goto done;
	}
	if (req->cmd->auth_send.spsp0 != 0x01) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_send_command, spsp0);
		goto done;
	}
	if (req->cmd->auth_send.spsp1 != 0x01) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_send_command, spsp1);
		goto done;
	}
	tl = le32_to_cpu(req->cmd->auth_send.tl);
	if (!tl) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_send_command, tl);
		goto done;
	}
	if (!nvmet_check_transfer_len(req, tl)) {
		pr_debug("%s: transfer length mismatch (%u)\n", __func__, tl);
		return;
	}

	d = kmalloc(tl, GFP_KERNEL);
	if (!d) {
		status = NVME_SC_INTERNAL;
		goto done;
	}

	status = nvmet_copy_from_sgl(req, 0, d, tl);
	if (status) {
		kfree(d);
		goto done;
	}

	data = d;
	pr_debug("%s: ctrl %d qid %d type %d id %d step %x\n", __func__,
		 ctrl->cntlid, req->sq->qid, data->auth_type, data->auth_id,
		 req->sq->dhchap_step);
	if (data->auth_type != NVME_AUTH_COMMON_MESSAGES &&
	    data->auth_type != NVME_AUTH_DHCHAP_MESSAGES) {
		req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
		req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_MESSAGE;
	} else if (data->auth_type == NVME_AUTH_COMMON_MESSAGES) {
		if (data->auth_id != req->sq->dhchap_step) {
			req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
			req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_MESSAGE;
		} else if (data->auth_id != NVME_AUTH_DHCHAP_MESSAGE_NEGOTIATE) {
			req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
			req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_MESSAGE;
		} else {
			/* Validate negotiation parameters */
			status = nvmet_auth_negotiate(req, d);
			if (status == 0)
				req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE;
			else {
				req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
				req->sq->dhchap_status = status;
				status = 0;
			}
		}
	} else if (data->auth_type == NVME_AUTH_DHCHAP_MESSAGES) {
		if (data->auth_id != req->sq->dhchap_step) {
			pr_debug("%s: ctrl %d qid %d step mismatch (%d != %d)\n",
				 __func__, ctrl->cntlid, req->sq->qid,
				 data->auth_id, req->sq->dhchap_step);
			req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
			req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_MESSAGE;
		} else if (le16_to_cpu(data->t_id) != req->sq->dhchap_transaction) {
			pr_debug("%s: ctrl %d qid %d invalid transaction %d (expected %d)\n",
				 __func__, ctrl->cntlid, req->sq->qid,
				 le16_to_cpu(data->t_id),
				 req->sq->dhchap_transaction);
			req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
			req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
		} else {
			switch (data->auth_id) {
			case NVME_AUTH_DHCHAP_MESSAGE_REPLY:
				status = nvmet_auth_reply(req, d);
				if (status == 0)
					req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1;
				else {
					req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
					req->sq->dhchap_status = status;
					status = 0;
				}
				break;
			case NVME_AUTH_DHCHAP_MESSAGE_SUCCESS2:
				req->sq->authenticated = true;
				pr_debug("%s: ctrl %d qid %d authenticated\n",
					 __func__, ctrl->cntlid, req->sq->qid);
				break;
			case NVME_AUTH_DHCHAP_MESSAGE_FAILURE2:
				status = nvmet_auth_failure2(req, d);
				if (status) {
					pr_warn("ctrl %d qid %d: DH-HMAC-CHAP negotiation failed (%d)\n",
						ctrl->cntlid, req->sq->qid,
						status);
					req->sq->dhchap_status = status;
					status = 0;
				}
				break;
			default:
				req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_MESSAGE;
				req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE2;
				break;
			}
		}
	} else {
		req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INVALID_MESSAGE;
		req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE2;
	}
	kfree(d);
done:
	pr_debug("%s: ctrl %d qid %d dhchap status %x step %x\n", __func__,
		 ctrl->cntlid, req->sq->qid,
		 req->sq->dhchap_status, req->sq->dhchap_step);
	if (status)
		pr_debug("%s: ctrl %d qid %d nvme status %x error loc %d\n",
			 __func__, ctrl->cntlid, req->sq->qid,
			 status, req->error_loc);
	req->cqe->result.u64 = 0;
	nvmet_req_complete(req, status);
	if (req->sq->dhchap_step == NVME_AUTH_DHCHAP_MESSAGE_FAILURE2)
		nvmet_ctrl_fatal_error(ctrl);
}

static int nvmet_auth_challenge(struct nvmet_req *req, void *d, int al)
{
	struct nvmf_auth_dhchap_challenge_data *data = d;
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	u8 *challenge;
	int ret;
	u32 seqnum = ctrl->dhchap_seqnum++;
	int data_size = sizeof(*d) + req->sq->dhchap_hash_len;

	if (ctrl->dh_tfm)
		data_size += crypto_kpp_maxsize(ctrl->dh_tfm);
	if (al < data_size) {
		pr_debug("%s: buffer too small (al %d need %d)\n", __func__,
			 al, data_size);
		return -EINVAL;
	}
	memset(data, 0, data_size);
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE;
	data->t_id = cpu_to_le16(req->sq->dhchap_transaction);
	data->hashid = req->sq->dhchap_hash_id;
	data->hl = req->sq->dhchap_hash_len;
	data->seqnum = cpu_to_le32(seqnum);
	challenge = kmalloc(data->hl, GFP_KERNEL);
	if (!challenge)
		return -ENOMEM;
	get_random_bytes(challenge, data->hl);
	memcpy(data->cval, challenge, data->hl);
	ret = nvmet_auth_host_hash(ctrl, data->hl, challenge,
				   req->sq->dhchap_response,
				   req->sq->dhchap_transaction, seqnum);
	kfree(challenge);
	if (ctrl->dh_tfm) {
		data->dhgid = ctrl->dh_gid;
		data->dhvlen = crypto_kpp_maxsize(ctrl->dh_tfm);
		ret = nvmet_auth_ctrl_exponential(req, data->cval + data->hl,
						  data->dhvlen);
	}
	pr_debug("%s: ctrl %d qid %d seq %d transaction %d hl %d dhvlen %d\n",
		 __func__,  ctrl->cntlid, req->sq->qid, seqnum,
		 req->sq->dhchap_transaction, data->hl, data->dhvlen);
	return ret;
}

static void nvmet_auth_success1(struct nvmet_req *req, void *d, int al)
{
	struct nvmf_auth_dhchap_success1_data *data = d;

	WARN_ON(al < sizeof(*data));
	memset(data, 0, sizeof(*data));
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1;
	data->t_id = cpu_to_le16(req->sq->dhchap_transaction);
	data->hl = req->sq->dhchap_hash_len;
	if (req->sq->dhchap_response) {
		data->rvalid = 1;
		memcpy(data->rval, req->sq->dhchap_response,
		       req->sq->dhchap_hash_len);
		kfree(req->sq->dhchap_response);
		req->sq->dhchap_response = NULL;
	}
}

static void nvmet_auth_failure1(struct nvmet_req *req, void *d, int al)
{
	struct nvmf_auth_dhchap_failure_data *data = d;

	WARN_ON(al < sizeof(*data));
	data->auth_type = NVME_AUTH_COMMON_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
	data->t_id = cpu_to_le32(req->sq->dhchap_transaction);
	data->reason_code = NVME_AUTH_DHCHAP_FAILURE_REASON_FAILED;
	data->reason_code_explanation = req->sq->dhchap_status;
}

void nvmet_execute_auth_receive(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	void *d;
	u32 al;
	u16 status = 0;

	if (req->cmd->auth_receive.secp != NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_receive_command, secp);
		goto done;
	}
	if (req->cmd->auth_receive.spsp0 != 0x01) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_receive_command, spsp0);
		goto done;
	}
	if (req->cmd->auth_receive.spsp1 != 0x01) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_receive_command, spsp1);
		goto done;
	}
	al = le32_to_cpu(req->cmd->auth_receive.al);
	if (!al) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		req->error_loc =
			offsetof(struct nvmf_auth_receive_command, al);
		goto done;
	}
	if (!nvmet_check_transfer_len(req, al)) {
		pr_debug("%s: transfer length mismatch (%u)\n", __func__, al);
		return;
	}

	d = kmalloc(al, GFP_KERNEL);
	if (!d) {
		status = NVME_SC_INTERNAL;
		goto done;
	}
	pr_debug("%s: ctrl %d qid %d step %x\n", __func__,
		 ctrl->cntlid, req->sq->qid, req->sq->dhchap_step);
	switch (req->sq->dhchap_step) {
	case NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE:
		status = nvmet_auth_challenge(req, d, al);
		if (status < 0) {
			pr_warn("ctrl %d qid %d: challenge error (%d)\n",
				ctrl->cntlid, req->sq->qid, status);
			status = NVME_SC_INTERNAL;
			break;
		}
		if (status) {
			req->sq->dhchap_status = status;
			nvmet_auth_failure1(req, d, al);
			pr_warn("ctrl %d qid %d: challenge status (%x)\n",
				ctrl->cntlid, req->sq->qid,
				req->sq->dhchap_status);
			status = 0;
			break;
		}
		req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_REPLY;
		break;
	case NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1:
		nvmet_auth_success1(req, d, al);
		req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_SUCCESS2;
		break;
	case NVME_AUTH_DHCHAP_MESSAGE_FAILURE1:
		nvmet_auth_failure1(req, d, al);
		pr_warn("ctrl %d qid %d failure1 (%x)\n",
			ctrl->cntlid, req->sq->qid, req->sq->dhchap_status);
		break;
	default:
		pr_warn("ctrl %d qid %d unhandled step (%d)\n",
			ctrl->cntlid, req->sq->qid, req->sq->dhchap_step);
		req->sq->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
		req->sq->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_FAILED;
		nvmet_auth_failure1(req, d, al);
		status = 0;
		break;
	}

	status = nvmet_copy_to_sgl(req, 0, d, al);
	kfree(d);
done:
	req->cqe->result.u64 = 0;
	nvmet_req_complete(req, status);
	if (req->sq->dhchap_step == NVME_AUTH_DHCHAP_MESSAGE_FAILURE1)
		nvmet_ctrl_fatal_error(ctrl);
}
