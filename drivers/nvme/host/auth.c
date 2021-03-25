// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Hannes Reinecke, SUSE Linux
 */

#include <linux/crc32.h>
#include <linux/base64.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include "nvme.h"
#include "fabrics.h"

#define NVME_FFDHE_MINSIZE 64

static u32 nvme_dhchap_seqnum;

struct nvme_dhchap_context {
	struct crypto_shash *shash_tfm;
	struct crypto_kpp *dh_tfm;
	char key[64];
	int qid;
	u32 seqnum;
	u16 transaction;
	u8 status;
	u8 hash_id;
	u8 hash_len;
	u8 dhgroup_id;
	u16 dhgroup_size;
	char challenge[64];
	char response[64];
	u8 *ctrl_key;
	int ctrl_key_len;
	u8 *host_key;
	int host_key_len;
	u8 *sess_key;
	int sess_key_len;
};

int nvme_auth_send(struct nvme_ctrl *ctrl, int qid, void *data, size_t tl)
{
	struct nvme_command cmd = {};
	blk_mq_req_flags_t flags = qid == NVME_QID_ANY ?
		0 : BLK_MQ_REQ_NOWAIT | BLK_MQ_REQ_RESERVED;
	struct request_queue *q = qid == NVME_QID_ANY ?
		ctrl->fabrics_q : ctrl->connect_q;
	int ret;

	cmd.auth_send.opcode = nvme_fabrics_command;
	cmd.auth_send.fctype = nvme_fabrics_type_auth_send;
	cmd.auth_send.secp = NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER;
	cmd.auth_send.spsp0 = 0x01;
	cmd.auth_send.spsp1 = 0x01;
	cmd.auth_send.tl = tl;

	ret = __nvme_submit_sync_cmd(q, &cmd, NULL, data, tl, 0, qid,
				     0, flags, false);
	if (ret)
		dev_dbg(ctrl->device,
			"%s: qid %d error %d\n", __func__, qid, ret);
	return ret;
}

int nvme_auth_receive(struct nvme_ctrl *ctrl, int qid, void *buf, size_t al,
		      u16 transaction, u8 expected_msg )
{
	struct nvme_command cmd = {};
	struct nvmf_auth_dhchap_failure_data *data = buf;
	blk_mq_req_flags_t flags = qid == NVME_QID_ANY ?
		0 : BLK_MQ_REQ_NOWAIT | BLK_MQ_REQ_RESERVED;
	struct request_queue *q = qid == NVME_QID_ANY ?
		ctrl->fabrics_q : ctrl->connect_q;
	int ret;

	cmd.auth_receive.opcode = nvme_fabrics_command;
	cmd.auth_receive.fctype = nvme_fabrics_type_auth_receive;
	cmd.auth_receive.secp = NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER;
	cmd.auth_receive.spsp0 = 0x01;
	cmd.auth_receive.spsp1 = 0x01;
	cmd.auth_receive.al = al;

	ret = __nvme_submit_sync_cmd(q, &cmd, NULL, buf, al, 0, qid,
				     0, flags, false);
	if (ret > 0) {
		dev_dbg(ctrl->device, "%s: qid %d nvme status %x\n",
			__func__, qid, ret);
		ret = -EIO;
	}
	if (ret < 0) {
		dev_dbg(ctrl->device, "%s: qid %d error %d\n",
			__func__, qid, ret);
		return ret;
	}
	dev_dbg(ctrl->device, "%s: qid %d auth_type %d auth_id %x\n",
		__func__, qid, data->auth_type, data->auth_id);
	if (data->auth_type == NVME_AUTH_COMMON_MESSAGES &&
	    data->auth_id == NVME_AUTH_DHCHAP_MESSAGE_FAILURE1) {
		return data->reason_code_explanation;
	}
	if (data->auth_type != NVME_AUTH_DHCHAP_MESSAGES ||
	    data->auth_id != expected_msg) {
		dev_warn(ctrl->device,
			 "%s: qid %d invalid message type %02x/%02x\n",
			 __func__, qid, data->auth_type, data->auth_id);
		return NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
	}
	if (le16_to_cpu(data->t_id) != transaction) {
		dev_warn(ctrl->device,
			 "%s: qid %d invalid transaction ID %d\n",
			 __func__, qid, le16_to_cpu(data->t_id));
		return NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
	}

	return 0;
}

int nvme_auth_dhchap_negotiate(struct nvme_ctrl *ctrl,
			       struct nvme_dhchap_context *chap,
			       void *buf, size_t buf_size)
{
	struct nvmf_auth_dhchap_negotiate_data *data = buf;
	size_t size = sizeof(*data) + sizeof(union nvmf_auth_protocol);

	if (buf_size < size)
		return -EINVAL;

	memset((u8 *)buf, 0, size);
	data->auth_type = NVME_AUTH_COMMON_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_NEGOTIATE;
	data->t_id = cpu_to_le16(chap->transaction);
	data->sc_c = 0; /* No secure channel concatenation */
	data->napd = 1;
	data->auth_protocol[0].dhchap.authid = NVME_AUTH_DHCHAP_AUTH_ID;
	data->auth_protocol[0].dhchap.halen = 3;
	data->auth_protocol[0].dhchap.dhlen = 3;
	data->auth_protocol[0].dhchap.idlist[0] = NVME_AUTH_DHCHAP_HASH_SHA256;
	data->auth_protocol[0].dhchap.idlist[1] = NVME_AUTH_DHCHAP_HASH_SHA384;
	data->auth_protocol[0].dhchap.idlist[2] = NVME_AUTH_DHCHAP_HASH_SHA512;
	data->auth_protocol[0].dhchap.idlist[3] = NVME_AUTH_DHCHAP_DHGROUP_NULL;
	data->auth_protocol[0].dhchap.idlist[4] = NVME_AUTH_DHCHAP_DHGROUP_ECDH;
	data->auth_protocol[0].dhchap.idlist[5] = NVME_AUTH_DHCHAP_DHGROUP_25519;

	return size;
}

int nvme_auth_dhchap_challenge(struct nvme_ctrl *ctrl,
			       struct nvme_dhchap_context *chap,
			       void *buf, size_t buf_size)
{
	struct nvmf_auth_dhchap_challenge_data *data = buf;
	size_t size = sizeof(*data) + data->hl + data->dhvlen;
	const char *gid_name;

	if (buf_size < size) {
		chap->status = NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
		return -ENOMSG;
	}

	if (data->hashid != NVME_AUTH_DHCHAP_HASH_SHA256 &&
	    data->hashid != NVME_AUTH_DHCHAP_HASH_SHA384 &&
	    data->hashid != NVME_AUTH_DHCHAP_HASH_SHA512) {
		dev_warn(ctrl->device,
			 "qid %d: DH-HMAC-CHAP: invalid HASH ID %d\n",
			 chap->qid, data->hashid);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
		return -EPROTO;
	}
	switch (data->dhgid) {
	case NVME_AUTH_DHCHAP_DHGROUP_NULL:
		gid_name = "null";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_2048:
		gid_name = "ffdhe2048";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_3072:
		gid_name = "ffdhe3072";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_4096:
		gid_name = "ffdhe4096";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_6144:
		gid_name = "ffdhe6144";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_8192:
		gid_name = "ffdhe8192";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_ECDH:
		gid_name = "ecdh";
		break;
	case NVME_AUTH_DHCHAP_DHGROUP_25519:
		gid_name = "curve25519";
		break;
	default:
		gid_name = NULL;
		break;
	}
	if (!gid_name) {
		dev_warn(ctrl->device,
			 "qid %d: DH-HMAC-CHAP: invalid DH group id %d\n",
			 chap->qid, data->dhgid);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
		return -EPROTO;
	}
	if (data->dhgid != NVME_AUTH_DHCHAP_DHGROUP_NULL) {
		if (data->dhvlen == 0) {
			dev_warn(ctrl->device,
				 "qid %d: DH-HMAC-CHAP: empty DH value\n",
				 chap->qid);
			chap->status = NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
			return -EPROTO;
		}
		chap->dh_tfm = crypto_alloc_kpp(gid_name, 0, 0);
		if (IS_ERR(chap->dh_tfm)) {
			dev_warn(ctrl->device,
				 "qid %d: DH-HMAC-CHAP: failed to initialize %s\n",
				 chap->qid, gid_name);
			chap->status = NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
			chap->dh_tfm = NULL;
			return -EPROTO;
		}
	} else if (data->dhvlen != 0) {
		dev_warn(ctrl->device,
			 "qid %d: DH-HMAC-CHAP: invalid DH value for NULL DH\n",
			chap->qid);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
		return -EPROTO;
	}
	dev_dbg(ctrl->device, "%s: qid %d requested hash id %d\n",
		__func__, chap->qid, data->hashid);
	chap->hash_id = data->hashid;
	if ((data->hashid == NVME_AUTH_DHCHAP_HASH_SHA256 &&
	     data->hl != 32) ||
	    (data->hashid == NVME_AUTH_DHCHAP_HASH_SHA384 &&
	     data->hl != 48) ||
	    (data->hashid == NVME_AUTH_DHCHAP_HASH_SHA512 &&
	     data->hl != 64)) {
		dev_warn(ctrl->device,
			 "qid %d: DH-HMAC-CHAP: invalid hash length\n",
			chap->qid);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
		return -EPROTO;
	}
	chap->hash_len = data->hl;
	chap->seqnum = le32_to_cpu(data->seqnum);
	memcpy(chap->challenge, data->cval, chap->hash_len);
	if (data->dhvlen) {
		chap->ctrl_key = kmalloc(data->dhvlen, GFP_KERNEL);
		if (!chap->ctrl_key)
			return -ENOMEM;
		chap->ctrl_key_len = data->dhvlen;
		memcpy(chap->ctrl_key, data->cval + chap->hash_len,
		       data->dhvlen);
		dev_dbg(ctrl->device, "ctrl public key %*ph\n",
			 (int)chap->ctrl_key_len, chap->ctrl_key);
	}

	return 0;
}

int nvme_auth_dhchap_reply(struct nvme_ctrl *ctrl,
			   struct nvme_dhchap_context *chap,
			   void *buf, size_t buf_size)
{
	struct nvmf_auth_dhchap_reply_data *data = buf;
	size_t size = sizeof(*data);

	size += 2 * chap->hash_len;
	if (ctrl->opts->dhchap_auth) {
		get_random_bytes(chap->challenge, chap->hash_len);
		chap->seqnum = nvme_dhchap_seqnum++;
	} else
		memset(chap->challenge, 0, chap->hash_len);

	if (chap->host_key_len)
		size += chap->host_key_len;

	if (buf_size < size)
		return -EINVAL;

	memset(buf, 0, size);
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_REPLY;
	data->t_id = cpu_to_le16(chap->transaction);
	data->hl = chap->hash_len;
	data->dhvlen = chap->host_key_len;
	data->seqnum = cpu_to_le32(chap->seqnum);
	memcpy(data->rval, chap->response, chap->hash_len);
	if (ctrl->opts->dhchap_auth) {
		dev_dbg(ctrl->device, "%s: qid %d ctrl challenge %*ph\n",
			__func__, chap->qid,
			chap->hash_len, chap->challenge);
		data->cvalid = 1;
		memcpy(data->rval + chap->hash_len, chap->challenge,
		       chap->hash_len);
	}
	if (chap->host_key_len) {
		dev_dbg(ctrl->device, "%s: qid %d host public key %*ph\n",
			__func__, chap->qid,
			chap->host_key_len, chap->host_key);
		memcpy(data->rval + 2 * chap->hash_len, chap->host_key,
		       chap->host_key_len);
	}
	return size;
}

int nvme_auth_dhchap_success1(struct nvme_ctrl *ctrl,
			      struct nvme_dhchap_context *chap,
			      void *buf, size_t buf_size)
{
	struct nvmf_auth_dhchap_success1_data *data = buf;
	size_t size = sizeof(*data);

	if (ctrl->opts->dhchap_auth)
		size += chap->hash_len;


	if (buf_size < size) {
		chap->status = NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
		return -ENOMSG;
	}

	if (data->hl != chap->hash_len) {
		dev_warn(ctrl->device,
			 "qid %d: DH-HMAC-CHAP: invalid hash length %d\n",
			 chap->qid, data->hl);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
		return -EPROTO;
	}

	if (!data->rvalid)
		return 0;

	/* Validate controller response */
	if (memcmp(chap->response, data->rval, data->hl)) {
		dev_dbg(ctrl->device, "%s: qid %d ctrl response %*ph\n",
			__func__, chap->qid, chap->hash_len, data->rval);
		dev_dbg(ctrl->device, "%s: qid %d host response %*ph\n",
			__func__, chap->qid, chap->hash_len, chap->response);
		dev_warn(ctrl->device,
			 "qid %d: DH-HMAC-CHAP: controller authentication failed\n",
			 chap->qid);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
		return -EPROTO;
	}
	dev_info(ctrl->device,
		 "qid %d: DH-HMAC-CHAP: controller authenticated\n",
		chap->qid);
	return 0;
}

int nvme_auth_dhchap_success2(struct nvme_ctrl *ctrl,
			      struct nvme_dhchap_context *chap,
			      void *buf, size_t buf_size)
{
	struct nvmf_auth_dhchap_success2_data *data = buf;
	size_t size = sizeof(*data);

	memset(buf, 0, size);
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_SUCCESS2;
	data->t_id = cpu_to_le16(chap->transaction);

	return size;
}

int nvme_auth_dhchap_failure2(struct nvme_ctrl *ctrl,
			      struct nvme_dhchap_context *chap,
			      void *buf, size_t buf_size)
{
	struct nvmf_auth_dhchap_failure_data *data = buf;
	size_t size = sizeof(*data);

	memset(buf, 0, size);
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_FAILURE2;
	data->t_id = cpu_to_le16(chap->transaction);
	data->reason_code = 1;
	data->reason_code_explanation = chap->status;

	return size;
}

int nvme_auth_select_hash(struct nvme_ctrl *ctrl,
			  struct nvme_dhchap_context *chap)
{
	char *hash_name;
	int ret;

	switch (chap->hash_id) {
	case NVME_AUTH_DHCHAP_HASH_SHA256:
		hash_name = "hmac(sha256)";
		break;
	case NVME_AUTH_DHCHAP_HASH_SHA384:
		hash_name = "hmac(sha384)";
		break;
	case NVME_AUTH_DHCHAP_HASH_SHA512:
		hash_name = "hmac(sha512)";
		break;
	default:
		hash_name = NULL;
		break;
	}
	if (!hash_name) {
		chap->status = NVME_AUTH_DHCHAP_FAILURE_NOT_USABLE;
		return -EPROTO;
	}
	chap->shash_tfm = crypto_alloc_shash(hash_name, 0,
					     CRYPTO_ALG_ALLOCATES_MEMORY);
	if (IS_ERR(chap->shash_tfm)) {
		chap->status = NVME_AUTH_DHCHAP_FAILURE_NOT_USABLE;
		chap->shash_tfm = NULL;
		return -EPROTO;
	}
	if (!chap->key) {
		dev_warn(ctrl->device, "qid %d: cannot select hash, no key\n",
			 chap->qid);
		chap->status = NVME_AUTH_DHCHAP_FAILURE_NOT_USABLE;
		return -EINVAL;
	}
	ret = crypto_shash_setkey(chap->shash_tfm, chap->key, chap->hash_len);
	if (ret) {
		chap->status = NVME_AUTH_DHCHAP_FAILURE_NOT_USABLE;
		crypto_free_shash(chap->shash_tfm);
		chap->shash_tfm = NULL;
		return ret;
	}
	dev_info(ctrl->device, "qid %d: DH-HMAC_CHAP: selected hash %s\n",
		 chap->qid, hash_name);
	return 0;
}

int nvme_auth_dhchap_host_response(struct nvme_ctrl *ctrl,
				   struct nvme_dhchap_context *chap)
{
	SHASH_DESC_ON_STACK(shash, chap->shash_tfm);
	u8 buf[4];
	int ret;

	dev_dbg(ctrl->device, "%s: qid %d host response seq %d transaction %d\n",
		__func__, chap->qid, chap->seqnum, chap->transaction);
	shash->tfm = chap->shash_tfm;
	ret = crypto_shash_init(shash);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, chap->challenge, chap->hash_len);
	if (ret)
		goto out;
	put_unaligned_le32(chap->seqnum, buf);
	ret = crypto_shash_update(shash, buf, 4);
	if (ret)
		goto out;
	put_unaligned_le16(chap->transaction, buf);
	ret = crypto_shash_update(shash, buf, 2);
	if (ret)
		goto out;
	memset(buf, 0, sizeof(buf));
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, "HostHost", 8);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->opts->host->nqn,
				  strlen(ctrl->opts->host->nqn));
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->opts->subsysnqn,
			    strlen(ctrl->opts->subsysnqn));
	if (ret)
		goto out;
	ret = crypto_shash_final(shash, chap->response);
out:
	return ret;
}

int nvme_auth_dhchap_controller_response(struct nvme_ctrl *ctrl,
					 struct nvme_dhchap_context *chap)
{
	SHASH_DESC_ON_STACK(shash, chap->shash_tfm);
	u8 buf[4];
	int ret;

	dev_dbg(ctrl->device, "%s: qid %d host response seq %d transaction %d\n",
		__func__, chap->qid, chap->seqnum, chap->transaction);
	dev_dbg(ctrl->device, "%s: qid %d challenge %*ph\n",
		__func__, chap->qid, chap->hash_len, chap->challenge);
	dev_dbg(ctrl->device, "%s: qid %d subsysnqn %s\n",
		__func__, chap->qid, ctrl->opts->subsysnqn);
	dev_dbg(ctrl->device, "%s: qid %d hostnqn %s\n",
		__func__, chap->qid, ctrl->opts->host->nqn);
	shash->tfm = chap->shash_tfm;
	ret = crypto_shash_init(shash);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, chap->challenge, chap->hash_len);
	if (ret)
		goto out;
	put_unaligned_le32(chap->seqnum, buf);
	ret = crypto_shash_update(shash, buf, 4);
	if (ret)
		goto out;
	put_unaligned_le16(chap->transaction, buf);
	ret = crypto_shash_update(shash, buf, 2);
	if (ret)
		goto out;
	memset(buf, 0, 4);
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, "Controller", 10);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->opts->subsysnqn,
				  strlen(ctrl->opts->subsysnqn));
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->opts->host->nqn,
				  strlen(ctrl->opts->host->nqn));
	if (ret)
		goto out;
	ret = crypto_shash_final(shash, chap->response);
out:
	return ret;
}

int nvme_auth_generate_key(struct nvme_ctrl *ctrl,
			   struct nvme_dhchap_context *chap)
{
	size_t dhchap_len = strlen(ctrl->opts->dhchap_secret) - 11;
	u8 *decoded_key;
	size_t decoded_len;
	u32 crc;

	if (memcmp(ctrl->opts->dhchap_secret, "DHHC-1:00:", 10))
		return -EINVAL;

	decoded_key = kzalloc(dhchap_len, GFP_KERNEL);
	if (!decoded_key)
		return -ENOMEM;
	decoded_len = base64_decode(ctrl->opts->dhchap_secret + 10,
				    dhchap_len, decoded_key);
	if (decoded_len != 36 && decoded_len != 52 && decoded_len != 68) {
		dev_warn(ctrl->dev,
			 "DH-HMAC-CHAP: unsupported key length %zu\n", dhchap_len);
		return -EKEYREJECTED;
	}
	/* The last four bytes is the CRC in little-endian format */
	decoded_len -= 4;
	crc = ~crc32(~0, decoded_key, decoded_len);

	if (get_unaligned_le32(decoded_key + decoded_len) != crc) {
		dev_warn(ctrl->dev,
			 "DH-HMAC-CHAP: key crc mismatch! (%u != %u)\n",
			 get_unaligned_le32(decoded_key + decoded_len), crc);
	}
	memcpy(chap->key, decoded_key, decoded_len);
	kfree(decoded_key);
	return 0;
}

int nvme_auth_dhchap_exponential(struct nvme_ctrl *ctrl,
				 struct nvme_dhchap_context *chap)
{
	struct kpp_request *req;
	struct crypto_wait wait;
	struct ecdh p = {0};
	struct scatterlist src, dst;
	u8 *pkey;
	int ret, pkey_len;

	p.curve_id = ECC_CURVE_NIST_P256;
	pkey_len = crypto_ecdh_key_len(&p);
	pkey = kzalloc(pkey_len, GFP_KERNEL);
	if (!pkey)
		return -ENOMEM;

	get_random_bytes(pkey, pkey_len);
	ret = crypto_ecdh_encode_key(pkey, pkey_len, &p);
	if (ret) {
		dev_dbg(ctrl->dev, "failed to encode pkey, error %d\n", ret);
		kfree(pkey);
		return ret;
	}
	ret = crypto_kpp_set_secret(chap->dh_tfm, pkey, pkey_len);
	if (ret) {
		dev_dbg(ctrl->dev, "failed to set secret, error %d\n", ret);
		kfree(pkey);
		return ret;
	}
	req = kpp_request_alloc(chap->dh_tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_exp;
	}

	chap->host_key_len = 64;
	chap->host_key = kzalloc(chap->host_key_len, GFP_KERNEL);
	if (!chap->host_key) {
		ret = -ENOMEM;
		goto out_free_req;
	}
	crypto_init_wait(&wait);
	kpp_request_set_input(req, NULL, 0);
	sg_init_one(&dst, chap->host_key, chap->host_key_len);
	kpp_request_set_output(req, &dst, chap->host_key_len);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_kpp_generate_public_key(req), &wait);
	if (ret) {
		dev_dbg(ctrl->dev,
			"failed to generate public key, error %d\n", ret);
		goto out_free_host;
	}

	chap->sess_key_len = 32;
	chap->sess_key = kmalloc(chap->sess_key_len, GFP_KERNEL);
	if (!chap->sess_key)
		goto out_free_host;

	crypto_init_wait(&wait);
	sg_init_one(&src, chap->ctrl_key, chap->ctrl_key_len);
	kpp_request_set_input(req, &src, chap->ctrl_key_len);
	sg_init_one(&dst, chap->sess_key, chap->sess_key_len);
	kpp_request_set_output(req, &dst, chap->sess_key_len);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_kpp_compute_shared_secret(req), &wait);
	if (ret) {
		dev_dbg(ctrl->dev,
			"failed to generate shared secret, error %d\n", ret);
		kfree_sensitive(chap->sess_key);
		chap->sess_key = NULL;
		chap->sess_key_len = 0;
	} else
		dev_dbg(ctrl->dev, "shared secret %*ph\n",
			 (int)chap->sess_key_len, chap->sess_key);
out_free_host:
	if (ret) {
		kfree(chap->host_key);
		chap->host_key = NULL;
		chap->host_key_len = 0;
		chap->status = NVME_AUTH_DHCHAP_FAILURE_INVALID_PAYLOAD;
	}
out_free_req:
	kpp_request_free(req);
out_free_exp:
	kfree_sensitive(pkey);

	return ret;
}

int nvme_auth_negotiate(struct nvme_ctrl *ctrl, int qid)
{
	struct nvme_dhchap_context *chap;
	void *buf;
	size_t buf_size, tl;
	int ret = 0;

	chap = kzalloc(sizeof(*chap), GFP_KERNEL);
	if (!chap)
		return -ENOMEM;
	chap->qid = qid;
	chap->transaction = ctrl->transaction++;

	ret = nvme_auth_generate_key(ctrl, chap);
	if (ret) {
		kfree(chap);
		return ret;
	}

	/*
	 * Allocate a large enough buffer for the entire negotiation:
	 * 16 byte header + 2 * 64 byte challenge and response data
	 */
	buf_size = 16 + 128;
	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	/* DH-HMAC-CHAP Step 1: send negotiate */
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP negotiate\n",
		__func__, qid);
	ret = nvme_auth_dhchap_negotiate(ctrl, chap, buf, buf_size);
	if (ret < 0)
		goto out;
	tl = ret;
	ret = nvme_auth_send(ctrl, qid, buf, tl);
	if (ret)
		goto out;

	memset(buf, 0, buf_size);
	ret = nvme_auth_receive(ctrl, qid, buf, buf_size, chap->transaction,
				NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE);
	if (ret < 0) {
		dev_dbg(ctrl->device,
			"%s: qid %d DH-HMAC-CHAP failed to receive challenge\n",
			__func__, qid);
		goto out;
	}
	if (ret > 0) {
		chap->status = ret;
		goto fail1;
	}

	/* DH-HMAC-CHAP Step 2: receive challenge */
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP challenge\n",
		__func__, qid);

	ret = nvme_auth_dhchap_challenge(ctrl, chap, buf, buf_size);
	if (ret) {
		/* Invalid parameters for negotiate */
		goto fail2;
	}

	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP select hash\n",
		__func__, qid);
	ret = nvme_auth_select_hash(ctrl, chap);
	if (ret)
		goto fail2;

	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP host response\n",
		__func__, qid);
	ret = nvme_auth_dhchap_host_response(ctrl, chap);
	if (ret)
		goto fail2;

	if (chap->ctrl_key_len) {
		dev_dbg(ctrl->device,
			"%s: qid %d DH-HMAC-DHAP DH exponential\n",
			__func__, qid);
		ret = nvme_auth_dhchap_exponential(ctrl, chap);
		if (ret)
			goto fail2;
	}

	/* DH-HMAC-CHAP Step 3: send reply */
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP reply\n",
		__func__, qid);
	ret = nvme_auth_dhchap_reply(ctrl, chap, buf, buf_size);
	if (ret < 0)
		goto fail2;

	tl = ret;
	ret = nvme_auth_send(ctrl, qid, buf, tl);
	if (ret)
		goto fail2;

	memset(buf, 0, buf_size);
	ret = nvme_auth_receive(ctrl, qid, buf, buf_size, chap->transaction,
				NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1);
	if (ret < 0) {
		dev_dbg(ctrl->device,
			"%s: qid %d DH-HMAC-CHAP failed to receive success1\n",
			__func__, qid);
		goto out;
	}
	if (ret > 0) {
		chap->status = ret;
		goto fail1;
	}

	if (ctrl->opts->dhchap_auth) {
		dev_dbg(ctrl->device,
			"%s: qid %d DH-HMAC-CHAP controller response\n",
			__func__, qid);
		ret = nvme_auth_dhchap_controller_response(ctrl, chap);
		if (ret)
			goto fail2;
	}

	/* DH-HMAC-CHAP Step 4: receive success1 */
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP success1\n",
		__func__, qid);
	ret = nvme_auth_dhchap_success1(ctrl, chap, buf, buf_size);
	if (ret < 0) {
		/* Controller authentication failed */
		goto fail2;
	}
	tl = ret;
	/* DH-HMAC-CHAP Step 5: send success2 */
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP success2\n",
		__func__, qid);
	tl = nvme_auth_dhchap_success2(ctrl, chap, buf, buf_size);
	ret = nvme_auth_send(ctrl, qid, buf, tl);
	if (!ret)
		goto out;

fail1:
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP failure1, status %x\n",
		__func__, qid, chap->status);
	goto out;

fail2:
	dev_dbg(ctrl->device, "%s: qid %d DH-HMAC-CHAP failure2, status %x\n",
		__func__, qid, chap->status);
	tl = nvme_auth_dhchap_failure2(ctrl, chap, buf, buf_size);
	ret = nvme_auth_send(ctrl, qid, buf, tl);

out:
	if (!ret && chap->status)
		ret = -EPROTO;
	if (!ret) {
		ctrl->dhchap_hash = chap->hash_id;
		ctrl->dhchap_dhgroup = chap->dhgroup_id;
	}
	kfree(buf);
	if (chap->shash_tfm)
		crypto_free_shash(chap->shash_tfm);
	kfree(chap);
	return ret;
}
