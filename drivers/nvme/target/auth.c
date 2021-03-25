// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe over Fabrics DH-HMAC-CHAP authentication.
 * Copyright (c) 2020 Hannes Reinecke, SUSE Software Solutions.
 * All rights reserved.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/curve25519.h>
#include <linux/crc32.h>
#include <linux/base64.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <asm/unaligned.h>

#include "nvmet.h"

struct nvmet_dhchap_dhgroup_map {
	int id;
	const char name[16];
	int privkey_size;
	int pubkey_size;
} dhgroup_map[] = {
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_NULL,
	  .name = "NULL", .privkey_size = 0, .pubkey_size = 0 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_2048,
	  .name = "ffdhe2048", .privkey_size = 64, .pubkey_size = 64 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_3072,
	  .name = "ffdhe3072", .privkey_size = 64, .pubkey_size = 64 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_4096,
	  .name = "ffdhe4096", .privkey_size = 64, .pubkey_size = 64 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_6144,
	  .name = "ffdhe6144", .privkey_size = 64, .pubkey_size = 64 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_8192,
	  .name = "ffdhe8192", .privkey_size = 64, .pubkey_size = 64 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_ECDH,
	  .name = "ecdh", .privkey_size = 32, .pubkey_size = 64 },
	{ .id = NVME_AUTH_DHCHAP_DHGROUP_25519,
	  .name = "curve25519", .privkey_size = CURVE25519_KEY_SIZE,
	  .pubkey_size = CURVE25519_KEY_SIZE },
};

const char *nvmet_dhchap_dhgroup_name( int dhgid )
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dhgroup_map); i++) {
		if (dhgroup_map[i].id == dhgid)
			return dhgroup_map[i].name;
	}
	return NULL;
}

struct nvmet_dhchap_hash_map {
	int id;
	int hash_len;
	const char name[15];
} hash_map[] = {
	{.id = NVME_AUTH_DHCHAP_HASH_SHA256,
	 .hash_len = 32,
	 .name = "hmac(sha256)", },
	{.id = NVME_AUTH_DHCHAP_HASH_SHA384,
	 .hash_len = 48,
	 .name = "hmac(sha384)", },
	{.id = NVME_AUTH_DHCHAP_HASH_SHA512,
	 .hash_len = 64,
	 .name = "hmac(sha512)", },
};

int nvmet_auth_extract_host_key(struct nvmet_host *host,
				unsigned char *dhchap_key,
				size_t dhchap_key_len)
{
	unsigned char *decoded_key;
	u32 crc;
	int decoded_key_len;
	size_t allocated_len;

	allocated_len = strlen(host->dhchap_secret) - 10;
	decoded_key = kzalloc(allocated_len, GFP_KERNEL);
	if (!decoded_key)
		return -ENOMEM;

	decoded_key_len = base64_decode(host->dhchap_secret + 10,
					allocated_len, decoded_key);
	if (decoded_key_len != 36 && decoded_key_len != 52 &&
	    decoded_key_len != 68) {
		pr_debug("Invalid DH-HMAC-CHAP key len %d\n",
			 decoded_key_len);
		kfree(decoded_key);
		return -EINVAL;
	}
	pr_debug("DH-HMAC-CHAP Key: %*ph\n",
		 (int)decoded_key_len, decoded_key);

	/* The last four bytes is the CRC in little-endian format */
	decoded_key_len -= 4;
	/*
	 * The linux implementation doesn't do pre- and post-increments,
	 * so we have to do it manually.
	 */
	crc = ~crc32(~0, decoded_key, decoded_key_len);

	if (get_unaligned_le32(decoded_key + decoded_key_len) != crc) {
		pr_debug("DH-HMAC-CHAP crc mismatch (key %08x, crc %08x)\n",
		       get_unaligned_le32(decoded_key + decoded_key_len), crc);
		kfree(decoded_key);
		return -EKEYREJECTED;
	}

	if (dhchap_key) {
		if (dhchap_key_len < decoded_key_len) {
			pr_debug("DH-HMAC-CHAP key buffer too small\n");
			decoded_key_len = -EINVAL;
		} else
			memcpy(dhchap_key, decoded_key, decoded_key_len);
	}
	kfree(decoded_key);
	return decoded_key_len;
}

int nvmet_auth_set_host_key(struct nvmet_host *host, const char *secret)
{
	int i, ret;
	char *end;

	if (sscanf(secret, "DHHC-1:%hhd:%*s", &host->dhchap_key_hash) != 1)
		return -EINVAL;
	if (host->dhchap_key_hash > 3) {
		pr_debug("Invalid DH-HMAC-CHAP hash id %d\n",
			 host->dhchap_key_hash);
		return -EINVAL;
	}
	if (host->dhchap_key_hash > 0) {
		/* Validate selected hash algorithm */
		for (i = 0; i < ARRAY_SIZE(hash_map); i++) {
			if (hash_map[i].id != host->dhchap_key_hash)
				continue;
			if (!crypto_has_shash(hash_map[i].name, 0, 0)) {
				pr_debug("DH-HMAC-CHAP hash %s unsupported\n",
					 hash_map[i].name);
				host->dhchap_key_hash = -1;
				return -EAGAIN;
			}
		}
	}
	host->dhchap_secret = kstrdup(secret, GFP_KERNEL);
	if (!host->dhchap_secret)
		return -ENOMEM;
	end = (char *)host->dhchap_secret + strlen(secret) - 1;
	while(end > (char *)host->dhchap_secret && isspace(*end)) {
		*end = '\0';
		end--;
	}
	ret = nvmet_auth_extract_host_key(host, NULL, 0);
	if (ret < 0) {
		kfree(host->dhchap_secret);
		host->dhchap_secret = NULL;
		return ret;
	}
	host->dhchap_key_len = ret;
	/* Select hash algorithm to use */
	i = ARRAY_SIZE(hash_map);
	while (--i >= 0 && !host->dhchap_hash_id) {
		if (hash_map[i].hash_len != host->dhchap_key_len)
			continue;
		if (crypto_has_shash(hash_map[i].name, 0, 0)) {
			host->dhchap_hash_id = hash_map[i].id;
			break;
		}
	}
	if (!host->dhchap_hash_id) {
		pr_warn("No usable hash for hash length %zu found\n",
			host->dhchap_key_len);
		kfree(host->dhchap_secret);
		host->dhchap_secret = NULL;
		host->dhchap_key_len = 0;
		return -EAGAIN;
	}
	pr_debug("Using hash %s\n", nvmet_auth_get_host_hash(host));
	return 0;
}

int nvmet_auth_set_host_hash(struct nvmet_host *host, const char *hash)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hash_map); i++) {
		if (!strncmp(hash_map[i].name, hash,
			     strlen(hash_map[i].name))) {
			if (i != NVME_AUTH_DHCHAP_DHGROUP_NULL) {
				if (!crypto_has_shash(hash_map[i].name, 0, 0))
					return -ENOTSUPP;
			}
			host->dhchap_hash_id = hash_map[i].id;
			return 0;
		}
	}
	return -EINVAL;
}

const char *nvmet_auth_get_host_hash(struct nvmet_host *host)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hash_map); i++) {
		if (hash_map[i].id == host->dhchap_hash_id)
			return hash_map[i].name;
	}
	return NULL;
}

int nvmet_auth_set_host_dhgroup(struct nvmet_host *host, const char *dhgroup)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dhgroup_map); i++) {
		if (!strncmp(dhgroup_map[i].name, dhgroup,
			     strlen(dhgroup_map[i].name))) {
			if (!crypto_has_kpp(dhgroup_map[i].name, 0, 0))
				return -EINVAL;
			/* We only support NULL, ECDH, and curve25519 for now */
			if (dhgroup_map[i].id != NVME_AUTH_DHCHAP_DHGROUP_ECDH &&
			    dhgroup_map[i].id != NVME_AUTH_DHCHAP_DHGROUP_25519 &&
			    dhgroup_map[i].id != NVME_AUTH_DHCHAP_DHGROUP_NULL)
				return -EINVAL;

			host->dhchap_dhgroup_id = dhgroup_map[i].id;
			return 0;
		}
	}
	return -EINVAL;
}

const char *nvmet_auth_get_host_dhgroup(struct nvmet_host *host)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dhgroup_map); i++) {
		if (dhgroup_map[i].id == host->dhchap_dhgroup_id)
			return dhgroup_map[i].name;
	}
	return NULL;
}

static int nvmet_auth_dhgroup_pubkey_size(int dhgroup_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dhgroup_map); i++) {
		if (dhgroup_map[i].id == dhgroup_id)
			return dhgroup_map[i].pubkey_size;
	}
	return -1;
}

static int nvmet_auth_dhgroup_privkey_size(int dhgroup_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dhgroup_map); i++) {
		if (dhgroup_map[i].id == dhgroup_id)
			return dhgroup_map[i].privkey_size;
	}
	return -1;
}

int nvmet_setup_dhgroup(struct nvmet_ctrl *ctrl, int dhgroup_id)
{
	struct nvmet_host_link *p;
	struct nvmet_host *host = NULL;
	const char *dhgroup_name;
	int ret = 0;

	if (dhgroup_id == NVME_AUTH_DHCHAP_DHGROUP_NULL)
		return 0;

	down_read(&nvmet_config_sem);
	if (ctrl->subsys->type == NVME_NQN_DISC)
		goto out_unlock;

	list_for_each_entry(p, &ctrl->subsys->hosts, entry) {
		if (strcmp(nvmet_host_name(p->host), ctrl->hostnqn))
			continue;
		host = p->host;
		break;
	}
	if (!host) {
		pr_debug("host %s not found\n", ctrl->hostnqn);
		ret = -EPERM;
		goto out_unlock;
	}

	if (host->dhchap_dhgroup_id != dhgroup_id) {
		pr_debug("dhgroup id mismatch (set %d - requested %d)\n",
			 host->dhchap_dhgroup_id, dhgroup_id);
		ret = -EINVAL;
		goto out_unlock;
	}
	dhgroup_name = nvmet_dhchap_dhgroup_name(dhgroup_id);
	ctrl->dh_tfm = crypto_alloc_kpp(dhgroup_name, 0, 0);
	if (IS_ERR(ctrl->dh_tfm)) {
		pr_debug("failed to setup DH group %d, err %ld\n",
			 dhgroup_id, PTR_ERR(ctrl->dh_tfm));
		ret = -ENOTSUPP;
		ctrl->dh_tfm = NULL;
	} else {
		ctrl->dh_gid = dhgroup_id;
		ctrl->dh_keysize = nvmet_auth_dhgroup_pubkey_size(dhgroup_id);
	}

out_unlock:
	up_read(&nvmet_config_sem);

	return ret;
}

int nvmet_setup_auth(struct nvmet_ctrl *ctrl, struct nvmet_req *req)
{
	int ret = 0;
	struct nvmet_host_link *p;
	struct nvmet_host *host = NULL;
	const char *hash_name;
	u8 *dhchap_key = NULL;

	down_read(&nvmet_config_sem);
	if (ctrl->subsys->type == NVME_NQN_DISC)
		goto out_unlock;

	list_for_each_entry(p, &ctrl->subsys->hosts, entry) {
		pr_debug("check %s\n", nvmet_host_name(p->host));
		if (strcmp(nvmet_host_name(p->host), ctrl->hostnqn))
			continue;
		host = p->host;
		break;
	}
	if (!host) {
		pr_debug("host %s not found\n", ctrl->hostnqn);
		ret = -EPERM;
		goto out_unlock;
	}
	if (!host->dhchap_secret) {
		pr_debug("No authentication provided\n");
		goto out_unlock;
	}

	hash_name = nvmet_auth_get_host_hash(host);
	if (!hash_name) {
		pr_debug("Hash ID %d invalid\n", host->dhchap_hash_id);
		ret = -EINVAL;
		goto out_unlock;
	}
	ctrl->shash_tfm = crypto_alloc_shash(hash_name, 0,
					     CRYPTO_ALG_ALLOCATES_MEMORY);
	if (IS_ERR(ctrl->shash_tfm)) {
		pr_debug("failed to allocate shash %s\n", hash_name);
		ret = PTR_ERR(ctrl->shash_tfm);
		ctrl->shash_tfm = NULL;
		goto out_unlock;
	}
	dhchap_key = kzalloc(host->dhchap_key_len, GFP_KERNEL);
	if (!dhchap_key) {
		ret = -ENOMEM;
		goto out_free_hash;
	}
	ret = nvmet_auth_extract_host_key(host, dhchap_key,
					  host->dhchap_key_len);
	if (ret < 0) {
		pr_debug("failed to extract host key, error %d\n", ret);
		kfree(dhchap_key);
		goto out_free_hash;
	}
	if (host->dhchap_key_hash) {
		struct crypto_shash *key_tfm;

		if (host->dhchap_key_hash != host->dhchap_hash_id)
			hash_name = hash_map[host->dhchap_key_hash].name;
		key_tfm = crypto_alloc_shash(hash_name, 0, 0);
		if (IS_ERR(key_tfm)) {
			ret = PTR_ERR(key_tfm);
			goto out_free_hash;
		} else {
			SHASH_DESC_ON_STACK(shash, key_tfm);
			ret = crypto_shash_setkey(key_tfm, dhchap_key,
						  host->dhchap_key_len);
			crypto_shash_init(shash);
			crypto_shash_update(shash, ctrl->subsys->subsysnqn,
					    strlen(ctrl->subsys->subsysnqn));
			crypto_shash_update(shash, "NVMe-over-Fabrics", 17);
			crypto_shash_final(shash, dhchap_key);
			crypto_free_shash(key_tfm);
		}
	}
	pr_debug("%s: using key %*ph\n", __func__,
		 (int)host->dhchap_key_len, dhchap_key);
	ret = crypto_shash_setkey(ctrl->shash_tfm, dhchap_key,
				  host->dhchap_key_len);
out_free_hash:
	if (ret) {
		if (dhchap_key)
			kfree(dhchap_key);
		crypto_free_shash(ctrl->shash_tfm);
		ctrl->shash_tfm = NULL;
	}
out_unlock:
	up_read(&nvmet_config_sem);

	return ret;
}

void nvmet_reset_auth(struct nvmet_ctrl *ctrl)
{
	if (ctrl->shash_tfm) {
		crypto_free_shash(ctrl->shash_tfm);
		ctrl->shash_tfm = NULL;
	}
	if (ctrl->dh_tfm) {
		crypto_free_kpp(ctrl->dh_tfm);
		ctrl->dh_tfm = NULL;
	}
}

bool nvmet_check_auth_status(struct nvmet_req *req)
{
	if (req->sq->ctrl->shash_tfm &&
	    !req->sq->authenticated)
		return false;
	return true;
}

int nvmet_auth_get_hash(struct nvmet_ctrl *ctrl, unsigned int *hash_len)
{
	int i;

	if (!ctrl->shash_tfm)
		return 0;
	for (i = 0; i < ARRAY_SIZE(hash_map); i++) {
		if (!strcmp(crypto_shash_alg_name(ctrl->shash_tfm),
			    hash_map[i].name)) {
			*hash_len = crypto_shash_digestsize(ctrl->shash_tfm);
			return hash_map[i].id;
		}
	}
	return 0;
}

int nvmet_auth_host_hash(struct nvmet_ctrl *ctrl,
		unsigned int shash_len, u8 *challenge, u8 *response,
		u32 seqnum, u16 transaction)
{
	SHASH_DESC_ON_STACK(shash, ctrl->shash_tfm);
	u8 buf[4];
	int ret;

	shash->tfm = ctrl->shash_tfm;
	ret = crypto_shash_init(shash);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, challenge, shash_len);
	if (ret)
		goto out;
	put_unaligned_le32(seqnum, buf);
	ret = crypto_shash_update(shash, buf, 4);
	if (ret)
		goto out;
	put_unaligned_le16(transaction, buf);
	ret = crypto_shash_update(shash, buf, 2);
	if (ret)
		goto out;
	memset(buf, 0, 4);
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, "HostHost", 8);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->hostnqn, strlen(ctrl->hostnqn));
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->subsysnqn,
				  strlen(ctrl->subsysnqn));
	if (ret)
		goto out;
	ret = crypto_shash_final(shash, response);
out:
	return 0;
}

int nvmet_auth_controller_hash(struct nvmet_ctrl *ctrl,
		unsigned int shash_len, u8 *challenge, u8 *response,
		u32 seqnum, u16 transaction)
{
	SHASH_DESC_ON_STACK(shash, ctrl->shash_tfm);
	u8 buf[4];
	int ret;

	pr_debug("%s: ctrl %d hash seq %d transaction %u\n", __func__,
		 ctrl->cntlid, seqnum, transaction);
	pr_debug("%s: ctrl %d challenge %*ph\n", __func__,
		 ctrl->cntlid, shash_len, challenge);
	pr_debug("%s: ctrl %d subsysnqn %s\n", __func__,
		 ctrl->cntlid, ctrl->subsysnqn);
	pr_debug("%s: ctrl %d hostnqn %s\n", __func__,
		 ctrl->cntlid, ctrl->hostnqn);
	shash->tfm = ctrl->shash_tfm;
	ret = crypto_shash_init(shash);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, challenge, shash_len);
	if (ret)
		goto out;
	put_unaligned_le32(seqnum, buf);
	ret = crypto_shash_update(shash, buf, 4);
	if (ret)
		goto out;
	put_unaligned_le16(transaction, buf);
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
	ret = crypto_shash_update(shash, ctrl->subsysnqn,
			    strlen(ctrl->subsysnqn));
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, buf, 1);
	if (ret)
		goto out;
	ret = crypto_shash_update(shash, ctrl->hostnqn, strlen(ctrl->hostnqn));
	if (ret)
		goto out;
	ret = crypto_shash_final(shash, response);
out:
	return 0;
}

int nvmet_auth_ctrl_exponential(struct nvmet_req *req,
				u8 *buf, int buf_size)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct kpp_request *kpp_req;
	struct crypto_wait wait;
	char *pkey;
	struct scatterlist dst;
	int ret, pkey_len;

	if (ctrl->dh_gid == NVME_AUTH_DHCHAP_DHGROUP_ECDH) {
		struct ecdh p = {0};

		p.curve_id = ECC_CURVE_NIST_P256;
		pkey_len = crypto_ecdh_key_len(&p);
		pkey = kmalloc(pkey_len, GFP_KERNEL);
		if (!pkey)
			return -ENOMEM;

		get_random_bytes(pkey, pkey_len);
		ret = crypto_ecdh_encode_key(pkey, pkey_len, &p);
		if (ret) {
			pr_debug("failed to encode private key, error %d\n",
				 ret);
			goto out;
		}
	} else if (ctrl->dh_gid == NVME_AUTH_DHCHAP_DHGROUP_25519) {
		pkey_len = CURVE25519_KEY_SIZE;
		pkey = kmalloc(pkey_len, GFP_KERNEL);
		if (!pkey)
			return -ENOMEM;
		get_random_bytes(pkey, pkey_len);
	} else {
		pr_warn("invalid dh group %d\n", ctrl->dh_gid);
		return -EINVAL;
	}
	ret = crypto_kpp_set_secret(ctrl->dh_tfm, pkey, pkey_len);
	if (ret) {
		pr_debug("failed to set private key, error %d\n", ret);
		goto out;
	}

	kpp_req = kpp_request_alloc(ctrl->dh_tfm, GFP_KERNEL);
	if (!kpp_req) {
		pr_debug("cannot allocate kpp request\n");
		ret = -ENOMEM;
		goto out;
	}

	crypto_init_wait(&wait);
	kpp_request_set_input(kpp_req, NULL, 0);
	sg_init_one(&dst, buf, buf_size);
	kpp_request_set_output(kpp_req, &dst, buf_size);
	kpp_request_set_callback(kpp_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_kpp_generate_public_key(kpp_req), &wait);
	kpp_request_free(kpp_req);
	if (ret) {
		pr_debug("failed to generate public key, err %d\n", ret);
		ret = -ENOKEY;
	} else
		pr_debug("%s: ctrl public key %*ph\n", __func__,
			 (int)buf_size, buf);

out:
	kfree_sensitive(pkey);
	return ret;
}

int nvmet_auth_ctrl_sesskey(struct nvmet_req *req,
			    u8 *pkey, int pkey_size)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct kpp_request *kpp_req;
	struct crypto_wait wait;
	struct scatterlist src, dst;
	int ret;

	req->sq->dhchap_skey_len =
		nvmet_auth_dhgroup_privkey_size(ctrl->dh_gid);
	req->sq->dhchap_skey = kzalloc(req->sq->dhchap_skey_len, GFP_KERNEL);
	if (!req->sq->dhchap_skey)
		return -ENOMEM;
	kpp_req = kpp_request_alloc(ctrl->dh_tfm, GFP_KERNEL);
	if (!kpp_req) {
		kfree(req->sq->dhchap_skey);
		req->sq->dhchap_skey = NULL;
		return -ENOMEM;
	}

	pr_debug("%s: host public key %*ph\n", __func__,
		 (int)pkey_size, pkey);
	crypto_init_wait(&wait);
	sg_init_one(&src, pkey, pkey_size);
	kpp_request_set_input(kpp_req, &src, pkey_size);
	sg_init_one(&dst, req->sq->dhchap_skey,
		req->sq->dhchap_skey_len);
	kpp_request_set_output(kpp_req, &dst, req->sq->dhchap_skey_len);
	kpp_request_set_callback(kpp_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_kpp_compute_shared_secret(kpp_req), &wait);
	kpp_request_free(kpp_req);
	if (ret)
		pr_debug("failed to compute shared secred, err %d\n", ret);
	else
		pr_debug("%s: shared secret %*ph\n", __func__,
			 (int)req->sq->dhchap_skey_len,
			 req->sq->dhchap_skey);

	return ret;
}
