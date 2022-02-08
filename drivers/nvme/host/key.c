#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/nvme.h>
#include <crypto/hash.h>
#include <crypto/hkdf.h>
#include <net/tls.h>
#include <keys/user-type.h>
#include <asm/unaligned.h>

#include "nvme.h"
#include "fabrics.h"
#include "key.h"

static struct key *nvme_keyring;

static int nvme_key_preparse(struct key_preparsed_payload *prep)
{
	struct user_key_payload *upayload;
	int datalen = prep->datalen;
	const char *data = prep->data;

	if (datalen <= 0 || !data)
		return -EINVAL;

	prep->quotalen = datalen;
	upayload = kmalloc(sizeof(*upayload) + datalen + 1, GFP_KERNEL);
	if (!upayload)
		return -ENOMEM;
	upayload->datalen = datalen;
	memcpy(upayload->data, data, datalen);
	upayload->data[datalen] = '\0';
	prep->payload.data[0] = upayload;
	return 0;
}

static void nvme_key_free_preparse(struct key_preparsed_payload *prep)
{
	kfree(prep->payload.data[0]);
}

static void nvme_key_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);
	seq_printf(m, ": %u", key->datalen);
}

static struct key_type key_type_nvme_dhchap = {
	.name           = "dhchap",
	.flags          = KEY_TYPE_NET_DOMAIN,
	.preparse       = nvme_key_preparse,
	.free_preparse  = nvme_key_free_preparse,
	.instantiate    = generic_key_instantiate,
	.revoke         = user_revoke,
	.destroy        = user_destroy,
	.describe       = nvme_key_describe,
	.read           = user_read,
};

struct key *nvme_keyring_insert_dhchap(char *hostnqn, char *subnqn, int hash,
				       void *key_data, size_t key_len)
{
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE * 2) + 5;
	key_ref_t keyref;
	key_perm_t keyperm =
		KEY_POS_SEARCH | KEY_POS_VIEW | KEY_POS_READ |
		KEY_USR_SEARCH | KEY_USR_VIEW | KEY_USR_READ;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%02d %s %s",
		hash, hostnqn, subnqn);

	/* create or update key */
	pr_debug("update dhchap key '%s'\n", identity);
	keyref = key_create_or_update(make_key_ref(nvme_keyring, true),
				      "dhchap", identity, key_data, key_len,
				      keyperm, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(keyref)) {
		pr_warn("failed to update dhchap key '%s', error %ld\n",
			identity, PTR_ERR(keyref));
		kfree(identity);
		return ERR_PTR(-ENOKEY);
	}
	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_insert_dhchap);

void nvme_keyring_revoke_dhchap(char *hostnqn, char *subnqn, int hash)
{
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE * 2) + 5;
	struct key *key;
	key_ref_t keyref;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return;

	snprintf(identity, identity_len, "%02d %s %s",
		hash, hostnqn, subnqn);

	/* register key */
	keyref = keyring_search(make_key_ref(nvme_keyring, true),
				&key_type_nvme_dhchap,
				identity, false);
	if (IS_ERR(keyref))
		return;

	key = key_ref_to_ptr(keyref);
	key_invalidate(key);
	key_put(key);
	kfree(identity);
}
EXPORT_SYMBOL_GPL(nvme_keyring_revoke_dhchap);

struct key *nvme_keyring_lookup_dhchap(char *hostnqn, char *subnqn, int hash)
{
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE * 2) + 5;
	key_ref_t keyref;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%02d %s %s", hash, hostnqn, subnqn);

	pr_debug("lookup dhchap key '%s'\n", identity);
	keyref = keyring_search(make_key_ref(nvme_keyring, true),
				&key_type_nvme_dhchap, identity, false);

	kfree(identity);
	if (IS_ERR(keyref)) {
		pr_debug("lookup dhchap key '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		return ERR_PTR(-ENOKEY);
	}

	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_lookup_dhchap);

static struct key_type key_type_nvme_psk = {
	.name           = "psk",
	.flags          = KEY_TYPE_NET_DOMAIN,
	.preparse       = nvme_key_preparse,
	.free_preparse  = nvme_key_free_preparse,
	.instantiate    = generic_key_instantiate,
	.revoke         = user_revoke,
	.destroy        = user_destroy,
	.describe       = nvme_key_describe,
	.read           = user_read,
};

struct key *nvme_keyring_insert_psk(struct key *nvme_key,
				    char *hostnqn, int hmac)
{
	char *identity;
	size_t identity_len = NVMF_NQN_SIZE + 4;
	const char *hmac_name = "hmac(sha256)";
	struct crypto_shash *hmac_tfm;
	const char *psk_prefix = "tls13 HostNQN";
	size_t infolen;
	u8 *prk, *info, *psk;
	struct user_key_payload *key_payload;
	size_t key_len;
	key_ref_t keyref;
	key_perm_t keyperm =
		KEY_POS_SEARCH | KEY_POS_VIEW | KEY_POS_READ |
		KEY_USR_SEARCH | KEY_USR_VIEW | KEY_USR_READ;
	int ret;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%02x %s", hmac, hostnqn);

	if (hmac == 2)
		hmac_name = "hmac(sha384)";

	hmac_tfm = crypto_alloc_shash(hmac_name, 0, 0);
	if (IS_ERR(hmac_tfm)) {
		ret = PTR_ERR(hmac_tfm);
		goto out_free_identity;
	}

	prk = kzalloc(crypto_shash_digestsize(hmac_tfm), GFP_KERNEL);
	if (!prk) {
		ret = -ENOMEM;
		goto out_free_shash;
	}

	key_payload = nvme_key->payload.data[0];
	key_len = key_payload->datalen;

	ret = hkdf_extract(hmac_tfm, key_payload->data, key_len, prk);
	if (ret)
		goto out_free_prk;

	ret = crypto_shash_setkey(hmac_tfm, prk, key_len);
	if (ret)
		goto out_free_prk;

	infolen = strlen(hostnqn) + strlen(psk_prefix) + 1;
	info = kzalloc(infolen, GFP_KERNEL);
	if (!info)
		goto out_free_prk;

	memcpy(info, psk_prefix, strlen(psk_prefix));
	memcpy(info + strlen(psk_prefix), hostnqn, strlen(hostnqn));

	psk = kzalloc(key_len, GFP_KERNEL);
	if (!psk) {
		ret = -ENOMEM;
		goto out_free_info;
	}
	ret = hkdf_expand(hmac_tfm, info, infolen, psk, key_len);
	if (ret)
		goto out_free_psk;

	pr_debug("update psk key '%s'\n", identity);
	keyref = key_create_or_update(make_key_ref(nvme_keyring, true),
				      "psk", identity, psk, key_len,
				      keyperm, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(keyref)) {
		pr_warn("failed to update psk '%s', error %ld\n",
			identity, PTR_ERR(keyref));
		ret = -ENOKEY;
	}
	ret = 0;

out_free_psk:
	kfree(psk);
out_free_info:
	kfree(info);
out_free_prk:
	kfree(prk);
out_free_shash:
	crypto_free_shash(hmac_tfm);
out_free_identity:
	kfree(identity);

	return ret ? ERR_PTR(ret) : key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_insert_psk);

struct key *nvme_keyring_lookup_psk(char *hostnqn, int hash)
{
	char *identity;
	size_t identity_len = NVMF_NQN_SIZE + 4;
	key_ref_t keyref;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%02d %s", hash, hostnqn);

	pr_debug("lookup psk key '%s'\n", identity);
	keyref = keyring_search(make_key_ref(nvme_keyring, true),
				&key_type_nvme_psk, identity, false);

	kfree(identity);
	if (IS_ERR(keyref)) {
		pr_debug("lookup psk key '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		return ERR_PTR(-ENOKEY);
	}

	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_lookup_psk);

struct key *nvme_keyring_insert_tls(struct key *nvme_key, struct nvme_ctrl *ctrl,
				    int hmac, bool generated)
{
	char *hostnqn = ctrl->opts->host->nqn;
	char *subnqn = nvmf_ctrl_subsysnqn(ctrl);
	struct crypto_shash *hmac_tfm;
	const char *hmac_name = "hmac(sha256)";
	const char *psk_prefix = "tls13 nvme-tls-psk";
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE) * 2 + 11;
	key_ref_t keyref;
	struct user_key_payload *key_payload;
	size_t infolen, key_len = 32;
	char *info;
	unsigned char *prk, *tls_key;
	int ret;

	if (!ctrl->opts)
		return ERR_PTR(-ENXIO);

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%s;%s;%s;NVMe0%c%02d %s %s",
		 ctrl->opts->host_traddr ? ctrl->opts->host_traddr : "",
		 ctrl->opts->traddr, ctrl->opts->trsvcid,
		 generated ? 'G' : 'R', hmac, hostnqn, subnqn);

	key_payload = nvme_key->payload.data[0];
	key_len = key_payload->datalen;

	if (hmac == 2) {
		hmac_name = "hmac(sha384)";
		key_len = 48;
	}

	hmac_tfm = crypto_alloc_shash(hmac_name, 0, 0);
	if (IS_ERR(hmac_tfm)) {
		ret = PTR_ERR(hmac_tfm);
		goto out_free_identity;
	}

	prk = kzalloc(crypto_shash_digestsize(hmac_tfm), GFP_KERNEL);
	if (!prk) {
		ret = -ENOMEM;
		goto out_free_shash;
	}

	ret = hkdf_extract(hmac_tfm, key_payload->data,
			   key_payload->datalen, prk);
	if (ret)
		goto out_free_prk;

	ret = crypto_shash_setkey(hmac_tfm, prk, key_payload->datalen);
	if (ret)
		goto out_free_prk;

	infolen = strlen(identity) + strlen(psk_prefix) + 1;
	info = kzalloc(infolen, GFP_KERNEL);
	if (!info)
		goto out_free_prk;

	memcpy(info, psk_prefix, strlen(psk_prefix));
	memcpy(info + strlen(psk_prefix), identity, strlen(identity));

	tls_key = kzalloc(key_len, GFP_KERNEL);
	if (!tls_key) {
		ret = -ENOMEM;
		goto out_free_info;
	}
	ret = hkdf_expand(hmac_tfm, info, infolen, tls_key, key_len);
	if (ret)
		goto out_free_key;
	pr_debug("refresh tls key '%s'\n", identity);
	keyref = tls_key_refresh(identity, tls_key, key_len);
	if (IS_ERR(keyref)) {
		pr_warn("refresh tls key '%s' failed, error %ld\n",
			identity, PTR_ERR(keyref));
		return ERR_PTR(-ENOKEY);
	}
	return key_ref_to_ptr(keyref);

out_free_key:
	kfree(tls_key);
out_free_info:
	kfree(info);
out_free_prk:
	kfree(prk);
out_free_shash:
	crypto_free_shash(hmac_tfm);
out_free_identity:
	kfree(identity);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(nvme_keyring_insert_tls);

struct key *nvme_keyring_lookup_tls(struct nvme_ctrl *ctrl, int hash, bool generated)
{
	char *hostnqn = ctrl->opts->host->nqn;
	char *subnqn = nvmf_ctrl_subsysnqn(ctrl);
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE) * 2 + 11;
	key_ref_t keyref;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%s;%s;%s;NVMe0%c%02d %s %s",
		 ctrl->opts->host_traddr ? ctrl->opts->host_traddr : "",
		 ctrl->opts->traddr, ctrl->opts->trsvcid,
		 generated ? 'G' : 'R', hash, hostnqn, subnqn);

	pr_debug("lookup tls key '%s'\n", identity);
	keyref = tls_key_lookup(identity);
	kfree(identity);
	if (IS_ERR(keyref)) {
		pr_debug("lookup tls key '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		return ERR_PTR(-ENOKEY);
	}

	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_lookup_tls);

int nvme_keyring_init(void)
{
	int result;

	nvme_keyring = keyring_alloc(".nvme",
				     GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				     current_cred(),
				     (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				     (KEY_USR_ALL & ~KEY_USR_SETATTR),
				     KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(nvme_keyring))
		return PTR_ERR(nvme_keyring);

	result = register_key_type(&key_type_nvme_dhchap);
	if (result)
		goto out_revoke;

	result = register_key_type(&key_type_nvme_psk);
	if (result)
		unregister_key_type(&key_type_nvme_dhchap);

out_revoke:
	if (result) {
		key_revoke(nvme_keyring);
		key_put(nvme_keyring);
	}

	return result;
}

void nvme_keyring_exit(void)
{
	unregister_key_type(&key_type_nvme_psk);
	unregister_key_type(&key_type_nvme_dhchap);
	key_revoke(nvme_keyring);
	key_put(nvme_keyring);
}
