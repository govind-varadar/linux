#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/nvme.h>
#include <crypto/hash.h>
#include <crypto/hkdf.h>
#include <keys/user-type.h>
#include <asm/unaligned.h>

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

static struct key_type key_type_nvme_generated = {
	.name           = "generated",
	.flags          = KEY_TYPE_NET_DOMAIN,
	.preparse       = nvme_key_preparse,
	.free_preparse  = nvme_key_free_preparse,
	.instantiate    = generic_key_instantiate,
	.revoke         = user_revoke,
	.destroy        = user_destroy,
	.describe       = nvme_key_describe,
	.read           = user_read,
};

struct key *nvme_keyring_insert_generated_key(char *hostnqn, char *subnqn,
		int hmac, void *key_data, size_t key_len)
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
		hmac, hostnqn, subnqn);

	/* create or update key */
	pr_debug("update generated key '%s'\n", identity);
	keyref = key_create_or_update(make_key_ref(nvme_keyring, true),
				      "generated", identity, key_data, key_len,
				      keyperm, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(keyref)) {
		pr_warn("failed to update generated key '%s', error %ld\n",
			identity, PTR_ERR(keyref));
		kfree(identity);
		return ERR_PTR(-ENOKEY);
	}
	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_insert_generated_key);

void nvme_keyring_revoke_generated_key(char *hostnqn, char *subnqn, int hmac)
{
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE * 2) + 5;
	struct key *key;
	key_ref_t keyref;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return;

	snprintf(identity, identity_len, "%02d %s %s",
		hmac, hostnqn, subnqn);

	/* register key */
	keyref = keyring_search(make_key_ref(nvme_keyring, true),
				&key_type_nvme_generated,
				identity, false);
	if (IS_ERR(keyref))
		return;

	key = key_ref_to_ptr(keyref);
	key_invalidate(key);
	key_put(key);
	kfree(identity);
}
EXPORT_SYMBOL_GPL(nvme_keyring_revoke_generated_key);

struct key *nvme_keyring_lookup_generated_key(char *hostnqn,
		char *subnqn, int hmac)
{
	char *identity;
	size_t identity_len = (NVMF_NQN_SIZE * 2) + 5;
	key_ref_t keyref;

	identity = kzalloc(identity_len, GFP_KERNEL);
	if (!identity)
		return ERR_PTR(-ENOMEM);

	snprintf(identity, identity_len, "%02d %s %s", hmac, hostnqn, subnqn);

	pr_debug("lookup generated key '%s'\n", identity);
	keyref = keyring_search(make_key_ref(nvme_keyring, true),
				&key_type_nvme_generated, identity, false);

	kfree(identity);
	if (IS_ERR(keyref)) {
		pr_debug("lookup generated key '%s' failed, error %ld\n",
			 identity, PTR_ERR(keyref));
		return ERR_PTR(-ENOKEY);
	}

	return key_ref_to_ptr(keyref);
}
EXPORT_SYMBOL_GPL(nvme_keyring_lookup_generated_key);

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

	result = register_key_type(&key_type_nvme_generated);
	if (result)
		goto out_revoke;

out_revoke:
	if (result) {
		key_revoke(nvme_keyring);
		key_put(nvme_keyring);
	}

	return result;
}

void nvme_keyring_exit(void)
{
	unregister_key_type(&key_type_nvme_generated);
	key_revoke(nvme_keyring);
	key_put(nvme_keyring);
}
