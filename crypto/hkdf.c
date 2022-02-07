// SPDX-License-Identifier: GPL-2.0
/*
 * Implementation of HKDF ("HMAC-based Extract-and-Expand Key Derivation
 * Function"), aka RFC 5869.  See also the original paper (Krawczyk 2010):
 * "Cryptographic Extraction and Key Derivation: The HKDF Scheme".
 *
 * This is used to derive keys from the fscrypt master keys.
 *
 * Copyright 2019 Google LLC
 */

#include <crypto/hash.h>
#include <crypto/sha2.h>

/*
 * HKDF consists of two steps:
 *
 * 1. HKDF-Extract: extract a pseudorandom key of length HKDF_HASHLEN bytes from
 *    the input keying material and optional salt.
 * 2. HKDF-Expand: expand the pseudorandom key into output keying material of
 *    any length, parameterized by an application-specific info string.
 *
 */

/* HKDF-Extract (RFC 5869 section 2.2), unsalted */
int hkdf_extract(struct crypto_shash *hmac_tfm, const u8 *ikm,
		 unsigned int ikmlen, u8 *prk)
{
	unsigned int prklen = crypto_shash_digestsize(hmac_tfm);
	u8 *default_salt;
	int err;

	default_salt = kzalloc(prklen, GFP_KERNEL);
	if (!default_salt)
		return -ENOMEM;
	err = crypto_shash_setkey(hmac_tfm, default_salt, prklen);
	if (!err)
		err = crypto_shash_tfm_digest(hmac_tfm, ikm, ikmlen, prk);

	kfree(default_salt);
	return err;
}
EXPORT_SYMBOL_GPL(hkdf_extract);

/*
 * HKDF-Expand (RFC 5869 section 2.3).
 * This expands the pseudorandom key, which was already keyed into @hmac_tfm,
 * into @okmlen bytes of output keying material parameterized by the
 * application-specific @info of length @infolen bytes.
 * This is thread-safe and may be called by multiple threads in parallel.
 */
int hkdf_expand(struct crypto_shash *hmac_tfm,
		const u8 *info, unsigned int infolen,
		u8 *okm, unsigned int okmlen)
{
	SHASH_DESC_ON_STACK(desc, hmac_tfm);
	unsigned int i, hashlen = crypto_shash_digestsize(hmac_tfm);
	int err;
	const u8 *prev = NULL;
	u8 counter = 1;
	u8 *tmp;

	if (WARN_ON(okmlen > 255 * hashlen))
		return -EINVAL;

	tmp = kzalloc(hashlen, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	desc->tfm = hmac_tfm;

	for (i = 0; i < okmlen; i += hashlen) {

		err = crypto_shash_init(desc);
		if (err)
			goto out;

		if (prev) {
			err = crypto_shash_update(desc, prev, hashlen);
			if (err)
				goto out;
		}

		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;

		BUILD_BUG_ON(sizeof(counter) != 1);
		if (okmlen - i < hashlen) {
			err = crypto_shash_finup(desc, &counter, 1, tmp);
			if (err)
				goto out;
			memcpy(&okm[i], tmp, okmlen - i);
			memzero_explicit(tmp, sizeof(tmp));
		} else {
			err = crypto_shash_finup(desc, &counter, 1, &okm[i]);
			if (err)
				goto out;
		}
		counter++;
		prev = &okm[i];
	}
	err = 0;
out:
	if (unlikely(err))
		memzero_explicit(okm, okmlen); /* so caller doesn't need to */
	shash_desc_zero(desc);
	kfree(tmp);
	return err;
}
EXPORT_SYMBOL_GPL(hkdf_expand);
