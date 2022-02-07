/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Hannes Reinecke, SUSE Software Solutions
 */

#ifndef _NVME_KEY_H
#define _NVME_KEY_H

struct key *nvme_keyring_insert_dhchap(char *hostnqn, char *subnqn, int hmac,
				       void *key_data, size_t key_len);
struct key *nvme_keyring_lookup_dhchap(char *hostnqn, char *subnqn, int hash);
void nvme_keyring_revoke_dhchap(char *hostnqn, char *subnqn, int hash);
struct key *nvme_keyring_insert_psk(struct key *nvme_key,
				    char *hostnqn, int hmac);
struct key *nvme_keyring_lookup_psk(char *hostnqn, int hash);
struct key *nvme_keyring_insert_tls(struct key *nvme_key,
				    char *hostnqn, char *subnqn, int hmac,
				    bool generated);
struct key *nvme_keyring_lookup_tls(char *hostnqn, char *subnqn,
				    int hash, bool generated);

int nvme_keyring_init(void);
void nvme_keyring_exit(void);

#endif /* _NVME_KEY_H */
