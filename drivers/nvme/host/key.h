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

int nvme_keyring_init(void);
void nvme_keyring_exit(void);

#endif /* _NVME_KEY_H */
