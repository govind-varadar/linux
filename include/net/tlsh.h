/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PF_TLSH protocol family socket handler.
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#ifndef _TLS_HANDSHAKE_H
#define _TLS_HANDSHAKE_H

extern int tls_client_hello(struct socket *sock,
			    void (*done)(void *data, int status),
			    void *data, const char *priorities,
			    key_serial_t key);

#endif /* _TLS_HANDSHAKE_H */
