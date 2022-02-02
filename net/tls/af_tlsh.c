// SPDX-License-Identifier: GPL-2.0-only
/*
 * PF_TLSH protocol family socket handler.
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 *
 * Listeners become ready when a kernel TLS consumer has a socket
 * that needs a client-side handshake. Accepting on that listener
 * fabricates a socket descriptor on which a user space TLS library
 * can perform a TLS handshake. Closing that descriptor signals to
 * the kernel that the handshake process is complete.
 */

/*
 * Socket reference counting
 *  A: listener socket initial reference
 *  B: listener socket on the global listener list
 *  C: listener socket while a ready AF_INET(6) socket is being enqueued
 *  D: listener socket while its accept queue is drained
 *
 *  I: ready AF_INET(6) socket waiting on a listener's accept queue
 *  J: ready AF_INET(6) socket with a consumer waiting for a completion callback
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/inet.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>
#include <net/tls.h>
#include <net/tlsh.h>

#include "trace.h"


static DEFINE_RWLOCK(tlsh_listener_lock);
static HLIST_HEAD(tlsh_listeners);

static void tlsh_register_listener(struct sock *sk)
{
	write_lock_bh(&tlsh_listener_lock);
	sk_add_node(sk, &tlsh_listeners);	/* Ref: B */
	write_unlock_bh(&tlsh_listener_lock);
}

static void tlsh_unregister_listener(struct sock *sk)
{
	write_lock_bh(&tlsh_listener_lock);
	sk_del_node_init(sk);			/* Ref: B */
	write_unlock_bh(&tlsh_listener_lock);
}

/**
 * tlsh_find_listener - find listener that matches an incoming connection
 * @incoming: connected socket to match to a listener
 *
 * Return values:
 *   On success, address of a listening AF_TLSH socket
 *   %NULL: No matching listener found
 */
static struct sock *tlsh_find_listener(struct sock *incoming)
{
	struct sock *listener;

	read_lock(&tlsh_listener_lock);

	sk_for_each(listener, &tlsh_listeners) {
		if (sock_net(listener) != sock_net(incoming))
			continue;
		if (listener->sk_tls_bind_family != AF_UNSPEC &&
		    listener->sk_tls_bind_family != incoming->sk_family)
			continue;

		goto out;
	}
	listener = NULL;

out:
	read_unlock(&tlsh_listener_lock);
	return listener;
}

/**
 * tlsh_accept_enqueue - add a socket to a listener's accept_q
 * @listener: listening socket
 * @sk: socket to enqueue on @listener
 *
 * Return values:
 *   On success, returns 0
 *   %-ENOMEM: Memory for skbs has been exhausted
 */
static int tlsh_accept_enqueue(struct sock *listener, struct sock *sk)
{
	struct sk_buff *skb;

	skb = alloc_skb(0, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	sock_hold(sk);	/* Ref: I */
	skb->sk = sk;
	skb_queue_tail(&listener->sk_receive_queue, skb);
	sk_acceptq_added(listener);
	listener->sk_data_ready(listener);
	return 0;
}

/**
 * tlsh_accept_dequeue - remove a socket from a listener's accept_q
 * @listener: listener socket to check
 *
 * Caller guarantees that @listener won't disappear.
 *
 * Return values:
 *   On success, return a TCP socket waiting for TLS service
 *   %NULL: No sockets on the accept queue
 */
static struct sock *tlsh_accept_dequeue(struct sock *listener)
{
	struct sk_buff *skb;
	struct sock *sk;

	skb = skb_dequeue(&listener->sk_receive_queue);
	if (!skb)
		return NULL;
	sk_acceptq_removed(listener);

	sk = skb->sk;
	skb->sk = NULL;
	kfree_skb(skb);
	sock_put(sk);	/* Ref: I */
	return sk;
}

static void tlsh_sock_save(struct sock *sk,
			   void (*done)(void *data, int status),
			   void *data)
{
	sock_hold(sk);	/* Ref: J */

	write_lock_bh(&sk->sk_callback_lock);

	sk->sk_tls_data = data;
	sk->sk_tls_handshake_done = done;
	sk->sk_saved_wq = sk->sk_wq_raw;
	sk->sk_saved_socket = sk->sk_socket;
	sk->sk_saved_uid = sk->sk_uid;

	write_unlock_bh(&sk->sk_callback_lock);
}

static void tlsh_sock_clear(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);

	sk->sk_tls_data = NULL;
	sk->sk_tls_handshake_done = NULL;

	write_unlock_bh(&sk->sk_callback_lock);

	sock_put(sk);	/* Ref: J (err) */
}

static void tlsh_sock_restore_locked(struct sock *sk)
{
	sk->sk_tls_data = NULL;
	sk->sk_tls_handshake_done = NULL;
	sk->sk_wq_raw = sk->sk_saved_wq;
	sk->sk_socket = sk->sk_saved_socket;
	sk->sk_uid = sk->sk_saved_uid;
}

/**
 * tlsh_handshake_done - the handshake is done or couldn't be started
 * @sk: socket that was requesting a handshake
 * @status: completion status
 *
 * Call the registered "done" callback for @sk.
 */
void tlsh_handshake_done(struct sock *sk, int status)
{
	void (*done)(void *data, int status);
	void *data;
	bool put;

	trace_tlsh_handshake_done(sk);

	put = false;
	write_lock_bh(&sk->sk_callback_lock);

	done = sk->sk_tls_handshake_done;
	data = sk->sk_tls_data;
	if (done) {
		tlsh_sock_restore_locked(sk);
		done(data, status);
		put = true;
	}

	write_unlock_bh(&sk->sk_callback_lock);
	if (put)
		sock_put(sk);	/* Ref: J */
}

/**
 * tlsh_accept_drain - clean up children queued for accept
 * @listener: listener socket to drain
 *
 */
static void tlsh_accept_drain(struct sock *listener)
{
	struct sock *sk;

	while ((sk = tlsh_accept_dequeue(listener)))
		tlsh_handshake_done(sk, -EACCES);
}

/**
 * tlsh_release - free an AF_TLSH socket
 * @sock: socket to release
 *
 * Return values:
 *   %0: success
 */
static int tlsh_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	trace_tlsh_release(sock);

	switch (sk->sk_family) {
	case AF_INET:
		return inet_release(sock);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return inet6_release(sock);
#endif
	case AF_TLSH:
		break;
	default:
		return 0;
	}

	sock_hold(sk);	/* Ref: D */
	sock_orphan(sk);
	lock_sock(sk);

	tlsh_unregister_listener(sk);
	tlsh_accept_drain(sk);

	sk->sk_state = TCP_CLOSE;
	sk->sk_shutdown |= SEND_SHUTDOWN;
	sk->sk_state_change(sk);

	sk->sk_tls_bind_family = AF_UNSPEC;
	sock->sk = NULL;
	release_sock(sk);
	sock_put(sk);	/* Ref: D */

	sock_put(sk);	/* Ref: A */
	return 0;
}

/**
 * tlsh_bind - bind a name to an AF_TLSH socket
 * @sock: socket to be bound
 * @uaddr: address to bind to
 * @addrlen: length in bytes of @uaddr
 *
 * Binding an AF_TLSH socket defines the family of addresses that
 * are able to be accept(2)'d. So, AF_INET for ipv4, AF_INET6 for
 * ipv6.
 *
 * Return values:
 *   %0: binding was successful.
 *   %-EPERM: Caller not privileged
 *   %-EINVAL: Family of @sock or @uaddr not supported
 */
static int tlsh_bind(struct socket *sock, struct sockaddr *uaddr, int addrlen)
{
	struct sock *sk = sock->sk;

	if (!capable(CAP_NET_BIND_SERVICE))
		return -EPERM;

	switch (uaddr->sa_family) {
	case AF_INET:
		if (addrlen != sizeof(struct sockaddr_in))
			return -EINVAL;
		sk->sk_tls_bind_family = AF_INET;
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		if (addrlen != sizeof(struct sockaddr_in6))
			return -EINVAL;
		sk->sk_tls_bind_family = AF_INET6;
		break;
#endif
	default:
		return -EAFNOSUPPORT;
	}

	trace_tlsh_bind(sock);
	return 0;
}

/**
 * tlsh_accept - return a connection waiting for a TLS handshake
 * @listener: listener socket which connection requests arrive on
 * @newsock: socket to move incoming connection to
 * @flags: SOCK_NONBLOCK and/or SOCK_CLOEXEC
 * @kern: 'true' for kernel-internal sockets (ignored)
 *
 * Return values:
 *   %0: @newsock has been initialized.
 *   %-EPERM: caller is not privileged
 */
static int tlsh_accept(struct socket *listener, struct socket *newsock, int flags,
		       bool kern)
{
	struct sock *sk = listener->sk, *newsk;
	DECLARE_WAITQUEUE(wait, current);
	long timeo;
	int rc;

	trace_tlsh_accept(listener);

	rc = -EPERM;
	if (!capable(CAP_NET_BIND_SERVICE))
		goto out;

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		rc = -EBADF;
		goto out_release;
	}

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

	rc = 0;
	add_wait_queue_exclusive(sk_sleep(sk), &wait);
	while (!(newsk = tlsh_accept_dequeue(sk))) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!timeo) {
			rc = -EAGAIN;
			break;
		}
		release_sock(sk);

		timeo = schedule_timeout(timeo);

		lock_sock(sk);
		if (sk->sk_state != TCP_LISTEN) {
			rc = -EBADF;
			break;
		}
		if (signal_pending(current)) {
			rc = sock_intr_errno(timeo);
			break;
		}
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);
	if (rc) {
		tlsh_handshake_done(sk, -EACCES);
		goto out_release;
	}

	sock_graft(newsk, newsock);
	trace_tlsh_newsock(newsock, newsk);

	/* prevent user agent close from releasing the kernel socket */
	sock_hold(newsk);

out_release:
	release_sock(sk);
out:
	return rc;
}

/**
 * tlsh_getname - retrieve src/dst address information
 * @sock: socket to query
 * @uaddr: buffer to fill in
 * @peer: value indicates which address to retrieve
 *
 * Return values:
 *   On success, a positive length of the address in @uaddr
 *   On error, a negative errno
 */
static int tlsh_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sock *sk = sock->sk;

	trace_tlsh_getname(sock);

	switch (sk->sk_family) {
	case AF_INET:
		return inet_getname(sock, uaddr, peer);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return inet6_getname(sock, uaddr, peer);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * tlsh_poll - check for data ready on an AF_TLSH socket
 * @file: file to check for work
 * @sock: socket associated with @file
 * @wait: poll table
 *
 * Return values:
 *    A mask of flags indicating what type of I/O is ready
 */
static __poll_t tlsh_poll(struct file *file, struct socket *sock,
			  poll_table *wait)
{
	struct sock *sk = sock->sk;
	__poll_t revents;

	sock_poll_wait(file, sock, wait);

	revents = 0;

	if (sk->sk_err)
		revents |= EPOLLERR;

	if (sk->sk_shutdown == SHUTDOWN_MASK)
		revents |= EPOLLHUP;
	if (sk->sk_type == SOCK_STREAM && sk->sk_state == TCP_CLOSE)
		revents |= EPOLLHUP;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		revents |= EPOLLRDHUP | EPOLLIN | EPOLLRDNORM;
	if (!skb_queue_empty_lockless(&sk->sk_receive_queue))
		revents |= EPOLLIN | EPOLLRDNORM;
	if (sk_is_readable(sk))
		revents |= EPOLLIN | EPOLLRDNORM;

	trace_tlsh_poll(sock, revents);
	return revents;
}

/**
 * tlsh_listen - move a PF_TLSH socket into a listening state
 * @sock: socket to transition to listening state
 * @backlog: size of backlog queue
 *
 * Return values:
 *   %0: @sock is now in a listening state
 *   %-EPERM: caller is not privileged
 *   %-EINVAL: invalid parameters
 */
static int tlsh_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int rc;

	if (!capable(CAP_NET_BIND_SERVICE))
		return -EPERM;

	lock_sock(sk);

	rc = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;
	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	sk->sk_max_ack_backlog = backlog;
	sk->sk_state = TCP_LISTEN;
	tlsh_register_listener(sk);

	trace_tlsh_listen(sock);
	rc = 0;

out:
	release_sock(sk);
	return rc;
}

/**
 * tlsh_setsockopt - Set a socket option
 * @sock: socket to act upon
 * @level: which network layer to act upon
 * @optname: which option to set
 * @optval: new value to set
 * @optlen: the size of the new value, in bytes
 *
 * Return values:
 *   %0: Success
 */
static int tlsh_setsockopt(struct socket *sock, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;

	trace_tlsh_setsockopt(sock);

	switch (sk->sk_family) {
	case AF_INET:
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
#endif
		return sock_common_setsockopt(sock, level,
					      optname, optval, optlen);
	default:
		return -EINVAL;
	}
}

/**
 * tlsh_getsockopt - Retrieve a socket option
 * @sock: socket to act upon
 * @level: which network layer to act upon
 * @optname: which option to retrieve
 * @optval: a buffer into which to receive the option's value
 * @optlen: the size of the receive buffer, in bytes
 *
 * Return values:
 *   %0: Success
 */
static int tlsh_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;

	trace_tlsh_getsockopt(sock);

	switch (sk->sk_family) {
	case AF_INET:
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
#endif
		return sock_common_getsockopt(sock, level,
					      optname, optval, optlen);
	default:
		return -EINVAL;
	}
}

/**
 * tlsh_sendmsg - Send a message on a socket
 * @sock: socket to send on
 * @msg: message to send
 * @size: size of message, in bytes
 *
 * Return values:
 *   %0: Success
 *   %-EOPNOTSUPP: Address family does not support this operation
 */
static int tlsh_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	trace_tlsh_sendmsg(sock);

	switch (sk->sk_family) {
	case AF_INET:
		return inet_sendmsg(sock, msg, size);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return inet6_sendmsg(sock, msg, size);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * tlsh_recvmsg - Receive a message from a socket
 * @sock: socket to receive from
 * @msg: buffer into which to receive
 * @size: size of buffer, in bytes
 * @flags: control settings
 *
 * Return values:
 *   %0: Success
 *   %-EOPNOTSUPP: Address family does not support this operation
 */
static int tlsh_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			int flags)
{
	struct sock *sk = sock->sk;

	trace_tlsh_recvmsg(sock);

	switch (sk->sk_family) {
	case AF_INET:
		return inet_recvmsg(sock, msg, size, flags);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return inet6_recvmsg(sock, msg, size, flags);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

static const struct proto_ops tlsh_ops = {
	.family		= PF_TLSH,
	.owner		= THIS_MODULE,

	.release	= tlsh_release,
	.bind		= tlsh_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= tlsh_accept,
	.getname	= tlsh_getname,
	.poll		= tlsh_poll,
	.ioctl		= sock_no_ioctl,
	.gettstamp	= sock_gettstamp,
	.listen		= tlsh_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= tlsh_setsockopt,
	.getsockopt	= tlsh_getsockopt,
	.sendmsg	= tlsh_sendmsg,
	.recvmsg	= tlsh_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};

/**
 * tlsh_pf_create - create an AF_TLSH socket
 * @net: network namespace to own the new socket
 * @sock: socket to initialize
 * @protocol: IP protocol number (ignored)
 * @kern: "boolean": 1 for kernel-internal sockets
 *
 * Return values:
 *   %0: @sock was initialized, and module ref count incremented.
 *   Negative errno values indicate initialization failed.
 */
int tlsh_pf_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;
	int rc;

	if (protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;

	/* only stream sockets are supported */
	if (sock->type != SOCK_STREAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &tlsh_ops;

	/* Ref: A */
	sk = sk_alloc(net, PF_TLSH, GFP_KERNEL, &tcp_prot, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			goto err_sk_put;
	}
	sk->sk_tls_bind_family = AF_UNSPEC;

	trace_tlsh_pf_create(sock);
	return 0;

err_sk_put:
	sock_orphan(sk);
	sk_free(sk);	/* Ref: A (err) */
	return rc;
}

/**
 * tls_client_hello_user - start a TLS handshake via a user mode helper
 * @sock: connected socket on which to perform the handshake
 * @done: function to call when the handshake has completed
 * @data: token to pass back to @done
 *
 * Return values:
 *   %0: Handshake started; ->done will be called when complete
 *   %-ENOENT: No user agent is available
 *   %-ENOMEM: Memory allocation failed
 */
int tls_client_hello_user(struct socket *sock,
			  void (*done)(void *data, int status),
			  void *data)
{
	struct sock *listener, *sk = sock->sk;
	int rc;

	rc = -ENOENT;
	listener = tlsh_find_listener(sk);
	if (!listener)
		goto out_err;

	sock_hold(listener);	/* Ref: C */
	tlsh_sock_save(sk, done, data);
	rc = tlsh_accept_enqueue(listener, sk);
	sock_put(listener);	/* Ref: C */
	if (rc)
		goto out_err;

	return 0;

out_err:
	tlsh_sock_clear(sk);
	return rc;
}
EXPORT_SYMBOL_GPL(tls_client_hello_user);
