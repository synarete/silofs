/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef SILOFS_SOCKET_H_
#define SILOFS_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

struct ucred;

/* network & sockets wrappers */
union silofs_sockaddr_u {
	struct sockaddr         sa;
	struct sockaddr_in      sa_in;
	struct sockaddr_in6     sa_in6;
	struct sockaddr_un      sa_un;
	struct sockaddr_storage sas;
};

struct silofs_sockaddr {
	union silofs_sockaddr_u u;
};

struct silofs_socket {
	int   fd;
	short family;
	short type;
	short proto;
	short pad_[3];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

silofs_attr_const uint16_t silofs_htons(uint16_t n);

silofs_attr_const uint32_t silofs_htonl(uint32_t n);

silofs_attr_const uint16_t silofs_ntohs(uint16_t n);

silofs_attr_const uint32_t silofs_ntohl(uint32_t n);

void silofs_ucred_self(struct ucred *uc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_msghdr_set_addr(struct msghdr                *mh,
			    const struct silofs_sockaddr *sa);

struct cmsghdr *silofs_cmsg_firsthdr(struct msghdr *mh);

struct cmsghdr *silofs_cmsg_nexthdr(struct msghdr *mh, struct cmsghdr *cmh);

silofs_attr_const size_t silofs_cmsg_align(size_t length);

silofs_attr_const size_t silofs_cmsg_space(size_t length);

silofs_attr_const size_t silofs_cmsg_len(size_t length);

void silofs_cmsg_pack_fd(struct cmsghdr *cmh, int fd);

int silofs_cmsg_unpack_fd(const struct cmsghdr *cmh, int *out_fd);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

__attribute__((const)) int silofs_check_portnum(int portnum);

int silofs_check_unixsock(const char *upath);

void silofs_sockaddr_none(struct silofs_sockaddr *sa);

void silofs_sockaddr_any(struct silofs_sockaddr *sa);

void silofs_sockaddr_any6(struct silofs_sockaddr *sa);

void silofs_sockaddr_loopback(struct silofs_sockaddr *sa, in_port_t port);

void silofs_sockaddr_setport(struct silofs_sockaddr *sa, in_port_t port);

int silofs_sockaddr_unix(struct silofs_sockaddr *sa, const char *path);

int silofs_sockaddr_abstract(struct silofs_sockaddr *sa, const char *name);

int silofs_sockaddr_pton(struct silofs_sockaddr *sa, const char *str);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_socket_open(struct silofs_socket *sock);

void silofs_socket_close(struct silofs_socket *sock);

void silofs_socket_fini(struct silofs_socket *sock);

int silofs_socket_rselect(const struct silofs_socket *sock,
			  const struct timespec      *ts);

int silofs_socket_bind(struct silofs_socket         *sock,
		       const struct silofs_sockaddr *sa);

int silofs_socket_listen(const struct silofs_socket *sock, int backlog);

int silofs_socket_accept(const struct silofs_socket *sock,
			 struct silofs_socket       *acsock,
			 struct silofs_sockaddr     *peer);

int silofs_socket_connect(const struct silofs_socket   *sock,
			  const struct silofs_sockaddr *sa);

int silofs_socket_shutdown(const struct silofs_socket *sock, int how);

int silofs_socket_shutdown_rdwr(const struct silofs_socket *sock);

int silofs_socket_setnodelay(const struct silofs_socket *sock);

int silofs_socket_setkeepalive(const struct silofs_socket *sock);

int silofs_socket_setreuseaddr(const struct silofs_socket *sock);

int silofs_socket_setnonblock(const struct silofs_socket *sock);

int silofs_socket_getpeercred(const struct silofs_socket *sock,
			      struct ucred               *cred);

int silofs_socket_getsockerror(const struct silofs_socket *sock, int *out_err);

int silofs_socket_send(const struct silofs_socket *sock, const void *buf,
		       size_t len, size_t *out_sent);

int silofs_socket_sendto(const struct silofs_socket *sock, const void *buf,
			 size_t bsz, const struct silofs_sockaddr *sladdr,
			 size_t *out_sent);

int silofs_socket_sendmsg(const struct silofs_socket *sock,
			  const struct msghdr *msgh, int flags,
			  size_t *out_sent);

int silofs_socket_recv(const struct silofs_socket *sock, void *buf, size_t len,
		       size_t *out_recv);

int silofs_socket_recvfrom(const struct silofs_socket *sock, void *buf,
			   size_t bsz, struct silofs_sockaddr *sa,
			   size_t *out_recv);

int silofs_socket_recvmsg(const struct silofs_socket *sock,
			  struct msghdr *msgh, int flags, size_t *out_recv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dgramsock_init(struct silofs_socket *sock);

void silofs_dgramsock_init6(struct silofs_socket *sock);

void silofs_dgramsock_initu(struct silofs_socket *sock);

void silofs_streamsock_init(struct silofs_socket *sock);

void silofs_streamsock_init6(struct silofs_socket *sock);

void silofs_streamsock_initu(struct silofs_socket *sock);

#endif /* SILOFS_SOCKET_H_ */
