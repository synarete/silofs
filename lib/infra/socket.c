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
#include <silofs/configs.h>
#include <silofs/syscall.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint16_t silofs_htons(uint16_t n)
{
	return htons(n);
}

uint32_t silofs_htonl(uint32_t n)
{
	return htonl(n);
}

uint16_t silofs_ntohs(uint16_t n)
{
	return ntohs(n);
}

uint32_t silofs_ntohl(uint32_t n)
{
	return ntohl(n);
}

void silofs_ucred_self(struct ucred *uc)
{
	uc->uid = getuid();
	uc->gid = getgid();
	uc->pid = getpid();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_check_portnum(int portnum)
{
	return ((portnum > 0) && (portnum < 65536)) ? 0 : -EINVAL;
}

int silofs_check_unixsock(const char *path)
{
	const struct sockaddr_un *un = NULL;

	return (path && (strlen(path) < sizeof(un->sun_path))) ? 0 : -EINVAL;
}

static void sockaddr_reset(struct silofs_sockaddr *sa)
{
	struct sockaddr *sa_common = &sa->u.sa;

	memset(sa_common, 0, sizeof(*sa_common));
}

static void sockaddr_clear_un(struct silofs_sockaddr *sa)
{
	struct sockaddr_un *sa_un = &sa->u.sa_un;

	memset(sa_un, 0, sizeof(*sa_un));
}

static sa_family_t sockaddr_family(const struct silofs_sockaddr *sa)
{
	return sa->u.sa.sa_family;
}

static socklen_t sockaddr_length_un(const struct silofs_sockaddr *sa)
{
	const char *sun_path;
	size_t sun_path_max;
	size_t sun_path_len = 0;
	const struct sockaddr_un *sa_un = &sa->u.sa_un;

	sun_path = sa_un->sun_path;
	sun_path_max = sizeof(sa_un->sun_path) - 1;
	if (sun_path[0] == '\0') {
		sun_path += 1;
		sun_path_max -= 1;
		sun_path_len += 1;
	}
	sun_path_len += strnlen(sun_path, sun_path_max);
	return (socklen_t)(sizeof(sa_un->sun_family) + sun_path_len);
}

static socklen_t sockaddr_length(const struct silofs_sockaddr *sa)
{
	socklen_t len;
	const sa_family_t family = sockaddr_family(sa);

	if (family == AF_INET) {
		len = sizeof(sa->u.sa_in);
	} else if (family == AF_INET6) {
		len = sizeof(sa->u.sa_in6);
	} else if (family == AF_UNIX) {
		len = sockaddr_length_un(sa);
	} else {
		len = 0;
	}
	return len;
}

void silofs_sockaddr_none(struct silofs_sockaddr *sa)
{
	sockaddr_reset(sa);
}

void silofs_sockaddr_any(struct silofs_sockaddr *sa)
{
	sockaddr_reset(sa);
	sa->u.sa_in.sin_family = AF_INET;
	sa->u.sa_in.sin_port = 0;
	sa->u.sa_in.sin_addr.s_addr = silofs_htonl(INADDR_ANY);
}

void silofs_sockaddr_any6(struct silofs_sockaddr *sa)
{
	sockaddr_reset(sa);
	sa->u.sa_in6.sin6_family = AF_INET6;
	sa->u.sa_in6.sin6_port = silofs_htons(0);
	memcpy(&sa->u.sa_in6.sin6_addr, &in6addr_any,
	       sizeof(sa->u.sa_in6.sin6_addr));
}

void silofs_sockaddr_loopback(struct silofs_sockaddr *sa, in_port_t port)
{
	sockaddr_reset(sa);
	sa->u.sa_in.sin_family = AF_INET;
	sa->u.sa_in.sin_port = silofs_htons(port);
	sa->u.sa_in.sin_addr.s_addr = silofs_htonl(INADDR_LOOPBACK);
}

void silofs_sockaddr_setport(struct silofs_sockaddr *sa, in_port_t port)
{
	const sa_family_t family = sockaddr_family(sa);

	if (family == AF_INET6) {
		sa->u.sa_in6.sin6_port = silofs_htons(port);
	} else if (family == AF_INET) {
		sa->u.sa_in.sin_port = silofs_htons(port);
	}
}

int silofs_sockaddr_unix(struct silofs_sockaddr *sa, const char *path)
{
	int err;

	err = silofs_check_unixsock(path);
	if (err) {
		return err;
	}
	sockaddr_clear_un(sa);
	sa->u.sa_un.sun_family = AF_UNIX;
	strncpy(sa->u.sa_un.sun_path, path, sizeof(sa->u.sa_un.sun_path) - 1);
	return 0;
}

int silofs_sockaddr_abstract(struct silofs_sockaddr *sa, const char *name)
{
	size_t len;
	int err;

	err = silofs_check_unixsock(name);
	if (err) {
		return err;
	}
	len = strlen(name);
	if (len >= (sizeof(sa->u.sa_un.sun_path) - 1)) {
		return -EINVAL;
	}
	sockaddr_clear_un(sa);
	sa->u.sa_un.sun_family = AF_UNIX;
	memcpy(&sa->u.sa_un.sun_path[1], name, len);
	return 0;
}

int silofs_sockaddr_pton(struct silofs_sockaddr *sa, const char *str)
{
	int res;
	int err = -EINVAL;

	sockaddr_reset(sa);
	if (strchr(str, ':') != NULL) {
		sa->u.sa_in6.sin6_family = AF_INET6;
		res = inet_pton(AF_INET6, str, &sa->u.sa_in6.sin6_addr);
		err = (res == 1) ? 0 : -errno;
	} else {
		sa->u.sa_in.sin_family = AF_INET;
		res = inet_aton(str, &sa->u.sa_in.sin_addr);
		err = (res != 0) ? 0 : -errno;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_msghdr_set_addr(struct msghdr *mh,
                            const struct silofs_sockaddr *sa)
{
	mh->msg_namelen = sockaddr_length(sa);
	mh->msg_name = silofs_unconst(sa);
}

struct cmsghdr *silofs_cmsg_firsthdr(struct msghdr *mh)
{
	return CMSG_FIRSTHDR(mh);
}

struct cmsghdr *silofs_cmsg_nexthdr(struct msghdr *mh, struct cmsghdr *cmh)
{
	return CMSG_NXTHDR(mh, cmh);
}

size_t silofs_cmsg_align(size_t length)
{
	return CMSG_ALIGN(length);
}

size_t silofs_cmsg_space(size_t length)
{
	return CMSG_SPACE(length);
}

size_t silofs_cmsg_len(size_t length)
{
	return CMSG_LEN(length);
}

static void *cmsg_data(const struct cmsghdr *cmh)
{
	return silofs_unconst(CMSG_DATA(cmh));
}

void silofs_cmsg_pack_fd(struct cmsghdr *cmh, int fd)
{
	cmh->cmsg_len = silofs_cmsg_len(sizeof(fd));
	cmh->cmsg_level = SOL_SOCKET;
	cmh->cmsg_type = SCM_RIGHTS;
	memmove(cmsg_data(cmh), &fd, sizeof(fd));
}

int silofs_cmsg_unpack_fd(const struct cmsghdr *cmh, int *out_fd)
{
	size_t size;

	if (cmh->cmsg_type != SCM_RIGHTS) {
		return -1;
	}
	size = cmh->cmsg_len - sizeof(*cmh);
	if (size != sizeof(*out_fd)) {
		return -1;
	}
	memmove(out_fd, cmsg_data(cmh), sizeof(*out_fd));
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void socket_init(struct silofs_socket *sock,
                        short family, short type, short proto)
{
	sock->fd = -1;
	sock->family = family;
	sock->type = type;
	sock->proto = proto;
}

static void socket_assign(struct silofs_socket *sock, int fd,
                          short family, short type, short proto)
{
	sock->fd = fd;
	sock->family = family;
	sock->type = type;
	sock->proto = proto;
}

static void socket_destroy(struct silofs_socket *sock)
{
	sock->fd = -1;
	sock->family = -1;
	sock->type = -1;
}

static bool socket_isopen(const struct silofs_socket *sock)
{
	return (sock->fd >= 0);
}

static int socket_checkopen(const struct silofs_socket *sock)
{
	return socket_isopen(sock) ? 0 : -EBADF;
}

static int socket_checkaddr(const struct silofs_socket *sock,
                            const struct silofs_sockaddr *sa)
{
	const sa_family_t family = sockaddr_family(sa);

	return (sock->family == (int)(family)) ? 0 : -EINVAL;
}

int silofs_socket_open(struct silofs_socket *sock)
{
	int err = -EALREADY;

	if (!socket_isopen(sock)) {
		err = silofs_sys_socket(sock->family, sock->type,
		                        sock->proto, &sock->fd);
	}
	return err;
}

static void socket_close(struct silofs_socket *sock)
{
	if (socket_isopen(sock)) {
		silofs_sys_close((sock->fd));
		sock->fd = -1;
	}
}

void silofs_socket_close(struct silofs_socket *sock)
{
	socket_close(sock);
}

void silofs_socket_fini(struct silofs_socket *sock)
{
	socket_close(sock);
	socket_destroy(sock);
}

int silofs_socket_rselect(const struct silofs_socket *sock,
                          const struct timespec *ts)
{
	int err = -EBADF;

	if (socket_isopen(sock)) {
		err = silofs_sys_pselect_rfd(sock->fd, ts);
	}
	return err;
}

int silofs_socket_bind(struct silofs_socket *sock,
                       const struct silofs_sockaddr *sa)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = socket_checkaddr(sock, sa);
	if (err) {
		return err;
	}
	err = silofs_sys_bind(sock->fd, &sa->u.sa, sockaddr_length(sa));
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_listen(const struct silofs_socket *sock, int backlog)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_listen(sock->fd, backlog);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_accept(const struct silofs_socket *sock,
                         struct silofs_socket *acsock,
                         struct silofs_sockaddr *peer)
{
	int err;
	int fd = -1;
	socklen_t addrlen = sizeof(*peer);

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	sockaddr_reset(peer);
	err = silofs_sys_accept(sock->fd, &peer->u.sa, &addrlen, &fd);
	if (err) {
		return err;
	}
	socket_assign(acsock, fd, sock->family, sock->type, sock->proto);
	return 0;
}

int silofs_socket_connect(const struct silofs_socket *sock,
                          const struct silofs_sockaddr *sa)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = socket_checkaddr(sock, sa);
	if (err) {
		return err;
	}
	err = silofs_sys_connect(sock->fd, &sa->u.sa, sockaddr_length(sa));
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_shutdown(const struct silofs_socket *sock, int how)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_shutdown(sock->fd, how);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_shutdown_rdwr(const struct silofs_socket *sock)
{
	return silofs_socket_shutdown(sock, SHUT_RDWR);
}

static int socket_setsockopt(const struct silofs_socket *sock, int level,
                             int optname, const void *optval, socklen_t len)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_setsockopt(sock->fd, level, optname, optval, len);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_setnodelay(const struct silofs_socket *sock)
{
	int nodelay = 1;

	return socket_setsockopt(sock, sock->proto, TCP_NODELAY,
	                         &nodelay, sizeof(nodelay));
}

int silofs_socket_setkeepalive(const struct silofs_socket *sock)
{
	int keepalive = 1;

	return socket_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
	                         &keepalive, sizeof(keepalive));
}

int silofs_socket_setreuseaddr(const struct silofs_socket *sock)
{
	int reuseaddr = 1;

	return socket_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	                         &reuseaddr, sizeof(reuseaddr));
}

int silofs_socket_setnonblock(const struct silofs_socket *sock)
{
	int err;
	int opts = 0;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_fcntl_getfl(sock->fd, &opts);
	if (err) {
		return err;
	}
	err = silofs_sys_fcntl_setfl(sock->fd, opts | O_NONBLOCK);
	if (err) {
		return err;
	}
	return 0;
}

static int socket_getsockopt(const struct silofs_socket *sock, int level,
                             int optname, void *optval, socklen_t *optlen)
{
	return silofs_sys_getsockopt(sock->fd, level, optname, optval, optlen);
}

int silofs_socket_getpeercred(const struct silofs_socket *sock,
                              struct ucred *cred)
{
	int err;
	socklen_t len = sizeof(*cred);

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = socket_getsockopt(sock, SOL_SOCKET, SO_PEERCRED, cred, &len);
	if (err) {
		return err;
	}
	if (len != sizeof(*cred)) {
		return -EINVAL;
	}
	return 0;
}

int silofs_socket_getsockerror(const struct silofs_socket *sock, int *out_err)
{
	int err;
	socklen_t len = sizeof(*out_err);

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = socket_getsockopt(sock, SOL_SOCKET, SO_ERROR, out_err, &len);
	if (err) {
		return err;
	}
	if (len != sizeof(*out_err)) {
		return -EINVAL;
	}
	return 0;
}

int silofs_socket_send(const struct silofs_socket *sock,
                       const void *buf, size_t len, size_t *out_sent)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_send(sock->fd, buf, len, 0, out_sent);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_sendto(const struct silofs_socket *sock, const void *buf,
                         size_t bsz, const struct silofs_sockaddr *soaddr,
                         size_t *out_sent)
{
	socklen_t len;
	const int fd = sock->fd;
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	len = sockaddr_length(soaddr);
	err = silofs_sys_sendto(fd, buf, bsz, 0, &soaddr->u.sa, len, out_sent);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_sendmsg(const struct silofs_socket *sock,
                          const struct msghdr *msgh, int flags,
                          size_t *out_sent)
{
	return silofs_sys_sendmsg(sock->fd, msgh, flags, out_sent);
}

int silofs_socket_recv(const struct silofs_socket *sock,
                       void *buf, size_t len, size_t *out_recv)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_recv(sock->fd, buf, len, 0, out_recv);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_recvfrom(const struct silofs_socket *sock, void *buf,
                           size_t bsz, struct silofs_sockaddr *sa,
                           size_t *out_recv)
{
	socklen_t len = sizeof(*sa);
	const int fd = sock->fd;
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	sockaddr_reset(sa);
	err = silofs_sys_recvfrom(fd, buf, bsz, 0, &sa->u.sa, &len, out_recv);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_socket_recvmsg(const struct silofs_socket *sock,
                          struct msghdr *msgh, int flags, size_t *out_recv)
{
	int err;

	err = socket_checkopen(sock);
	if (err) {
		return err;
	}
	err = silofs_sys_recvmsg(sock->fd, msgh, flags, out_recv);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dgramsock_init(struct silofs_socket *sock)
{
	socket_init(sock, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

void silofs_dgramsock_init6(struct silofs_socket *sock)
{
	socket_init(sock, PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
}

void silofs_dgramsock_initu(struct silofs_socket *sock)
{
	socket_init(sock, AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
}


void silofs_streamsock_init(struct silofs_socket *sock)
{
	socket_init(sock, PF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void silofs_streamsock_init6(struct silofs_socket *sock)
{
	socket_init(sock, PF_INET6, SOCK_STREAM, IPPROTO_TCP);
}

void silofs_streamsock_initu(struct silofs_socket *sock)
{
	socket_init(sock, AF_UNIX, SOCK_STREAM, IPPROTO_IP);
}



