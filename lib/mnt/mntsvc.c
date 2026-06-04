/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/config-am.h>
#include <linux/magic.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>

#include <silofs/errors.h>
#include <silofs/mntsvc.h>
#include <silofs/base.h>
#include <silofs/str.h>
#include "mstypes.h"

struct silofs_cmsg_buf {
	long cms[CMSG_SPACE(sizeof(int)) / sizeof(long)];
	long pad;
} silofs_attr_aligned8;

struct silofs_ms_env_obj {
	struct silofs_mntsrv ms_srv;
	struct silofs_ms_env ms_env;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define MKFSINFO(t_, n_, a_, i_) \
	{                        \
		.vfstype = (t_), \
		.name = (n_),    \
		.allowed = (a_), \
		.isfuse = (i_),  \
	}

static const struct silofs_fsinfo fsinfo_allowed[] = {
	MKFSINFO(FUSE_SUPER_MAGIC, "FUSE", 0, 1),
	MKFSINFO(TMPFS_MAGIC, "TMPFS", 0, 0),
	MKFSINFO(XFS_SUPER_MAGIC, "XFS", 1, 0),
	MKFSINFO(EXT2_SUPER_MAGIC, "EXT2", 1, 0),
	MKFSINFO(EXT3_SUPER_MAGIC, "EXT3", 1, 0),
	MKFSINFO(EXT4_SUPER_MAGIC, "EXT4", 1, 0),
	MKFSINFO(BTRFS_SUPER_MAGIC, "BTRFS", 1, 0),
	MKFSINFO(CEPH_SUPER_MAGIC, "CEPH", 1, 0),
	MKFSINFO(CIFS_SUPER_MAGIC, "CIFS", 1, 0),
	MKFSINFO(ECRYPTFS_SUPER_MAGIC, "ECRYPTFS", 0, 0),
	MKFSINFO(F2FS_SUPER_MAGIC, "F2FS", 1, 0),
	MKFSINFO(NFS_SUPER_MAGIC, "NFS", 1, 0),
	MKFSINFO(OVERLAYFS_SUPER_MAGIC, "OVERLAYFS", 0, 0),
};

const struct silofs_fsinfo *silofs_fsinfo_by_vfstype(long vfstype)
{
	const struct silofs_fsinfo *fsinfo = nullptr;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(fsinfo_allowed); ++i) {
		fsinfo = &fsinfo_allowed[i];
		if (fsinfo->vfstype == vfstype) {
			break;
		}
		fsinfo = nullptr;
	}
	return fsinfo;
}

static int check_mntdir_fstype(long vfstype)
{
	const struct silofs_fsinfo *fsinfo;

	fsinfo = silofs_fsinfo_by_vfstype(vfstype);
	if (fsinfo == nullptr) {
		return -SILOFS_EINVAL;
	}
	if (fsinfo->isfuse || !fsinfo->allowed) {
		return -SILOFS_EMOUNT;
	}
	return 0;
}

static int check_mntpoint_fstype(const char *path)
{
	struct statfs stfs;
	int err;

	err = silofs_sys_statfs(path, &stfs);
	if (err) {
		return err;
	}
	err = check_mntdir_fstype(stfs.f_type);
	if (err) {
		return err;
	}
	return 0;
}

static int check_mntpoint(const char *path, uid_t caller_uid, bool mounting)
{
	struct stat st = { .st_ino = 0 };
	int err;

	err = silofs_sys_stat(path, &st);
	if ((err == -EACCES) && !mounting) {
		/*
		 * special case where having a live mount without FUSE
		 * 'allow_other' option; thus even privileged user can not
		 * access to mount point. Fine with us
		 *
		 * TODO: at least try to parse '/proc/self/mounts'
		 */
		return 0;
	}
	if (err) {
		return err;
	}
	if (!S_ISDIR(st.st_mode)) {
		return -SILOFS_ENOTDIR;
	}
	if (mounting) {
		if (st.st_nlink > 2) {
			return -SILOFS_ENOTEMPTY;
		}
		if (st.st_ino == SILOFS_INO_ROOT) {
			return -SILOFS_EBUSY;
		}
		if (caller_uid != st.st_uid) {
			return -SILOFS_EMOUNT;
		}
		err = check_mntpoint_fstype(path);
		if (err) {
			return err;
		}
	} else {
		if (st.st_ino != SILOFS_INO_ROOT) {
			return -SILOFS_EINVAL;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void close_fd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		silofs_panic("close-error: fd=%d err=%d", *pfd, err);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool equal_mntpath(const char *path1, const char *path2)
{
	struct silofs_strview sv_path1;
	struct silofs_strview sv_path2;

	silofs_strview_init(&sv_path1, path1);
	silofs_strview_trim_chr(&sv_path1, '/', &sv_path1);

	silofs_strview_init(&sv_path2, path2);
	silofs_strview_trim_chr(&sv_path2, '/', &sv_path2);

	return (sv_path1.len > 0) && (sv_path1.len == sv_path2.len) &&
	       silofs_strview_nisequal(&sv_path1, sv_path2.str, sv_path2.len);
}

static bool equal_path_by_stat(const char *path1, const struct stat *st2)
{
	struct stat st1 = { .st_size = -1 };
	int err;

	err = silofs_sys_stat(path1, &st1);
	if (err) {
		return false;
	}
	if (st1.st_ino != st2->st_ino) {
		return false;
	}
	if (st1.st_dev != st2->st_dev) {
		return false;
	}
	if (st1.st_mode != st2->st_mode) {
		return false;
	}
	return true;
}

static int check_canonical_path(const char *path)
{
	char *cpath = nullptr;
	int err     = 0;

	if (!silofs_str_length(path)) {
		return -SILOFS_EINVAL;
	}
	cpath = canonicalize_file_name(path);
	if (cpath == nullptr) {
		return -errno;
	}
	if (strcmp(path, cpath) != 0) {
		log_info("canonical-path-mismatch: '%s' '%s'", path, cpath);
		err = -SILOFS_EINVAL;
	}
	free(cpath);
	return err;
}

static int check_mount_path(const char *path, uid_t caller_uid)
{
	int err;

	err = check_canonical_path(path);
	if (err) {
		return err;
	}
	err = check_mntpoint(path, caller_uid, true);
	if (err) {
		log_info("illegal mount-point: %s %d", path, err);
	}
	return err;
}

static int check_umount_path(const char *path, uid_t caller_uid, bool force)
{
	int err;

	err = check_mntpoint(path, caller_uid, false);
	if (err) {
		if (err != -ENOTCONN) {
			log_info("unable to umount: %s %d", path, err);
			return err;
		}
		if (!force) {
			log_info("cannot umount unforced: %s %d", path, err);
			return err;
		}
	}
	return 0;
}

static int check_fuse_dev(const char *devname)
{
	struct stat st = { .st_size = -1 };
	int err;

	err = silofs_sys_stat(devname, &st);
	if (err) {
		log_info("no-stat: %s %d", devname, err);
		return err;
	}
	if (!S_ISCHR(st.st_mode)) {
		log_info("not-a-char-device: %s", devname);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int open_fuse_dev(const char *devname, int *out_fd)
{
	int err;

	*out_fd = -1;

	err = check_fuse_dev(devname);
	if (err) {
		return err;
	}
	err = silofs_sys_open(devname, O_RDWR | O_CLOEXEC, 0, out_fd);
	if (err) {
		log_info("failed to open fuse device: %s", devname);
		return err;
	}
	return 0;
}

static int format_mount_data(const struct silofs_mntparams *mntp, int fd,
                             char *dat, size_t dsz)
{
	size_t len;
	int ret;

	ret = snprintf(dat, dsz,
	               "default_permissions,max_read=%zu,fd=%d,"
	               "rootmode=0%o,user_id=%d,group_id=%d",
	               mntp->max_read, fd, mntp->root_mode, mntp->user_id,
	               mntp->group_id);
	if ((ret <= 0) || ((size_t)ret >= dsz)) {
		return -SILOFS_EINVAL;
	}
	if (!mntp->allowother) {
		return 0;
	}
	len = silofs_str_length(dat);
	dat += len;
	dsz -= len;
	if (dsz < 13) {
		return -SILOFS_EINVAL;
	}
	len = strlcpy(dat, ",allow_other", dsz);
	if (len >= dsz) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

/*
 * TODO-0059: Switch to modern Linux APIs
 *
 * Use fd-base mount syscalls (open_tree, mount_setattr etc.). See example code
 * in 'man (2) mount_setattr'.
 */
static int do_mount_fuse_fs(const struct silofs_mntparams *mntp,
                            const char *path, int *out_fd)
{
	char data[256]  = "";
	const char *dev = "/dev/fuse";
	const char *src = "silofs";
	const char *fst = "fuse.silofs";
	int err;

	*out_fd = -1;

	err = open_fuse_dev(dev, out_fd);
	if (err) {
		goto out_err;
	}
	err = format_mount_data(mntp, *out_fd, data, sizeof(data));
	if (err) {
		goto out_err;
	}
	err = silofs_sys_mount(src, path, fst, mntp->flags, data);
	if (err) {
		log_info("mount failure: path='%s' flags=0x%lx data='%s'",
		         path, (long)mntp->flags, data);
		goto out_err;
	}
	return 0;
out_err:
	close_fd(out_fd);
	return err;
}

static int do_umount_fuse_fs(const struct silofs_mntparams *mntp)
{
	return silofs_sys_umount2(mntp->path, (int)mntp->flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mntmsg_status(const struct silofs_mntmsg *mmsg)
{
	return -abs((int)mmsg->mn_status);
}

static void mntmsg_set_status(struct silofs_mntmsg *mmsg, int status)
{
	mmsg->mn_status = (uint32_t)abs(status);
}

static void mntmsg_init(struct silofs_mntmsg *mmsg, enum silofs_mntcmd cmd)
{
	SILOFS_STATICASSERT_LE(sizeof(struct silofs_mntmsg), 2048);

	silofs_memzero(mmsg, sizeof(*mmsg));
	mntmsg_set_status(mmsg, 0);
	mmsg->mn_magic         = SILOFS_META_MAGIC;
	mmsg->mn_version_major = (uint16_t)silofs_version.major;
	mmsg->mn_version_minor = (uint16_t)silofs_version.minor;
	mmsg->mn_cmd           = (uint32_t)cmd;
}

static void mntmsg_reset(struct silofs_mntmsg *mmsg)
{
	mntmsg_init(mmsg, SILOFS_MNTCMD_NONE);
}

static const char *mntmsg_path(const struct silofs_mntmsg *mmsg)
{
	const char *path    = (const char *)(mmsg->mn_path);
	const size_t maxlen = sizeof(mmsg->mn_path);
	const size_t len    = strnlen(path, maxlen);

	return (len && (len < maxlen)) ? path : nullptr;
}

static int mntmsg_set_path(struct silofs_mntmsg *mmsg, const char *path)
{
	const size_t len = silofs_str_length(path);

	if (!len || (len >= sizeof(mmsg->mn_path))) {
		return -SILOFS_EINVAL;
	}
	memcpy(mmsg->mn_path, path, len);
	return 0;
}

static void mntmsg_to_params(const struct silofs_mntmsg *mmsg,
                             struct silofs_mntparams *mntp)
{
	mntp->path       = mntmsg_path(mmsg);
	mntp->flags      = mmsg->mn_flags;
	mntp->user_id    = mmsg->mn_user_id;
	mntp->group_id   = mmsg->mn_group_id;
	mntp->root_mode  = mmsg->mn_root_mode;
	mntp->max_read   = mmsg->mn_max_read;
	mntp->allowother = (mmsg->mn_allowother > 0);
	mntp->checkonly  = (mmsg->mn_checkonly > 0);
}

static int mntmsg_from_params(struct silofs_mntmsg *mmsg,
                              const struct silofs_mntparams *mntp)
{
	mmsg->mn_flags      = mntp->flags;
	mmsg->mn_user_id    = (uint32_t)mntp->user_id;
	mmsg->mn_group_id   = (uint32_t)mntp->group_id;
	mmsg->mn_root_mode  = (uint32_t)mntp->root_mode;
	mmsg->mn_max_read   = (uint32_t)mntp->max_read;
	mmsg->mn_allowother = mntp->allowother ? 1 : 0;
	mmsg->mn_checkonly  = mntp->checkonly ? 1 : 0;

	return mntp->path ? mntmsg_set_path(mmsg, mntp->path) : 0;
}

static int mntmsg_setup(struct silofs_mntmsg *mmsg, enum silofs_mntcmd cmd,
                        const struct silofs_mntparams *mntp)
{
	mntmsg_init(mmsg, cmd);
	return mntmsg_from_params(mmsg, mntp);
}

static int
mntmsg_mount(struct silofs_mntmsg *mmsg, const struct silofs_mntparams *mntp)
{
	return mntmsg_setup(mmsg, SILOFS_MNTCMD_MOUNT, mntp);
}

static int
mntmsg_umount(struct silofs_mntmsg *mmsg, const struct silofs_mntparams *mntp)
{
	return mntmsg_setup(mmsg, SILOFS_MNTCMD_UMOUNT, mntp);
}

static int mntmsg_handshake(struct silofs_mntmsg *mmsg,
                            const struct silofs_mntparams *mntp)
{
	return mntmsg_setup(mmsg, SILOFS_MNTCMD_HANDSHAKE, mntp);
}

static enum silofs_mntcmd mntmsg_cmd(const struct silofs_mntmsg *mmsg)
{
	return (enum silofs_mntcmd)mmsg->mn_cmd;
}

static int mntmsg_check(const struct silofs_mntmsg *mmsg)
{
	if (mmsg->mn_magic != SILOFS_META_MAGIC) {
		return -SILOFS_EINVAL;
	}
	if (mmsg->mn_version_major != silofs_version.major) {
		return -SILOFS_EPROTO;
	}
	if (mmsg->mn_version_minor > silofs_version.minor) {
		return -SILOFS_EPROTO;
	}
	switch (mntmsg_cmd(mmsg)) {
	case SILOFS_MNTCMD_HANDSHAKE:
	case SILOFS_MNTCMD_MOUNT:
	case SILOFS_MNTCMD_UMOUNT:
		break;
	case SILOFS_MNTCMD_NONE:
	default:
		return -SILOFS_EINVAL;
	}
	return 0;
}

enum {
	SENDRECVMSG_RETRY_MAX = 10,
};

static int try_sendmsg(const struct silofs_socket *sock,
                       const struct msghdr *mh, size_t *out_nbytes)
{
	const int flags = MSG_EOR | MSG_NOSIGNAL;
	int err;

	for (int i = 0; i < SENDRECVMSG_RETRY_MAX; ++i) {
		err = silofs_socket_sendmsg(sock, mh, flags, out_nbytes);
		if (err != -EINTR) {
			break;
		}
	}
	return err;
}

static int check_post_sendmsg(const struct msghdr *mh, size_t nbytes)
{
	if (nbytes < sizeof(*mh)) {
		return -SILOFS_ECOMM;
	}
	if (nbytes != sizeof(struct silofs_mntmsg)) {
		return -SILOFS_EPROTO;
	}
	return 0;
}

static int
do_sendmsg(const struct silofs_socket *sock, const struct msghdr *mh)
{
	size_t nbytes = 0;
	int err;

	err = try_sendmsg(sock, mh, &nbytes);
	if (err) {
		return err;
	}
	err = check_post_sendmsg(mh, nbytes);
	if (err) {
		return err;
	}
	return 0;
}

/*
 * TODO-0033: Use pidfd_getfd(2) to transfer fuse fd
 *
 * Consider using Linux modern pidfd_open(2) + pidfd_getfd(2) to send FUSE fd
 * back to client process. See also: https://lwn.net/Articles/808997/
 */
static void do_pack_fd(struct msghdr *mh, int fd)
{
	struct cmsghdr *cmh;

	cmh = silofs_cmsg_firsthdr(mh);
	if (cmh != nullptr) {
		silofs_cmsg_pack_fd(cmh, fd);
	}
}

static int mntmsg_send(const struct silofs_mntmsg *mmsg,
                       const struct silofs_socket *sock, int fd)
{
	struct silofs_cmsg_buf cb = {
		.pad = 0,
	};
	struct iovec iov = {
		.iov_base = unconst(mmsg),
		.iov_len  = sizeof(*mmsg),
	};
	struct msghdr msg = {
		.msg_name       = nullptr,
		.msg_namelen    = 0,
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = cb.cms,
		.msg_controllen = (fd > 0) ? sizeof(cb.cms) : 0,
		.msg_flags      = 0,
	};

	do_pack_fd(&msg, fd);
	return do_sendmsg(sock, &msg);
}

static int try_recvmsg(const struct silofs_socket *sock, struct msghdr *mh,
                       size_t *out_nbytes)
{
	const int flags = MSG_WAITALL | MSG_NOSIGNAL | MSG_TRUNC |
	                  MSG_CMSG_CLOEXEC;
	int err;

	for (int i = 0; i < SENDRECVMSG_RETRY_MAX; ++i) {
		err = silofs_socket_recvmsg(sock, mh, flags, out_nbytes);
		if (err != -EINTR) {
			break;
		}
	}
	return err;
}

static int
check_post_recvmsg(struct msghdr *mh, size_t nbytes, bool allow_cmsg)
{
	struct cmsghdr *cmh = nullptr;

	if (nbytes < sizeof(*mh)) {
		return -SILOFS_EBADMSG;
	}
	if (nbytes != sizeof(struct silofs_mntmsg)) {
		return -SILOFS_EBADMSG;
	}
	if (mh->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		return -SILOFS_EBADMSG;
	}
	cmh = silofs_cmsg_firsthdr(mh);
	if (cmh == nullptr) {
		return 0;
	}
	if (!allow_cmsg) {
		return -SILOFS_EBADMSG;
	}
	cmh = silofs_cmsg_nexthdr(mh, cmh);
	if (cmh != nullptr) {
		return -SILOFS_EBADMSG;
	}
	return 0;
}

static int do_recvmsg(const struct silofs_socket *sock, struct msghdr *mh,
                      bool allow_cmsg)
{
	size_t nbytes = 0;
	int err;

	err = try_recvmsg(sock, mh, &nbytes);
	if (err) {
		return err;
	}
	err = check_post_recvmsg(mh, nbytes, allow_cmsg);
	if (err) {
		log_info("recvmsg: bad input: nbytes=%zu err=%d", nbytes, err);
		return err;
	}
	return 0;
}

static int do_unpack_fd(struct msghdr *mh, int *out_fd)
{
	struct cmsghdr *cmh;

	*out_fd = -1;
	cmh     = silofs_cmsg_firsthdr(mh);
	return (cmh != nullptr) ? silofs_cmsg_unpack_fd(cmh, out_fd) : 0;
}

static int mntmsg_recv(const struct silofs_mntmsg *mmsg,
                       const struct silofs_socket *sock, int *out_fd)
{
	struct silofs_cmsg_buf cb = {
		.pad = 0,
	};
	struct iovec iov = {
		.iov_base = unconst(mmsg),
		.iov_len  = sizeof(*mmsg),
	};
	struct msghdr msg = {
		.msg_name       = nullptr,
		.msg_namelen    = 0,
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = cb.cms,
		.msg_controllen = sizeof(cb.cms),
		.msg_flags      = 0,
	};
	int err;
	bool want_fd = (out_fd != nullptr);

	if (want_fd) {
		/* do no allow padding other then output fd */
		const size_t fd_cmsg_len = silofs_cmsg_len(sizeof(*out_fd));

		memset(cb.cms, -1, sizeof(cb.cms));
		msg.msg_control    = cb.cms;
		msg.msg_controllen = silofs_min(sizeof(cb.cms), fd_cmsg_len);
	}

	err = do_recvmsg(sock, &msg, want_fd);
	if (!err && want_fd) {
		err = do_unpack_fd(&msg, out_fd);
	}
	return err;
}

static int mntmsg_recv2(const struct silofs_mntmsg *mmsg,
                        const struct silofs_socket *sock)
{
	return mntmsg_recv(mmsg, sock, nullptr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mntsvc_reset_peer_ucred(struct silofs_mntsvc *msvc)
{
	msvc->ms_peer_ucred.pid = (pid_t)(-1);
	msvc->ms_peer_ucred.uid = (uid_t)(-1);
	msvc->ms_peer_ucred.gid = (gid_t)(-1);
	memset(msvc->ms_peer_ids, 0, sizeof(msvc->ms_peer_ids));
}

static void mntsvc_init(struct silofs_mntsvc *msvc)
{
	silofs_socket_reset(&msvc->ms_asock);
	silofs_sockaddr_none(&msvc->ms_peer);
	mntsvc_reset_peer_ucred(msvc);
	msvc->ms_page_size = (uint32_t)silofs_sc_page_size();
	msvc->ms_fuse_fd   = -1;
	msvc->ms_mntd_fd   = -1;
	msvc->ms_srv       = nullptr;
}

static void mntsvc_close_fds(struct silofs_mntsvc *msvc)
{
	close_fd(&msvc->ms_fuse_fd);
	close_fd(&msvc->ms_mntd_fd);
}

static void mntsvc_close_sock(struct silofs_mntsvc *msvc)
{
	silofs_socket_fini(&msvc->ms_asock);
	silofs_sockaddr_none(&msvc->ms_peer);
}

static void mntsvc_fini(struct silofs_mntsvc *msvc)
{
	mntsvc_close_sock(msvc);
	mntsvc_close_fds(msvc);
	mntsvc_reset_peer_ucred(msvc);
	msvc->ms_srv = nullptr;
}

static void mntsvc_format_peer_ids(struct silofs_mntsvc *msvc)
{
	const struct ucred *cred = &msvc->ms_peer_ucred;

	snprintf(msvc->ms_peer_ids, sizeof(msvc->ms_peer_ids) - 1,
	         "[pid=%d,uid=%d,gid=%d]", cred->pid, cred->uid, cred->gid);
}

static int mntsvc_accept_from(struct silofs_mntsvc *msvc,
                              const struct silofs_socket *sock)
{
	int err;

	err = silofs_socket_accept(sock, &msvc->ms_asock, &msvc->ms_peer);
	if (err) {
		return err;
	}
	err = silofs_socket_getpeercred(&msvc->ms_asock, &msvc->ms_peer_ucred);
	if (err) {
		silofs_socket_fini(&msvc->ms_asock);
		return err;
	}
	mntsvc_format_peer_ids(msvc);
	log_info("new-connection: peer=%s", msvc->ms_peer_ids);
	return 0;
}

static void mntsvc_term_peer(struct silofs_mntsvc *msvc)
{
	log_info("end-connection: peer=%s", msvc->ms_peer_ids);
	silofs_socket_shutdown_rdwr(&msvc->ms_asock);
	silofs_socket_fini(&msvc->ms_asock);
	silofs_makesock_seqpacketu(&msvc->ms_asock);
	mntsvc_reset_peer_ucred(msvc);
}

static int
mntsvc_recv_request(struct silofs_mntsvc *msvc, struct silofs_mntmsg *mmsg)
{
	int err;

	mntmsg_reset(mmsg);
	err = mntmsg_recv2(mmsg, &msvc->ms_asock);
	if (err) {
		return err;
	}
	err = mntmsg_check(mmsg);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_check_mount_mntrule(const struct silofs_mntsvc *msvc,
                                      const struct silofs_mntparams *mntp)
{
	struct stat st                       = { .st_size = -1 };
	const struct silofs_mntrule *mrule   = nullptr;
	const struct silofs_mntrules *mrules = nullptr;
	const uid_t uid_none                 = (uid_t)(-1);
	const uid_t uid_peer                 = msvc->ms_peer_ucred.uid;
	int err;

	mrules = msvc->ms_srv->ms_rules;
	if (mrules == nullptr) {
		log_info("no rules for: '%s' peer=%s", mntp->path,
		         msvc->ms_peer_ids);
		return -SILOFS_EMOUNT;
	}
	err = silofs_sys_stat(mntp->path, &st);
	if (err) {
		log_info("no stat for: '%s' peer=%s", mntp->path,
		         msvc->ms_peer_ids);
		return err;
	}
	for (size_t i = 0; i < mrules->nrules; ++i) {
		mrule = &mrules->rules[i];
		if (equal_path_by_stat(mrule->path, &st)) {
			break;
		}
		mrule = nullptr;
	}
	if (mrule == nullptr) {
		log_info("no valid mount-rule for: '%s' peer=%s", mntp->path,
		         msvc->ms_peer_ids);
		return -SILOFS_EMOUNT;
	}
	if ((mrule->uid != uid_none) && (mrule->uid != uid_peer)) {
		log_info("not allowed to mount: uid=%ld '%s' peer=%s",
		         (long)uid_peer, mntp->path, msvc->ms_peer_ids);
		return -SILOFS_EMOUNT;
	}
	/*
	 * TODO-0048: Support 'recursive' mount option.
	 *
	 * Use path as prefix and allow mount for any of its sub-directories.
	 */
	return 0;
}

static int mntsvc_check_umount_mntrule(const struct silofs_mntsvc *msvc,
                                       const struct silofs_mntparams *mntp)
{
	const struct silofs_mntrule *mrule   = nullptr;
	const struct silofs_mntrules *mrules = nullptr;
	const uid_t uid_none                 = (uid_t)(-1);
	const uid_t uid_peer                 = msvc->ms_peer_ucred.uid;

	mrules = msvc->ms_srv->ms_rules;
	if (!mrules || !mrules->nrules) {
		/* no mount-rules -- ignored */
		return 0;
	}
	for (size_t i = 0; i < mrules->nrules; ++i) {
		mrule = &mrules->rules[i];
		if (equal_mntpath(mrule->path, mntp->path)) {
			break;
		}
		mrule = nullptr;
	}
	if (mrule == nullptr) {
		log_info("no rule with: '%s'", mntp->path);
		return -SILOFS_EUMOUNT;
	}
	if ((mrule->uid != uid_none) && (mrule->uid != uid_peer)) {
		log_info("not allowed to umount: uid=%ld '%s'", (long)uid_peer,
		         mntp->path);
		return -SILOFS_EUMOUNT;
	}
	return 0;
}

#define ALLOWED_MS_FLAGS \
	(MS_LAZYTIME | MS_NOEXEC | MS_NOSUID | MS_NODEV | MS_RDONLY)

static int mntsvc_check_mount(const struct silofs_mntsvc *msvc,
                              const struct silofs_mntparams *mntp)
{
	constexpr uint64_t allowed_ms_flags = ALLOWED_MS_FLAGS;
	const struct ucred *peer_cred       = &msvc->ms_peer_ucred;
	int err;

	if (mntp->flags & ~allowed_ms_flags) {
		return -SILOFS_EOPNOTSUPP;
	}
	if ((mntp->root_mode & S_IRWXU) == 0) {
		return -SILOFS_EOPNOTSUPP;
	}
	if ((mntp->root_mode & S_IFDIR) == 0) {
		return -SILOFS_EINVAL;
	}
	if ((mntp->user_id != peer_cred->uid) ||
	    (mntp->group_id != peer_cred->gid)) {
		return -SILOFS_EACCES;
	}
	if (mntp->max_read < (2 * msvc->ms_page_size)) {
		return -SILOFS_EINVAL;
	}
	if (mntp->max_read > (512 * msvc->ms_page_size)) {
		return -SILOFS_EINVAL;
	}
	if (mntp->path == nullptr) {
		return -SILOFS_EINVAL;
	}
	err = mntsvc_check_mount_mntrule(msvc, mntp);
	if (err) {
		return err;
	}
	err = check_mount_path(mntp->path, peer_cred->uid);
	if (err) {
		return err;
	}
	return 0;
}

static int mntvc_pre_mount(struct silofs_mntsvc *msvc,
                           const struct silofs_mntparams *mntp,
                           struct silofs_strbuf *out_sbuf)
{
	struct stat st       = {};
	const uid_t peer_uid = msvc->ms_peer_ucred.uid;
	const int o_flags    = O_PATH | O_NOFOLLOW | O_DIRECTORY;
	int err, mntd_fd = -1;

	err = silofs_sys_open(mntp->path, o_flags, 0, &mntd_fd);
	if (err) {
		log_info("mount: failed to open mount-dir: '%s' o_flags=0%o "
		         "err=%d",
		         mntp->path, o_flags, err);
		goto out_err;
	}
	err = silofs_sys_fstat(mntd_fd, &st);
	if (err) {
		log_info("mount: failed to fstat mount-dir: '%s' o_flags=0%o "
		         "err=%d",
		         mntp->path, o_flags, err);
		goto out_err;
	}
	if (st.st_uid != peer_uid) {
		log_info("mount: not owner: '%s' uid=%d peer_uid=%d",
		         mntp->path, (int)st.st_uid, (int)peer_uid);
		err = -SILOFS_EMOUNT;
		goto out_err;
	}
	silofs_strbuf_sprintf(out_sbuf, "/proc/self/fd/%d", mntd_fd);
	msvc->ms_mntd_fd = mntd_fd;
	return 0;
out_err:
	close_fd(&mntd_fd);
	return err;
}

static int mntsvc_do_mount(struct silofs_mntsvc *msvc,
                           const struct silofs_mntparams *mntp)
{
	struct silofs_strbuf proc_path;
	int err;

	err = mntvc_pre_mount(msvc, mntp, &proc_path);
	if (err) {
		return err;
	}

	err = do_mount_fuse_fs(mntp, proc_path.str, &msvc->ms_fuse_fd);
	if (err) {
		return err;
	}

	log_info("mount ok: '%s' flags=0x%lx uid=%d gid=%d rootmode=0%o "
	         "max_read=%zu fuse_fd=%d peer=%s",
	         mntp->path, mntp->flags, mntp->user_id, mntp->group_id,
	         mntp->root_mode, mntp->max_read, msvc->ms_fuse_fd,
	         msvc->ms_peer_ids);
	return 0;
}

static int mntsvc_exec_mount(struct silofs_mntsvc *msvc,
                             const struct silofs_mntparams *mntp)
{
	int err;

	err = mntsvc_check_mount(msvc, mntp);
	if (err) {
		return err;
	}
	if (mntp->checkonly) {
		return 0;
	}
	err = mntsvc_do_mount(msvc, mntp);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_check_umount(const struct silofs_mntsvc *msvc,
                               const struct silofs_mntparams *mntp)
{
	const uint64_t mnt_allow      = MNT_DETACH | MNT_FORCE;
	const struct ucred *peer_cred = &msvc->ms_peer_ucred;
	const char *path              = mntp->path;
	int err;
	bool force;

	if (!silofs_str_length(path)) {
		return -SILOFS_EPERM;
	}
	if (mntp->flags & ~mnt_allow) {
		return -SILOFS_EINVAL;
	}
	if ((mntp->flags | mnt_allow) != mnt_allow) {
		return -SILOFS_EINVAL;
	}
	force = (mntp->flags & MNT_FORCE) > 0;
	err   = check_umount_path(path, peer_cred->uid, force);
	if (err) {
		return err;
	}
	err = mntsvc_check_umount_mntrule(msvc, mntp);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_do_umount(struct silofs_mntsvc *msvc,
                            const struct silofs_mntparams *mntp)
{
	int err;

	err = do_umount_fuse_fs(mntp);
	log_info("umount: '%s' flags=0x%lx peer=%s err=%d", mntp->path,
	         mntp->flags, msvc->ms_peer_ids, err);

	unused(msvc);
	return err;
}

static int mntsvc_exec_umount(struct silofs_mntsvc *msvc,
                              const struct silofs_mntparams *mntp)
{
	int err;

	err = mntsvc_check_umount(msvc, mntp);
	if (err && (err != -ENOTCONN)) {
		return err;
	}
	err = mntsvc_do_umount(msvc, mntp);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_exec_handshake(struct silofs_mntsvc *msvc,
                                 const struct silofs_mntparams *mntp)
{
	/* TODO: check params */
	unused(msvc);
	unused(mntp);

	return 0;
}

static void
mntsvc_exec_request(struct silofs_mntsvc *msvc, struct silofs_mntmsg *mmsg)
{
	struct silofs_mntparams mntp = { .flags = 0 };
	const enum silofs_mntcmd cmd = mntmsg_cmd(mmsg);
	int err                      = 0;

	mntmsg_to_params(mmsg, &mntp);

	log_info("exec-request: cmd=%d", cmd);
	switch (cmd) {
	case SILOFS_MNTCMD_HANDSHAKE:
		err = mntsvc_exec_handshake(msvc, &mntp);
		break;
	case SILOFS_MNTCMD_MOUNT:
		err = mntsvc_exec_mount(msvc, &mntp);
		break;
	case SILOFS_MNTCMD_UMOUNT:
		err = mntsvc_exec_umount(msvc, &mntp);
		break;
	case SILOFS_MNTCMD_NONE:
	default:
		err = -SILOFS_EOPNOTSUPP;
		break;
	}
	mntmsg_set_status(mmsg, err);
}

static void mntsvc_fill_response(const struct silofs_mntsvc *msvc,
                                 struct silofs_mntmsg *mmsg)
{
	const int status             = mntmsg_status(mmsg);
	const enum silofs_mntcmd cmd = mntmsg_cmd(mmsg);

	mntmsg_init(mmsg, cmd);
	mntmsg_set_status(mmsg, status);
	unused(msvc);
}

static void mntsvc_send_response(struct silofs_mntsvc *msvc,
                                 const struct silofs_mntmsg *mmsg)
{
	const int cmd    = (int)mmsg->mn_cmd;
	const int status = (int)mmsg->mn_status;
	int err;

	log_info("send response: cmd=%d status=%d peer=%s", cmd, status,
	         msvc->ms_peer_ids);
	err = mntmsg_send(mmsg, &msvc->ms_asock, msvc->ms_fuse_fd);
	if (err) {
		log_err("failed to send response: "
		        "cmd=%d status=%d peer=%s err=%d",
		        cmd, status, msvc->ms_peer_ids, err);
	}
}

static void
mntsvc_serve_once(struct silofs_mntsvc *msvc, struct silofs_mntmsg *mmsg)
{
	int err;

	mntmsg_reset(mmsg);
	err = mntsvc_recv_request(msvc, mmsg);
	if (!err) {
		mntsvc_exec_request(msvc, mmsg);
		mntsvc_fill_response(msvc, mmsg);
		mntsvc_send_response(msvc, mmsg);
	}
	mntmsg_reset(mmsg);
}

static void mntsvc_serve_request(struct silofs_mntsvc *msvc)
{
	struct silofs_mntmsg *mmsg = &msvc->ms_mmsg;

	mntsvc_serve_once(msvc, mmsg);
	mntsvc_term_peer(msvc);
	mntsvc_close_fds(msvc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
mntsrv_init(struct silofs_mntsrv *msrv, const struct silofs_ms_args *ms_args)
{
	memcpy(&msrv->ms_args, ms_args, sizeof(msrv->ms_args));
	silofs_makesock_seqpacketu(&msrv->ms_lsock);
	mntsvc_init(&msrv->ms_svc);
	msrv->ms_rules = nullptr;
}

static void mntsrv_fini_sock(struct silofs_mntsrv *msrv)
{
	silofs_socket_shutdown_rdwr(&msrv->ms_lsock);
	silofs_socket_fini(&msrv->ms_lsock);
}

static void mntsrv_fini(struct silofs_mntsrv *msrv)
{
	mntsrv_fini_sock(msrv);
	mntsvc_fini(&msrv->ms_svc);
	msrv->ms_rules = nullptr;
}

static int mntsrv_setrules(struct silofs_mntsrv *msrv,
                           const struct silofs_mntrules *mrules)
{
	msrv->ms_rules = mrules;
	/* TODO: check rules validity */
	return 0;
}

static int mntsrv_open(struct silofs_mntsrv *msrv)
{
	struct silofs_socket *sock = &msrv->ms_lsock;
	int err;

	err = silofs_socket_open(sock);
	if (err) {
		return err;
	}
	err = silofs_socket_setkeepalive(sock);
	if (err) {
		return err;
	}
	err = silofs_socket_setnonblock(sock);
	if (err) {
		return err;
	}
	return 0;
}

static void mntsrv_close(struct silofs_mntsrv *msrv)
{
	silofs_socket_close(&msrv->ms_lsock);
}

static int mntsrv_bind_abstract(struct silofs_mntsrv *msrv)
{
	struct silofs_sockaddr saddr;
	struct silofs_socket *sock = &msrv->ms_lsock;
	const char *sockname       = silofs_mntrpc_sockname();
	int err;

	silofs_sockaddr_abstract(&saddr, sockname);
	err = silofs_socket_bind(sock, &saddr);
	if (err) {
		return err;
	}
	log_info("bind-socket: @%s", sockname);
	return 0;
}

static const char *mntsrv_runstatedir(const struct silofs_mntsrv *msrv)
{
	const char *statedir_args = msrv->ms_args.runstatedir;
	const char *statedir_conf = SILOFS_RUNSTATEDIR;

	return (statedir_args != nullptr) ? statedir_args : statedir_conf;
}

static int
mntsrv_make_unixaddr(const struct silofs_mntsrv *msrv, char *buf, size_t bsz)
{
	const char *statedir = mntsrv_runstatedir(msrv);
	const char *sockname = silofs_mntrpc_sockname();
	ssize_t len;

	len = snprintf(buf, bsz, "%s/%s", statedir, sockname);
	if ((size_t)len >= bsz) {
		log_err("invalid unix sock: %s/%s", statedir, sockname);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int mntsrv_bind_unix(struct silofs_mntsrv *msrv)
{
	char unix_addr[104] = "";
	struct silofs_sockaddr saddr;
	struct silofs_socket *sock = &msrv->ms_lsock;
	int err;

	err = mntsrv_make_unixaddr(msrv, unix_addr, sizeof(unix_addr));
	if (err) {
		return err;
	}
	err = silofs_sockaddr_unix(&saddr, unix_addr);
	if (err) {
		return err;
	}
	err = silofs_socket_bind(sock, &saddr);
	if (err) {
		return err;
	}
	log_info("bind-socket: %s", unix_addr);
	return 0;
}

static int mntsrv_bind(struct silofs_mntsrv *msrv)
{
	int err;

	if (msrv->ms_args.use_abstract) {
		err = mntsrv_bind_abstract(msrv);
	} else {
		err = mntsrv_bind_unix(msrv);
	}
	return err;
}

static int mntsrv_wait_incoming(struct silofs_mntsrv *msrv)
{
	struct timespec ts = { .tv_sec = 1 };

	return silofs_socket_rselect(&msrv->ms_lsock, &ts);
}

static int mntsrv_listen(struct silofs_mntsrv *msrv)
{
	return silofs_socket_listen(&msrv->ms_lsock, 1);
}

static int mntsrv_wait_conn(struct silofs_mntsrv *msrv, long sec_wait)
{
	const struct timespec ts = { .tv_sec = sec_wait, .tv_nsec = 0 };
	int err;

	err = silofs_socket_rselect(&msrv->ms_lsock, &ts);
	if (err) {
		return err;
	}
	mntsvc_init(&msrv->ms_svc);
	return 0;
}

static int mntsrv_accept_conn(struct silofs_mntsrv *msrv)
{
	struct silofs_mntsvc *msvc = &msrv->ms_svc;
	int err;

	err = mntsvc_accept_from(msvc, &msrv->ms_lsock);
	if (err) {
		return err;
	}
	msvc->ms_srv = msrv;
	return 0;
}

static void mntsrv_fini_conn(struct silofs_mntsrv *msrv)
{
	mntsvc_fini(&msrv->ms_svc);
}

static int mntsrv_serve_conn(struct silofs_mntsrv *msrv)
{
	int err;

	err = mntsrv_accept_conn(msrv);
	if (err) {
		goto out;
	}
	mntsvc_serve_request(&msrv->ms_svc);
out:
	mntsrv_fini_conn(msrv);
	return err;
}

static int mntsrv_wait_and_serve_conn(struct silofs_mntsrv *msrv)
{
	int err;

	err = mntsrv_wait_conn(msrv, 5);
	if (err) {
		return err;
	}
	err = mntsrv_serve_conn(msrv);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
mse_init(struct silofs_ms_env *mse, const struct silofs_ms_args *ms_args)
{
	mntsrv_init(mse->ms_srv, ms_args);
	mse->ms_active = 0;
	mse->ms_signum = 0;
	return 0;
}

static void mse_fini(struct silofs_ms_env *mse)
{
	mntsrv_fini(mse->ms_srv);
	mse->ms_active = 0;
}

int silofs_mse_new(const struct silofs_ms_args *ms_args,
                   struct silofs_ms_env **out_mse)
{
	struct silofs_ms_env *mse         = nullptr;
	struct silofs_ms_env_obj *mse_obj = nullptr;
	void *mem;
	int err;

	err = silofs_zmalloc(sizeof(*mse_obj), &mem);
	if (err) {
		return err;
	}
	mse_obj     = mem;
	mse         = &mse_obj->ms_env;
	mse->ms_srv = &mse_obj->ms_srv;

	err = mse_init(mse, ms_args);
	if (err) {
		mse_fini(mse);
		free(mem);
		return err;
	}
	*out_mse = mse;
	silofs_burnstack();
	return 0;
}

static struct silofs_ms_env_obj *mse_obj_of(struct silofs_ms_env *mse)
{
	return mut_container_of(mse, struct silofs_ms_env_obj, ms_env);
}

void silofs_mse_del(struct silofs_ms_env *mse)
{
	struct silofs_ms_env_obj *mse_obj = mse_obj_of(mse);

	mse_fini(mse);
	silofs_zfree(mse_obj, sizeof(*mse_obj));
	silofs_burnstack();
}

static int silofs_mse_open(struct silofs_ms_env *mse,
                           const struct silofs_mntrules *mrules)
{
	struct silofs_mntsrv *msrv = mse->ms_srv;
	int err;

	err = mntsrv_setrules(msrv, mrules);
	if (err) {
		return err;
	}
	err = mntsrv_open(msrv);
	if (err) {
		mntsrv_fini_sock(msrv);
		return err;
	}
	err = mntsrv_bind(msrv);
	if (err) {
		mntsrv_fini_sock(msrv);
		return err;
	}
	return 0;
}

static bool transient_error(int err)
{
	return (err == -ETIMEDOUT) || (err == -EINTR);
}

static int mse_exec_serve_loop(struct silofs_ms_env *mse)
{
	struct silofs_mntsrv *msrv = mse->ms_srv;
	int err;

	while (mse->ms_active) {
		err = mntsrv_wait_and_serve_conn(msrv);
		if (err && !transient_error(err)) {
			/* TODO: handle non-valid terminating errors */
			log_info("exec error: err=%d", err);
		}
	}
	return 0;
}

static int mse_exec_some(struct silofs_ms_env *mse)
{
	struct silofs_mntsrv *msrv = mse->ms_srv;
	int err;

	err = mntsrv_wait_incoming(msrv);
	if (err) {
		return err;
	}
	err = mntsrv_listen(msrv);
	if (err) {
		return err;
	}
	err = mse_exec_serve_loop(mse);
	if (err) {
		return err;
	}
	return 0;
}

static int mse_start_exec(struct silofs_ms_env *mse)
{
	const char *sock = silofs_mntrpc_sockname();
	int err;

	log_info("start serve: sock=@%s", sock);
	mse->ms_active = 1;
	while (mse->ms_active) {
		sleep(1);
		err = mse_exec_some(mse);
		silofs_burnstack();

		if (err && !transient_error(err)) {
			log_info("serve error: err=%d", err);
		}
	}
	log_info("done serve: sock=@%s", sock);
	return 0;
}

static void silofs_mse_close(struct silofs_ms_env *mse)
{
	struct silofs_mntsrv *msrv = mse->ms_srv;

	mntsrv_close(msrv);
	mntsrv_fini(msrv);
}

int silofs_mse_serve(struct silofs_ms_env *mse,
                     const struct silofs_mntrules *mrules)
{
	int err = 0;

	err = silofs_mse_open(mse, mrules);
	if (!err) {
		err = mse_start_exec(mse);
		silofs_mse_close(mse);
	}
	return err;
}

void silofs_mse_halt(struct silofs_ms_env *mse, int signum)
{
	silofs_log_info("halt mount service: signum=%d", signum);
	mse->ms_signum = signum;
	mse->ms_active = 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mntclnt_init(struct silofs_mntclnt *mclnt)
{
	const char *sockname = silofs_mntrpc_sockname();

	silofs_makesock_seqpacketu(&mclnt->mc_sock);
	silofs_sockaddr_abstract(&mclnt->mc_srvaddr, sockname);
}

static void mntclnt_fini(struct silofs_mntclnt *mclnt)
{
	silofs_socket_fini(&mclnt->mc_sock);
	silofs_memzero(mclnt, sizeof(*mclnt));
}

static int mntclnt_connect(struct silofs_mntclnt *mclnt)
{
	struct silofs_socket *sock = &mclnt->mc_sock;
	int err;

	err = silofs_socket_open(sock);
	if (err) {
		return err;
	}
	err = silofs_socket_connect(sock, &mclnt->mc_srvaddr);
	if (err) {
		silofs_socket_fini(sock);
		return err;
	}
	return 0;
}

static int mntclnt_disconnect(struct silofs_mntclnt *mclnt)
{
	int err;

	err = silofs_socket_shutdown_rdwr(&mclnt->mc_sock);
	return err;
}

static int
mntclnt_handshake(const struct silofs_mntclnt *mclnt,
                  const struct silofs_mntparams *mntp, int *out_status)
{
	struct silofs_mntmsg mmsg;
	const struct silofs_socket *sock = &mclnt->mc_sock;
	int err;

	*out_status = -SILOFS_ECOMM;

	err = mntmsg_handshake(&mmsg, mntp);
	if (err) {
		return err;
	}
	err = mntmsg_send(&mmsg, sock, -1);
	if (err) {
		return err;
	}
	err = mntmsg_recv2(&mmsg, sock);
	if (err) {
		return err;
	}
	err = mntmsg_check(&mmsg);
	if (err) {
		return err;
	}
	*out_status = mntmsg_status(&mmsg);
	return 0;
}

static int mntclnt_mount(const struct silofs_mntclnt *mclnt,
                         const struct silofs_mntparams *mntp, int *out_status,
                         int *out_fd)
{
	struct silofs_mntmsg mmsg;
	const struct silofs_socket *sock = &mclnt->mc_sock;
	int err;

	*out_status = -SILOFS_ECOMM;
	*out_fd     = -1;

	err = mntmsg_mount(&mmsg, mntp);
	if (err) {
		return err;
	}
	err = mntmsg_send(&mmsg, sock, -1);
	if (err) {
		return err;
	}
	err = mntmsg_recv(&mmsg, sock, out_fd);
	if (err) {
		return err;
	}
	err = mntmsg_check(&mmsg);
	if (err) {
		return err;
	}
	*out_status = mntmsg_status(&mmsg);
	return 0;
}

static int mntclnt_umount(const struct silofs_mntclnt *mclnt,
                          const struct silofs_mntparams *mntp, int *out_status)
{
	struct silofs_mntmsg mmsg;
	const struct silofs_socket *sock = &mclnt->mc_sock;
	int err;

	*out_status = -SILOFS_ECOMM;
	err         = mntmsg_umount(&mmsg, mntp);
	if (err) {
		return err;
	}
	err = mntmsg_send(&mmsg, sock, -1);
	if (err) {
		return err;
	}
	err = mntmsg_recv2(&mmsg, sock);
	if (err) {
		return err;
	}
	err = mntmsg_check(&mmsg);
	if (err) {
		return err;
	}
	*out_status = mntmsg_status(&mmsg);
	return 0;
}

static int do_rpc_mount(struct silofs_mntclnt *mclnt,
                        const struct silofs_mntparams *mntp, int *out_fd)
{
	int err;
	int status = -1;

	err = mntclnt_connect(mclnt);
	if (err) {
		return err;
	}
	err = mntclnt_mount(mclnt, mntp, &status, out_fd);
	if (err) {
		return err;
	}
	err = mntclnt_disconnect(mclnt);
	if (err) {
		return err;
	}
	return status;
}

int silofs_mntrpc_mount(const char *mountpoint, uid_t uid, gid_t gid,
                        size_t max_read, unsigned long ms_flags,
                        bool allow_other, bool check_only, int *out_fd)
{
	struct silofs_mntclnt mclnt;
	struct silofs_mntparams mntp = {
		.path       = mountpoint,
		.flags      = ms_flags,
		.root_mode  = S_IFDIR | S_IRWXU,
		.user_id    = uid,
		.group_id   = gid,
		.max_read   = max_read,
		.allowother = allow_other,
		.checkonly  = check_only,
	};
	int err;

	*out_fd = -1;
	mntclnt_init(&mclnt);
	err = do_rpc_mount(&mclnt, &mntp, out_fd);
	mntclnt_fini(&mclnt);

	if (err || check_only) {
		close_fd(out_fd);
	}
	return err;
}

static int do_rpc_umount(struct silofs_mntclnt *mclnt,
                         const struct silofs_mntparams *mntp)
{
	int err;
	int status = -1;

	err = mntclnt_connect(mclnt);
	if (err) {
		return err;
	}
	err = mntclnt_umount(mclnt, mntp, &status);
	if (err) {
		return err;
	}
	err = mntclnt_disconnect(mclnt);
	if (err) {
		return err;
	}
	return status;
}

int silofs_mntrpc_umount(const char *mountpoint, uid_t uid, gid_t gid,
                         unsigned int mnt_flags)
{
	struct silofs_mntclnt mclnt;
	struct silofs_mntparams mntp = {
		.path     = mountpoint,
		.flags    = mnt_flags,
		.user_id  = uid,
		.group_id = gid,
	};
	int err;

	mntclnt_init(&mclnt);
	err = do_rpc_umount(&mclnt, &mntp);
	mntclnt_fini(&mclnt);

	return err;
}

static int do_rpc_handshake(struct silofs_mntclnt *mclnt,
                            const struct silofs_mntparams *mntp)
{
	int err;
	int status = -1;

	err = mntclnt_connect(mclnt);
	if (err) {
		return err;
	}
	err = mntclnt_handshake(mclnt, mntp, &status);
	if (err) {
		return err;
	}
	err = mntclnt_disconnect(mclnt);
	if (err) {
		return err;
	}
	return status;
}

int silofs_mntrpc_handshake(uid_t uid, gid_t gid)
{
	struct silofs_mntclnt mclnt;
	struct silofs_mntparams mntp = {
		.user_id  = uid,
		.group_id = gid,
	};
	int err;

	mntclnt_init(&mclnt);
	err = do_rpc_handshake(&mclnt, &mntp);
	mntclnt_fini(&mclnt);

	return err;
}

const char *silofs_mntrpc_sockname(void)
{
	return SILOFS_MNTSOCK_NAME;
}
