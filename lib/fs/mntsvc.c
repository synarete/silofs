/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <fcntl.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum silofs_mntcmd {
	SILOFS_MNTCMD_NONE      = 0,
	SILOFS_MNTCMD_HANDSHAKE = 1,
	SILOFS_MNTCMD_MOUNT     = 2,
	SILOFS_MNTCMD_UMOUNT    = 3,
};

struct silofs_mntmsg {
	uint32_t        mn_magic;
	uint16_t        mn_version_major;
	uint16_t        mn_version_minor;
	uint32_t        mn_cmd;
	uint32_t        mn_status;
	uint64_t        mn_flags;
	uint32_t        mn_user_id;
	uint32_t        mn_group_id;
	uint32_t        mn_root_mode;
	uint32_t        mn_max_read;
	uint8_t         mn_allowother;
	uint8_t         mn_checkonly;
	uint8_t         mn_reserved2[86];
	uint8_t         mn_path[SILOFS_MNTPATH_MAX];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_cmsg_buf {
	long cms[CMSG_SPACE(sizeof(int)) / sizeof(long)];
	long pad;
} silofs_aligned8;

struct silofs_mntparams {
	const char *path;
	uint64_t flags;
	uid_t   user_id;
	gid_t   group_id;
	mode_t  root_mode;
	size_t  max_read;
	bool    allowother;
	bool    checkonly;
};

struct silofs_mntclnt {
	struct silofs_socket    mc_sock;
	struct silofs_sockaddr  mc_srvaddr;
};


struct silofs_mntsvc {
	struct silofs_sockaddr  ms_peer;
	struct ucred            ms_peer_ucred;
	char                    ms_peer_ids[52];
	struct silofs_mntsrv   *ms_srv;
	struct silofs_socket    ms_asock;
	int                     ms_fuse_fd;
};

struct silofs_mntsrv {
	struct silofs_ms_args           ms_args;
	const struct silofs_mntrules   *ms_rules;
	struct silofs_socket            ms_lsock;
	struct silofs_mntsvc            ms_svc;
};

struct silofs_ms_env {
	struct silofs_mntsrv *ms_srv;
	int ms_active;
	int ms_signum;
};

struct silofs_ms_env_obj {
	struct silofs_mntsrv    ms_srv;
	struct silofs_ms_env    ms_env;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Known file-systems */
#define FUSE_SUPER_MAGIC        0x65735546 /*  from kernel 'fs/fuse/inode.c' */
#define TMPFS_MAGIC             0x01021994
#define XFS_SB_MAGIC            0x58465342
#define EXT234_SUPER_MAGIC      0x0000EF53
#define ZFS_SUPER_MAGIC         0x2FC12FC1
#define BTRFS_SUPER_MAGIC       0x9123683E
#define CEPH_SUPER_MAGIC        0x00C36400
#define CIFS_MAGIC_NUMBER       0xFF534D42
#define ECRYPTFS_SUPER_MAGIC    0x0000F15F
#define F2FS_SUPER_MAGIC        0xF2F52010
#define NFS_SUPER_MAGIC         0x00006969
#define NTFS_SB_MAGIC           0x5346544E
#define OVERLAYFS_SUPER_MAGIC   0x794C7630

#define MKFSINFO(t_, n_, a_, i_) \
	{ .vfstype = (t_), .name = (n_), .allowed = (a_), .isfuse = (i_) }


static const struct silofs_fsinfo fsinfo_allowed[] = {
	MKFSINFO(FUSE_SUPER_MAGIC, "FUSE", 0, 1),
	MKFSINFO(TMPFS_MAGIC, "TMPFS", 0, 0),
	MKFSINFO(XFS_SB_MAGIC, "XFS", 1, 0),
	MKFSINFO(EXT234_SUPER_MAGIC, "EXT234", 1, 0),
	MKFSINFO(ZFS_SUPER_MAGIC, "ZFS", 1, 0),
	MKFSINFO(BTRFS_SUPER_MAGIC, "BTRFS", 1, 0),
	MKFSINFO(CEPH_SUPER_MAGIC, "CEPH", 1, 0),
	MKFSINFO(CIFS_MAGIC_NUMBER, "CIFS", 1, 0),
	MKFSINFO(ECRYPTFS_SUPER_MAGIC, "ECRYPTFS", 0, 0),
	MKFSINFO(F2FS_SUPER_MAGIC, "F2FS", 1, 0),
	MKFSINFO(NFS_SUPER_MAGIC, "NFS", 1, 0),
	MKFSINFO(NTFS_SB_MAGIC, "NTFS", 1, 0),
	MKFSINFO(OVERLAYFS_SUPER_MAGIC, "OVERLAYFS", 0, 0)
};

const struct silofs_fsinfo *silofs_fsinfo_by_vfstype(long vfstype)
{
	const struct silofs_fsinfo *fsinfo = NULL;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(fsinfo_allowed); ++i) {
		fsinfo = &fsinfo_allowed[i];
		if (fsinfo->vfstype == vfstype) {
			break;
		}
		fsinfo = NULL;
	}
	return fsinfo;
}

int silofs_check_mntdir_fstype(long vfstype)
{
	const struct silofs_fsinfo *fsinfo;

	fsinfo = silofs_fsinfo_by_vfstype(vfstype);
	if (fsinfo == NULL) {
		return -SILOFS_EINVAL;
	}
	if (fsinfo->isfuse || !fsinfo->allowed) {
		return -SILOFS_EMOUNT;
	}
	return 0;
}

static int silofs_check_mntpoint(const char *path,
                                 uid_t caller_uid, bool mounting)
{
	struct statfs stfs;
	struct stat st;
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
	if (mounting && (st.st_nlink > 2)) {
		return -SILOFS_ENOTEMPTY;
	}
	if (mounting && (st.st_ino == SILOFS_INO_ROOT)) {
		return -SILOFS_EBUSY;
	}
	if (!mounting && (st.st_ino != SILOFS_INO_ROOT)) {
		return -SILOFS_EINVAL;
	}
	if (!mounting) {
		return 0;
	}
	err = silofs_sys_statfs(path, &stfs);
	if (err) {
		return err;
	}
	if (caller_uid != st.st_uid) {
		return -SILOFS_EMOUNT;
	}
	err = silofs_check_mntdir_fstype(stfs.f_type);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void close_fd(int *pfd)
{
	int err;

	if ((pfd != NULL) && (*pfd > 0)) {
		err = silofs_sys_close(*pfd);
		if (err) {
			silofs_panic("close-error: fd=%d err=%d", *pfd, err);
		}
		*pfd = -1;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool equal_mntpath(const char *path1, const char *path2)
{
	struct silofs_substr sp1;
	struct silofs_substr sp2;

	silofs_substr_init(&sp1, path1);
	silofs_substr_trim_chr(&sp1, '/', &sp1);

	silofs_substr_init(&sp2, path2);
	silofs_substr_trim_chr(&sp2, '/', &sp2);

	return (sp1.len > 0) && (sp1.len == sp2.len) &&
	       silofs_substr_nisequal(&sp1, sp2.str, sp2.len);
}

static bool equal_path_by_stat(const char *path1, const struct stat *st2)
{
	struct stat st1;
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
	char *cpath = NULL;
	int err = 0;

	if (!path || !strlen(path)) {
		return -SILOFS_EINVAL;
	}
	cpath = canonicalize_file_name(path);
	if (cpath == NULL) {
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
	err = silofs_check_mntpoint(path, caller_uid, true);
	if (err) {
		log_info("illegal mount-point: %s %d", path, err);
	}
	return err;
}

static int check_umount_path(const char *path, uid_t caller_uid, bool force)
{
	int err;

	err = silofs_check_mntpoint(path, caller_uid, false);
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
	struct stat st;
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

static int format_mount_data(const struct silofs_mntparams *mntp,
                             int fd, char *dat, int dat_size)
{
	int ret;
	size_t len;

	ret = snprintf(dat, (size_t)dat_size,
	               "default_permissions,max_read=%d,fd=%d,"
	               "rootmode=0%o,user_id=%d,group_id=%d,%s",
	               (int)mntp->max_read, fd, mntp->root_mode,
	               mntp->user_id, mntp->group_id,
	               mntp->allowother ? "allow_other" : "");
	if ((ret <= 0) || (ret >= dat_size)) {
		return -SILOFS_EINVAL;
	}
	len = strlen(dat);
	if (dat[len - 1] == ',') {
		dat[len - 1] = '\0';
	}
	return 0;
}

static int do_fuse_mount(const struct silofs_mntparams *mntp, int *out_fd)
{
	int err;
	const char *dev = "/dev/fuse";
	const char *src = "silofs";
	const char *fst = "fuse.silofs";
	char data[256] = "";

	err = open_fuse_dev(dev, out_fd);
	if (err) {
		return err;
	}
	err = format_mount_data(mntp, *out_fd, data, (int)sizeof(data));
	if (err) {
		close_fd(out_fd);
		return err;
	}
	err = silofs_sys_mount(src, mntp->path, fst, mntp->flags, data);
	if (err) {
		close_fd(out_fd);
		return err;
	}
	return 0;
}

static int do_fuse_umount(const struct silofs_mntparams *mntp)
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
	mmsg->mn_magic = SILOFS_META_MAGIC;
	mmsg->mn_version_major = (uint16_t)silofs_version.major;
	mmsg->mn_version_minor = (uint16_t)silofs_version.minor;
	mmsg->mn_cmd = (uint32_t)cmd;
}

static void mntmsg_reset(struct silofs_mntmsg *mmsg)
{
	mntmsg_init(mmsg, SILOFS_MNTCMD_NONE);
}

static const char *mntmsg_path(const struct silofs_mntmsg *mmsg)
{
	const char *path = (const char *)(mmsg->mn_path);
	const size_t maxlen = sizeof(mmsg->mn_path);
	const size_t len = strnlen(path, maxlen);

	return (len && (len < maxlen)) ? path : NULL;
}

static int mntmsg_set_path(struct silofs_mntmsg *mmsg, const char *path)
{
	size_t len;

	if (path == NULL) {
		return -SILOFS_EINVAL;
	}
	len = strlen(path);
	if (len >= sizeof(mmsg->mn_path)) {
		return -SILOFS_EINVAL;
	}
	memcpy(mmsg->mn_path, path, len);
	return 0;
}

static void mntmsg_to_params(const struct silofs_mntmsg *mmsg,
                             struct silofs_mntparams *mntp)
{
	mntp->path = mntmsg_path(mmsg);
	mntp->flags = mmsg->mn_flags;
	mntp->user_id = mmsg->mn_user_id;
	mntp->group_id = mmsg->mn_group_id;
	mntp->root_mode = mmsg->mn_root_mode;
	mntp->max_read = mmsg->mn_max_read;
	mntp->allowother = (mmsg->mn_allowother > 0);
	mntp->checkonly = (mmsg->mn_checkonly > 0);
}

static int mntmsg_from_params(struct silofs_mntmsg *mmsg,
                              const struct silofs_mntparams *mntp)
{
	mmsg->mn_flags = mntp->flags;
	mmsg->mn_user_id = (uint32_t)mntp->user_id;
	mmsg->mn_group_id = (uint32_t)mntp->group_id;
	mmsg->mn_root_mode = (uint32_t)mntp->root_mode;
	mmsg->mn_max_read = (uint32_t)mntp->max_read;
	mmsg->mn_allowother = mntp->allowother ? 1 : 0;
	mmsg->mn_checkonly = mntp->checkonly ? 1 : 0;

	return mntp->path ? mntmsg_set_path(mmsg, mntp->path) : 0;
}

static int mntmsg_setup(struct silofs_mntmsg *mmsg, enum silofs_mntcmd cmd,
                        const struct silofs_mntparams *mntp)
{
	mntmsg_init(mmsg, cmd);
	return mntmsg_from_params(mmsg, mntp);
}

static int mntmsg_mount(struct silofs_mntmsg *mmsg,
                        const struct silofs_mntparams *mntp)
{
	return mntmsg_setup(mmsg, SILOFS_MNTCMD_MOUNT, mntp);
}

static int mntmsg_umount(struct silofs_mntmsg *mmsg,
                         const struct silofs_mntparams *mntp)
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

static int do_sendmsg(const struct silofs_socket *sock,
                      const struct msghdr *msg)
{
	size_t nbytes = 0;
	int retry = 8;
	int err;

	while (retry--) {
		err = silofs_socket_sendmsg(sock, msg, MSG_NOSIGNAL, &nbytes);
		if (err != -EINTR) {
			break;
		}
	}
	if (err) {
		return err;
	}
	if (nbytes < sizeof(*msg)) {
		return -SILOFS_ECOMM;
	}
	return 0;
}

/*
 * TODO-0033: Use pidfd_getfd(2) to transfer fuse fd
 *
 * Consider using Linux modern pidfd_open(2) + pidfd_getfd(2) to send FUSE fd
 * back to client process. See also: https://lwn.net/Articles/808997/
 */
static void do_pack_fd(struct msghdr *msg, int fd)
{
	struct cmsghdr *cmsg = NULL;

	if (fd > 0) {
		cmsg = silofs_cmsg_firsthdr(msg);
		silofs_cmsg_pack_fd(cmsg, fd);
	}
}

static int mntmsg_send(const struct silofs_mntmsg *mmsg,
                       const struct silofs_socket *sock, int fd)
{
	struct silofs_cmsg_buf cb = {
		.pad = 0
	};
	struct iovec iov = {
		.iov_base = unconst(mmsg),
		.iov_len  = sizeof(*mmsg)
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cb.cms,
		.msg_controllen = (fd > 0) ? sizeof(cb.cms) : 0,
		.msg_flags = 0
	};

	do_pack_fd(&msg, fd);
	return do_sendmsg(sock, &msg);
}

static int do_recvmsg(const struct silofs_socket *sock, struct msghdr *msg)
{
	size_t nbytes = 0;
	int retry = 8;
	int err;

	while (retry--) {
		err = silofs_socket_recvmsg(sock, msg, MSG_WAITALL, &nbytes);
		if (err != -EINTR) {
			break;
		}
	}
	if (err) {
		return err;
	}
	if (nbytes < sizeof(*msg)) {
		return -SILOFS_ECOMM;
	}
	return 0;
}

static int do_unpack_fd(struct msghdr *msg, int *out_fd)
{
	int err;
	struct cmsghdr *cmsg;

	cmsg = silofs_cmsg_firsthdr(msg);
	if (cmsg != NULL) {
		err = silofs_cmsg_unpack_fd(cmsg, out_fd);
	} else {
		*out_fd = -1;
		err = 0;
	}
	return err;
}

static int mntmsg_recv(const struct silofs_mntmsg *mmsg,
                       const struct silofs_socket *sock, int *out_fd)
{
	struct silofs_cmsg_buf cb = {
		.pad = 0
	};
	struct iovec iov = {
		.iov_base = unconst(mmsg),
		.iov_len  = sizeof(*mmsg)
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cb.cms,
		.msg_controllen = sizeof(cb.cms),
		.msg_flags = 0
	};
	int err;

	*out_fd = -1;
	err = do_recvmsg(sock, &msg);
	if (err) {
		return err;
	}
	err = do_unpack_fd(&msg, out_fd);
	if (err) {
		return err;
	}
	return 0;
}

static int mntmsg_recv2(const struct silofs_mntmsg *mmsg,
                        const struct silofs_socket *sock)
{
	int err;
	int dummy_fd = -1;

	err = mntmsg_recv(mmsg, sock, &dummy_fd);
	close_fd(&dummy_fd);
	return err;
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
	silofs_streamsock_initu(&msvc->ms_asock);
	silofs_sockaddr_none(&msvc->ms_peer);
	mntsvc_reset_peer_ucred(msvc);
	msvc->ms_fuse_fd = -1;
	msvc->ms_srv = NULL;
}

static void mntsvc_close_fuse_fd(struct silofs_mntsvc *msvc)
{
	close_fd(&msvc->ms_fuse_fd);
}

static void mntsvc_close_sock(struct silofs_mntsvc *msvc)
{
	silofs_socket_fini(&msvc->ms_asock);
	silofs_sockaddr_none(&msvc->ms_peer);
}

static void mntsvc_fini(struct silofs_mntsvc *msvc)
{
	mntsvc_close_sock(msvc);
	mntsvc_close_fuse_fd(msvc);
	mntsvc_reset_peer_ucred(msvc);
	msvc->ms_srv = NULL;
}

static void mntsvc_format_peer_ids(struct silofs_mntsvc *msvc)
{
	const struct ucred *cred = &msvc->ms_peer_ucred;
	const size_t bsz = sizeof(msvc->ms_peer_ids);
	char *buf = msvc->ms_peer_ids;

	snprintf(buf, bsz - 1, "[pid=%d,uid=%d,gid=%d]",
	         cred->pid, cred->uid, cred->gid);
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
	silofs_streamsock_initu(&msvc->ms_asock);
	mntsvc_reset_peer_ucred(msvc);
}

static int mntsvc_recv_request(struct silofs_mntsvc *msvc,
                               struct silofs_mntmsg *mmsg)
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

static int
mntsvc_check_mount_mntrule(const struct silofs_mntsvc *msvc,
                           const struct silofs_mntparams *mntp)
{
	struct stat st;
	const struct silofs_mntrule *mrule = NULL;
	const struct silofs_mntrules *mrules = NULL;
	const uid_t uid_none = (uid_t)(-1);
	const uid_t uid_peer = msvc->ms_peer_ucred.uid;
	int err;

	mrules = msvc->ms_srv->ms_rules;
	if (mrules == NULL) {
		log_info("no rules for: '%s' peer=%s",
		         mntp->path, msvc->ms_peer_ids);
		return -SILOFS_EMOUNT;
	}
	err = silofs_sys_stat(mntp->path, &st);
	if (err) {
		log_info("no stat for: '%s' peer=%s",
		         mntp->path, msvc->ms_peer_ids);
		return err;
	}
	for (size_t i = 0; i < mrules->nrules; ++i) {
		mrule = &mrules->rules[i];
		if (equal_path_by_stat(mrule->path, &st)) {
			break;
		}
		mrule = NULL;
	}
	if (mrule == NULL) {
		log_info("no valid mount-rule for: '%s' peer=%s",
		         mntp->path, msvc->ms_peer_ids);
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

static int
mntsvc_check_umount_mntrule(const struct silofs_mntsvc *msvc,
                            const struct silofs_mntparams *mntp)
{
	const struct silofs_mntrule *mrule = NULL;
	const struct silofs_mntrules *mrules = NULL;
	const uid_t uid_none = (uid_t)(-1);
	const uid_t uid_peer = msvc->ms_peer_ucred.uid;

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
		mrule = NULL;
	}
	if (mrule == NULL) {
		log_info("no rule with: '%s'", mntp->path);
		return -SILOFS_EUMOUNT;
	}
	if ((mrule->uid != uid_none) && (mrule->uid != uid_peer)) {
		log_info("not allowed to umount: uid=%ld '%s'",
		         (long)uid_peer, mntp->path);
		return -SILOFS_EUMOUNT;
	}
	return 0;
}

static int mntsvc_check_mount(const struct silofs_mntsvc *msvc,
                              const struct silofs_mntparams *mntp)
{
	int err;
	size_t page_size;
	const struct ucred *peer_cred = &msvc->ms_peer_ucred;
	const unsigned long sup_mnt_mask =
	        (MS_LAZYTIME | MS_NOEXEC | MS_NOSUID | MS_NODEV | MS_RDONLY);

	if (mntp->flags & ~sup_mnt_mask) {
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
	page_size = (size_t)silofs_sc_page_size();
	if (mntp->max_read < (2 * page_size)) {
		return -SILOFS_EINVAL;
	}
	if (mntp->max_read > (512 * page_size)) {
		return -SILOFS_EINVAL;
	}
	if (mntp->path == NULL) {
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

static int mntsvc_do_mount(struct silofs_mntsvc *msvc,
                           const struct silofs_mntparams *mntp)
{
	int err;

	err = do_fuse_mount(mntp, &msvc->ms_fuse_fd);
	log_info("mount: '%s' flags=0x%lx uid=%d gid=%d rootmode=0%o "
	         "max_read=%u fuse_fd=%d peer=%s err=%d",
	         mntp->path, mntp->flags, mntp->user_id, mntp->group_id,
	         mntp->root_mode, mntp->max_read, msvc->ms_fuse_fd,
	         msvc->ms_peer_ids, err);

	return err;
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
	const uint64_t mnt_allow = MNT_DETACH | MNT_FORCE;
	const struct ucred *peer_cred = &msvc->ms_peer_ucred;
	const char *path = mntp->path;
	int err;
	bool force;

	if (!strlen(path)) {
		return -SILOFS_EPERM;
	}
	if (mntp->flags & ~mnt_allow) {
		return -SILOFS_EINVAL;
	}
	if ((mntp->flags | mnt_allow) != mnt_allow) {
		return -SILOFS_EINVAL;
	}
	force = (mntp->flags & MNT_FORCE) > 0;
	err = check_umount_path(path, peer_cred->uid, force);
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

	err = do_fuse_umount(mntp);
	log_info("umount: '%s' flags=0x%lx peer=%s err=%d",
	         mntp->path, mntp->flags, msvc->ms_peer_ids, err);

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

static void mntsvc_exec_request(struct silofs_mntsvc *msvc,
                                struct silofs_mntmsg *mmsg)
{
	struct silofs_mntparams mntp;
	const enum silofs_mntcmd cmd = mntmsg_cmd(mmsg);
	int err = 0;

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
	const int status = mntmsg_status(mmsg);
	const enum silofs_mntcmd cmd = mntmsg_cmd(mmsg);

	mntmsg_init(mmsg, cmd);
	mntmsg_set_status(mmsg, status);
	unused(msvc);
}

static void mntsvc_send_response(struct silofs_mntsvc *msvc,
                                 const struct silofs_mntmsg *mmsg)
{
	const int cmd = (int)mmsg->mn_cmd;
	const int status = (int)mmsg->mn_status;
	int err;

	log_info("send response: cmd=%d status=%d peer=%s",
	         cmd, status, msvc->ms_peer_ids);
	err = mntmsg_send(mmsg, &msvc->ms_asock, msvc->ms_fuse_fd);
	if (err) {
		log_err("failed to send response: " \
		        "cmd=%d status=%d peer=%s err=%d",
		        cmd, status, msvc->ms_peer_ids, err);
	}
}

static void mntsvc_serve_request(struct silofs_mntsvc *msvc)
{
	struct silofs_mntmsg mmsg;
	int err;

	mntmsg_reset(&mmsg);
	err = mntsvc_recv_request(msvc, &mmsg);
	if (!err) {
		mntsvc_exec_request(msvc, &mmsg);
		mntsvc_fill_response(msvc, &mmsg);
		mntsvc_send_response(msvc, &mmsg);
		mntsvc_term_peer(msvc);
		mntsvc_close_fuse_fd(msvc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mntsrv_init(struct silofs_mntsrv *msrv,
                        const struct silofs_ms_args *ms_args)
{
	memcpy(&msrv->ms_args, ms_args, sizeof(msrv->ms_args));
	silofs_streamsock_initu(&msrv->ms_lsock);
	mntsvc_init(&msrv->ms_svc);
	msrv->ms_rules = NULL;
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
	msrv->ms_rules = NULL;
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
	int err;
	struct silofs_socket *sock = &msrv->ms_lsock;

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
	const char *sock_name = SILOFS_MNTSOCK_NAME;
	int err;

	silofs_sockaddr_abstract(&saddr, sock_name);
	err = silofs_socket_bind(sock, &saddr);
	if (err) {
		return err;
	}
	log_info("bind-socket: @%s", sock_name);
	return 0;
}

static int mntsrv_make_unixaddr(const struct silofs_mntsrv *msrv,
                                char *buf, size_t bsz)
{
	const char *base_path = msrv->ms_args.runstatedir;
	const char *sock_name = SILOFS_MNTSOCK_NAME;
	ssize_t len;

	len = snprintf(buf, bsz, "%s/%s", base_path, sock_name);
	if ((size_t)len >= bsz) {
		log_err("invalid unix sock: %s/%s", base_path, sock_name);
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int mntsrv_bind_unix(struct silofs_mntsrv *msrv)
{
	char un_addr[104] = "";
	struct silofs_sockaddr saddr;
	struct silofs_socket *sock = &msrv->ms_lsock;
	int err;

	err = mntsrv_make_unixaddr(msrv, un_addr, sizeof(un_addr));
	if (err) {
		return err;
	}
	err = silofs_sockaddr_unix(&saddr, un_addr);
	if (err) {
		return err;
	}
	err = silofs_socket_bind(sock, &saddr);
	if (err) {
		return err;
	}
	log_info("bind-socket: %s", un_addr);
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
	const struct timespec ts = {
		.tv_sec = sec_wait,
		.tv_nsec = 0
	};
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
	if (!err) {
		mntsvc_serve_request(&msrv->ms_svc);
	}
	mntsrv_fini_conn(msrv);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mse_init(struct silofs_ms_env *mse,
                    const struct silofs_ms_args *ms_args)
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
	void *mem = NULL;
	struct silofs_ms_env *mse = NULL;
	struct silofs_ms_env_obj *mse_obj = NULL;
	int err;

	err = silofs_zmalloc(sizeof(*mse_obj), &mem);
	if (err) {
		return err;
	}
	mse_obj = mem;
	mse = &mse_obj->ms_env;
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
	return container_of(mse, struct silofs_ms_env_obj, ms_env);
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

static int silofs_mse_exec_one(struct silofs_ms_env *mse)
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

static int silofs_mse_exec(struct silofs_ms_env *mse)
{
	const char *sock = SILOFS_MNTSOCK_NAME;
	int err;

	log_info("start serve: sock=@%s", sock);
	mse->ms_active = 1;
	while (mse->ms_active) {
		sleep(1);
		err = silofs_mse_exec_one(mse);
		silofs_burnstack();

		/* TODO: handle non-valid terminating errors */
		if (err && (err != -ETIMEDOUT)) {
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
		err = silofs_mse_exec(mse);
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
	silofs_streamsock_initu(&mclnt->mc_sock);
	silofs_sockaddr_abstract(&mclnt->mc_srvaddr, SILOFS_MNTSOCK_NAME);
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

static int mntclnt_handshake(const struct silofs_mntclnt *mclnt,
                             const struct silofs_mntparams *mntp,
                             int *out_status)
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
                         const struct silofs_mntparams *mntp,
                         int *out_status, int *out_fd)
{
	struct silofs_mntmsg mmsg;
	const struct silofs_socket *sock = &mclnt->mc_sock;
	int err;

	*out_status = -SILOFS_ECOMM;
	*out_fd = -1;
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
	err = mntmsg_umount(&mmsg, mntp);
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
		.path = mountpoint,
		.flags = ms_flags,
		.root_mode = S_IFDIR | S_IRWXU,
		.user_id = uid,
		.group_id = gid,
		.max_read = max_read,
		.allowother = allow_other,
		.checkonly = check_only,
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

int silofs_mntrpc_umount(const char *mountpoint,
                         uid_t uid, gid_t gid, unsigned int mnt_flags)
{
	struct silofs_mntclnt mclnt;
	struct silofs_mntparams mntp = {
		.path = mountpoint,
		.flags = mnt_flags,
		.user_id = uid,
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
		.user_id = uid,
		.group_id = gid,
	};
	int err;

	mntclnt_init(&mclnt);
	err = do_rpc_handshake(&mclnt, &mntp);
	mntclnt_fini(&mclnt);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_is_fuse_fstype(long fstype)
{
	return (fstype == FUSE_SUPER_MAGIC);
}

