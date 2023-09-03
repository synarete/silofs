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
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>


bool silofs_user_cap_fowner(const struct silofs_cred *cred)
{
	/* TODO: CAP_FOWNER */
	return uid_isroot(cred->uid);
}

bool silofs_user_cap_sys_admin(const struct silofs_cred *cred)
{
	/* TODO: CAP_SYS_ADMIN */
	return uid_isroot(cred->uid);
}

static bool silofs_user_cap_fsetid(const struct silofs_cred *cred)
{
	/* TODO: CAP_SYS_ADMIN */
	return uid_isroot(cred->uid);
}

static bool silofs_user_cap_chown(const struct silofs_cred *cred)
{
	/* TODO: CAP_CHOWN */
	return uid_isroot(cred->uid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0001: Support setxflags/getxflags ioctls
 *
 * Have support for xflags attributes per inode. Follow XFS' extended flags
 * per inode. At minimum, have support for S_IMMUTABLE of inode. That is, an
 * inode which can not be modified or removed.
 *
 * See kernel's 'xfs_ioc_getxflags/xfs_ioc_setxflags'
 */

/*
 * TODO-0002: Track meta-blocks per inode
 *
 * For each inode (+ entire file-system) track number on meta-blocks.
 * Especially important for deep/sparse dir/file inodes.
 */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ts_to_cpu(const struct silofs_timespec *vts, struct timespec *ts)
{
	if (ts != NULL) {
		ts->tv_sec = (time_t)silofs_le64_to_cpu(vts->t_sec);
		ts->tv_nsec = (long)silofs_le64_to_cpu(vts->t_nsec);
	}
}

static void cpu_to_ts(const struct timespec *ts, struct silofs_timespec *vts)
{
	if (ts != NULL) {
		vts->t_sec = silofs_cpu_to_le64((uint64_t)ts->tv_sec);
		vts->t_nsec = silofs_cpu_to_le64((uint64_t)ts->tv_nsec);
	}
}

static void assign_ts(struct timespec *ts, const struct timespec *other)
{
	ts->tv_sec = other->tv_sec;
	ts->tv_nsec = other->tv_nsec;
}

static void assign_xts(struct statx_timestamp *xts, const struct timespec *ts)
{
	xts->tv_sec = ts->tv_sec;
	xts->tv_nsec = (uint32_t)(ts->tv_nsec);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t inode_ino(const struct silofs_inode *inode)
{
	return silofs_cpu_to_ino(inode->i_ino);
}

static void inode_set_ino(struct silofs_inode *inode, ino_t ino)
{
	inode->i_ino = silofs_ino_to_cpu(ino);
}

static ino_t inode_parent(const struct silofs_inode *inode)
{
	return silofs_cpu_to_ino(inode->i_parent);
}

static void inode_set_parent(struct silofs_inode *inode, ino_t ino)
{
	inode->i_parent = silofs_cpu_to_ino(ino);
}

static uid_t inode_uid(const struct silofs_inode *inode)
{
	return silofs_le32_to_cpu(inode->i_uid);
}

static void inode_set_uid(struct silofs_inode *inode, uid_t uid)
{
	inode->i_uid = silofs_cpu_to_le32(uid);
}

static gid_t inode_gid(const struct silofs_inode *inode)
{
	return silofs_le32_to_cpu(inode->i_gid);
}

static void inode_set_gid(struct silofs_inode *inode, uid_t gid)
{
	inode->i_gid = silofs_cpu_to_le32(gid);
}

static mode_t inode_mode(const struct silofs_inode *inode)
{
	return silofs_le32_to_cpu(inode->i_mode);
}

static void inode_set_mode(struct silofs_inode *inode, mode_t mode)
{
	inode->i_mode = silofs_cpu_to_le32(mode);
}

static loff_t inode_size(const struct silofs_inode *inode)
{
	return silofs_off_to_cpu(inode->i_size);
}

static void inode_set_size(struct silofs_inode *inode, loff_t off)
{
	inode->i_size = silofs_cpu_to_off(off);
}

static loff_t inode_span(const struct silofs_inode *inode)
{
	return silofs_off_to_cpu(inode->i_span);
}

static void inode_set_span(struct silofs_inode *inode, loff_t off)
{
	inode->i_span = silofs_cpu_to_off(off);
}

static blkcnt_t inode_blocks(const struct silofs_inode *inode)
{
	return (blkcnt_t)silofs_le64_to_cpu(inode->i_blocks);
}

static void inode_set_blocks(struct silofs_inode *inode, blkcnt_t blocks)
{
	inode->i_blocks = silofs_cpu_to_le64((uint64_t)blocks);
}

static nlink_t inode_nlink(const struct silofs_inode *inode)
{
	return (nlink_t)silofs_le64_to_cpu(inode->i_nlink);
}

static void inode_set_nlink(struct silofs_inode *inode, nlink_t nlink)
{
	inode->i_nlink = silofs_cpu_to_le64((uint64_t)nlink);
}

static long inode_revision(const struct silofs_inode *inode)
{
	return (long)silofs_le64_to_cpu(inode->i_revision);
}

static void inode_set_revision(struct silofs_inode *inode, long r)
{
	inode->i_revision = silofs_cpu_to_le64((uint64_t)r);
}

static uint64_t inode_generation(const struct silofs_inode *inode)
{
	return silofs_le64_to_cpu(inode->i_generation);
}

static void inode_set_generation(struct silofs_inode *inode, uint64_t gen)
{
	inode->i_generation = silofs_cpu_to_le64(gen);
}

static void inode_inc_revision(struct silofs_inode *inode)
{
	inode_set_revision(inode, inode_revision(inode) + 1);
}

static enum silofs_inodef inode_flags(const struct silofs_inode *inode)
{
	return silofs_le32_to_cpu(inode->i_flags);
}

static void inode_set_flags(struct silofs_inode *inode,
                            enum silofs_inodef flags)
{
	inode->i_flags = silofs_cpu_to_le32(flags);
}

static bool inode_has_flags(struct silofs_inode *inode,
                            enum silofs_inodef mask)
{
	return (inode_flags(inode) & mask) == mask;
}

static unsigned int inode_rdev_major(const struct silofs_inode *inode)
{
	return silofs_le32_to_cpu(inode->i_rdev_major);
}

static unsigned int inode_rdev_minor(const struct silofs_inode *inode)
{
	return silofs_le32_to_cpu(inode->i_rdev_minor);
}

static void inode_set_rdev(struct silofs_inode *inode,
                           unsigned int maj, unsigned int min)
{
	inode->i_rdev_major = silofs_cpu_to_le32(maj);
	inode->i_rdev_minor = silofs_cpu_to_le32(min);
}

static void inode_btime(const struct silofs_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_tm.btime, ts);
}

static void inode_set_btime(struct silofs_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_tm.btime);
}

static void inode_atime(const struct silofs_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_tm.atime, ts);
}

static void inode_set_atime(struct silofs_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_tm.atime);
}

static void inode_mtime(const struct silofs_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_tm.mtime, ts);
}

static void inode_set_mtime(struct silofs_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_tm.mtime);
}

static void inode_ctime(const struct silofs_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_tm.ctime, ts);
}

static void inode_set_ctime(struct silofs_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_tm.ctime);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ino_t silofs_ii_xino_of(const struct silofs_inode_info *ii)
{
	return ii_isrootd(ii) ? SILOFS_INO_ROOT : ii_ino(ii);
}

ino_t silofs_ii_ino_of(const struct silofs_inode_info *ii)
{
	return inode_ino(ii->inode);
}

ino_t silofs_ii_parent(const struct silofs_inode_info *ii)
{
	return inode_parent(ii->inode);
}

uid_t silofs_ii_uid(const struct silofs_inode_info *ii)
{
	return inode_uid(ii->inode);
}

gid_t silofs_ii_gid(const struct silofs_inode_info *ii)
{
	return inode_gid(ii->inode);
}

mode_t silofs_ii_mode(const struct silofs_inode_info *ii)
{
	return inode_mode(ii->inode);
}

nlink_t silofs_ii_nlink(const struct silofs_inode_info *ii)
{
	return inode_nlink(ii->inode);
}

loff_t silofs_ii_size(const struct silofs_inode_info *ii)
{
	return inode_size(ii->inode);
}

loff_t silofs_ii_span(const struct silofs_inode_info *ii)
{
	return inode_span(ii->inode);
}

blkcnt_t silofs_ii_blocks(const struct silofs_inode_info *ii)
{
	return inode_blocks(ii->inode);
}

uint64_t silofs_ii_generation(const struct silofs_inode_info *ii)
{
	return inode_generation(ii->inode);
}

static dev_t ii_rdev(const struct silofs_inode_info *ii)
{
	const struct silofs_inode *inode = ii->inode;

	return makedev(inode_rdev_major(inode), inode_rdev_minor(inode));
}

static unsigned int i_rdev_major_of(const struct silofs_inode_info *ii)
{
	return inode_rdev_major(ii->inode);
}

static unsigned int i_rdev_minor_of(const struct silofs_inode_info *ii)
{
	return inode_rdev_minor(ii->inode);
}

bool silofs_ii_isdir(const struct silofs_inode_info *ii)
{
	return S_ISDIR(ii_mode(ii));
}

bool silofs_ii_isreg(const struct silofs_inode_info *ii)
{
	return S_ISREG(ii_mode(ii));
}

bool silofs_ii_islnk(const struct silofs_inode_info *ii)
{
	return S_ISLNK(ii_mode(ii));
}

bool silofs_ii_isfifo(const struct silofs_inode_info *ii)
{
	return S_ISFIFO(ii_mode(ii));
}

bool silofs_ii_issock(const struct silofs_inode_info *ii)
{
	return S_ISSOCK(ii_mode(ii));
}

bool silofs_ii_isrootd(const struct silofs_inode_info *ii)
{
	return ii_isdir(ii) && (ii_ino(ii) == SILOFS_INO_ROOT);
}

void silofs_ii_fixup_as_rootdir(struct silofs_inode_info *ii)
{
	struct silofs_inode *inode = ii->inode;

	inode_set_parent(inode, ii_ino(ii));
	inode_set_nlink(inode, 2);
	inode_set_flags(inode, SILOFS_INODEF_ROOTD);
	ii_dirtify(ii);
}

bool silofs_is_rootdir(const struct silofs_inode_info *ii)
{
	return ii_isdir(ii) && inode_has_flags(ii->inode, SILOFS_INODEF_ROOTD);
}

enum silofs_inodef silofs_ii_flags(const struct silofs_inode_info *ii)
{
	return inode_flags(ii->inode);
}

static void silofs_ii_times(const struct silofs_inode_info *ii,
                            struct silofs_itimes *tms)
{
	const struct silofs_inode *inode = ii->inode;

	inode_btime(inode, &tms->btime);
	inode_atime(inode, &tms->atime);
	inode_mtime(inode, &tms->mtime);
	inode_ctime(inode, &tms->ctime);
}

bool silofs_ii_isevictable(const struct silofs_inode_info *ii)
{
	bool ret = false;

	if (!ii->i_dq_vis.dq.sz && !ii->i_nopen) {
		ret = silofs_lni_isevictable(&ii->i_vi.v);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void silofs_setup_ispecial(struct silofs_inode_info *ii, dev_t rdev)
{
	const unsigned int rdev_major = major(rdev);
	const unsigned int rdev_minor = minor(rdev);

	inode_set_rdev(ii->inode, rdev_major, rdev_minor);
	ii_dirtify(ii);
}

/*
 * TODO-0008: Per-inode extra accounting
 *
 * Track number of meta-data bytes allocated per inode.
 *
 *
 * TODO-0010: Store timezone in inode
 */
static void inode_setup_common(struct silofs_inode *inode, ino_t ino,
                               const struct silofs_inew_params *inp)
{
	inode_set_ino(inode, ino);
	inode_set_parent(inode, inp->parent_ino);
	inode_set_uid(inode, inp->creds.fs_cred.uid);
	inode_set_gid(inode, inp->creds.fs_cred.gid);
	inode_set_mode(inode, inp->mode & ~inp->creds.fs_cred.umask);
	inode_set_flags(inode, 0);
	inode_set_size(inode, 0);
	inode_set_span(inode, 0);
	inode_set_blocks(inode, 0);
	inode_set_nlink(inode, 0);
	inode_set_revision(inode, 0);
	inode_set_generation(inode, 0);
}

static void ii_setup_inode(struct silofs_inode_info *ii,
                           const struct silofs_inew_params *inp)
{
	struct silofs_inode *inode = ii->inode;
	const ino_t ino = ii_ino(ii);

	inode_setup_common(inode, ino, inp);
	silofs_ii_setup_xattr(ii);
	if (ii_isdir(ii)) {
		silofs_setup_dir(ii, inp->parent_mode, 1);
	} else if (ii_isreg(ii)) {
		silofs_setup_reg(ii);
	} else if (ii_islnk(ii)) {
		silofs_setup_symlnk(ii);
	} else {
		silofs_setup_ispecial(ii, inp->rdev);
	}
}

void silofs_ii_set_generation(struct silofs_inode_info *ii, uint64_t gen)
{
	inode_set_generation(ii->inode, gen);
	ii_dirtify(ii);
}

void silofs_ii_stamp_mark_visible(struct silofs_inode_info *ii)
{
	silofs_stamp_meta_of(ii_to_vi(ii));
	ii_dirtify(ii);
}

void silofs_ii_setup_by(struct silofs_inode_info *ii,
                        const struct silofs_inew_params *inp)
{
	ii_setup_inode(ii, inp);
	ii_update_itimes(ii, &inp->creds, SILOFS_IATTR_TIMES);
	ii_dirtify(ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ts_setup_now(struct timespec *ts)
{
	ts->tv_sec = 0;
	ts->tv_nsec = UTIME_NOW;
}

static void itimes_setup_now(struct silofs_itimes *itimes)
{
	ts_setup_now(&itimes->atime);
	ts_setup_now(&itimes->ctime);
	ts_setup_now(&itimes->mtime);
	ts_setup_now(&itimes->btime);
}

static void itimes_copy(struct silofs_itimes *itimes,
                        const struct silofs_itimes *other)
{
	silofs_ts_copy(&itimes->atime, &other->atime);
	silofs_ts_copy(&itimes->ctime, &other->ctime);
	silofs_ts_copy(&itimes->mtime, &other->mtime);
	silofs_ts_copy(&itimes->btime, &other->btime);
}

static void iattr_set_times(struct silofs_iattr *iattr,
                            const struct silofs_itimes *itimes)
{
	itimes_copy(&iattr->ia_t, itimes);
}

static void iattr_init(struct silofs_iattr *iattr, ino_t ino)
{
	silofs_memzero(iattr, sizeof(*iattr));
	iattr->ia_ino = ino;
}

static void iattr_setup_with(struct silofs_iattr *iattr, ino_t ino,
                             const struct silofs_itimes *itimes)
{
	iattr_init(iattr, ino);
	iattr_set_times(iattr, itimes);
}

void silofs_setup_iattr_of(struct silofs_iattr *iattr, ino_t ino)
{
	iattr_init(iattr, ino);
	itimes_setup_now(&iattr->ia_t);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static mode_t itype_of(mode_t mode)
{
	return S_IFMT & mode;
}

static bool uid_isnull(uid_t uid)
{
	const uid_t uid_none = (uid_t)(-1);

	return uid_eq(uid, uid_none);
}

static bool gid_isnull(gid_t gid)
{
	const gid_t gid_none = (gid_t)(-1);

	return gid_eq(gid, gid_none);
}

static bool user_isowner(const struct silofs_cred *cred,
                         const struct silofs_inode_info *ii)
{
	return uid_eq(cred->uid, ii_uid(ii));
}

static bool has_itype(const struct silofs_inode_info *ii, mode_t mode)
{
	const mode_t imode = ii_mode(ii);

	return (itype_of(imode) == itype_of(mode));
}

static int check_waccess(const struct silofs_task *task,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, W_OK);
}

static int check_xaccess_parent(struct silofs_task *task,
                                const struct silofs_inode_info *ii)
{
	struct silofs_inode_info *parent_ii = NULL;
	ino_t parent;
	int err;

	if (!ii_isdir(ii) || ii_isrootd(ii)) {
		return 0;
	}
	parent = ii_parent(ii);
	err = silofs_stage_inode(task, parent, SILOFS_STG_CUR, &parent_ii);
	if (err) {
		return err;
	}
	if (!ii_isdir(parent_ii)) {
		return -SILOFS_EFSCORRUPTED; /* XXX */
	}
	err = silofs_do_access(task, parent_ii, X_OK);
	if (err) {
		return err;
	}
	return 0;
}

static void kill_suid_sgid(struct silofs_inode_info *ii, long flags)
{
	mode_t mask = 0;
	const mode_t mode = ii_mode(ii);

	if ((flags & SILOFS_IATTR_KILL_SUID) && (mode & S_ISUID)) {
		mask |= S_ISUID;
	}
	if ((flags & SILOFS_IATTR_KILL_SGID) &&
	    ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))) {
		mask |= S_ISGID;
	}
	if (mask) {
		inode_set_mode(ii->inode, mode & ~mask);
		ii_dirtify(ii);
	}
}

static mode_t new_mode_of(const struct silofs_inode_info *ii, mode_t mask)
{
	const mode_t fmt_mask = S_IFMT;

	return (ii_mode(ii) & fmt_mask) | (mask & ~fmt_mask);
}

static int check_chmod(const struct silofs_task *task,
                       struct silofs_inode_info *ii, mode_t mode)
{
	const struct silofs_creds *creds = task_creds(task);
	int ret = -SILOFS_EPERM;

	if (!itype_of(mode) || has_itype(ii, mode)) {
		if (user_isowner(&creds->fs_cred, ii)) {
			ret =  0;
		} else if (silofs_user_cap_fowner(&creds->host_cred)) {
			ret = 0;
		}
	}
	return ret;
}

static void update_times_attr(const struct silofs_task *task,
                              struct silofs_inode_info *ii,
                              enum silofs_iattr_flags attr_flags,
                              const struct silofs_itimes *itimes)
{
	struct silofs_iattr iattr;

	silofs_setup_iattr_of(&iattr, ii_ino(ii));
	memcpy(&iattr.ia_t, itimes, sizeof(iattr.ia_t));
	iattr.ia_flags = attr_flags;
	ii_update_iattrs(ii, &task->t_oper.op_creds, &iattr);
}

/*
 * TODO-0013: Allow file-sealing
 *
 * Support special mode for file as read-only permanently (immutable).
 */

static void update_post_chmod(const struct silofs_task *task,
                              struct silofs_inode_info *ii,
                              struct silofs_iattr *iattr)
{
	const gid_t gid = ii_gid(ii);
	const struct silofs_creds *creds = &task->t_oper.op_creds;
	const struct silofs_cred *cred = &creds->fs_cred;

	iattr->ia_flags |= SILOFS_IATTR_MODE | SILOFS_IATTR_CTIME;
	if (!gid_eq(gid, cred->gid) && !silofs_user_cap_fsetid(cred)) {
		iattr->ia_flags |= SILOFS_IATTR_KILL_SGID;
	}
	ii_update_iattrs(ii, creds, iattr);
}

static int do_chmod(struct silofs_task *task,
                    struct silofs_inode_info *ii, mode_t mode,
                    const struct silofs_itimes *itimes)
{
	int err;
	struct silofs_iattr iattr = { .ia_flags = 0 };

	err = check_chmod(task, ii, mode);
	if (err) {
		return err;
	}
	err = check_xaccess_parent(task, ii);
	if (err) {
		return err;
	}

	iattr_setup_with(&iattr, ii_ino(ii), itimes);
	iattr.ia_mode = new_mode_of(ii, mode);
	update_post_chmod(task, ii, &iattr);
	return 0;
}

int silofs_do_chmod(struct silofs_task *task,
                    struct silofs_inode_info *ii, mode_t mode,
                    const struct silofs_itimes *itimes)
{
	int err;

	ii_incref(ii);
	err = do_chmod(task, ii, mode, itimes);
	ii_decref(ii);
	return err;
}

static int check_cap_chown(const struct silofs_task *task)
{
	const struct silofs_creds *creds = task_creds(task);

	return silofs_user_cap_chown(&creds->host_cred) ? 0 : -SILOFS_EPERM;
}

static int check_chown_uid(const struct silofs_task *task,
                           const struct silofs_inode_info *ii, uid_t uid)
{
	if (uid_eq(uid, ii_uid(ii))) {
		return 0;
	}
	return check_cap_chown(task);
}

static int check_chown_gid(const struct silofs_task *task,
                           const struct silofs_inode_info *ii, gid_t gid)
{
	const struct silofs_creds *creds = task_creds(task);

	if (gid_eq(gid, ii_gid(ii))) {
		return 0;
	}
	if (user_isowner(&creds->fs_cred, ii)) {
		return 0;
	}
	return check_cap_chown(task);
}

static int check_chown(const struct silofs_task *task,
                       const struct silofs_inode_info *ii,
                       uid_t uid, gid_t gid)
{
	int err = 0;

	if (!uid_isnull(uid)) {
		err = check_chown_uid(task, ii, uid);
	}
	if (!gid_isnull(gid) && !err) {
		err = check_chown_gid(task, ii, gid);
	}
	return err;
}

static void update_post_chown(const struct silofs_task *task,
                              struct silofs_inode_info *ii,
                              struct silofs_iattr *iattr)
{
	const mode_t mode = ii_mode(ii);
	const mode_t mask = S_IXUSR | S_IXGRP | S_IXOTH;

	iattr->ia_flags |= SILOFS_IATTR_CTIME;
	if (mode & mask) {
		iattr->ia_flags |= SILOFS_IATTR_KILL_SUID;
		iattr->ia_flags |= SILOFS_IATTR_KILL_SGID;
	}
	ii_update_iattrs(ii, &task->t_oper.op_creds, iattr);
}

static int do_chown(const struct silofs_task *task,
                    struct silofs_inode_info *ii, uid_t uid, gid_t gid,
                    const struct silofs_itimes *itimes)
{
	int err;
	bool chown_uid = !uid_isnull(uid);
	bool chown_gid = !gid_isnull(gid);
	struct silofs_iattr iattr = { .ia_flags = 0 };

	if (!chown_uid && !chown_gid) {
		return 0; /* no-op */
	}
	err = check_chown(task, ii, uid, gid);
	if (err) {
		return err;
	}
	iattr_setup_with(&iattr, ii_ino(ii), itimes);
	if (chown_uid) {
		iattr.ia_uid = uid;
		iattr.ia_flags |= SILOFS_IATTR_UID;
	}
	if (chown_gid) {
		iattr.ia_gid = gid;
		iattr.ia_flags |= SILOFS_IATTR_GID;
	}
	update_post_chown(task, ii, &iattr);
	return 0;
}

int silofs_do_chown(const struct silofs_task *task,
                    struct silofs_inode_info *ii, uid_t uid, gid_t gid,
                    const struct silofs_itimes *itimes)
{
	int err;

	ii_incref(ii);
	err = do_chown(task, ii, uid, gid, itimes);
	ii_decref(ii);
	return err;
}

static bool is_utime_now(const struct timespec *tv)
{
	return (tv->tv_nsec == UTIME_NOW);
}

static bool is_utime_omit(const struct timespec *tv)
{
	return (tv->tv_nsec == UTIME_OMIT);
}

static int check_utimens(const struct silofs_task *task,
                         struct silofs_inode_info *ii)
{
	const struct silofs_creds *creds = task_creds(task);
	int err;

	if (user_isowner(&creds->fs_cred, ii)) {
		return 0;
	}
	/* TODO: check SILOFS_CAPF_FOWNER */
	/* TODO: Follow "Permissions requirements" in UTIMENSAT(2) */
	err = check_waccess(task, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_utimens(const struct silofs_task *task,
                      struct silofs_inode_info *ii,
                      const struct silofs_itimes *itimes)
{
	const struct silofs_creds *creds = &task->t_oper.op_creds;
	const struct timespec *ctime = &itimes->ctime;
	const struct timespec *atime = &itimes->atime;
	const struct timespec *mtime = &itimes->mtime;
	int err;

	err = check_utimens(task, ii);
	if (err) {
		return err;
	}
	if (is_utime_now(atime)) {
		ii_update_itimes(ii, creds, SILOFS_IATTR_ATIME);
	} else if (!is_utime_omit(atime)) {
		update_times_attr(task, ii, SILOFS_IATTR_ATIME, itimes);
	}
	if (is_utime_now(mtime)) {
		ii_update_itimes(ii, creds, SILOFS_IATTR_MTIME);
	} else if (!is_utime_omit(mtime)) {
		update_times_attr(task, ii, SILOFS_IATTR_MTIME, itimes);
	}
	if (!is_utime_omit(ctime)) {
		update_times_attr(task, ii, SILOFS_IATTR_CTIME, itimes);
	}
	return 0;
}


int silofs_do_utimens(const struct silofs_task *task,
                      struct silofs_inode_info *ii,
                      const struct silofs_itimes *itimes)
{
	int err;

	ii_incref(ii);
	err = do_utimens(task, ii, itimes);
	ii_decref(ii);
	return err;
}

static int check_parent_dir_ii(struct silofs_task *task,
                               const struct silofs_inode_info *ii)
{
	struct silofs_inode_info *parent_ii = NULL;
	ino_t parent;
	int err;

	if (!ii_isdir(ii) || ii_isrootd(ii)) {
		return 0;
	}
	parent = ii_parent(ii);
	if (ino_isnull(parent)) {
		return ii->i_nopen ? 0 : -SILOFS_ENOENT;
	}
	err = silofs_stage_inode(task, parent, SILOFS_STG_CUR, &parent_ii);
	if (err) {
		return err;
	}
	if (!ii_isdir(parent_ii)) {
		return -SILOFS_EFSCORRUPTED; /* XXX */
	}
	return 0;
}

/*
 * TODO-0004: Submit a patch to Linux kernel which support readdir of
 * multiple pages, possible using 'st_blksize' as hint.
 *
 * As of glibc-2.28 'opendir' uses 'st_blksize' as a hint to for size
 * of internal allocated buffer of 'DIR', which in turn passed to
 * 'getdents' system call. Unfortunately, currently FUSE chops readdir
 * into single page iterations.
 */
static blksize_t stat_blksize_of(const struct silofs_inode_info *ii)
{
	blksize_t bsz = SILOFS_LBK_SIZE;

	if (ii_isreg(ii) && (ii_size(ii) < bsz)) {
		bsz = SILOFS_FILE_HEAD2_LEAF_SIZE;
	}
	return bsz;
}

static blkcnt_t stat_blocks_of(const struct silofs_inode_info *ii)
{
	const size_t frg_size = 512;
	const ssize_t kb_size = SILOFS_KB_SIZE;
	const blkcnt_t blocks = ii_blocks(ii);
	const size_t nbytes = (size_t)(blocks * kb_size);

	return (blkcnt_t)div_round_up(nbytes, frg_size);
}

void silofs_ii_statof(const struct silofs_inode_info *ii,
                      struct silofs_stat *st)
{
	struct silofs_itimes tms;

	silofs_memzero(st, sizeof(*st));
	st->st.st_ino = ii_xino(ii);
	st->st.st_mode = ii_mode(ii);
	st->st.st_nlink = ii_nlink(ii);
	st->st.st_uid = ii_uid(ii);
	st->st.st_gid = ii_gid(ii);
	st->st.st_rdev = ii_rdev(ii);
	st->st.st_size = ii_size(ii);
	st->st.st_blocks = stat_blocks_of(ii);
	st->st.st_blksize = stat_blksize_of(ii);
	st->gen = ii_generation(ii);
	silofs_ii_times(ii, &tms);
	assign_ts(&st->st.st_atim, &ii->i_atime_lazy);
	assign_ts(&st->st.st_ctim, &tms.ctime);
	assign_ts(&st->st.st_mtim, &tms.mtime);
}

static void silofs_statx_of(const struct silofs_inode_info *ii,
                            unsigned int request_mask, struct statx *stx)
{
	struct silofs_itimes tms;
	const mode_t ifmt = S_IFMT;
	const unsigned int statx_times =
	        STATX_ATIME | STATX_BTIME | STATX_CTIME | STATX_MTIME;

	silofs_memzero(stx, sizeof(*stx));
	if (request_mask & STATX_NLINK) {
		stx->stx_nlink = (uint32_t)ii_nlink(ii);
		stx->stx_mask |= STATX_NLINK;
	}
	if (request_mask & STATX_UID) {
		stx->stx_uid = ii_uid(ii);
		stx->stx_mask |= STATX_UID;
	}
	if (request_mask & STATX_GID) {
		stx->stx_gid = ii_gid(ii);
		stx->stx_mask |= STATX_GID;
	}
	if (request_mask & STATX_TYPE) {
		stx->stx_mode |= (uint16_t)(ii_mode(ii) & ifmt);
		stx->stx_mask |= STATX_TYPE;
	}
	if (request_mask & STATX_MODE) {
		stx->stx_mode |= (uint16_t)(ii_mode(ii) & ~ifmt);
		stx->stx_mask |= STATX_MODE;
	}
	if (request_mask & STATX_INO) {
		stx->stx_ino = ii_xino(ii);
		stx->stx_mask |= STATX_INO;
	}
	if (request_mask & STATX_SIZE) {
		stx->stx_size = (uint64_t)ii_size(ii);
		stx->stx_mask |= STATX_SIZE;
	}
	if (request_mask & STATX_BLOCKS) {
		stx->stx_blocks = (uint64_t)stat_blocks_of(ii);
		stx->stx_mask |= STATX_BLOCKS;
	}

	stx->stx_blksize = (uint32_t)stat_blksize_of(ii);
	stx->stx_rdev_minor =  i_rdev_minor_of(ii);
	stx->stx_rdev_major =  i_rdev_major_of(ii);

	stx->stx_attributes_mask = STATX_ATTR_ENCRYPTED;
	stx->stx_attributes = STATX_ATTR_ENCRYPTED;

	if (request_mask & statx_times) {
		silofs_ii_times(ii, &tms);
		assign_xts(&stx->stx_atime, &ii->i_atime_lazy);
		assign_xts(&stx->stx_btime, &tms.btime);
		assign_xts(&stx->stx_ctime, &tms.ctime);
		assign_xts(&stx->stx_mtime, &tms.mtime);
		stx->stx_mask |= statx_times;
	}
}

/*
 * TODO-0016: Support strict-access mode
 *
 * Have special mode where only root & self may read inode's attributes.
 */
static int check_getattr(struct silofs_task *task,
                         const struct silofs_inode_info *ii)
{
	return check_parent_dir_ii(task, ii);
}

static int do_getattr(struct silofs_task *task,
                      const struct silofs_inode_info *ii,
                      struct silofs_stat *out_st)
{
	int err;

	err = check_getattr(task, ii);
	if (err) {
		return err;
	}
	silofs_ii_statof(ii, out_st);
	return 0;
}

int silofs_do_getattr(struct silofs_task *task,
                      struct silofs_inode_info *ii,
                      struct silofs_stat *out_st)
{
	int err;

	ii_incref(ii);
	err = do_getattr(task, ii, out_st);
	ii_decref(ii);
	return err;
}

static int do_statx(struct silofs_task *task,
                    const struct silofs_inode_info *ii,
                    unsigned int request_mask, struct statx *out_stx)
{
	int err;

	err = check_getattr(task, ii);
	if (err) {
		return err;
	}
	silofs_statx_of(ii, request_mask, out_stx);
	return 0;
}

int silofs_do_statx(struct silofs_task *task, struct silofs_inode_info *ii,
                    unsigned int request_mask, struct statx *out_stx)
{
	int err;

	ii_incref(ii);
	err = do_statx(task, ii, request_mask, out_stx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct timespec *
timespec_of(const struct timespec *ts_in, const struct silofs_creds *creds)
{
	const struct timespec *ts = ts_in;

	if (ts_in->tv_nsec == UTIME_NOW) {
		ts = &creds->ts;
	} else if (ts_in->tv_nsec == UTIME_OMIT) {
		ts = NULL;
	}
	return ts;
}

static void ii_update_atime(struct silofs_inode_info *ii,
                            const struct timespec *atime)
{
	if (atime != NULL) {
		memcpy(&ii->i_atime_lazy, atime, sizeof(ii->i_atime_lazy));
	}
}

static void ii_update_inode_attr(struct silofs_inode_info *ii,
                                 const struct silofs_creds *creds,
                                 enum silofs_iattr_flags attr_flags,
                                 const struct silofs_iattr *iattr)
{
	long flags = (long)attr_flags;
	struct silofs_inode *inode;
	const struct timespec *ts;

	if (ii == NULL) {
		return; /* e.g., rename */
	}
	if (flags & (SILOFS_IATTR_LAZY | SILOFS_IATTR_ATIME)) {
		ts = timespec_of(&iattr->ia_t.atime, creds);
		ii_update_atime(ii, ts);
		flags &= ~SILOFS_IATTR_ATIME;
	}
	flags &= ~SILOFS_IATTR_LAZY;
	if (!flags) {
		return;
	}
	inode = ii->inode;
	if (flags & SILOFS_IATTR_PARENT) {
		inode_set_parent(inode, iattr->ia_parent);
	}
	if (flags & SILOFS_IATTR_SIZE) {
		inode_set_size(inode, iattr->ia_size);
	}
	if (flags & SILOFS_IATTR_SPAN) {
		inode_set_span(inode, iattr->ia_span);
	}
	if (flags & SILOFS_IATTR_BLOCKS) {
		inode_set_blocks(inode, iattr->ia_blocks);
	}
	if (flags & SILOFS_IATTR_NLINK) {
		silofs_assert_lt(iattr->ia_nlink, UINT_MAX);
		inode_set_nlink(inode, iattr->ia_nlink);
	}
	if (flags & SILOFS_IATTR_MODE) {
		inode_set_mode(inode, iattr->ia_mode);
	}
	if (flags & SILOFS_IATTR_UID) {
		inode_set_uid(inode, iattr->ia_uid);
	}
	if (flags & SILOFS_IATTR_GID) {
		inode_set_gid(inode, iattr->ia_gid);
	}
	if (flags & SILOFS_IATTR_BTIME) {
		ts = timespec_of(&iattr->ia_t.btime, creds);
		inode_set_btime(inode, ts);
	}
	if (flags & SILOFS_IATTR_MTIME) {
		ts = timespec_of(&iattr->ia_t.mtime, creds);
		inode_set_mtime(inode, ts);
	}
	if (flags & SILOFS_IATTR_CTIME) {
		ts = timespec_of(&iattr->ia_t.ctime, creds);
		inode_set_ctime(inode, ts);
	}
	if (flags & SILOFS_IATTR_ATIME) {
		ts = timespec_of(&iattr->ia_t.atime, creds);
		inode_set_atime(inode, ts);
		silofs_ii_refresh_atime(ii, true);
	} else if (flags & SILOFS_IATTR_TIMES) {
		silofs_ii_refresh_atime(ii, false);
	}
	if (flags & (SILOFS_IATTR_KILL_SUID | SILOFS_IATTR_KILL_SGID)) {
		kill_suid_sgid(ii, flags);
	}
	inode_inc_revision(inode);
	ii_dirtify(ii);
}

void silofs_ii_update_iattrs(struct silofs_inode_info *ii,
                             const struct silofs_creds *creds,
                             const struct silofs_iattr *iattr)
{
	struct silofs_creds dummy_creds = {
		.ts.tv_sec = 0
	};

	ii_update_inode_attr(ii, creds ? creds : &dummy_creds,
	                     iattr->ia_flags, iattr);
}

void silofs_ii_update_itimes(struct silofs_inode_info *ii,
                             const struct silofs_creds *creds,
                             enum silofs_iattr_flags attr_flags)
{
	struct silofs_iattr iattr;
	const enum silofs_iattr_flags mask = SILOFS_IATTR_TIMES;

	silofs_setup_iattr_of(&iattr, ii_ino(ii));
	ii_update_inode_attr(ii, creds, attr_flags & mask, &iattr);
}

void silofs_ii_refresh_atime(struct silofs_inode_info *ii, bool to_volatile)
{
	if (to_volatile) {
		inode_atime(ii->inode, &ii->i_atime_lazy);
	} else {
		inode_set_atime(ii->inode, &ii->i_atime_lazy);
	}
}

static blkcnt_t recalc_iblocks(const struct silofs_inode_info *ii,
                               enum silofs_stype stype, long dif)
{
	blkcnt_t cnt;
	const size_t nkbs = stype_nkbs(stype);
	const blkcnt_t blocks = ii_blocks(ii);

	if (dif > 0) {
		cnt = blocks + (blkcnt_t)(nkbs * (size_t)dif);
	} else {
		cnt = blocks - (blkcnt_t)(nkbs * (size_t)labs(dif));
	}
	return cnt;
}

void silofs_ii_update_iblocks(struct silofs_inode_info *ii,
                              const struct silofs_creds *creds,
                              enum silofs_stype stype, long dif)
{
	struct silofs_iattr iattr;

	silofs_setup_iattr_of(&iattr, ii_ino(ii));
	iattr.ia_blocks = recalc_iblocks(ii, stype, dif);
	iattr.ia_flags = SILOFS_IATTR_BLOCKS;

	ii_update_iattrs(ii, creds, &iattr);
}

void silofs_ii_update_isize(struct silofs_inode_info *ii,
                            const struct silofs_creds *creds, loff_t size)
{
	struct silofs_iattr iattr;

	silofs_setup_iattr_of(&iattr, ii_ino(ii));
	iattr.ia_size = size;
	iattr.ia_flags = SILOFS_IATTR_SIZE;

	ii_update_iattrs(ii, creds, &iattr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_inode_specific(const struct silofs_inode *inode)
{
	const mode_t mode = inode_mode(inode);
	int err = 0;

	if (S_ISDIR(mode)) {
		err = silofs_verify_dir_inode(inode);
	} else {
		/* TODO: ALL type */
		err = 0;
	}
	return err;
}

static int verify_inode_head(const struct silofs_inode *inode)
{
	ino_t ino;
	loff_t size;
	nlink_t nlink;
	mode_t mode;
	int err;

	ino = inode_ino(inode);
	err = silofs_verify_ino(ino);
	if (err) {
		log_err("bad inode: ino=%ld", ino);
		return err;
	}
	size = inode_size(inode);
	if ((size < 0) || (size > (LONG_MAX / 2))) {
		log_err("bad inode: ino=%ld size=%ld", ino, (long)size);
		return -SILOFS_EFSCORRUPTED;
	}
	nlink = inode_nlink(inode);
	if (nlink > SILOFS_LINK_MAX) {
		log_err("bad inode: ino=%ld nlink=%ld", ino, (long)nlink);
		return -SILOFS_EFSCORRUPTED;
	}
	mode = inode_mode(inode);
	if ((mode & S_IFMT) == 0) {
		log_err("bad inode: ino=%ld mode=0%lo", ino, (long)mode);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int verify_inode_flags(const struct silofs_inode *inode)
{
	const mode_t mode = inode_mode(inode);
	const ino_t ino = inode_ino(inode);
	const enum silofs_inodef flags = inode_flags(inode);
	const enum silofs_inodef fmask =
	        SILOFS_INODEF_ROOTD | SILOFS_INODEF_FTYPE2;

	if ((flags & SILOFS_INODEF_ROOTD) && !S_ISDIR(mode)) {
		log_err("bad inode: ino=%ld mode=0%lo flags=%x",
		        ino, (long)mode, flags);
		return -SILOFS_EFSCORRUPTED;
	}
	if ((flags & ~fmask) > 0) {
		log_err("unsupported inode flags: ino=%ld flags=%x",
		        ino, flags);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_inode(const struct silofs_inode *inode)
{
	int err;

	err = verify_inode_head(inode);
	if (err) {
		return err;
	}
	err = verify_inode_flags(inode);
	if (err) {
		return err;
	}
	err = silofs_verify_inode_xattr(inode);
	if (err) {
		return err;
	}
	err = verify_inode_specific(inode);
	if (err) {
		return err;
	}
	return err;
}

