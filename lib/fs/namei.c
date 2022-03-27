/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>
#include <silofs/fs/walk.h>
#include <silofs/fs/pack.h>
#include <silofs/fs/ioctls.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>


static int namestr_to_hash(const struct silofs_inode_info *dir_ii,
                           const struct silofs_namestr *ns,
                           uint64_t *out_hash);

static bool dir_hasflag(const struct silofs_inode_info *dir_ii,
                        enum silofs_dirf mask)
{
	const enum silofs_dirf flags = silofs_dir_flags(dir_ii);

	return ((flags & mask) == mask);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool has_nlookup_mode(const struct silofs_inode_info *ii)
{
	const struct silofs_sb_info *sbi = ii_sbi(ii);

	return ((sbi->s_ctl_flags & SILOFS_F_NLOOKUP) != 0);
}

static void ii_sub_nlookup(struct silofs_inode_info *ii, long n)
{
	if (has_nlookup_mode(ii)) {
		ii->i_nlookup -= n;
	}
}

static void ii_inc_nlookup(struct silofs_inode_info *ii, int err)
{
	if (!err && likely(ii != NULL) && has_nlookup_mode(ii)) {
		ii->i_nlookup++;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool isowner(const struct silofs_fs_ctx *fs_ctx,
                    const struct silofs_inode_info *ii)
{
	const struct silofs_creds *creds = &fs_ctx->fsc_oper.op_creds;

	return uid_eq(creds->ucred.uid, ii_uid(ii));
}

static bool has_cap_fowner(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_creds *creds = &fs_ctx->fsc_oper.op_creds;

	return silofs_user_cap_fowner(&creds->ucred);
}

static int check_isdir(const struct silofs_inode_info *ii)
{
	return ii_isdir(ii) ? 0 : -ENOTDIR;
}

static int check_notdir(const struct silofs_inode_info *ii)
{
	return ii_isdir(ii) ? -EISDIR : 0;
}

static int check_opened(const struct silofs_inode_info *ii)
{
	return !ii->i_nopen ? -EBADF : 0;
}

static int check_reg_or_fifo(const struct silofs_inode_info *ii)
{
	if (ii_isdir(ii)) {
		return -EISDIR;
	}
	if (!ii_isreg(ii) && !ii_isfifo(ii)) {
		return -EINVAL;
	}
	return 0;
}

static int check_open_limit(const struct silofs_inode_info *ii)
{
	const int i_open_max = INT_MAX / 2;
	const struct silofs_fs_apex *apex = ii_apex(ii);

	if (!ii->i_nopen &&
	    !(apex->ap_ops.op_iopen < apex->ap_ops.op_iopen_max)) {
		return -ENFILE;
	}
	if (ii->i_nopen >= i_open_max) {
		return -ENFILE;
	}
	return 0;
}

static void update_nopen(struct silofs_inode_info *ii, int n)
{
	struct silofs_fs_apex *apex = ii_apex(ii);

	silofs_assert_ge(ii->i_nopen + n, 0);
	silofs_assert_lt(ii->i_nopen + n, INT_MAX);

	if ((n > 0) && (ii->i_nopen == 0)) {
		apex->ap_ops.op_iopen++;
	} else if ((n < 0) && (ii->i_nopen == 1)) {
		apex->ap_ops.op_iopen--;
	}
	ii->i_nopen += n;
}

static bool has_sticky_bit(const struct silofs_inode_info *dir_ii)
{
	const mode_t mode = ii_mode(dir_ii);

	return ((mode & S_ISVTX) == S_ISVTX);
}

static int check_sticky(const struct silofs_fs_ctx *fs_ctx,
                        const struct silofs_inode_info *dir_ii,
                        const struct silofs_inode_info *ii)
{
	if (!has_sticky_bit(dir_ii)) {
		return 0; /* No sticky-bit, we're fine */
	}
	if (isowner(fs_ctx, dir_ii)) {
		return 0;
	}
	if (ii && isowner(fs_ctx, ii)) {
		return 0;
	}
	if (has_cap_fowner(fs_ctx)) {
		return 0;
	}
	return -EPERM;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_creds *creds_of(const struct silofs_fs_ctx *fs_ctx)
{
	return &fs_ctx->fsc_oper.op_creds;
}

static int new_inode(const struct silofs_fs_ctx *fs_ctx,
                     const struct silofs_inode_info *parent_dir_ii,
                     mode_t mode, dev_t rdev,
                     struct silofs_inode_info **out_ii)
{
	const ino_t parent_ino = ii_ino(parent_dir_ii);
	const mode_t parent_mode = ii_mode(parent_dir_ii);
	struct silofs_sb_info *sbi = ii_sbi(parent_dir_ii);

	return silofs_spawn_inode(sbi, creds_of(fs_ctx), parent_ino,
	                          parent_mode, mode, rdev, out_ii);
}

static int new_dir_inode(const struct silofs_fs_ctx *fs_ctx,
                         const struct silofs_inode_info *parent_dir_ii,
                         mode_t mode, struct silofs_inode_info **out_ii)
{
	const mode_t ifmt = S_IFMT;
	const mode_t dir_mode = (mode & ~ifmt) | S_IFDIR;

	return new_inode(fs_ctx, parent_dir_ii, dir_mode, 0, out_ii);
}

static int new_reg_inode(const struct silofs_fs_ctx *fs_ctx,
                         const struct silofs_inode_info *parent_dir_ii,
                         mode_t mode, struct silofs_inode_info **out_ii)
{
	const mode_t ifmt = S_IFMT;
	const mode_t reg_mode = (mode & ~ifmt) | S_IFREG;

	return new_inode(fs_ctx, parent_dir_ii, reg_mode, 0, out_ii);
}

static int new_lnk_inode(const struct silofs_fs_ctx *fs_ctx,
                         const struct silofs_inode_info *parent_dir_ii,
                         struct silofs_inode_info **out_ii)
{
	const mode_t lnk_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFLNK;

	return new_inode(fs_ctx, parent_dir_ii, lnk_mode, 0, out_ii);
}

static int new_inode_by_mode(const struct silofs_fs_ctx *fs_ctx,
                             const struct silofs_inode_info *parent_dir_ii,
                             mode_t mode, dev_t rdev,
                             struct silofs_inode_info **out_ii)
{
	int err;

	if (S_ISREG(mode)) {
		err = new_reg_inode(fs_ctx, parent_dir_ii, mode, out_ii);
	} else if (S_ISLNK(mode)) {
		err = new_lnk_inode(fs_ctx, parent_dir_ii, out_ii);
	} else if (S_ISFIFO(mode) || S_ISSOCK(mode)) {
		err = new_inode(fs_ctx, parent_dir_ii, mode, rdev, out_ii);
	} else {
		err = -EOPNOTSUPP;
	}
	return err;
}

static int del_inode(struct silofs_inode_info *ii)
{
	return silofs_remove_inode(ii_sbi(ii), ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_access(const struct silofs_fs_ctx *fs_ctx,
                     const struct silofs_inode_info *ii, int mode)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);
	const uid_t uid = creds->ucred.uid;
	const gid_t gid = creds->ucred.gid;
	const uid_t i_uid = ii_uid(ii);
	const gid_t i_gid = ii_gid(ii);
	const mode_t i_mode = ii_mode(ii);
	const mode_t mask = (mode_t)mode;
	mode_t rwx = 0;

	if (uid_isroot(uid)) {
		rwx |= R_OK | W_OK;
		if (S_ISREG(i_mode)) {
			if (i_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
				rwx |= X_OK;
			}
		} else {
			rwx |= X_OK;
		}
	} else if (uid_eq(uid, i_uid)) {
		/* Owner permissions */
		if (i_mode & S_IRUSR) {
			rwx |= R_OK;
		}
		if (i_mode & S_IWUSR) {
			rwx |= W_OK;
		}
		if (i_mode & S_IXUSR) {
			rwx |= X_OK;
		}
	} else if (gid_eq(gid, i_gid)) {
		/* Group permissions */
		if (i_mode & S_IRGRP) {
			rwx |= R_OK;
		}
		if (i_mode & S_IWGRP) {
			rwx |= W_OK;
		}
		if (i_mode & S_IXGRP) {
			rwx |= X_OK;
		}
		/* TODO: Check for supplementary groups */
	} else {
		/* Other permissions */
		if (i_mode & S_IROTH) {
			rwx |= R_OK;
		}
		if (i_mode & S_IWOTH) {
			rwx |= W_OK;
		}
		if (i_mode & S_IXOTH) {
			rwx |= X_OK;
		}
	}
	return ((rwx & mask) == mask) ? 0 : -EACCES;
}

int silofs_do_access(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *ii, int mode)
{
	int err;

	ii_incref(ii);
	err = do_access(fs_ctx, ii, mode);
	ii_decref(ii);
	return err;
}

static int check_on_writable_fs(const struct silofs_inode_info *ii)
{
	return silof_check_writable_fs(ii_sbi(ii));
}

static int check_waccess(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(fs_ctx, ii, W_OK);
}

static int check_xaccess(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(fs_ctx, ii, X_OK);
}

static int check_raccess(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(fs_ctx, ii, R_OK);
}

static int check_dir_waccess(const struct silofs_fs_ctx *fs_ctx,
                             struct silofs_inode_info *ii)
{
	int err;

	err = check_on_writable_fs(ii);
	if (err) {
		return err;
	}
	err = check_isdir(ii);
	if (err) {
		return err;
	}
	err = check_waccess(fs_ctx, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_name(const struct silofs_namestr *name)
{
	/* TODO: redundant checks; namestr should have valid name; remove */
	if (name->str.len == 0) {
		return -EINVAL;
	}
	if (name->str.len > SILOFS_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	if (memchr(name->str.str, '/', name->str.len)) {
		return -EINVAL;
	}
	return 0;
}

static int check_dir_and_name(const struct silofs_inode_info *ii,
                              const struct silofs_namestr *name)
{
	int err;

	err = check_isdir(ii);
	if (err) {
		return err;
	}
	err = check_name(name);
	if (err) {
		return err;
	}
	return 0;
}

static int check_lookup(const struct silofs_fs_ctx *fs_ctx,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	int err;

	err = check_dir_and_name(dir_ii, name);
	if (err) {
		return err;
	}
	err = check_xaccess(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int assign_namehash(const struct silofs_inode_info *dir_ii,
                           const struct silofs_namestr *nstr,
                           struct silofs_qstr *qstr)
{
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = namestr_to_hash(dir_ii, nstr, &qstr->hash);
	if (err) {
		return err;
	}
	qstr->str.str = nstr->str.str;
	qstr->str.len = nstr->str.len;
	return 0;
}

static int lookup_by_name(const struct silofs_fs_ctx *fs_ctx,
                          struct silofs_inode_info *dir_ii,
                          const struct silofs_namestr *nstr, ino_t *out_ino)
{
	struct silofs_qstr name;
	struct silofs_ino_dt ino_dt;
	int err;

	err = assign_namehash(dir_ii, nstr, &name);
	if (err) {
		return err;
	}
	err = silofs_lookup_dentry(fs_ctx, dir_ii, &name, &ino_dt);
	if (err) {
		return err;
	}
	*out_ino = ino_dt.ino;
	return 0;
}

static int stage_by_name(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         enum silofs_stage_flags stg_flags,
                         struct silofs_inode_info **out_ii)
{
	struct silofs_sb_info *sbi = ii_sbi(dir_ii);
	ino_t ino;
	int err;

	err = lookup_by_name(fs_ctx, dir_ii, name, &ino);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(sbi, ino, stg_flags, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_lookup(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	err = check_lookup(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = stage_by_name(fs_ctx, dir_ii, name, SILOFS_STAGE_RDONLY, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_lookup(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_lookup(fs_ctx, dir_ii, name, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static int check_create_mode(mode_t mode)
{
	if (S_ISDIR(mode)) {
		return -EISDIR;
	}
	if (S_ISLNK(mode)) {
		return -EINVAL;
	}
	if (!S_ISREG(mode) && !S_ISFIFO(mode) && !S_ISSOCK(mode)) {
		return -EOPNOTSUPP;
	}
	return 0;
}

static int check_nodent(const struct silofs_fs_ctx *fs_ctx,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	ino_t ino;
	int err;

	err = lookup_by_name(fs_ctx, dir_ii, name, &ino);
	if (err == 0) {
		return -EEXIST;
	}
	return (err == -ENOENT) ? 0 : err;
}

static int check_add_dentry(const struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name)
{
	const size_t ndents_max = SILOFS_DIR_ENTRIES_MAX;
	size_t ndents;
	int err;

	err = check_dir_and_name(dir_ii, name);
	if (err) {
		return err;
	}
	ndents = silofs_dir_ndentries(dir_ii);
	if (!(ndents < ndents_max)) {
		return -EMLINK;
	}
	/* Special case for directory which is still held by open fd */
	if (ii_nlink(dir_ii) < 2) {
		return -ENOENT;
	}
	return 0;
}

static int check_dir_can_add(const struct silofs_fs_ctx *fs_ctx,
                             struct silofs_inode_info *dir_ii,
                             const struct silofs_namestr *name)
{
	int err;

	err = check_dir_waccess(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	err = check_nodent(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_add_dentry(dir_ii, name);
	if (err) {
		return err;
	}
	return 0;
}

static int check_create(const struct silofs_fs_ctx *fs_ctx,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name, mode_t mode)
{
	int err;

	err = check_on_writable_fs(dir_ii);
	if (err) {
		return err;
	}
	err = check_dir_can_add(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_create_mode(mode);
	if (err) {
		return err;
	}
	return 0;
}

static int do_add_dentry(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *nstr,
                         struct silofs_inode_info *ii,
                         bool del_upon_failure)
{
	int err;
	struct silofs_qstr name;

	err = assign_namehash(dir_ii, nstr, &name);
	if (err) {
		return err;
	}
	err = silofs_add_dentry(fs_ctx, dir_ii, &name, ii);
	if (err && del_upon_failure) {
		del_inode(ii);
	}
	return err;
}

static int do_create(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_create(fs_ctx, dir_ii, name, mode);
	if (err) {
		return err;
	}
	err = new_inode_by_mode(fs_ctx, dir_ii, mode, 0, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(fs_ctx, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	update_nopen(ii, 1);
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_create(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_create(fs_ctx, dir_ii, name, mode, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static int check_mknod(const struct silofs_fs_ctx *fs_ctx,
                       struct silofs_inode_info *dir_ii,
                       const struct silofs_namestr *name,
                       mode_t mode, dev_t rdev)
{
	int err;
	const struct silofs_sb_info *sbi = ii_sbi(dir_ii);

	err = check_dir_can_add(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	if (S_ISDIR(mode)) {
		return -EISDIR;
	}
	if (S_ISLNK(mode)) {
		return -EINVAL;
	}
	if (!S_ISFIFO(mode) && !S_ISSOCK(mode) &&
	    !S_ISCHR(mode) && !S_ISBLK(mode)) {
		return -EOPNOTSUPP;
	}
	if (S_ISCHR(mode) || S_ISBLK(mode)) {
		if (rdev == 0) {
			return -EINVAL;
		}
		if (sbi->s_ms_flags & MS_NODEV) {
			return -EOPNOTSUPP;
		}
	} else {
		if (rdev != 0) {
			return -EINVAL; /* XXX see man 3p mknod */
		}
	}
	return 0;
}

static int create_special_inode(const struct silofs_fs_ctx *fs_ctx,
                                struct silofs_inode_info *dir_ii,
                                mode_t mode, dev_t rdev,
                                struct silofs_inode_info **out_ii)
{
	int err;

	err = new_inode(fs_ctx, dir_ii, mode, rdev, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_mknod_reg(const struct silofs_fs_ctx *fs_ctx,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name, mode_t mode,
                        struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = do_create(fs_ctx, dir_ii, name, mode, &ii);
	if (err) {
		return err;
	}
	/* create reg via 'mknod' does not follow by release */
	update_nopen(ii, -1);
	*out_ii = ii;
	return 0;
}

static int do_mknod_special(const struct silofs_fs_ctx *fs_ctx,
                            struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name,
                            mode_t mode, dev_t rdev,
                            struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_mknod(fs_ctx, dir_ii, name, mode, rdev);
	if (err) {
		return err;
	}
	err = create_special_inode(fs_ctx, dir_ii, mode, rdev, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(fs_ctx, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);

	/* can not use 'nopen' as FUSE does not sent OPEN on fifo, and
	 * therefore no RELEASE */
	ii->i_pinned = true;

	*out_ii = ii;
	return 0;
}

int silofs_do_mknod(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name,
                    mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii)
{
	int err;
	const bool mknod_reg = S_ISREG(mode);

	ii_incref(dir_ii);
	if (mknod_reg) {
		err = do_mknod_reg(fs_ctx, dir_ii, name, mode, out_ii);
	} else {
		err = do_mknod_special(fs_ctx, dir_ii, name,
		                       mode, dev, out_ii);
	}
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static int o_flags_to_rwx(int o_flags)
{
	int mask = 0;

	if ((o_flags & O_RDWR) == O_RDWR) {
		mask = R_OK | W_OK;
	} else if ((o_flags & O_WRONLY) == O_WRONLY) {
		mask = W_OK;
	} else if ((o_flags & O_RDONLY) == O_RDONLY) {
		mask = R_OK;
	}
	if ((o_flags & O_TRUNC) == O_TRUNC) {
		mask |= W_OK;
	}
	if ((o_flags & O_APPEND) == O_APPEND) {
		mask |= W_OK;
	}
	return mask;
}

static int check_open_flags(const struct silofs_inode_info *ii, int o_flags)
{
	if (o_flags & O_DIRECTORY) {
		return -EISDIR;
	}
	if (o_flags & (O_CREAT | O_EXCL)) {
		return -EEXIST; /* XXX ? */
	}
	if (ii_isreg(ii) && (o_flags & O_TRUNC) &&
	    !(o_flags & (O_WRONLY | O_RDWR))) {
		return -EACCES;
	}
	return 0;
}

static int check_open(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *ii, int o_flags)
{
	int err;
	int rwx;

	err = check_reg_or_fifo(ii);
	if (err) {
		return err;
	}
	err = check_open_flags(ii, o_flags);
	if (err) {
		return err;
	}
	rwx = o_flags_to_rwx(o_flags);
	err = silofs_do_access(fs_ctx, ii, rwx);
	if (err) {
		return err;
	}
	err = check_open_limit(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int post_open(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *ii, int o_flags)
{
	return (ii_isreg(ii) && (o_flags & O_TRUNC)) ?
	       silofs_do_truncate(fs_ctx, ii, 0) : 0;
}

static int do_open(const struct silofs_fs_ctx *fs_ctx,
                   struct silofs_inode_info *ii, int o_flags)
{
	int err;

	err = check_open(fs_ctx, ii, o_flags);
	if (err) {
		return err;
	}
	err = post_open(fs_ctx, ii, o_flags);
	if (err) {
		return err;
	}
	update_nopen(ii, 1);
	return 0;
}

int silofs_do_open(const struct silofs_fs_ctx *fs_ctx,
                   struct silofs_inode_info *ii, int o_flags)
{
	int err;

	ii_incref(ii);
	err = do_open(fs_ctx, ii, o_flags);
	ii_decref(ii);
	return err;
}

static int drop_ispecific(struct silofs_inode_info *ii)
{
	int err;

	if (ii_isdir(ii)) {
		err = silofs_drop_dir(ii);
	} else if (ii_isreg(ii)) {
		err = silofs_drop_reg(ii);
	} else if (ii_islnk(ii)) {
		err = silofs_drop_symlink(ii);
	} else {
		err = 0;
	}
	return err;
}

static int drop_unlinked(struct silofs_inode_info *ii)
{
	int err;

	err = silofs_drop_xattr(ii);
	if (err) {
		return err;
	}
	err = drop_ispecific(ii);
	if (err) {
		return err;
	}
	err = del_inode(ii);
	if (err) {
		return err;
	}
	return 0;
}

/*
 * TODO-0022: Do not allocate special files persistently
 *
 * Special files which are created via FUSE_MKNOD (FIFO, SOCK et.al.) should
 * not be allocated on persistent volume. They should have special ino
 * enumeration and should live in volatile memory only.
 *
 * More specifically to the case of 'dropable' here, there is no 'FUSE_RLEASE'
 * to mknod, even if it is held open by a file-descriptor. Defer space release
 * to later on when forget.
 *
 * Need further investigating on the kernel side.
 */
static bool ii_isnlink_orphan(const struct silofs_inode_info *ii)
{
	const bool isdir = ii_isdir(ii);
	const nlink_t nlink = ii_nlink(ii);

	if (isdir && (nlink > 1)) {
		return false;
	}
	if (!isdir && nlink) {
		return false;
	}
	return true;
}

static bool ii_isevictable(const struct silofs_inode_info *ii)
{
	return silofs_ii_isevictable(ii);
}

static bool ii_isdropable(const struct silofs_inode_info *ii)
{
	if (!ii_isevictable(ii)) {
		return false;
	}
	if (!ii_isnlink_orphan(ii)) {
		return false;
	}
	return true;
}

static int try_prune_inode(const struct silofs_fs_ctx *fs_ctx,
                           struct silofs_inode_info *ii, bool update_ctime)
{
	if (!ii->i_nopen && ii_isnlink_orphan(ii)) {
		ii_undirtify(ii);
	}
	if (ii_isdropable(ii)) {
		return drop_unlinked(ii);
	}
	if (update_ctime) {
		ii_update_itimes(ii, creds_of(fs_ctx), SILOFS_IATTR_CTIME);
	}
	return 0;
}

static int remove_dentry_of(const struct silofs_fs_ctx *fs_ctx,
                            struct silofs_inode_info *dir_ii,
                            struct silofs_inode_info *ii,
                            const struct silofs_qstr *name)
{
	int err;

	ii_incref(ii);
	err = silofs_remove_dentry(fs_ctx, dir_ii, name);
	ii_decref(ii);
	return err;
}

static int do_remove_and_prune(const struct silofs_fs_ctx *fs_ctx,
                               struct silofs_inode_info *dir_ii,
                               const struct silofs_namestr *nstr,
                               struct silofs_inode_info *ii)
{
	int err;
	struct silofs_qstr name;

	err = assign_namehash(dir_ii, nstr, &name);
	if (err) {
		return err;
	}
	err = remove_dentry_of(fs_ctx, dir_ii, ii, &name);
	if (err) {
		return err;
	}
	err = try_prune_inode(fs_ctx, ii, true);
	if (err) {
		return err;
	}
	return 0;
}

static int check_prepare_unlink(const struct silofs_fs_ctx *fs_ctx,
                                struct silofs_inode_info *dir_ii,
                                const struct silofs_namestr *nstr,
                                struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_dir_waccess(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(fs_ctx, dir_ii, nstr, SILOFS_STAGE_MUTABLE, &ii);
	if (err) {
		return err;
	}
	err = check_sticky(fs_ctx, dir_ii, ii);
	if (err) {
		return err;
	}
	err = check_notdir(ii);
	if (err) {
		return err;
	}
	*out_ii = ii;
	return 0;
}

static int do_unlink(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *nstr)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_prepare_unlink(fs_ctx, dir_ii, nstr, &ii);
	if (err) {
		return err;
	}
	err = do_remove_and_prune(fs_ctx, dir_ii, nstr, ii);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_unlink(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name)
{
	int err;

	ii_incref(dir_ii);
	err = do_unlink(fs_ctx, dir_ii, name);
	ii_decref(dir_ii);
	return err;
}

static int check_nomlink(const struct silofs_inode_info *ii)
{
	const size_t link_max = SILOFS_LINK_MAX;

	return (ii_nlink(ii) < link_max) ? 0 : -EMLINK;
}

static int check_link(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      struct silofs_inode_info *ii)
{
	int err;

	err = check_dir_waccess(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	err = check_notdir(ii);
	if (err) {
		return err;
	}
	err = check_nodent(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_nomlink(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_link(const struct silofs_fs_ctx *fs_ctx,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *nstr,
                   struct silofs_inode_info *ii)
{
	int err;

	err = check_link(fs_ctx, dir_ii, nstr, ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(fs_ctx, dir_ii, nstr, ii, false);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);
	ii_update_itimes(ii, creds_of(fs_ctx), SILOFS_IATTR_CTIME);

	return 0;
}

int silofs_do_link(const struct silofs_fs_ctx *fs_ctx,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info *ii)
{
	int err;

	ii_incref(dir_ii);
	ii_incref(ii);
	err = do_link(fs_ctx, dir_ii, name, ii);
	ii_inc_nlookup(ii, err);
	ii_decref(ii);
	ii_decref(dir_ii);
	return err;
}

static int check_mkdir(const struct silofs_fs_ctx *fs_ctx,
                       struct silofs_inode_info *dir_ii,
                       const struct silofs_namestr *name)
{
	int err;

	err = check_dir_can_add(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_nomlink(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_mkdir(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii;

	err = check_mkdir(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = new_dir_inode(fs_ctx, dir_ii, mode, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(fs_ctx, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_mkdir(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_mkdir(fs_ctx, dir_ii, name, mode, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static bool dir_isempty(const struct silofs_inode_info *dir_ii)
{
	if (ii_nlink(dir_ii) > 2) {
		return false;
	}
	if (silofs_dir_ndentries(dir_ii)) {
		return false;
	}
	return true;
}

static int check_rmdir_child(const struct silofs_fs_ctx *fs_ctx,
                             const struct silofs_inode_info *parent_ii,
                             const struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_on_writable_fs(parent_ii);
	if (err) {
		return err;
	}
	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	if (!dir_isempty(dir_ii)) {
		return -ENOTEMPTY;
	}
	if (ii_isrootd(dir_ii)) {
		return -EBUSY;
	}
	err = check_sticky(fs_ctx, parent_ii, dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_prepare_rmdir(const struct silofs_fs_ctx *fs_ctx,
                               struct silofs_inode_info *dir_ii,
                               const struct silofs_namestr *name,
                               struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_dir_waccess(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(fs_ctx, dir_ii, name, SILOFS_STAGE_MUTABLE, &ii);
	if (err) {
		return err;
	}
	err = check_rmdir_child(fs_ctx, dir_ii, ii);
	if (err) {
		return err;
	}
	*out_ii = ii;
	return 0;
}

static int do_rmdir(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_prepare_rmdir(fs_ctx, dir_ii, name, &ii);
	if (err) {
		return err;
	}
	err = do_remove_and_prune(fs_ctx, dir_ii, name, ii);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_rmdir(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name)
{
	int err;

	ii_incref(dir_ii);
	err = do_rmdir(fs_ctx, dir_ii, name);
	ii_decref(dir_ii);
	return err;
}

static int create_lnk_inode(const struct silofs_fs_ctx *fs_ctx,
                            const struct silofs_inode_info *dir_ii,
                            const struct silofs_str *linkpath,
                            struct silofs_inode_info **out_ii)
{
	int err;

	err = new_lnk_inode(fs_ctx, dir_ii, out_ii);
	if (err) {
		return err;
	}
	err = silofs_setup_symlink(fs_ctx, *out_ii, linkpath);
	if (err) {
		del_inode(*out_ii);
		return err;
	}
	return 0;
}

static int check_symval(const struct silofs_str *symval)
{
	if (symval->len == 0) {
		return -EINVAL;
	}
	if (symval->len > SILOFS_SYMLNK_MAX) {
		return -ENAMETOOLONG;
	}
	return 0;
}

static int check_symlink(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         const struct silofs_str *symval)
{
	int err;

	err = check_dir_can_add(fs_ctx, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_symval(symval);
	if (err) {
		return err;
	}
	return 0;
}

static int do_symlink(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_symlink(fs_ctx, dir_ii, name, symval);
	if (err) {
		return err;
	}
	err = create_lnk_inode(fs_ctx, dir_ii, symval, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(fs_ctx, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(fs_ctx), SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_symlink(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_symlink(fs_ctx, dir_ii, name, symval, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int flush_dirty_of(const struct silofs_inode_info *ii, int flags)
{
	return silofs_apex_flush_dirty(ii_apex(ii), flags);
}

static int flush_dirty_now(struct silofs_fs_apex *apex)
{
	return silofs_apex_flush_dirty(apex, SILOFS_F_NOW);
}

static int check_opendir(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = check_raccess(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	err = check_open_limit(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_opendir(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_opendir(fs_ctx, dir_ii);
	if (err) {
		return err;
	}
	update_nopen(dir_ii, 1);
	return 0;
}

int silofs_do_opendir(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *dir_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_opendir(fs_ctx, dir_ii);
	ii_decref(dir_ii);

	return err;
}

/*
 * TODO-0017: Shrink sparse dir-tree upon last close
 *
 * Try to shrink sparse dir hash-tree upon last close. Note that we should
 * not do so while dir is held open, as it may corrupt active readdir.
 */
static int check_releasedir(const struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = check_opened(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_releasedir(struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_releasedir(dir_ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(dir_ii, 0);
	if (err) {
		return err;
	}
	update_nopen(dir_ii, -1);
	return 0;
}

int silofs_do_releasedir(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *dir_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_releasedir(dir_ii);
	ii_decref(dir_ii);

	return !err ? try_prune_inode(fs_ctx, dir_ii, false) : err;
}

static int check_notdir_and_opened(const struct silofs_inode_info *ii)
{
	int err;

	err = check_notdir(ii);
	if (err) {
		return err;
	}
	err = check_opened(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_release(const struct silofs_inode_info *ii)
{
	return check_notdir_and_opened(ii);
}

static int do_release(struct silofs_inode_info *ii)
{
	int err;

	err = check_release(ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(ii, 0);
	if (err) {
		return err;
	}
	update_nopen(ii, -1);
	return 0;
}

int silofs_do_release(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *ii)
{
	int err;

	ii_incref(ii);
	err = do_release(ii);
	ii_decref(ii);

	return !err ? try_prune_inode(fs_ctx, ii, false) : err;
}

static int check_fsyncdir(const struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = check_opened(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_fsyncdir(const struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_fsyncdir(dir_ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(dir_ii, SILOFS_F_SYNC);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_fsyncdir(const struct silofs_fs_ctx *fs_ctx,
                       struct silofs_inode_info *dir_ii, bool dsync)
{
	int err;

	ii_incref(dir_ii);
	err = do_fsyncdir(dir_ii);
	ii_decref(dir_ii);

	silofs_unused(fs_ctx);
	silofs_unused(dsync);

	return err;
}

static int check_fsync(const struct silofs_inode_info *ii)
{
	return check_notdir_and_opened(ii);
}

static int do_fsync(const struct silofs_inode_info *ii)
{
	int err;

	err = check_fsync(ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(ii, SILOFS_F_SYNC);
	if (err) {
		return err;
	}
	return 0;
}

/*
 * TODO-0029: Revisit fsync semantics
 *
 * Re-think it over. See also:
 * https://lwn.net/Articles/351422/
 * https://lwn.net/Articles/322823/
 */
int silofs_do_fsync(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *ii, bool datasync)
{
	int err;

	ii_incref(ii);
	err = do_fsync(ii);
	ii_decref(ii);

	silofs_unused(fs_ctx);
	silofs_unused(datasync);

	return err;
}

int silofs_do_flush(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *ii)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);
	const uid_t uid = creds->ucred.uid;
	const int flags = (uid == 0) ? SILOFS_F_NOW : 0;

	return flush_dirty_of(ii, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_dentry_ref {
	struct silofs_inode_info *dir_ii;
	const struct silofs_namestr *name;
	struct silofs_inode_info *ii;
};

static int check_add_dentry_at(const struct silofs_dentry_ref *dref)
{
	return check_add_dentry(dref->dir_ii, dref->name);
}

static int do_add_dentry_at(const struct silofs_fs_ctx *fs_ctx,
                            struct silofs_dentry_ref *dref,
                            struct silofs_inode_info *ii)

{
	int err;

	err = do_add_dentry(fs_ctx, dref->dir_ii, dref->name, ii, false);
	if (err) {
		return err;
	}
	dref->ii = ii;
	return 0;
}

static int do_remove_and_prune_at(const struct silofs_fs_ctx *fs_ctx,
                                  struct silofs_dentry_ref *dref)
{
	int err;

	err = do_remove_and_prune(fs_ctx, dref->dir_ii, dref->name, dref->ii);
	if (err) {
		return err;
	}
	dref->ii = NULL;
	return 0;
}

static int do_rename_move(const struct silofs_fs_ctx *fs_ctx,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	err = check_add_dentry_at(new_dref);
	if (err) {
		return err;
	}
	err = do_remove_and_prune_at(fs_ctx, cur_dref);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(fs_ctx, new_dref, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_move(const struct silofs_fs_ctx *fs_ctx,
                       struct silofs_dentry_ref *cur_dref,
                       struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	ii_incref(ii);
	err = do_rename_move(fs_ctx, cur_dref, new_dref);
	ii_decref(ii);
	return err;
}

static int rename_unlink(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_dentry_ref *dref)
{
	return do_remove_and_prune_at(fs_ctx, dref);
}

static int do_rename_replace(const struct silofs_fs_ctx *fs_ctx,
                             struct silofs_dentry_ref *cur_dref,
                             struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	err = do_remove_and_prune_at(fs_ctx, cur_dref);
	if (err) {
		return err;
	}
	err = do_remove_and_prune_at(fs_ctx, new_dref);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(fs_ctx, new_dref, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_replace(const struct silofs_fs_ctx *fs_ctx,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	ii_incref(ii);
	err = do_rename_replace(fs_ctx, cur_dref, new_dref);
	ii_decref(ii);
	return err;
}

static int do_rename_exchange(const struct silofs_fs_ctx *fs_ctx,
                              struct silofs_dentry_ref *dref1,
                              struct silofs_dentry_ref *dref2)
{
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;
	int err;

	err = do_remove_and_prune_at(fs_ctx, dref1);
	if (err) {
		return err;
	}
	err = do_remove_and_prune_at(fs_ctx, dref2);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(fs_ctx, dref2, ii1);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(fs_ctx, dref1, ii2);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_exchange(const struct silofs_fs_ctx *fs_ctx,
                           struct silofs_dentry_ref *dref1,
                           struct silofs_dentry_ref *dref2)
{
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;
	int err;

	ii_incref(ii1);
	ii_incref(ii2);
	err = do_rename_exchange(fs_ctx, dref1, dref2);
	ii_decref(ii2);
	ii_decref(ii1);
	return err;
}

static int rename_specific(const struct silofs_fs_ctx *fs_ctx,
                           struct silofs_dentry_ref *cur_dref,
                           struct silofs_dentry_ref *new_dref, int flags)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);
	int err;

	if (new_dref->ii == NULL) {
		err = rename_move(fs_ctx, cur_dref, new_dref);
	} else if (cur_dref->ii == new_dref->ii) {
		err = rename_unlink(fs_ctx, cur_dref);
	} else if (flags & RENAME_EXCHANGE) {
		err = rename_exchange(fs_ctx, cur_dref, new_dref);
	} else {
		err = rename_replace(fs_ctx, cur_dref, new_dref);
	}
	ii_update_itimes(cur_dref->dir_ii, creds, SILOFS_IATTR_MCTIME);
	ii_update_itimes(new_dref->dir_ii, creds, SILOFS_IATTR_MCTIME);
	return err;
}

static int check_rename_exchange(const struct silofs_dentry_ref *cur_dref,
                                 const struct silofs_dentry_ref *new_dref)
{
	int err;
	const struct silofs_inode_info *ii = cur_dref->ii;
	const struct silofs_inode_info *old_ii = new_dref->ii;

	if (ii == NULL) {
		return -EINVAL;
	}
	err = check_on_writable_fs(ii);
	if (err) {
		return err;
	}
	if ((ii != old_ii) && (ii_isdir(ii) != ii_isdir(old_ii))) {
		if (ii_isdir(old_ii)) {
			err = check_nomlink(new_dref->dir_ii);
		} else {
			err = check_nomlink(cur_dref->dir_ii);
		}
	}
	return err;
}

static int check_rename(const struct silofs_fs_ctx *fs_ctx,
                        const struct silofs_dentry_ref *cur_dref,
                        const struct silofs_dentry_ref *new_dref, int flags)
{
	int err = 0;
	const struct silofs_inode_info *ii = cur_dref->ii;
	const struct silofs_inode_info *old_ii = new_dref->ii;
	const bool old_exists = (old_ii != NULL);

	if (flags & RENAME_WHITEOUT) {
		return -EINVAL;
	}
	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE)) {
		return -EINVAL;
	}
	if ((flags & RENAME_NOREPLACE) && old_exists) {
		return -EEXIST;
	}
	if ((flags & RENAME_EXCHANGE) && !old_exists) {
		return -ENOENT;
	}
	if (flags & RENAME_EXCHANGE) {
		return check_rename_exchange(cur_dref, new_dref);
	}
	if (old_exists && ii_isdir(old_ii) && (old_ii != ii)) {
		err = (ii == NULL) ? check_nomlink(new_dref->dir_ii) :
		      check_rmdir_child(fs_ctx, cur_dref->dir_ii, old_ii);
	}
	return err;
}

static int check_stage_rename_at(const struct silofs_fs_ctx *fs_ctx,
                                 struct silofs_dentry_ref *dref, bool new_de)
{
	int err;

	err = check_dir_waccess(fs_ctx, dref->dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(fs_ctx, dref->dir_ii, dref->name,
	                    SILOFS_STAGE_MUTABLE, &dref->ii);
	if (err) {
		return ((err == -ENOENT) && new_de) ? 0 : err;
	}
	err = check_sticky(fs_ctx, dref->dir_ii, dref->ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_rename(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags)
{
	int err;
	struct silofs_dentry_ref cur_dref = {
		.dir_ii = dir_ii,
		.name = name,
	};
	struct silofs_dentry_ref new_dref = {
		.dir_ii = newdir_ii,
		.name = newname,
	};

	err = check_stage_rename_at(fs_ctx, &cur_dref, false);
	if (err) {
		return err;
	}
	err = check_stage_rename_at(fs_ctx, &new_dref, true);
	if (err) {
		return err;
	}
	err = check_rename(fs_ctx, &cur_dref, &new_dref, flags);
	if (err) {
		return err;
	}
	err = rename_specific(fs_ctx, &cur_dref, &new_dref, flags);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_rename(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags)
{
	int err;

	ii_incref(dir_ii);
	ii_incref(newdir_ii);
	err = do_rename(fs_ctx, dir_ii, name, newdir_ii, newname, flags);
	ii_decref(newdir_ii);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0028: Use statvfs.f_bsize=BK (64K) and KB to statvfs.f_frsize=KB (1K)
 *
 * The semantics of statvfs and statfs are not entirely clear; in particular,
 * statvfs(3p) states that statvfs.f_blocks define the file-system's size in
 * f_frsize units, where f_bfree is number of free blocks (but without stating
 * explicit units). For now, we force 4K units to both, but need more
 * investigations before changing, especially with respect to various
 * user-space tools.
 */
static fsblkcnt_t bytes_to_fsblkcnt(size_t nbytes, size_t unit)
{
	return (fsblkcnt_t)nbytes / unit;
}

static void fill_statvfs(const struct silofs_sb_info *sbi, struct statvfs *stv)
{
	const size_t funit = 4 * SILOFS_KB_SIZE;
	const size_t bsize = funit;
	const size_t frsize = funit;
	const size_t nbytes_max = silofs_sbi_vspace_capacity(sbi);
	const size_t nbytes_use = silofs_sbi_nused_bytes(sbi);
	const size_t nbytes_free = nbytes_max - nbytes_use;
	const fsfilcnt_t nfiles_max = silofs_sbi_inodes_limit(sbi);
	const fsfilcnt_t nfiles_cur = silofs_sbi_inodes_current(sbi);

	silofs_assert_ge(nbytes_max, nbytes_use);

	silofs_memzero(stv, sizeof(*stv));
	stv->f_bsize = bsize;
	stv->f_frsize = frsize;
	stv->f_blocks = bytes_to_fsblkcnt(nbytes_max, frsize);
	stv->f_bfree = bytes_to_fsblkcnt(nbytes_free, bsize);
	stv->f_bavail = stv->f_bfree;
	stv->f_files = nfiles_max;
	stv->f_ffree = nfiles_max - nfiles_cur;
	stv->f_favail = stv->f_ffree;
	stv->f_namemax = SILOFS_NAME_MAX;
	stv->f_fsid = SILOFS_FSID_MAGIC;
}

static void fill_statfsx(const struct silofs_sb_info *sbi,
                         struct silofs_query_statfsx *stx)
{
	struct silofs_space_stat sp_st;

	silofs_sbi_space_stat(sbi, &sp_st);
	stx->f_uptime = silofs_time_now() - sbi->s_mntime;
	stx->f_msflags = sbi->s_ms_flags;
	stx->f_bsize = silofs_sbi_vspace_capacity(sbi);
	stx->f_bused = silofs_sbi_nused_bytes(sbi);
	stx->f_ilimit = silofs_sbi_inodes_limit(sbi);
	stx->f_icurr = silofs_sbi_inodes_current(sbi);
	stx->f_umeta = (uint64_t)sp_st.uspace_nmeta;
	stx->f_vmeta = (uint64_t)sp_st.vspace_nmeta;
	stx->f_vdata = (uint64_t)sp_st.vspace_ndata;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_statvfs(const struct silofs_fs_ctx *fs_ctx,
                      const struct silofs_inode_info *ii,
                      struct statvfs *out_stv)
{
	unused(fs_ctx);
	fill_statvfs(ii_sbi(ii), out_stv);
	return 0;
}

int silofs_do_statvfs(const struct silofs_fs_ctx *op,
                      struct silofs_inode_info *ii, struct statvfs *out_stv)
{
	int err;

	ii_incref(ii);
	err = do_statvfs(op, ii, out_stv);
	ii_decref(ii);
	return err;
}

static void fill_strbuf(char *buf, size_t bsz, const char *str)
{
	if ((str != NULL) && (bsz > 0)) {
		strncpy(buf, str, bsz - 1);
		buf[bsz - 1] = '\0';
	}
}

static void fill_query_version(const struct silofs_inode_info *ii,
                               struct silofs_ioc_query *query)
{
	const char *verstr = silofs_version.string;

	query->u.version.v_major = silofs_version.major;
	query->u.version.v_minor = silofs_version.minor;
	query->u.version.v_sublevel = silofs_version.sublevel;
	fill_strbuf(query->u.version.v_str,
	            sizeof(query->u.version.v_str), verstr);
	unused(ii);
}

static void fill_query_repo(const struct silofs_inode_info *ii,
                            struct silofs_ioc_query *query)
{
	const struct silofs_fs_apex *apex = ii_apex(ii);
	const struct silofs_repo *repo = apex->ap_mrepo;

	fill_strbuf(query->u.repo.r_path,
	            sizeof(query->u.repo.r_path), repo->re_root_dir);
}

static void fill_query_fsname(const struct silofs_inode_info *ii,
                              struct silofs_ioc_query *query)
{
	const struct silofs_fs_apex *apex = ii_apex(ii);
	const char *fsname = apex->ap_args->main_name;

	fill_strbuf(query->u.fsname.f_name,
	            sizeof(query->u.fsname.f_name), fsname);
}

static void fill_query_statfsx(const struct silofs_inode_info *ii,
                               struct silofs_ioc_query *query)
{
	fill_statfsx(ii_sbi(ii), &query->u.statfsx);
}

static int do_query_statx(const struct silofs_fs_ctx *fs_ctx,
                          struct silofs_inode_info *ii,
                          struct silofs_ioc_query *query)
{
	int err;
	enum silofs_dirf dflags;
	const unsigned int req_mask = STATX_ALL | STATX_BTIME;
	const enum silofs_inodef iflags = silofs_ii_flags(ii);

	err = silofs_do_statx(fs_ctx, ii, req_mask, &query->u.statx.stx);
	if (err) {
		return err;
	}
	query->u.statx.stx_iflags = (uint32_t)iflags;
	if (ii_isdir(ii)) {
		dflags = silofs_dir_flags(ii);
		query->u.statx.stx_dirflags = (uint32_t)dflags;
	}
	return 0;
}

static int do_query_subcmd(const struct silofs_fs_ctx *fs_ctx,
                           struct silofs_inode_info *ii,
                           enum silofs_query_type qtype,
                           struct silofs_ioc_query *query)
{
	int err = 0;

	silofs_memzero(&query->u, sizeof(query->u));

	switch (qtype) {
	case SILOFS_QUERY_VERSION:
		fill_query_version(ii, query);
		break;
	case SILOFS_QUERY_REPO:
		fill_query_repo(ii, query);
		break;
	case SILOFS_QUERY_FSNAME:
		fill_query_fsname(ii, query);
		break;
	case SILOFS_QUERY_STATFSX:
		fill_query_statfsx(ii, query);
		break;
	case SILOFS_QUERY_STATX:
		err = do_query_statx(fs_ctx, ii, query);
		break;
	case SILOFS_QUERY_NONE:
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

static int do_query(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *ii,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *query)
{
	int err;

	err = check_raccess(fs_ctx, ii);
	if (err) {
		return err;
	}
	err = do_query_subcmd(fs_ctx, ii, qtype, query);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_query(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *ii, int qtype,
                    struct silofs_ioc_query *out_qry)
{
	int err;

	ii_incref(ii);
	err = do_query(fs_ctx, ii, qtype, out_qry);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_fsowner(const struct silofs_fs_ctx *fs_ctx,
                         const struct silofs_sb_info *sbi)
{
	const struct silofs_creds *creds = creds_of(fs_ctx);

	return uid_eq(creds->ucred.uid, sbi->s_owner.uid) ? 0 : -EPERM;
}

static int check_nonactive_fsname(const struct silofs_inode_info *ii,
                                  const struct silofs_namestr *name)
{
	struct silofs_namestr name_src;
	const struct silofs_fs_apex *apex = ii_apex(ii);
	int err;

	err = check_name(name);
	if (err) {
		return err;
	}
	err = silofs_check_fs_name(name);
	if (err) {
		return err;
	}
	silofs_apex_main_fsname(apex, &name_src);
	if (silofs_namestr_isequal(name, &name_src)) {
		return -EEXIST;
	}
	return 0;
}

static bool has_main_bootsec(const struct silofs_inode_info *ii,
                             const struct silofs_namestr *name)
{
	struct silofs_bootsec bsec;
	const struct silofs_fs_apex *apex = ii_apex(ii);

	return silofs_repo_load_bsec(apex->ap_mrepo, name, &bsec) == 0;
}

static int check_no_bootsec(const struct silofs_inode_info *ii,
                            const struct silofs_namestr *name)
{
	return has_main_bootsec(ii, name) ? -EEXIST : 0;
}

static int check_has_bootsec(const struct silofs_inode_info *ii,
                             const struct silofs_namestr *name)
{
	return has_main_bootsec(ii, name) ? 0 : -ENOENT;
}

static int check_clone_flags(int flags)
{
	const int allow_flags = 0;

	return (flags & ~allow_flags) ? -EINVAL : 0;
}

static int check_dupfs(const struct silofs_fs_ctx *fs_ctx,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name)
{
	int err;

	err = check_on_writable_fs(ii);
	if (err) {
		return err;
	}
	err = check_isdir(ii);
	if (err) {
		return err;
	}
	err = check_raccess(fs_ctx, ii);
	if (err) {
		return err;
	}
	err = check_fsowner(fs_ctx, ii_sbi(ii));
	if (err) {
		return err;
	}
	err = check_nonactive_fsname(ii, name);
	if (err) {
		return err;
	}
	err = check_no_bootsec(ii, name);
	if (err) {
		return err;
	}
	return 0;
}

static int check_clone(const struct silofs_fs_ctx *fs_ctx,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name, int flags)
{
	int err;

	err = check_dupfs(fs_ctx, ii, name);
	if (err) {
		return err;
	}
	err = check_clone_flags(flags);
	if (err) {
		return err;
	}
	return 0;
}

static int do_clone(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, int flags)
{
	struct silofs_fs_apex *apex = fs_ctx->fsc_apex;
	int err;

	err = check_clone(fs_ctx, dir_ii, name, flags);
	if (err) {
		return err;
	}
	err = flush_dirty_now(apex);
	if (err) {
		return err;
	}
	err = silofs_apex_forkfs(apex, name);
	if (err) {
		return err;
	}
	err = flush_dirty_now(apex);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_clone(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, int flags)
{
	int err;

	ii_incref(dir_ii);
	err = do_clone(fs_ctx, dir_ii, name, flags);
	ii_decref(dir_ii);
	return err;
}

static int check_unrefs(const struct silofs_fs_ctx *fs_ctx,
                        struct silofs_inode_info *ii,
                        const struct silofs_namestr *name)
{
	int err;

	err = check_raccess(fs_ctx, ii);
	if (err) {
		return err;
	}
	err = check_nonactive_fsname(ii, name);
	if (err) {
		return err;
	}
	err = check_has_bootsec(ii, name);
	if (err) {
		return err;
	}
	return 0;
}

static int unrefs_by_name(const struct silofs_inode_info *ii,
                          const struct silofs_namestr *name)
{
	const struct silofs_fs_apex *apex = ii_apex(ii);

	return silofs_repo_remove_bsec(apex->ap_mrepo, name);
}

static int do_unrefs(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *ii,
                     const struct silofs_namestr *name)
{
	int err;

	err = check_unrefs(fs_ctx, ii, name);
	if (err) {
		return err;
	}
	err = unrefs_by_name(ii, name);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_unrefs(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *ii,
                     const struct silofs_namestr *name)
{
	int err;

	ii_incref(ii);
	err = do_unrefs(fs_ctx, ii, name);
	ii_decref(ii);
	return err;
}

static int check_inspect(const struct silofs_fs_ctx *fs_ctx,
                         struct silofs_inode_info *ii)
{
	int err;

	err = check_raccess(fs_ctx, ii);
	if (err) {
		return err;
	}
	err = check_on_writable_fs(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int inspect_uspace(const struct silofs_inode_info *ii)
{
	struct silofs_bootsec bsec;
	struct silofs_namestr name;
	struct silofs_uspace_visitor usv;
	struct silofs_fs_apex *apex = ii_apex(ii);
	struct silofs_sb_info *sbi = NULL;
	int err;

	silofs_usvisitor_init(&usv, apex->ap_alif);
	err = silofs_apex_boot_name(apex, &name);
	if (err) {
		goto out;
	}
	err = silofs_apex_load_boot(apex, &name, &bsec);
	if (err) {
		goto out;
	}
	err = flush_dirty_now(apex);
	if (err) {
		goto out;
	}
	err = silofs_apex_stage_super(apex, &bsec.sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	err = silofs_walk_space_tree(sbi, &usv.vis);
	if (err) {
		goto out;
	}
out:
	silofs_usvisitor_fini(&usv);
	return err;
}

static int do_inspect(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *ii)
{
	int err;

	err = check_inspect(fs_ctx, ii);
	if (err) {
		return err;
	}
	err = inspect_uspace(ii);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_inspect(const struct silofs_fs_ctx *fs_ctx,
                      struct silofs_inode_info *ii)
{
	int err;

	ii_incref(ii);
	err = do_inspect(fs_ctx, ii);
	ii_decref(ii);
	return err;
}

int silof_check_writable_fs(const struct silofs_sb_info *sbi)
{
	return silofs_sbi_isrofs(sbi) ? -EROFS : 0;
}

static bool unirepo_mode(const struct silofs_fs_ctx *fs_ctx)
{
	const struct silofs_repo *mrepo = fs_ctx->fsc_apex->ap_mrepo;
	const struct silofs_repo *crepo = fs_ctx->fsc_apex->ap_crepo;
	bool uni = false;

	if (mrepo && crepo) {
		uni = !strcmp(mrepo->re_root_dir, crepo->re_root_dir);
	}
	return uni;
}

static int check_pack(const struct silofs_fs_ctx *fs_ctx,
                      const struct silofs_namestr *src_name,
                      const struct silofs_namestr *dst_name)
{
	const int eq = silofs_namestr_isequal(src_name, dst_name);
	int err;

	err = silofs_check_fs_name(src_name);
	if (err) {
		return err;
	}
	err = silofs_check_fs_name(dst_name);
	if (err) {
		return err;
	}
	if (eq && unirepo_mode(fs_ctx)) {
		return -EEXIST;
	}
	return 0;
}

int silofs_do_pack(const struct silofs_fs_ctx *fs_ctx,
                   const struct silofs_namestr *src_name,
                   const struct silofs_namestr *dst_name)
{
	struct silofs_fs_apex *apex = fs_ctx->fsc_apex;
	int err;

	err = check_pack(fs_ctx, src_name, dst_name);
	if (err) {
		return err;
	}
	err = flush_dirty_now(apex);
	if (err) {
		return err;
	}
	err = silofs_apex_pack_fs(apex, src_name, dst_name);
	if (err) {
		return err;
	}
	err = flush_dirty_now(apex);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_unpack(const struct silofs_fs_ctx *fs_ctx,
                     const struct silofs_namestr *src_name,
                     const struct silofs_namestr *dst_name)
{
	struct silofs_fs_apex *apex = fs_ctx->fsc_apex;
	int err;

	err = check_pack(fs_ctx, src_name, dst_name);
	if (err) {
		return err;
	}
	err = flush_dirty_now(apex);
	if (err) {
		return err;
	}
	err = silofs_apex_unpack_fs(apex, src_name, dst_name);
	if (err) {
		return err;
	}
	err = flush_dirty_now(apex);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

union silofs_utf32_name_buf {
	char dat[4 * (SILOFS_NAME_MAX + 1)];
	uint32_t utf32[SILOFS_NAME_MAX + 1];
} silofs_aligned64;


static int check_utf8_name(const struct silofs_fs_apex *apex,
                           const struct silofs_namestr *nstr)
{
	union silofs_utf32_name_buf unb;
	char *in = unconst(nstr->str.str);
	char *out = unb.dat;
	size_t len = nstr->str.len;
	size_t outlen = sizeof(unb.dat);
	size_t datlen;
	size_t ret;

	ret = iconv(apex->ap_iconv, &in, &len, &out, &outlen);
	if ((ret != 0) || len || (outlen % 4)) {
		return errno ? -errno : -EINVAL;
	}
	datlen = sizeof(unb.dat) - outlen;
	if (datlen == 0) {
		return -EINVAL;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t namehash_by_sha256(const struct silofs_mdigest *md,
                                   const char *name, size_t nlen)
{
	struct silofs_hash256 sha256;

	silofs_sha256_of(md, name, nlen, &sha256);
	return silofs_hash256_to_u64(&sha256);
}

static const struct silofs_mdigest *
ii_mdigest_of(const struct silofs_inode_info *ii)
{
	return &ii->i_vi.v_ti.t_apex->ap_crypto->md;
}

static int name_to_hash(const struct silofs_inode_info *dir_ii,
                        const char *name, size_t nlen, uint64_t *out_hash)
{
	int err;
	const struct silofs_mdigest *md = ii_mdigest_of(dir_ii);
	const enum silofs_dirf flags = silofs_dir_flags(dir_ii);

	if (flags & SILOFS_DIRF_HASH_SHA256) {
		*out_hash = namehash_by_sha256(md, name, nlen);
		err = 0;
	} else {
		*out_hash = 0;
		err = -EFSCORRUPTED;
	}
	return err;
}

static int namestr_to_hash(const struct silofs_inode_info *dir_ii,
                           const struct silofs_namestr *ns, uint64_t *out_hash)
{
	return name_to_hash(dir_ii, ns->str.str, ns->str.len, out_hash);
}

static int check_name_len(const struct silofs_namestr *nstr)
{
	if (nstr->str.len == 0) {
		return -EINVAL;
	}
	if (nstr->str.len > SILOFS_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	return 0;
}

static int check_name_dat(const struct silofs_namestr *nstr)
{
	if (nstr->str.str == NULL) {
		return -EINVAL;
	}
	if (memchr(nstr->str.str, '/', nstr->str.len)) {
		return -EINVAL;
	}
	if (nstr->str.str[nstr->str.len] != '\0') {
		return -EINVAL;
	}
	return 0;
}

static int check_name_str(const struct silofs_namestr *nstr)
{
	int err;

	err = check_name_len(nstr);
	if (err) {
		return err;
	}
	err = check_name_dat(nstr);
	if (err) {
		return err;
	}
	return 0;
}

static int check_ascii_fs_name(const struct silofs_namestr *nstr)
{
	const char *allowed =
	        "abcdefghijklmnopqrstuvwxyz"
	        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	        "0123456789_-+.";
	struct silofs_substr ss;
	size_t n;

	silofs_substr_init_rd(&ss, nstr->str.str, nstr->str.len);
	if (!silofs_substr_isprint(&ss)) {
		return -EINVAL;
	}
	n = silofs_substr_count_if(&ss, silofs_chr_isspace);
	if (n > 0) {
		return -EINVAL;
	}
	n = silofs_substr_count_if(&ss, silofs_chr_iscntrl);
	if (n > 0) {
		return -EINVAL;
	}
	n = silofs_substr_find_first_not_of(&ss, allowed);
	if (n < ss.len) {
		return -EINVAL;
	}
	return 0;
}

int silofs_check_fs_name(const struct silofs_namestr *nstr)
{
	int err;

	err = check_name_str(nstr);
	if (err) {
		return err;
	}
	if (nstr->str.str[0] == '.') {
		return -EINVAL;
	}
	if (nstr->str.len > (SILOFS_NAME_MAX / 2)) {
		return -ENAMETOOLONG;
	}
	err = check_ascii_fs_name(nstr);
	if (err) {
		return err;
	}
	return 0;
}

static int check_valid_encoding(const struct silofs_inode_info *ii,
                                const struct silofs_namestr *nstr)
{
	int ret = 0;

	if (ii_isdir(ii) && dir_hasflag(ii, SILOFS_DIRF_NAME_UTF8)) {
		ret = check_utf8_name(ii_apex(ii), nstr);
	}
	return ret;
}

int silofs_make_namestr_by(struct silofs_namestr *nstr,
                           const struct silofs_inode_info *ii, const char *s)
{
	int err;

	silofs_namestr_init(nstr, s);
	err = check_name_str(nstr);
	if (err) {
		return err;
	}
	err = check_valid_encoding(ii, nstr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_make_fsnamestr(struct silofs_namestr *nstr, const char *s)
{
	silofs_namestr_init(nstr, s);
	return silofs_check_fs_name(nstr);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int try_forget_cached_ii(struct silofs_inode_info *ii)
{
	if ((ii->i_nlookup <= 0) && ii_isevictable(ii)) {
		silofs_cache_forget_vnode(ii_cache(ii), ii_to_vi(ii));
	}
	return 0;
}

int silofs_do_forget(const struct silofs_fs_ctx *fs_ctx,
                     struct silofs_inode_info *ii, size_t nlookup)
{
	int err;

	ii_sub_nlookup(ii, (long)nlookup);

	if (ii->i_pinned) {
		/* case of prune special files created by MKNOD */
		ii->i_pinned = false;
		err = try_prune_inode(fs_ctx, ii, false);
	} else {
		err = try_forget_cached_ii(ii);
	}
	return err;
}
