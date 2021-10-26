/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/super.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>
#include <silofs/fs/ioctls.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
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

static bool isowner(const struct silofs_oper *op,
                    const struct silofs_inode_info *ii)
{
	return uid_eq(op->ucred.uid, ii_uid(ii));
}

static bool has_cap_fowner(const struct silofs_oper *op)
{
	return silofs_user_cap_fowner(&op->ucred);
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
	    !(apex->fa_ops.op_iopen < apex->fa_ops.op_iopen_max)) {
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
		apex->fa_ops.op_iopen++;
	} else if ((n < 0) && (ii->i_nopen == 1)) {
		apex->fa_ops.op_iopen--;
	}
	ii->i_nopen += n;
}

static bool has_sticky_bit(const struct silofs_inode_info *dir_ii)
{
	const mode_t mode = ii_mode(dir_ii);

	return ((mode & S_ISVTX) == S_ISVTX);
}

static int check_sticky(const struct silofs_oper *op,
                        const struct silofs_inode_info *dir_ii,
                        const struct silofs_inode_info *ii)
{
	if (!has_sticky_bit(dir_ii)) {
		return 0; /* No sticky-bit, we're fine */
	}
	if (isowner(op, dir_ii)) {
		return 0;
	}
	if (ii && isowner(op, ii)) {
		return 0;
	}
	if (has_cap_fowner(op)) {
		return 0;
	}
	return -EPERM;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int new_inode(const struct silofs_oper *op,
                     const struct silofs_inode_info *parent_dir_ii,
                     mode_t mode, dev_t rdev,
                     struct silofs_inode_info **out_ii)
{
	const ino_t parent_ino = ii_ino(parent_dir_ii);
	const mode_t parent_mode = ii_mode(parent_dir_ii);
	struct silofs_sb_info *sbi = ii_sbi(parent_dir_ii);

	return silofs_spawn_inode(sbi, op, parent_ino, parent_mode,
	                          mode, rdev, out_ii);
}

static int new_dir_inode(const struct silofs_oper *op,
                         const struct silofs_inode_info *parent_dir_ii,
                         mode_t mode, struct silofs_inode_info **out_ii)
{
	const mode_t ifmt = S_IFMT;
	const mode_t dir_mode = (mode & ~ifmt) | S_IFDIR;

	return new_inode(op, parent_dir_ii, dir_mode, 0, out_ii);
}

static int new_reg_inode(const struct silofs_oper *op,
                         const struct silofs_inode_info *parent_dir_ii,
                         mode_t mode, struct silofs_inode_info **out_ii)
{
	const mode_t ifmt = S_IFMT;
	const mode_t reg_mode = (mode & ~ifmt) | S_IFREG;

	return new_inode(op, parent_dir_ii, reg_mode, 0, out_ii);
}

static int new_lnk_inode(const struct silofs_oper *op,
                         const struct silofs_inode_info *parent_dir_ii,
                         struct silofs_inode_info **out_ii)
{
	const mode_t lnk_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFLNK;

	return new_inode(op, parent_dir_ii, lnk_mode, 0, out_ii);
}

static int new_inode_by_mode(const struct silofs_oper *op,
                             const struct silofs_inode_info *parent_dir_ii,
                             mode_t mode, dev_t rdev,
                             struct silofs_inode_info **out_ii)
{
	int err;

	if (S_ISREG(mode)) {
		err = new_reg_inode(op, parent_dir_ii, mode, out_ii);
	} else if (S_ISLNK(mode)) {
		err = new_lnk_inode(op, parent_dir_ii, out_ii);
	} else if (S_ISFIFO(mode) || S_ISSOCK(mode)) {
		err = new_inode(op, parent_dir_ii, mode, rdev, out_ii);
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

static int do_access(const struct silofs_oper *op,
                     const struct silofs_inode_info *ii, int mode)
{
	mode_t rwx = 0;
	const uid_t uid = op->ucred.uid;
	const gid_t gid = op->ucred.gid;
	const uid_t i_uid = ii_uid(ii);
	const gid_t i_gid = ii_gid(ii);
	const mode_t i_mode = ii_mode(ii);
	const mode_t mask = (mode_t)mode;

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

int silofs_do_access(const struct silofs_oper *op,
                     struct silofs_inode_info *ii, int mode)
{
	int err;

	ii_incref(ii);
	err = do_access(op, ii, mode);
	ii_decref(ii);
	return err;
}

static int check_on_writable_fs(const struct silofs_inode_info *ii)
{
	return silof_check_writable_fs(ii_sbi(ii));
}

static int check_waccess(const struct silofs_oper *op,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(op, ii, W_OK);
}

static int check_xaccess(const struct silofs_oper *op,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(op, ii, X_OK);
}

static int check_raccess(const struct silofs_oper *op,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(op, ii, R_OK);
}

static int check_dir_waccess(const struct silofs_oper *op,
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
	err = check_waccess(op, ii);
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

static int check_lookup(const struct silofs_oper *op,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	int err;

	err = check_dir_and_name(dir_ii, name);
	if (err) {
		return err;
	}
	err = check_xaccess(op, dir_ii);
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

static int lookup_by_name(const struct silofs_oper *op,
                          struct silofs_inode_info *dir_ii,
                          const struct silofs_namestr *nstr, ino_t *out_ino)
{
	int err;
	struct silofs_qstr name;
	struct silofs_ino_dt ino_dt;

	err = assign_namehash(dir_ii, nstr, &name);
	if (err) {
		return err;
	}
	err = silofs_lookup_dentry(op, dir_ii, &name, &ino_dt);
	if (err) {
		return err;
	}
	*out_ino = ino_dt.ino;
	return 0;
}

static int stage_by_name(const struct silofs_oper *op,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         enum silofs_stage_flags stg_flags,
                         struct silofs_inode_info **out_ii)
{
	int err;
	ino_t ino;
	struct silofs_sb_info *sbi = ii_sbi(dir_ii);

	err = lookup_by_name(op, dir_ii, name, &ino);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(sbi, ino, stg_flags, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_lookup(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	err = check_lookup(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = stage_by_name(op, dir_ii, name, SILOFS_STAGE_RDONLY, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_lookup(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_lookup(op, dir_ii, name, out_ii);
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

static int check_nodent(const struct silofs_oper *op,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	int err;
	ino_t ino;

	err = lookup_by_name(op, dir_ii, name, &ino);
	if (err == 0) {
		return -EEXIST;
	}
	return (err == -ENOENT) ? 0 : err;
}

static int check_add_dentry(const struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name)
{
	int err;
	size_t ndents;
	const size_t ndents_max = SILOFS_DIR_ENTRIES_MAX;

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

static int check_dir_can_add(const struct silofs_oper *op,
                             struct silofs_inode_info *dir_ii,
                             const struct silofs_namestr *name)
{
	int err;

	err = check_dir_waccess(op, dir_ii);
	if (err) {
		return err;
	}
	err = check_nodent(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_add_dentry(dir_ii, name);
	if (err) {
		return err;
	}
	return 0;
}

static int check_create(const struct silofs_oper *op,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name, mode_t mode)
{
	int err;

	err = check_on_writable_fs(dir_ii);
	if (err) {
		return err;
	}
	err = check_dir_can_add(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_create_mode(mode);
	if (err) {
		return err;
	}
	return 0;
}

static int do_add_dentry(const struct silofs_oper *op,
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
	err = silofs_add_dentry(op, dir_ii, &name, ii);
	if (err && del_upon_failure) {
		del_inode(ii);
	}
	return err;
}

static int do_create(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_create(op, dir_ii, name, mode);
	if (err) {
		return err;
	}
	err = new_inode_by_mode(op, dir_ii, mode, 0, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(op, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	update_nopen(ii, 1);
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_create(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_create(op, dir_ii, name, mode, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static int check_mknod(const struct silofs_oper *op,
                       struct silofs_inode_info *dir_ii,
                       const struct silofs_namestr *name,
                       mode_t mode, dev_t rdev)
{
	int err;
	const struct silofs_sb_info *sbi = ii_sbi(dir_ii);

	err = check_dir_can_add(op, dir_ii, name);
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

static int create_special_inode(const struct silofs_oper *op,
                                struct silofs_inode_info *dir_ii,
                                mode_t mode, dev_t rdev,
                                struct silofs_inode_info **out_ii)
{
	int err;

	err = new_inode(op, dir_ii, mode, rdev, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_mknod_reg(const struct silofs_oper *op,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name, mode_t mode,
                        struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = do_create(op, dir_ii, name, mode, &ii);
	if (err) {
		return err;
	}
	/* create reg via 'mknod' does not follow by release */
	update_nopen(ii, -1);
	*out_ii = ii;
	return 0;
}

static int do_mknod_special(const struct silofs_oper *op,
                            struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name,
                            mode_t mode, dev_t rdev,
                            struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_mknod(op, dir_ii, name, mode, rdev);
	if (err) {
		return err;
	}
	err = create_special_inode(op, dir_ii, mode, rdev, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(op, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);

	/* can not use 'nopen' as FUSE does not sent OPEN on fifo, and
	 * therefore no RELEASE */
	ii->i_pinned = true;

	*out_ii = ii;
	return 0;
}

int silofs_do_mknod(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name,
                    mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii)
{
	int err;
	const bool mknod_reg = S_ISREG(mode);

	ii_incref(dir_ii);
	if (mknod_reg) {
		err = do_mknod_reg(op, dir_ii, name, mode, out_ii);
	} else {
		err = do_mknod_special(op, dir_ii, name, mode, dev, out_ii);
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

static int check_open(const struct silofs_oper *op,
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
	err = silofs_do_access(op, ii, rwx);
	if (err) {
		return err;
	}
	err = check_open_limit(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int post_open(const struct silofs_oper *op,
                     struct silofs_inode_info *ii, int o_flags)
{
	return (ii_isreg(ii) && (o_flags & O_TRUNC)) ?
	       silofs_do_truncate(op, ii, 0) : 0;
}

static int do_open(const struct silofs_oper *op,
                   struct silofs_inode_info *ii, int o_flags)
{
	int err;

	err = check_open(op, ii, o_flags);
	if (err) {
		return err;
	}
	err = post_open(op, ii, o_flags);
	if (err) {
		return err;
	}
	update_nopen(ii, 1);
	return 0;
}

int silofs_do_open(const struct silofs_oper *op,
                   struct silofs_inode_info *ii, int o_flags)
{
	int err;

	ii_incref(ii);
	err = do_open(op, ii, o_flags);
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

static int try_prune_inode(const struct silofs_oper *op,
                           struct silofs_inode_info *ii, bool update_ctime)
{
	if (!ii->i_nopen && ii_isnlink_orphan(ii)) {
		ii_undirtify(ii);
	}
	if (ii_isdropable(ii)) {
		return drop_unlinked(ii);
	}
	if (update_ctime) {
		update_itimes(op, ii, SILOFS_IATTR_CTIME);
	}
	return 0;
}

static int remove_dentry_of(const struct silofs_oper *op,
                            struct silofs_inode_info *dir_ii,
                            struct silofs_inode_info *ii,
                            const struct silofs_qstr *name)
{
	int err;

	ii_incref(ii);
	err = silofs_remove_dentry(op, dir_ii, name);
	ii_decref(ii);
	return err;
}

static int do_remove_and_prune(const struct silofs_oper *op,
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
	err = remove_dentry_of(op, dir_ii, ii, &name);
	if (err) {
		return err;
	}
	err = try_prune_inode(op, ii, true);
	if (err) {
		return err;
	}
	return 0;
}

static int check_prepare_unlink(const struct silofs_oper *op,
                                struct silofs_inode_info *dir_ii,
                                const struct silofs_namestr *nstr,
                                struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_dir_waccess(op, dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(op, dir_ii, nstr, SILOFS_STAGE_MUTABLE, &ii);
	if (err) {
		return err;
	}
	err = check_sticky(op, dir_ii, ii);
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

static int do_unlink(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *nstr)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_prepare_unlink(op, dir_ii, nstr, &ii);
	if (err) {
		return err;
	}
	err = do_remove_and_prune(op, dir_ii, nstr, ii);
	if (err) {
		return err;
	}
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_unlink(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name)
{
	int err;

	ii_incref(dir_ii);
	err = do_unlink(op, dir_ii, name);
	ii_decref(dir_ii);
	return err;
}

static int check_nomlink(const struct silofs_inode_info *ii)
{
	const size_t link_max = SILOFS_LINK_MAX;

	return (ii_nlink(ii) < link_max) ? 0 : -EMLINK;
}

static int check_link(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      struct silofs_inode_info *ii)
{
	int err;

	err = check_dir_waccess(op, dir_ii);
	if (err) {
		return err;
	}
	err = check_notdir(ii);
	if (err) {
		return err;
	}
	err = check_nodent(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_nomlink(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_link(const struct silofs_oper *op,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *nstr,
                   struct silofs_inode_info *ii)
{
	int err;

	err = check_link(op, dir_ii, nstr, ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(op, dir_ii, nstr, ii, false);
	if (err) {
		return err;
	}
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);
	update_itimes(op, ii, SILOFS_IATTR_CTIME);

	return 0;
}

int silofs_do_link(const struct silofs_oper *op,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info *ii)
{
	int err;

	ii_incref(dir_ii);
	ii_incref(ii);
	err = do_link(op, dir_ii, name, ii);
	ii_inc_nlookup(ii, err);
	ii_decref(ii);
	ii_decref(dir_ii);
	return err;
}

static int check_mkdir(const struct silofs_oper *op,
                       struct silofs_inode_info *dir_ii,
                       const struct silofs_namestr *name)
{
	int err;

	err = check_dir_can_add(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_nomlink(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_mkdir(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii;

	err = check_mkdir(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = new_dir_inode(op, dir_ii, mode, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(op, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_mkdir(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_mkdir(op, dir_ii, name, mode, out_ii);
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

static int check_rmdir_child(const struct silofs_oper *op,
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
	err = check_sticky(op, parent_ii, dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_prepare_rmdir(const struct silofs_oper *op,
                               struct silofs_inode_info *dir_ii,
                               const struct silofs_namestr *name,
                               struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_dir_waccess(op, dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(op, dir_ii, name, SILOFS_STAGE_MUTABLE, &ii);
	if (err) {
		return err;
	}
	err = check_rmdir_child(op, dir_ii, ii);
	if (err) {
		return err;
	}
	*out_ii = ii;
	return 0;
}

static int do_rmdir(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_prepare_rmdir(op, dir_ii, name, &ii);
	if (err) {
		return err;
	}
	err = do_remove_and_prune(op, dir_ii, name, ii);
	if (err) {
		return err;
	}
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_rmdir(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name)
{
	int err;

	ii_incref(dir_ii);
	err = do_rmdir(op, dir_ii, name);
	ii_decref(dir_ii);
	return err;
}

static int create_lnk_inode(const struct silofs_oper *op,
                            const struct silofs_inode_info *dir_ii,
                            const struct silofs_str *linkpath,
                            struct silofs_inode_info **out_ii)
{
	int err;

	err = new_lnk_inode(op, dir_ii, out_ii);
	if (err) {
		return err;
	}
	err = silofs_setup_symlink(op, *out_ii, linkpath);
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

static int check_symlink(const struct silofs_oper *op,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         const struct silofs_str *symval)
{
	int err;

	err = check_dir_can_add(op, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_symval(symval);
	if (err) {
		return err;
	}
	return 0;
}

static int do_symlink(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_symlink(op, dir_ii, name, symval);
	if (err) {
		return err;
	}
	err = create_lnk_inode(op, dir_ii, symval, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(op, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	update_itimes(op, dir_ii, SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_symlink(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_symlink(op, dir_ii, name, symval, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_opendir(const struct silofs_oper *op,
                         struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = check_raccess(op, dir_ii);
	if (err) {
		return err;
	}
	err = check_open_limit(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_opendir(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_opendir(op, dir_ii);
	if (err) {
		return err;
	}
	update_nopen(dir_ii, 1);
	return 0;
}

int silofs_do_opendir(const struct silofs_oper *op,
                      struct silofs_inode_info *dir_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_opendir(op, dir_ii);
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

static int flush_dirty_of(const struct silofs_inode_info *ii, int flags)
{
	return silofs_apex_flush_dirty(ii_apex(ii), flags);
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

int silofs_do_releasedir(const struct silofs_oper *op,
                         struct silofs_inode_info *dir_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_releasedir(dir_ii);
	ii_decref(dir_ii);

	return !err ? try_prune_inode(op, dir_ii, false) : err;
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

int silofs_do_release(const struct silofs_oper *op,
                      struct silofs_inode_info *ii)
{
	int err;

	ii_incref(ii);
	err = do_release(ii);
	ii_decref(ii);

	return !err ? try_prune_inode(op, ii, false) : err;
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

int silofs_do_fsyncdir(const struct silofs_oper *op,
                       struct silofs_inode_info *dir_ii, bool dsync)
{
	int err;

	ii_incref(dir_ii);
	err = do_fsyncdir(dir_ii);
	ii_decref(dir_ii);

	silofs_unused(op);
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
 * TODO-0029 Revisit fsync semantics
 *
 * Re-think it over. See also:
 * https://lwn.net/Articles/351422/
 * https://lwn.net/Articles/322823/
 */
int silofs_do_fsync(const struct silofs_oper *op,
                    struct silofs_inode_info *ii, bool datasync)
{
	int err;

	ii_incref(ii);
	err = do_fsync(ii);
	ii_decref(ii);

	silofs_unused(op);
	silofs_unused(datasync);

	return err;
}

int silofs_do_flush(const struct silofs_oper *op,
                    struct silofs_inode_info *ii)
{
	const int flags = (op->ucred.uid == 0) ? SILOFS_F_NOW : 0;

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

static int do_add_dentry_at(const struct silofs_oper *op,
                            struct silofs_dentry_ref *dref,
                            struct silofs_inode_info *ii)

{
	int err;

	err = do_add_dentry(op, dref->dir_ii, dref->name, ii, false);
	if (err) {
		return err;
	}
	dref->ii = ii;
	return 0;
}

static int do_remove_and_prune_at(const struct silofs_oper *op,
                                  struct silofs_dentry_ref *dref)
{
	int err;

	err = do_remove_and_prune(op, dref->dir_ii, dref->name, dref->ii);
	if (err) {
		return err;
	}
	dref->ii = NULL;
	return 0;
}

static int do_rename_move(const struct silofs_oper *op,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	int err;
	struct silofs_inode_info *ii = cur_dref->ii;

	err = check_add_dentry_at(new_dref);
	if (err) {
		return err;
	}
	err = do_remove_and_prune_at(op, cur_dref);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(op, new_dref, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_move(const struct silofs_oper *op,
                       struct silofs_dentry_ref *cur_dref,
                       struct silofs_dentry_ref *new_dref)
{
	int err;
	struct silofs_inode_info *ii = cur_dref->ii;

	ii_incref(ii);
	err = do_rename_move(op, cur_dref, new_dref);
	ii_decref(ii);
	return err;
}

static int rename_unlink(const struct silofs_oper *op,
                         struct silofs_dentry_ref *dref)
{
	return do_remove_and_prune_at(op, dref);
}

static int do_rename_replace(const struct silofs_oper *op,
                             struct silofs_dentry_ref *cur_dref,
                             struct silofs_dentry_ref *new_dref)
{
	int err;
	struct silofs_inode_info *ii = cur_dref->ii;

	err = do_remove_and_prune_at(op, cur_dref);
	if (err) {
		return err;
	}
	err = do_remove_and_prune_at(op, new_dref);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(op, new_dref, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_replace(const struct silofs_oper *op,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	int err;
	struct silofs_inode_info *ii = cur_dref->ii;

	ii_incref(ii);
	err = do_rename_replace(op, cur_dref, new_dref);
	ii_decref(ii);
	return err;
}

static int do_rename_exchange(const struct silofs_oper *op,
                              struct silofs_dentry_ref *dref1,
                              struct silofs_dentry_ref *dref2)
{
	int err;
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;

	err = do_remove_and_prune_at(op, dref1);
	if (err) {
		return err;
	}
	err = do_remove_and_prune_at(op, dref2);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(op, dref2, ii1);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(op, dref1, ii2);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_exchange(const struct silofs_oper *op,
                           struct silofs_dentry_ref *dref1,
                           struct silofs_dentry_ref *dref2)
{
	int err;
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;

	ii_incref(ii1);
	ii_incref(ii2);
	err = do_rename_exchange(op, dref1, dref2);
	ii_decref(ii2);
	ii_decref(ii1);
	return err;
}

static int rename_specific(const struct silofs_oper *op,
                           struct silofs_dentry_ref *cur_dref,
                           struct silofs_dentry_ref *new_dref, int flags)
{
	int err;

	if (new_dref->ii == NULL) {
		err = rename_move(op, cur_dref, new_dref);
	} else if (cur_dref->ii == new_dref->ii) {
		err = rename_unlink(op, cur_dref);
	} else if (flags & RENAME_EXCHANGE) {
		err = rename_exchange(op, cur_dref, new_dref);
	} else {
		err = rename_replace(op, cur_dref, new_dref);
	}
	update_itimes(op, cur_dref->dir_ii, SILOFS_IATTR_MCTIME);
	update_itimes(op, new_dref->dir_ii, SILOFS_IATTR_MCTIME);
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

static int check_rename(const struct silofs_oper *op,
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
		      check_rmdir_child(op, cur_dref->dir_ii, old_ii);
	}
	return err;
}

static int check_stage_rename_at(const struct silofs_oper *op,
                                 struct silofs_dentry_ref *dref, bool new_de)
{
	int err;

	err = check_dir_waccess(op, dref->dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(op, dref->dir_ii, dref->name,
	                    SILOFS_STAGE_MUTABLE, &dref->ii);
	if (err) {
		return ((err == -ENOENT) && new_de) ? 0 : err;
	}
	err = check_sticky(op, dref->dir_ii, dref->ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_rename(const struct silofs_oper *op,
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

	err = check_stage_rename_at(op, &cur_dref, false);
	if (err) {
		return err;
	}
	err = check_stage_rename_at(op, &new_dref, true);
	if (err) {
		return err;
	}
	err = check_rename(op, &cur_dref, &new_dref, flags);
	if (err) {
		return err;
	}
	err = rename_specific(op, &cur_dref, &new_dref, flags);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_rename(const struct silofs_oper *op,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags)
{
	int err;

	ii_incref(dir_ii);
	ii_incref(newdir_ii);
	err = do_rename(op, dir_ii, name, newdir_ii, newname, flags);
	ii_decref(newdir_ii);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_statvfs(const struct silofs_oper *op,
                      const struct silofs_inode_info *ii,
                      struct statvfs *out_stv)
{
	const struct silofs_sb_info *sbi = ii_sbi(ii);

	unused(op);
	silofs_statvfs_of(sbi, out_stv);
	return 0;
}

int silofs_do_statvfs(const struct silofs_oper *op,
                      struct silofs_inode_info *ii, struct statvfs *out_stv)
{
	int err;

	ii_incref(ii);
	err = do_statvfs(op, ii, out_stv);
	ii_decref(ii);
	return err;
}

static void fill_query_version(const struct silofs_inode_info *ii,
                               struct silofs_ioc_query *query)
{
	query->u.version.major = silofs_version.major;
	query->u.version.minor = silofs_version.minor;
	query->u.version.sublevel = silofs_version.sublevel;
	strncpy(query->u.version.string, silofs_version.string,
	        sizeof(query->u.version.string) - 1);
	unused(ii);
}

static void fill_query_volume(const struct silofs_inode_info *ii,
                              struct silofs_ioc_query *query)
{
	const struct silofs_fs_apex *apex = ii_apex(ii);
	const char *repodir = apex->fa_repo->re_base_dir;

	query->u.volume.size = 0; /* XXX FIXME */
	if (repodir != NULL) {
		strncpy(query->u.volume.path, repodir,
		        sizeof(query->u.volume.path) - 1);
	}
}

static void fill_query_fsinfo(const struct silofs_inode_info *ii,
                              struct silofs_ioc_query *query)
{
	const struct silofs_sb_info *sbi = ii_sbi(ii);

	query->u.fsinfo.uptime = silofs_time_now() - sbi->s_mntime;
	query->u.fsinfo.msflags = sbi->s_ms_flags;
}

static void fill_query_inode(const struct silofs_inode_info *ii,
                             struct silofs_ioc_query *query)
{
	const enum silofs_inodef iflags = silofs_ii_flags(ii);
	const enum silofs_dirf dirflags =
	        ii_isdir(ii) ? silofs_dir_flags(ii) : 0;

	query->u.inode.iflags = (uint32_t)iflags;
	query->u.inode.dirflags = (uint32_t)dirflags;
}

static int fill_query_result(const struct silofs_inode_info *ii,
                             struct silofs_ioc_query *query)
{
	const enum silofs_query_type qtype = query->qtype;

	silofs_memzero(&query->u, sizeof(query->u));

	switch (qtype) {
	case SILOFS_QUERY_VERSION:
		fill_query_version(ii, query);
		break;
	case SILOFS_QUERY_VOLUME:
		fill_query_volume(ii, query);
		break;
	case SILOFS_QUERY_FSINFO:
		fill_query_fsinfo(ii, query);
		break;
	case SILOFS_QUERY_INODE:
		fill_query_inode(ii, query);
		break;
	case SILOFS_QUERY_NONE:
	default:
		return -EINVAL;
	}
	return 0;
}

static int do_query(const struct silofs_oper *op,
                    struct silofs_inode_info *ii,
                    struct silofs_ioc_query *query)
{
	int err;

	err = check_raccess(op, ii);
	if (err) {
		return err;
	}
	err = fill_query_result(ii, query);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_query(const struct silofs_oper *op,
                    struct silofs_inode_info *ii,
                    struct silofs_ioc_query *out_qry)
{
	int err;

	ii_incref(ii);
	err = do_query(op, ii, out_qry);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_fsowner(const struct silofs_sb_info *sbi,
                         const struct silofs_oper *op)
{
	return uid_eq(op->ucred.uid, sbi->s_owner.uid) ? 0 : -EPERM;
}

static int check_snapable_dir(const struct silofs_inode_info *ii)
{
	if (!ii_isdir(ii)) {
		return -ENOTDIR;
	}
	return 0;
}

static int check_clone(const struct silofs_oper *op,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name, int flags)
{
	int err;

	err = check_on_writable_fs(ii);
	if (err) {
		return err;
	}
	err = check_snapable_dir(ii);
	if (err) {
		return err;
	}
	err = check_raccess(op, ii);
	if (err) {
		return err;
	}
	err = check_fsowner(ii_sbi(ii), op);
	if (err) {
		return err;
	}
	err = check_name(name);
	if (err) {
		return err;
	}
	silofs_unused(flags);
	return 0;
}

static int do_clone(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, int flags)
{
	int err;
	struct silofs_fs_apex *apex = ii_apex(dir_ii);

	err = check_clone(op, dir_ii, name, flags);
	if (err) {
		return err;
	}
	err = silofs_apex_flush_dirty(apex, SILOFS_F_NOW);
	if (err) {
		return err;
	}
	err = silofs_apex_forkfs(apex, name);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_clone(const struct silofs_oper *op,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, int flags)
{
	int err;

	ii_incref(dir_ii);
	err = do_clone(op, dir_ii, name, flags);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

union silofs_utf32_name_buf {
	char dat[4 * (SILOFS_NAME_MAX + 1)];
	uint32_t utf32[SILOFS_NAME_MAX + 1];
} silofs_aligned64;


static int check_utf8_name(const struct silofs_fs_apex *apex,
                           const char *name, size_t name_len)
{
	union silofs_utf32_name_buf unb;
	char *in = unconst(name);
	char *out = unb.dat;
	size_t len = name_len;
	size_t outlen = sizeof(unb.dat);
	size_t datlen;
	size_t ret;

	ret = iconv(apex->fa_iconv, &in, &len, &out, &outlen);
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

static uint64_t u64_of(const uint8_t p[8])
{
	uint64_t u = 0;

	u |= (uint64_t)(p[0]) << 56;
	u |= (uint64_t)(p[1]) << 48;
	u |= (uint64_t)(p[2]) << 40;
	u |= (uint64_t)(p[3]) << 32;
	u |= (uint64_t)(p[4]) << 24;
	u |= (uint64_t)(p[5]) << 16;
	u |= (uint64_t)(p[6]) << 8;
	u |= (uint64_t)(p[7]);

	return u;
}

static uint64_t hash256_to_u64(const struct silofs_hash256 *hash)
{
	const uint8_t *h = hash->hash;

	STATICASSERT_EQ(ARRAY_SIZE(hash->hash), 4 * sizeof(uint64_t));

	return u64_of(h) ^ u64_of(h + 8) ^ u64_of(h + 16) ^ u64_of(h + 24);
}

static uint64_t namehash_by_sha256(const struct silofs_mdigest *md,
                                   const char *name, size_t nlen)
{
	struct silofs_hash256 sha256;

	silofs_sha256_of(md, name, nlen, &sha256);
	return hash256_to_u64(&sha256);
}

static const struct silofs_mdigest *
ii_mdigest_of(const struct silofs_inode_info *ii)
{
	return &ii->i_vi.v_ti.t_apex->fa_crypto->md;
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

static int check_valid_name(const char *name, size_t len)
{
	if (len == 0) {
		return -EINVAL;
	}
	if (len > SILOFS_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	if (memchr(name, '/', len)) {
		return -EINVAL;
	}
	if (name[len] != '\0') {
		return -EINVAL;
	}
	return 0;
}

static int check_valid_encoding(const struct silofs_inode_info *dir_ii,
                                const char *name, size_t name_len)
{
	return dir_hasflag(dir_ii, SILOFS_DIRF_NAME_UTF8) ?
	       check_utf8_name(ii_apex(dir_ii), name, name_len) : 0;
}

int silofs_make_namestr(const struct silofs_inode_info *dir_ii,
                        const char *name, struct silofs_namestr *nstr)
{
	int err;
	size_t len;

	len = strnlen(name, SILOFS_NAME_MAX + 1);
	err = check_valid_name(name, len);
	if (err) {
		return err;
	}
	err = check_valid_encoding(dir_ii, name, len);
	if (err) {
		return err;
	}
	nstr->str.str = name;
	nstr->str.len = len;
	return 0;
}

int silofs_check_name(const char *name)
{
	const size_t nlen_max = SILOFS_NAME_MAX;

	return check_valid_name(name, strnlen(name, nlen_max));
}

int silof_check_writable_fs(const struct silofs_sb_info *sbi)
{
	return silofs_sbi_isrofs(sbi) ? -EROFS : 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int try_forget_cached_ii(struct silofs_inode_info *ii)
{
	if ((ii->i_nlookup <= 0) && ii_isevictable(ii)) {
		silofs_cache_forget_vnode(ii_cache(ii), ii_to_vi(ii));
	}
	return 0;
}

int silofs_do_forget(const struct silofs_oper *op,
                     struct silofs_inode_info *ii, size_t nlookup)
{
	int err;

	ii_sub_nlookup(ii, (long)nlookup);

	if (ii->i_pinned) {
		/* case of prune special files created by MKNOD */
		ii->i_pinned = false;
		err = try_prune_inode(op, ii, false);
	} else {
		err = try_forget_cached_ii(ii);
	}
	return err;
}
