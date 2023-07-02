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
#include <silofs/ioctls.h>
#include <silofs/fs-private.h>
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


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

union silofs_utf32_name_buf {
	char dat[4 * (SILOFS_NAME_MAX + 1)];
	uint32_t utf32[SILOFS_NAME_MAX + 1];
} silofs_aligned64;


static int check_utf8_name(const struct silofs_uber *uber,
                           const struct silofs_namestr *nstr)
{
	union silofs_utf32_name_buf unb;
	char *in = unconst(nstr->s.str);
	char *out = unb.dat;
	size_t len = nstr->s.len;
	size_t outlen = sizeof(unb.dat);
	size_t datlen;
	size_t ret;

	ret = iconv(uber->ub_iconv, &in, &len, &out, &outlen);
	if ((ret != 0) || len || (outlen % 4)) {
		return errno ? -errno : -SILOFS_EINVAL;
	}
	datlen = sizeof(unb.dat) - outlen;
	if (datlen == 0) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool has_nlookup_mode(const struct silofs_inode_info *ii)
{
	const struct silofs_uber *uber = ii_uber(ii);

	return ((uber->ub_ctl_flags & SILOFS_UBF_NLOOKUP) > 0);
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

static const struct silofs_mdigest *
dii_mdigest(const struct silofs_inode_info *dii)
{
	const struct silofs_uber *uber = ii_uber(dii);

	return &uber->ub_crypto.md;
}

static uint64_t
dii_namehash_by_sha256(const struct silofs_inode_info *dii,
                       const char *name, size_t nlen)
{
	struct silofs_hash256 sha256;

	silofs_sha256_of(dii_mdigest(dii), name, nlen, &sha256);
	return silofs_hash256_to_u64(&sha256);
}

static uint64_t
dii_namehash_by_xxh64(const struct silofs_inode_info *dir_ii,
                      const char *name, size_t nlen)
{
	return silofs_hash_xxh64(name, nlen, silofs_dir_seed(dir_ii));
}

static int dii_nbuf_to_hash(const struct silofs_inode_info *dir_ii,
                            const struct silofs_namebuf *nbuf,
                            size_t nlen, uint64_t *out_hash)
{
	const enum silofs_dirhfn dhfn = silofs_dir_hfn(dir_ii);

	switch (dhfn) {
	case SILOFS_DIRHASH_SHA256:
		*out_hash = dii_namehash_by_sha256(dir_ii, nbuf->name, nlen);
		break;
	case SILOFS_DIRHASH_XXH64:
		*out_hash = dii_namehash_by_xxh64(dir_ii, nbuf->name, nlen);
		break;
	default:
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int
dii_name_to_hash(const struct silofs_inode_info *dir_ii,
                 const struct silofs_namestr *nstr, uint64_t *out_hash)
{
	struct silofs_namebuf nbuf;
	const size_t alen = 8 * div_round_up(nstr->s.len, 8);

	STATICASSERT_EQ(sizeof(nbuf.name) % 8, 0);

	if (likely(nstr->s.len >= sizeof(nbuf.name))) {
		return -SILOFS_EINVAL;
	}
	silofs_memzero(&nbuf, sizeof(nbuf));
	silofs_namebuf_assign_str(&nbuf, nstr);
	return dii_nbuf_to_hash(dir_ii, &nbuf, alen, out_hash);
}

static bool
dii_hasflag(const struct silofs_inode_info *dir_ii, enum silofs_dirf mask)
{
	const enum silofs_dirf flags = silofs_dir_flags(dir_ii);

	return ((flags & mask) == mask);
}

static int dii_check_name_encoding(const struct silofs_inode_info *dir_ii,
                                   const struct silofs_namestr *nstr)
{
	int ret = 0;

	if (dii_hasflag(dir_ii, SILOFS_DIRF_NAME_UTF8)) {
		ret = check_utf8_name(ii_uber(dir_ii), nstr);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_creds *creds_of(const struct silofs_task *task)
{
	return &task->t_oper.op_creds;
}

static bool isowner(const struct silofs_task *task,
                    const struct silofs_inode_info *ii)
{
	const struct silofs_creds *creds = creds_of(task);

	return uid_eq(creds->icred.uid, ii_uid(ii));
}

static bool has_cap_fowner(const struct silofs_task *task)
{
	const struct silofs_creds *creds = creds_of(task);

	return silofs_user_cap_fowner(&creds->xcred);
}

static int check_isdir(const struct silofs_inode_info *ii)
{
	return ii_isdir(ii) ? 0 : -SILOFS_ENOTDIR;
}

static int check_notdir(const struct silofs_inode_info *ii)
{
	return ii_isdir(ii) ? -SILOFS_EISDIR : 0;
}

static int check_opened(const struct silofs_inode_info *ii)
{
	return !ii->i_nopen ? -SILOFS_EBADF : 0;
}

static int check_reg_or_fifo(const struct silofs_inode_info *ii)
{
	if (ii_isdir(ii)) {
		return -SILOFS_EISDIR;
	}
	if (!ii_isreg(ii) && !ii_isfifo(ii)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int check_open_limit(const struct silofs_inode_info *ii)
{
	const struct silofs_uber *uber = ii_uber(ii);
	const size_t total_iopen_max = uber->ub_ops.op_iopen_max;
	const size_t iopen_max = total_iopen_max / 2;

	if (uber->ub_ops.op_iopen >= total_iopen_max) {
		return -SILOFS_EMFILE;
	}
	if (ii->i_nopen >= (long)iopen_max) {
		return -SILOFS_EMFILE;
	}
	return 0;
}

static void update_nopen(struct silofs_inode_info *ii, int n)
{
	struct silofs_uber *uber = ii_uber(ii);

	silofs_assert_ge(ii->i_nopen + n, 0);
	silofs_assert_lt(ii->i_nopen + n, INT_MAX);

	if ((n > 0) && (ii->i_nopen == 0)) {
		uber->ub_ops.op_iopen++;
	} else if ((n < 0) && (ii->i_nopen == 1)) {
		uber->ub_ops.op_iopen--;
	}
	ii->i_nopen += n;
}

static bool has_sticky_bit(const struct silofs_inode_info *dir_ii)
{
	const mode_t mode = ii_mode(dir_ii);

	return ((mode & S_ISVTX) == S_ISVTX);
}

static int check_sticky(const struct silofs_task *task,
                        const struct silofs_inode_info *dir_ii,
                        const struct silofs_inode_info *ii)
{
	if (!has_sticky_bit(dir_ii)) {
		return 0; /* No sticky-bit, we're fine */
	}
	if (isowner(task, dir_ii)) {
		return 0;
	}
	if (ii && isowner(task, ii)) {
		return 0;
	}
	if (has_cap_fowner(task)) {
		return 0;
	}
	return -SILOFS_EPERM;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int spawn_inode(struct silofs_task *task,
                       const struct silofs_inode_info *parent_dii,
                       mode_t mode, dev_t rdev,
                       struct silofs_inode_info **out_ii)
{
	const ino_t parent_ino = ii_ino(parent_dii);
	const mode_t parent_mode = ii_mode(parent_dii);

	return silofs_spawn_inode_of(task, parent_ino, parent_mode,
	                             mode, rdev, out_ii);
}

static int spawn_dir_inode(struct silofs_task *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, struct silofs_inode_info **out_ii)
{
	const mode_t ifmt = S_IFMT;
	const mode_t dir_mode = (mode & ~ifmt) | S_IFDIR;

	return spawn_inode(task, parent_dii, dir_mode, 0, out_ii);
}

static int spawn_reg_inode(struct silofs_task *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, struct silofs_inode_info **out_ii)
{
	const mode_t ifmt = S_IFMT;
	const mode_t reg_mode = (mode & ~ifmt) | S_IFREG;

	return spawn_inode(task, parent_dii, reg_mode, 0, out_ii);
}

static int spawn_lnk_inode(struct silofs_task *task,
                           const struct silofs_inode_info *parent_dii,
                           struct silofs_inode_info **out_ii)
{
	const mode_t lnk_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFLNK;

	return spawn_inode(task, parent_dii, lnk_mode, 0, out_ii);
}

static int spawn_inode_by_mode(struct silofs_task *task,
                               const struct silofs_inode_info *parent_dii,
                               mode_t mode, dev_t rdev,
                               struct silofs_inode_info **out_ii)
{
	int err;

	if (S_ISREG(mode)) {
		err = spawn_reg_inode(task, parent_dii, mode, out_ii);
	} else if (S_ISLNK(mode)) {
		err = spawn_lnk_inode(task, parent_dii, out_ii);
	} else if (S_ISFIFO(mode) || S_ISSOCK(mode)) {
		err = spawn_inode(task, parent_dii, mode, rdev, out_ii);
	} else if (S_ISDIR(mode)) {
		err = -SILOFS_EISDIR;
	} else {
		err = -SILOFS_EOPNOTSUPP;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_access(const struct silofs_task *task,
                     const struct silofs_inode_info *ii, int mode)
{
	const struct silofs_creds *creds = creds_of(task);
	const uid_t uid = creds->icred.uid;
	const gid_t gid = creds->icred.gid;
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
	return ((rwx & mask) == mask) ? 0 : -SILOFS_EACCES;
}

int silofs_do_access(const struct silofs_task *task,
                     struct silofs_inode_info *ii, int mode)
{
	int err;

	ii_incref(ii);
	err = do_access(task, ii, mode);
	ii_decref(ii);
	return err;
}

static int check_on_writable_fs(const struct silofs_inode_info *ii)
{
	return silof_sbi_check_mut_fs(ii_sbi(ii));
}

static int check_waccess(const struct silofs_task *task,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, W_OK);
}

static int check_xaccess(const struct silofs_task *task,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, X_OK);
}

static int check_raccess(const struct silofs_task *task,
                         struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, R_OK);
}

static int check_dir_waccess(const struct silofs_task *task,
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
	err = check_waccess(task, ii);
	if (err) {
		return err;
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
	err = silofs_check_name(name);
	if (err) {
		return err;
	}
	return 0;
}

static int check_lookup(const struct silofs_task *task,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	int err;

	err = check_dir_and_name(dir_ii, name);
	if (err) {
		return err;
	}
	err = check_xaccess(task, dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int assign_namehash(const struct silofs_inode_info *dir_ii,
                           const struct silofs_namestr *nstr,
                           struct silofs_qstr *qstr)
{
	uint64_t hash = 0;
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = dii_name_to_hash(dir_ii, nstr, &hash);
	if (err) {
		return err;
	}
	qstr->hash = hash;
	qstr->s.str = nstr->s.str;
	qstr->s.len = nstr->s.len;
	return 0;
}

static int lookup_by_name(struct silofs_task *task,
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
	err = silofs_lookup_dentry(task, dir_ii, &name, &ino_dt);
	if (err) {
		return err;
	}
	*out_ino = ino_dt.ino;
	return 0;
}

static int stage_by_name(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         enum silofs_stg_mode stg_mode,
                         struct silofs_inode_info **out_ii)
{
	ino_t ino;
	int err;

	err = lookup_by_name(task, dir_ii, name, &ino);
	if (err) {
		return err;
	}
	err = silofs_stage_inode(task, ino, stg_mode, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_lookup(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	err = check_lookup(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = stage_by_name(task, dir_ii, name, SILOFS_STG_CUR, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_lookup(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_lookup(task, dir_ii, name, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static int check_create_mode(mode_t mode)
{
	if (S_ISDIR(mode)) {
		return -SILOFS_EISDIR;
	}
	if (S_ISLNK(mode)) {
		return -SILOFS_EINVAL;
	}
	if (!S_ISREG(mode) && !S_ISFIFO(mode) && !S_ISSOCK(mode)) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int check_nodent(struct silofs_task *task,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	ino_t ino;
	int err;

	err = lookup_by_name(task, dir_ii, name, &ino);
	if (err == 0) {
		return -SILOFS_EEXIST;
	}
	return (err == -SILOFS_ENOENT) ? 0 : err;
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
		return -SILOFS_EMLINK;
	}
	/* Special case for directory which is still held by open fd */
	if (ii_nlink(dir_ii) < 2) {
		return -SILOFS_ENOENT;
	}
	return 0;
}

static int check_dir_can_add(struct silofs_task *task,
                             struct silofs_inode_info *dir_ii,
                             const struct silofs_namestr *name)
{
	int err;

	err = check_dir_waccess(task, dir_ii);
	if (err) {
		return err;
	}
	err = check_nodent(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_add_dentry(dir_ii, name);
	if (err) {
		return err;
	}
	return 0;
}

static int check_create(struct silofs_task *task,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name, mode_t mode)
{
	int err;

	err = check_on_writable_fs(dir_ii);
	if (err) {
		return err;
	}
	err = check_dir_can_add(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_create_mode(mode);
	if (err) {
		return err;
	}
	err = check_open_limit(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_add_dentry(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *nstr,
                         struct silofs_inode_info *ii,
                         bool del_upon_failure)
{
	struct silofs_qstr name;
	int err;

	err = assign_namehash(dir_ii, nstr, &name);
	if (err) {
		return err;
	}
	err = silofs_add_dentry(task, dir_ii, &name, ii);
	if (err && del_upon_failure) {
		silofs_remove_inode_by(task, ii);
	}
	return err;
}

static int do_create(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_create(task, dir_ii, name, mode);
	if (err) {
		return err;
	}
	err = spawn_inode_by_mode(task, dir_ii, mode, 0, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(task, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	update_nopen(ii, 1);
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_create(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_create(task, dir_ii, name, mode, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

static int check_mknod(struct silofs_task *task,
                       struct silofs_inode_info *dir_ii,
                       const struct silofs_namestr *name,
                       mode_t mode, dev_t rdev)
{
	int err;

	err = check_dir_can_add(task, dir_ii, name);
	if (err) {
		return err;
	}
	if (S_ISDIR(mode)) {
		return -SILOFS_EISDIR;
	}
	if (S_ISLNK(mode)) {
		return -SILOFS_EINVAL;
	}
	if (!S_ISFIFO(mode) && !S_ISSOCK(mode) &&
	    !S_ISCHR(mode) && !S_ISBLK(mode)) {
		return -SILOFS_EOPNOTSUPP;
	}
	if (S_ISCHR(mode) || S_ISBLK(mode)) {
		if (rdev == 0) {
			return -SILOFS_EINVAL;
		}
		if (task->t_uber->ub_ms_flags & MS_NODEV) {
			return -SILOFS_EOPNOTSUPP;
		}
	} else {
		if (rdev != 0) {
			return -SILOFS_EINVAL; /* XXX see man 3p mknod */
		}
	}
	return 0;
}

static int create_special_inode(struct silofs_task *task,
                                struct silofs_inode_info *dir_ii,
                                mode_t mode, dev_t rdev,
                                struct silofs_inode_info **out_ii)
{
	int err;

	err = spawn_inode(task, dir_ii, mode, rdev, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_mknod_reg(struct silofs_task *task,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name, mode_t mode,
                        struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = do_create(task, dir_ii, name, mode, &ii);
	if (err) {
		return err;
	}
	/* create reg via 'mknod' does not follow by release */
	update_nopen(ii, -1);
	*out_ii = ii;
	return 0;
}

static int do_mknod_special(struct silofs_task *task,
                            struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name,
                            mode_t mode, dev_t rdev,
                            struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_mknod(task, dir_ii, name, mode, rdev);
	if (err) {
		return err;
	}
	err = create_special_inode(task, dir_ii, mode, rdev, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(task, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);

	/* can not use 'nopen' as FUSE does not sent OPEN on fifo, and
	 * therefore no RELEASE */
	ii->i_vi.v.flags |= SILOFS_LNF_PINNED;

	*out_ii = ii;
	return 0;
}

int silofs_do_mknod(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name,
                    mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii)
{
	int err;
	const bool mknod_reg = S_ISREG(mode);

	ii_incref(dir_ii);
	if (mknod_reg) {
		err = do_mknod_reg(task, dir_ii, name, mode, out_ii);
	} else {
		err = do_mknod_special(task, dir_ii, name,
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
	if (!ii_isdir(ii) && (o_flags & O_DIRECTORY)) {
		return -SILOFS_EISDIR;
	}
	if (o_flags & (O_CREAT | O_EXCL)) {
		return -SILOFS_EEXIST; /* XXX ? */
	}
	if (ii_isreg(ii) && (o_flags & O_TRUNC) &&
	    !(o_flags & (O_WRONLY | O_RDWR))) {
		return -SILOFS_EACCES;
	}
	if (ii_isdir(ii) && (o_flags & O_DIRECT)) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int check_open(const struct silofs_task *task,
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
	err = silofs_do_access(task, ii, rwx);
	if (err) {
		return err;
	}
	err = check_open_limit(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int post_open(struct silofs_task *task,
                     struct silofs_inode_info *ii, int o_flags)
{
	return (ii_isreg(ii) && (o_flags & O_TRUNC)) ?
	       silofs_do_truncate(task, ii, 0) : 0;
}

static int do_open(struct silofs_task *task,
                   struct silofs_inode_info *ii, int o_flags)
{
	int err;

	err = check_open(task, ii, o_flags);
	if (err) {
		return err;
	}
	err = post_open(task, ii, o_flags);
	if (err) {
		return err;
	}
	update_nopen(ii, 1);
	return 0;
}

int silofs_do_open(struct silofs_task *task,
                   struct silofs_inode_info *ii, int o_flags)
{
	int err;

	ii_incref(ii);
	err = do_open(task, ii, o_flags);
	ii_decref(ii);
	return err;
}

static void ii_undirtify_all(struct silofs_inode_info *ii)
{
	silofs_ii_undirtify_vis(ii);
	silofs_ii_undirtify(ii);
}

static int drop_ispecific(struct silofs_task *task,
                          struct silofs_inode_info *ii)
{
	int err = 0;

	if (ii_isdir(ii)) {
		err = silofs_drop_dir(task, ii);
	} else if (ii_isreg(ii)) {
		err = silofs_drop_reg(task, ii);
	} else if (ii_islnk(ii)) {
		err = silofs_drop_symlink(task, ii);
	}
	if (!err) {
		ii_undirtify_all(ii);
	}
	return err;
}

static int drop_unlinked(struct silofs_task *task,
                         struct silofs_inode_info *ii)
{
	int err;

	err = silofs_drop_xattr(task, ii);
	if (err) {
		return err;
	}
	err = drop_ispecific(task, ii);
	if (err) {
		return err;
	}
	err = silofs_remove_inode_by(task, ii);
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

static int try_prune_inode(struct silofs_task *task,
                           struct silofs_inode_info *ii, bool update_ctime)
{
	if (!ii->i_nopen && ii_isnlink_orphan(ii)) {
		ii_undirtify_all(ii);
	}
	if (ii_isdropable(ii)) {
		return drop_unlinked(task, ii);
	}
	if (update_ctime) {
		ii_update_itimes(ii, creds_of(task), SILOFS_IATTR_CTIME);
	}
	return 0;
}

static int remove_dentry(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         struct silofs_inode_info *ii,
                         const struct silofs_qstr *name)
{
	int err;

	ii_incref(ii);
	err = silofs_remove_dentry(task, dir_ii, name);
	ii_decref(ii);
	return err;
}

static int remove_dentry_of(struct silofs_task *task,
                            struct silofs_inode_info *dir_ii,
                            struct silofs_inode_info *ii,
                            const struct silofs_namestr *nstr)
{
	struct silofs_qstr name;
	int err;

	err = assign_namehash(dir_ii, nstr, &name);
	if (err) {
		return err;
	}
	err = remove_dentry(task, dir_ii, ii, &name);
	if (err) {
		return err;
	}
	return 0;
}

static int remove_de_and_prune(struct silofs_task *task,
                               struct silofs_inode_info *dir_ii,
                               struct silofs_inode_info *ii,
                               const struct silofs_namestr *nstr)
{
	int err;

	err = remove_dentry_of(task, dir_ii, ii, nstr);
	if (err) {
		return err;
	}
	err = try_prune_inode(task, ii, true);
	if (err) {
		return err;
	}
	return 0;
}

static int remove_de_and_update(struct silofs_task *task,
                                struct silofs_inode_info *dir_ii,
                                struct silofs_inode_info *ii,
                                const struct silofs_namestr *nstr)
{
	int err;

	err = remove_dentry_of(task, dir_ii, ii, nstr);
	if (err) {
		return err;
	}
	ii_update_itimes(ii, creds_of(task), SILOFS_IATTR_CTIME);
	return 0;
}

static int check_prepare_unlink(struct silofs_task *task,
                                struct silofs_inode_info *dir_ii,
                                const struct silofs_namestr *nstr,
                                struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_dir_waccess(task, dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(task, dir_ii, nstr, SILOFS_STG_COW, &ii);
	if (err) {
		return err;
	}
	err = check_sticky(task, dir_ii, ii);
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

static int do_unlink(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *nstr)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_prepare_unlink(task, dir_ii, nstr, &ii);
	if (err) {
		return err;
	}
	err = remove_de_and_prune(task, dir_ii, ii, nstr);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_unlink(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *nstr)
{
	int err;

	ii_incref(dir_ii);
	err = do_unlink(task, dir_ii, nstr);
	ii_decref(dir_ii);
	return err;
}

static int check_nomlink(const struct silofs_inode_info *ii)
{
	const size_t link_max = SILOFS_LINK_MAX;

	return (ii_nlink(ii) < link_max) ? 0 : -SILOFS_EMLINK;
}

static int check_link(struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      struct silofs_inode_info *ii)
{
	int err;

	err = check_dir_waccess(task, dir_ii);
	if (err) {
		return err;
	}
	err = check_notdir(ii);
	if (err) {
		return err;
	}
	err = check_nodent(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_nomlink(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_link(struct silofs_task *task,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *nstr,
                   struct silofs_inode_info *ii)
{
	int err;

	err = check_link(task, dir_ii, nstr, ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(task, dir_ii, nstr, ii, false);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);
	ii_update_itimes(ii, creds_of(task), SILOFS_IATTR_CTIME);

	return 0;
}

int silofs_do_link(struct silofs_task *task,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info *ii)
{
	int err;

	ii_incref(dir_ii);
	ii_incref(ii);
	err = do_link(task, dir_ii, name, ii);
	ii_inc_nlookup(ii, err);
	ii_decref(ii);
	ii_decref(dir_ii);
	return err;
}

static int check_mkdir(struct silofs_task *task,
                       struct silofs_inode_info *dir_ii,
                       const struct silofs_namestr *name)
{
	int err;

	err = check_dir_can_add(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_nomlink(dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_mkdir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_mkdir(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = spawn_dir_inode(task, dir_ii, mode, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(task, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_mkdir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_mkdir(task, dir_ii, name, mode, out_ii);
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

static int check_rmdir_child(const struct silofs_task *task,
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
		return -SILOFS_ENOTEMPTY;
	}
	if (ii_isrootd(dir_ii)) {
		return -SILOFS_EBUSY;
	}
	err = check_sticky(task, parent_ii, dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_prepare_rmdir(struct silofs_task *task,
                               struct silofs_inode_info *dir_ii,
                               const struct silofs_namestr *name,
                               struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = NULL;

	err = check_dir_waccess(task, dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(task, dir_ii, name, SILOFS_STG_COW, &ii);
	if (err) {
		return err;
	}
	err = check_rmdir_child(task, dir_ii, ii);
	if (err) {
		return err;
	}
	*out_ii = ii;
	return 0;
}

static int do_rmdir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *nstr)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_prepare_rmdir(task, dir_ii, nstr, &ii);
	if (err) {
		return err;
	}
	err = remove_de_and_prune(task, dir_ii, ii, nstr);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_rmdir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name)
{
	int err;

	ii_incref(dir_ii);
	err = do_rmdir(task, dir_ii, name);
	ii_decref(dir_ii);
	return err;
}

static int create_lnk_inode(struct silofs_task *task,
                            const struct silofs_inode_info *dir_ii,
                            const struct silofs_str *linkpath,
                            struct silofs_inode_info **out_ii)
{
	int err;

	err = spawn_lnk_inode(task, dir_ii, out_ii);
	if (err) {
		return err;
	}
	err = silofs_setup_symlink(task, *out_ii, linkpath);
	if (err) {
		silofs_remove_inode_by(task, *out_ii);
		return err;
	}
	return 0;
}

static int check_symval(const struct silofs_str *symval)
{
	if (symval->len == 0) {
		return -SILOFS_EINVAL;
	}
	if (symval->len > SILOFS_SYMLNK_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	return 0;
}

static int check_symlink(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         const struct silofs_str *symval)
{
	int err;

	err = check_dir_can_add(task, dir_ii, name);
	if (err) {
		return err;
	}
	err = check_symval(symval);
	if (err) {
		return err;
	}
	return 0;
}

static int do_symlink(struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = NULL;
	int err;

	err = check_symlink(task, dir_ii, name, symval);
	if (err) {
		return err;
	}
	err = create_lnk_inode(task, dir_ii, symval, &ii);
	if (err) {
		return err;
	}
	err = do_add_dentry(task, dir_ii, name, ii, true);
	if (err) {
		return err;
	}
	ii_update_itimes(dir_ii, creds_of(task), SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_symlink(struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_str *symval,
                      struct silofs_inode_info **out_ii)
{
	int err;

	ii_incref(dir_ii);
	err = do_symlink(task, dir_ii, name, symval, out_ii);
	ii_inc_nlookup(*out_ii, err);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_opendir_flags(const struct silofs_inode_info *ii, int o_flags)
{
	return (ii_isdir(ii) && (o_flags & O_DIRECT)) ? -SILOFS_EOPNOTSUPP : 0;
}

static int check_opendir(const struct silofs_task *task,
                         struct silofs_inode_info *dir_ii, int o_flags)
{
	int err;

	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	err = check_raccess(task, dir_ii);
	if (err) {
		return err;
	}
	err = check_open_limit(dir_ii);
	if (err) {
		return err;
	}
	err = check_opendir_flags(dir_ii, o_flags);
	if (err) {
		return err;
	}
	return 0;
}

static int do_opendir(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii, int o_flags)
{
	int err;

	err = check_opendir(task, dir_ii, o_flags);
	if (err) {
		return err;
	}
	update_nopen(dir_ii, 1);
	return 0;
}

int silofs_do_opendir(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii, int o_flags)
{
	int err;

	ii_incref(dir_ii);
	err = do_opendir(task, dir_ii, o_flags);
	ii_decref(dir_ii);

	return err;
}

static int check_releasedir_flags(int o_flags)
{
	return (o_flags & O_DIRECT) ? -SILOFS_EOPNOTSUPP : 0;
}

/*
 * TODO-0017: Shrink sparse dir-tree upon last close
 *
 * Try to shrink sparse dir hash-tree upon last close. Note that we should
 * not do so while dir is held open, as it may corrupt active readdir.
 */
static int
check_releasedir(const struct silofs_inode_info *dir_ii, int o_flags)
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
	err = check_releasedir_flags(o_flags);
	if (err) {
		return err;
	}
	return 0;
}

static int flush_dirty_of(struct silofs_task *task,
                          struct silofs_inode_info *ii, int flags)
{
	int ret = 0;

	if (silofs_ii_isdirty(ii) || ii->i_dq_vis.dq_accum) {
		ret = silofs_flush_dirty(task, ii, flags);
	}
	return ret;
}

static int do_releasedir_flush(struct silofs_task *task,
                               struct silofs_inode_info *dir_ii,
                               int o_flags, bool flush)
{
	int flags = SILOFS_F_RELEASE;

	if (o_flags & (O_SYNC | O_DSYNC)) {
		flags |= SILOFS_F_FSYNC;
	}
	if (flush) {
		flags |= SILOFS_F_NOW;
	}
	return flush_dirty_of(task, dir_ii, flags);
}

static int do_releasedir(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         int o_flags, bool flush)
{
	int err;

	err = check_releasedir(dir_ii, o_flags);
	if (err) {
		return err;
	}
	err = do_releasedir_flush(task, dir_ii, o_flags, flush);
	if (err) {
		return err;
	}
	update_nopen(dir_ii, -1);
	return 0;
}

int silofs_do_releasedir(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         int o_flags, bool flush)
{
	int err;

	ii_incref(dir_ii);
	err = do_releasedir(task, dir_ii, o_flags, flush);
	ii_decref(dir_ii);

	return !err ? try_prune_inode(task, dir_ii, false) : err;
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

static int do_release(struct silofs_task *task,
                      struct silofs_inode_info *ii, bool flush)
{
	const int flags = flush ? SILOFS_F_NOW : SILOFS_F_RELEASE;
	int err;

	err = check_release(ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(task, ii, flags);
	if (err) {
		return err;
	}
	update_nopen(ii, -1);
	return 0;
}

int silofs_do_release(struct silofs_task *task,
                      struct silofs_inode_info *ii, bool flush)
{
	int err;

	ii_incref(ii);
	err = do_release(task, ii, flush);
	ii_decref(ii);

	return !err ? try_prune_inode(task, ii, false) : err;
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

static int do_fsyncdir(struct silofs_task *task,
                       struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_fsyncdir(dir_ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(task, dir_ii, SILOFS_F_FSYNC);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_fsyncdir(struct silofs_task *task,
                       struct silofs_inode_info *dir_ii, bool dsync)
{
	int err;

	ii_incref(dir_ii);
	err = do_fsyncdir(task, dir_ii);
	ii_decref(dir_ii);

	silofs_unused(dsync);
	return err;
}

static int check_fsync(const struct silofs_inode_info *ii)
{
	return check_notdir_and_opened(ii);
}

static int do_fsync(struct silofs_task *task,
                    struct silofs_inode_info *ii)
{
	int err;

	err = check_fsync(ii);
	if (err) {
		return err;
	}
	err = flush_dirty_of(task, ii, SILOFS_F_FSYNC);
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
int silofs_do_fsync(struct silofs_task *task,
                    struct silofs_inode_info *ii, bool datasync)
{
	int err;

	ii_incref(ii);
	err = do_fsync(task, ii);
	ii_decref(ii);

	silofs_unused(datasync);
	return err;
}

int silofs_do_flush(struct silofs_task *task,
                    struct silofs_inode_info *ii, bool now)
{
	return flush_dirty_of(task, ii, now ? SILOFS_F_NOW : 0);
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

static int do_add_dentry_at(struct silofs_task *task,
                            struct silofs_dentry_ref *dref,
                            struct silofs_inode_info *ii)

{
	int err;

	err = do_add_dentry(task, dref->dir_ii, dref->name, ii, false);
	if (err) {
		return err;
	}
	dref->ii = ii;
	return 0;
}

static int remove_de_and_prune_at(struct silofs_task *task,
                                  struct silofs_dentry_ref *dref)
{
	int err;

	err = remove_de_and_prune(task, dref->dir_ii, dref->ii, dref->name);
	if (err) {
		return err;
	}
	dref->ii = NULL;
	return 0;
}

static int remove_de_and_update_at(struct silofs_task *task,
                                   struct silofs_dentry_ref *dref)
{
	int err;

	err = remove_de_and_update(task, dref->dir_ii, dref->ii, dref->name);
	if (err) {
		return err;
	}
	dref->ii = NULL;
	return 0;
}


static int do_rename_move(struct silofs_task *task,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	err = check_add_dentry_at(new_dref);
	if (err) {
		return err;
	}
	err = remove_de_and_update_at(task, cur_dref);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(task, new_dref, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_move(struct silofs_task *task,
                       struct silofs_dentry_ref *cur_dref,
                       struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	ii_incref(ii);
	err = do_rename_move(task, cur_dref, new_dref);
	ii_decref(ii);
	return err;
}

static int rename_unlink(struct silofs_task *task,
                         struct silofs_dentry_ref *dref)
{
	return remove_de_and_prune_at(task, dref);
}

static int do_rename_replace(struct silofs_task *task,
                             struct silofs_dentry_ref *cur_dref,
                             struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	err = remove_de_and_prune_at(task, new_dref);
	if (err) {
		return err;
	}
	err = remove_de_and_update_at(task, cur_dref);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(task, new_dref, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_replace(struct silofs_task *task,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	ii_incref(ii);
	err = do_rename_replace(task, cur_dref, new_dref);
	ii_decref(ii);
	return err;
}

static int do_rename_exchange(struct silofs_task *task,
                              struct silofs_dentry_ref *dref1,
                              struct silofs_dentry_ref *dref2)
{
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;
	int err;

	err = remove_de_and_update_at(task, dref1);
	if (err) {
		return err;
	}
	err = remove_de_and_update_at(task, dref2);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(task, dref2, ii1);
	if (err) {
		return err;
	}
	err = do_add_dentry_at(task, dref1, ii2);
	if (err) {
		return err;
	}
	return 0;
}

static int rename_exchange(struct silofs_task *task,
                           struct silofs_dentry_ref *dref1,
                           struct silofs_dentry_ref *dref2)
{
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;
	int err;

	ii_incref(ii1);
	ii_incref(ii2);
	err = do_rename_exchange(task, dref1, dref2);
	ii_decref(ii2);
	ii_decref(ii1);
	return err;
}

static int rename_specific(struct silofs_task *task,
                           struct silofs_dentry_ref *cur_dref,
                           struct silofs_dentry_ref *new_dref, int flags)
{
	const struct silofs_creds *creds = creds_of(task);
	int err;

	if (new_dref->ii == NULL) {
		err = rename_move(task, cur_dref, new_dref);
	} else if (cur_dref->ii == new_dref->ii) {
		err = rename_unlink(task, cur_dref);
	} else if (flags & RENAME_EXCHANGE) {
		err = rename_exchange(task, cur_dref, new_dref);
	} else {
		err = rename_replace(task, cur_dref, new_dref);
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
		return -SILOFS_EINVAL;
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

static int check_rename(const struct silofs_task *task,
                        const struct silofs_dentry_ref *cur_dref,
                        const struct silofs_dentry_ref *new_dref, int flags)
{
	int err = 0;
	const struct silofs_inode_info *ii = cur_dref->ii;
	const struct silofs_inode_info *old_ii = new_dref->ii;
	const bool old_exists = (old_ii != NULL);

	if (flags & RENAME_WHITEOUT) {
		return -SILOFS_EINVAL;
	}
	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE)) {
		return -SILOFS_EINVAL;
	}
	if ((flags & RENAME_NOREPLACE) && old_exists) {
		return -SILOFS_EEXIST;
	}
	if ((flags & RENAME_EXCHANGE) && !old_exists) {
		return -SILOFS_ENOENT;
	}
	if (flags & RENAME_EXCHANGE) {
		return check_rename_exchange(cur_dref, new_dref);
	}
	if (old_exists && ii_isdir(old_ii) && (old_ii != ii)) {
		err = (ii == NULL) ? check_nomlink(new_dref->dir_ii) :
		      check_rmdir_child(task, cur_dref->dir_ii, old_ii);
	}
	return err;
}

static int check_stage_rename_at(struct silofs_task *task,
                                 struct silofs_dentry_ref *dref, bool new_de)
{
	int err;

	err = check_dir_waccess(task, dref->dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(task, dref->dir_ii, dref->name,
	                    SILOFS_STG_COW, &dref->ii);
	if (err) {
		return ((err == -SILOFS_ENOENT) && new_de) ? 0 : err;
	}
	err = check_sticky(task, dref->dir_ii, dref->ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_stage_rename_at2(struct silofs_task *task,
                                  struct silofs_dentry_ref *dref,
                                  struct silofs_dentry_ref *dalt, bool new_de)
{
	int ret;

	ii_incref(dalt->dir_ii);
	ii_incref(dalt->ii);
	ret = check_stage_rename_at(task, dref, new_de);
	ii_decref(dalt->ii);
	ii_decref(dalt->dir_ii);
	return ret;
}

static int do_rename(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags)
{
	struct silofs_dentry_ref cur_dref = {
		.dir_ii = dir_ii,
		.name = name,
	};
	struct silofs_dentry_ref new_dref = {
		.dir_ii = newdir_ii,
		.name = newname,
	};
	int err;

	err = check_stage_rename_at(task, &cur_dref, false);
	if (err) {
		return err;
	}
	err = check_stage_rename_at2(task, &new_dref, &cur_dref, true);
	if (err) {
		return err;
	}
	err = check_rename(task, &cur_dref, &new_dref, flags);
	if (err) {
		return err;
	}
	err = rename_specific(task, &cur_dref, &new_dref, flags);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_rename(struct silofs_task *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags)
{
	int err;

	ii_incref(dir_ii);
	ii_incref(newdir_ii);
	err = do_rename(task, dir_ii, name, newdir_ii, newname, flags);
	ii_decref(newdir_ii);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fill_spstats(const struct silofs_sb_info *sbi,
                         struct silofs_query_spstats *qsp)
{
	struct silofs_spacestats spst;

	silofs_sti_collect_stats(&sbi->sb_sti, &spst);
	silofs_spacestats_export(&spst, &qsp->spst);
}

static void fill_proc(const struct silofs_uber *uber,
                      struct silofs_query_proc *qpr)
{
	struct silofs_alloc_stat alst;
	const struct silofs_cache *cache = uber->ub.cache;

	silofs_allocstat(uber->ub.alloc, &alst);
	silofs_memzero(qpr, sizeof(*qpr));
	qpr->uid = uber->ub_owner.uid;
	qpr->gid = uber->ub_owner.gid;
	qpr->pid = uber->ub.fs_args->pid;
	qpr->msflags = uber->ub_ms_flags;
	qpr->uptime = silofs_uber_uptime(uber);
	qpr->iopen_max = uber->ub_ops.op_iopen_max;
	qpr->iopen_cur = uber->ub_ops.op_iopen;
	qpr->memsz_max = alst.nbytes_max;
	qpr->memsz_cur = alst.nbytes_use;
	qpr->bopen_cur = cache->c_blobf_lm.lm_lru.sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_statvfs(const struct silofs_task *task, struct statvfs *out_stv)
{
	const struct silofs_sb_info *sbi = task_sbi(task);

	silofs_sti_fill_statvfs(&sbi->sb_sti, out_stv);
	return 0;
}

int silofs_do_statvfs(const struct silofs_task *task,
                      struct silofs_inode_info *ii, struct statvfs *out_stv)
{
	int err;

	ii_incref(ii);
	err = do_statvfs(task, out_stv);
	ii_decref(ii);
	return err;
}

static void fill_strbuf(char *buf, size_t bsz, const struct silofs_str *s)
{
	if ((s != NULL) && (bsz > 0)) {
		memcpy(buf, s->str, min(bsz - 1, s->len));
		buf[bsz - 1] = '\0';
	}
}

static void fill_query_version(const struct silofs_inode_info *ii,
                               struct silofs_ioc_query *query)
{
	struct silofs_str s = {
		.str = silofs_version.string,
		.len = silofs_str_length(silofs_version.string),
	};
	const size_t bsz = sizeof(query->u.version.string);

	query->u.version.major = silofs_version.major;
	query->u.version.minor = silofs_version.minor;
	query->u.version.sublevel = silofs_version.sublevel;
	fill_strbuf(query->u.version.string, bsz, &s);
	unused(ii);
}

static struct silofs_repo *repo_of(const struct silofs_uber *uber)
{
	return uber->ub.repo;
}

static void fill_query_bootsec(const struct silofs_inode_info *ii,
                               struct silofs_ioc_query *query)
{
	const struct silofs_uber *uber = ii_uber(ii);
	const struct silofs_repo *repo = uber->ub.repo;
	const struct silofs_bootpath *bpath = NULL;
	size_t bsz;

	bpath = &repo->re.bootpath;

	bsz = sizeof(query->u.bootsec.repo);
	fill_strbuf(query->u.bootsec.repo, bsz, &bpath->repodir);

	bsz = sizeof(query->u.bootsec.name);
	fill_strbuf(query->u.bootsec.name, bsz, &bpath->name.s);
}

static void fill_query_proc(const struct silofs_inode_info *ii,
                            struct silofs_ioc_query *query)
{
	fill_proc(ii_uber(ii), &query->u.proc);
}

static void fill_query_spstats(const struct silofs_inode_info *ii,
                               struct silofs_ioc_query *query)
{
	fill_spstats(ii_sbi(ii), &query->u.spstats);
}

static int do_query_statx(struct silofs_task *task,
                          struct silofs_inode_info *ii,
                          struct silofs_ioc_query *query)
{
	const unsigned int req_mask = STATX_ALL | STATX_BTIME;
	const enum silofs_inodef iflags = silofs_ii_flags(ii);
	enum silofs_dirf dflags;
	int err;

	err = silofs_do_statx(task, ii, req_mask, &query->u.statx.stx);
	if (err) {
		return err;
	}
	query->u.statx.iflags = (uint32_t)iflags;
	if (ii_isdir(ii)) {
		dflags = silofs_dir_flags(ii);
		query->u.statx.dirflags = (uint32_t)dflags;
	}
	return 0;
}

static int do_query_subcmd(struct silofs_task *task,
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
	case SILOFS_QUERY_BOOTSEC:
		fill_query_bootsec(ii, query);
		break;
	case SILOFS_QUERY_PROC:
		fill_query_proc(ii, query);
		break;
	case SILOFS_QUERY_SPSTATS:
		fill_query_spstats(ii, query);
		break;
	case SILOFS_QUERY_STATX:
		err = do_query_statx(task, ii, query);
		break;
	case SILOFS_QUERY_NONE:
	default:
		err = -SILOFS_EINVAL;
		break;
	}
	return err;
}

static int do_query(struct silofs_task *task,
                    struct silofs_inode_info *ii,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *query)
{
	int err;

	err = check_raccess(task, ii);
	if (err) {
		return err;
	}
	err = do_query_subcmd(task, ii, qtype, query);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_query(struct silofs_task *task,
                    struct silofs_inode_info *ii,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *out_qry)
{
	int err;

	ii_incref(ii);
	err = do_query(task, ii, qtype, out_qry);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_fsowner(const struct silofs_task *task)
{
	const struct silofs_creds *creds = creds_of(task);
	const uid_t owner_uid = task->t_uber->ub_owner.uid;

	return uid_eq(creds->xcred.uid, owner_uid) ? 0 : -SILOFS_EPERM;
}

static int check_clone_flags(int flags)
{
	const int allow_flags = 0;

	return (flags & ~allow_flags) ? -SILOFS_EINVAL : 0;
}

static int check_clone(const struct silofs_task *task,
                       struct silofs_inode_info *ii, int flags)
{
	int err;

	err = check_isdir(ii);
	if (err) {
		return err;
	}
	err = check_on_writable_fs(ii);
	if (err) {
		return err;
	}
	err = check_raccess(task, ii);
	if (err) {
		return err;
	}
	err = check_fsowner(task);
	if (err) {
		return err;
	}
	err = check_clone_flags(flags);
	if (err) {
		return err;
	}
	return 0;
}

static int do_post_clone_updates(const struct silofs_task *task,
                                 const struct silofs_bootsecs *bsecs)
{
	struct silofs_repo *repo = NULL;
	const struct silofs_bootsec *bsec = NULL;
	int err = 0;

	repo = repo_of(task->t_uber);
	for (size_t i = 0; i < ARRAY_SIZE(bsecs->bsec); ++i) {
		bsec = &bsecs->bsec[i];
		err = silofs_repo_save_bootsec(repo, &bsec->uuid, bsec);
		if (err) {
			break;
		}
	}
	return err;
}

static int flush_and_sync_blobs(struct silofs_task *task)
{
	const struct silofs_cache *cache = task_cache(task);
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = silofs_cache_fsync_blobs(cache);
	if (err) {
		return err;
	}
	return 0;
}

static int do_clone(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii, int flags,
                    struct silofs_bootsecs *out_bsecs)
{
	struct silofs_uber *uber = task->t_uber;
	int err;

	err = check_clone(task, dir_ii, flags);
	if (err) {
		return err;
	}
	err = flush_and_sync_blobs(task);
	if (err) {
		return err;
	}
	err = silofs_uber_forkfs(uber, out_bsecs);
	if (err) {
		return err;
	}
	err = flush_and_sync_blobs(task);
	if (err) {
		return err;
	}
	err = do_post_clone_updates(task, out_bsecs);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_clone(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii, int flags,
                    struct silofs_bootsecs *out_bsecs)
{
	int err;

	ii_incref(dir_ii);
	err = do_clone(task, dir_ii, flags, out_bsecs);
	ii_decref(dir_ii);
	return err;
}

int silofs_do_inspect(struct silofs_task *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = silofs_walk_inspect_fs(task, task_sbi(task));
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_unrefs(struct silofs_task *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = silofs_walk_unref_fs(task, task_sbi(task));
	if (err) {
		return err;
	}
	return 0;
}

static int check_syncfs(const struct silofs_inode_info *ii, int flags)
{
	if (!ii_isdir(ii) && !ii_isreg(ii)) {
		return -SILOFS_EINVAL;
	}
	if (flags > 2) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

int silofs_do_syncfs(struct silofs_task *task,
                     struct silofs_inode_info *ii, int flags)
{
	int err;

	err = check_syncfs(ii, flags);
	if (err) {
		return err;
	}
	err = flush_and_sync_blobs(task);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_timedout(struct silofs_task *task, int flags)
{
	int err;

	err = silofs_flush_dirty(task, NULL, flags);
	if (!err) {
		silofs_relax_cache_by(task, flags);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_make_namestr_by(struct silofs_namestr *nstr,
                           const struct silofs_inode_info *ii, const char *s)
{
	int err;

	err = silofs_make_namestr(nstr, s);
	if (err) {
		return err;
	}
	if (!ii_isdir(ii)) {
		return 0;
	}
	err = dii_check_name_encoding(ii, nstr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int try_forget_cached_ii(struct silofs_inode_info *ii)
{
	if ((ii->i_nlookup <= 0) && ii_isevictable(ii)) {
		silofs_cache_forget_vi(ii_cache(ii), ii_to_vi(ii));
	}
	return 0;
}

int silofs_do_forget(struct silofs_task *task,
                     struct silofs_inode_info *ii, size_t nlookup)
{
	const int flags = ii->i_vi.v.flags;
	int err;

	ii_sub_nlookup(ii, (long)nlookup);
	if (flags & SILOFS_LNF_PINNED) {
		/* case of prune special files created by MKNOD */
		ii->i_vi.v.flags = flags & ~SILOFS_LNF_PINNED;
		err = try_prune_inode(task, ii, false);
	} else {
		err = try_forget_cached_ii(ii);
	}
	return err;
}
