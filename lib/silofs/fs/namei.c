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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>

#include <silofs/ioctls.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>
#include <silofs/run.h>

static bool ii_ispinned(const struct silofs_inode_info *ii)
{
	const int flags = (int)(ii->i_lni.vn_flags);

	return (flags & SILOFS_LNF_PINNED) > 0;
}

static void ii_unpin(struct silofs_inode_info *ii)
{
	const int flags = (int)(ii->i_lni.vn_flags);

	ii->i_lni.vn_flags =
		(enum silofs_lni_flags)(flags & ~SILOFS_LNF_PINNED);
}

static void ii_set_pinned(struct silofs_inode_info *ii)
{
	ii->i_lni.vn_flags |= SILOFS_LNF_PINNED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int get_sbi(const struct silofs_task_ctx *task,
                   struct silofs_sbnode_info **out_sbi)
{
	int err;

	err = silofs_curr_sbi(task, out_sbi);
	return_if_err(err);

	silofs_sbi_incref(*out_sbi);
	return 0;
}

static void put_sbi(struct silofs_sbnode_info *sbi)
{
	if (sbi != nullptr) {
		silofs_sbi_decref(sbi);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool has_nlookup_mode(const struct silofs_task_ctx *task)
{
	return (task->corefs->fsroot->ctl_flags & SILOFS_F_NLOOKUP) > 0;
}

static void sub_nlookup(const struct silofs_task_ctx *task,
                        struct silofs_inode_info *ii, long n)
{
	if (has_nlookup_mode(task)) {
		ii->i_nlookup -= n;
	}
}

static void inc_nlookup(const struct silofs_task_ctx *task,
                        struct silofs_inode_info *ii, int err)
{
	if (!err && (ii != nullptr) && has_nlookup_mode(task)) {
		ii->i_nlookup++;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool
isowner(const struct silofs_task_ctx *task, const struct silofs_inode_info *ii)
{
	const struct silofs_creds *creds = &task->auth.creds;

	return silofs_uid_eq(creds->fs_cred.uid, silofs_ii_uid(ii));
}

static bool has_cap_fowner(const struct silofs_task_ctx *task)
{
	const struct silofs_creds *creds = &task->auth.creds;

	return silofs_user_cap_fowner(&creds->host_cred);
}

static int check_isdir(const struct silofs_inode_info *ii)
{
	return silofs_ii_isdir(ii) ? 0 : -SILOFS_ENOTDIR;
}

static int check_notdir(const struct silofs_inode_info *ii)
{
	return silofs_ii_isdir(ii) ? -SILOFS_EISDIR : 0;
}

static int check_opened(const struct silofs_inode_info *ii)
{
	return !ii->i_nopen ? -SILOFS_EBADF : 0;
}

static int check_reg_or_fifo(const struct silofs_inode_info *ii)
{
	if (silofs_ii_isdir(ii)) {
		return -SILOFS_EISDIR;
	}
	if (!silofs_ii_isreg(ii) && !silofs_ii_isfifo(ii)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int check_open_limit(const struct silofs_task_ctx *task,
                            const struct silofs_inode_info *ii)
{
	const struct silofs_fsroot *fsroot = task->corefs->fsroot;
	const size_t total_iopen_max       = fsroot->opstat.op_iopen_max;
	const size_t total_iopn_cur        = fsroot->opstat.op_iopen;
	const size_t iopen_max             = total_iopen_max / 2;

	if (total_iopn_cur >= total_iopen_max) {
		return -SILOFS_EMFILE;
	}
	if (ii->i_nopen >= (long)iopen_max) {
		return -SILOFS_EMFILE;
	}
	return 0;
}

static void
update_nopen(struct silofs_task_ctx *task, struct silofs_inode_info *ii, int n)
{
	struct silofs_opstat *opstat = &task->corefs->fsroot->opstat;

	silofs_assert_ge(ii->i_nopen + n, 0);
	silofs_assert_lt(ii->i_nopen + n, INT_MAX);

	if ((n > 0) && (ii->i_nopen == 0)) {
		opstat->op_iopen++;
	} else if ((n < 0) && (ii->i_nopen == 1)) {
		opstat->op_iopen--;
	}
	ii->i_nopen += n;
}

static bool has_sticky_bit(const struct silofs_inode_info *dir_ii)
{
	const mode_t mode = silofs_ii_mode(dir_ii);

	return ((mode & S_ISVTX) == S_ISVTX);
}

static int check_sticky(const struct silofs_task_ctx *task,
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

static enum silofs_inodef make_inodef(enum silofs_inodef flags, int mask)
{
	return (enum silofs_inodef)((int)flags & mask);
}

static enum silofs_inodef
derive_inodef(const struct silofs_inode_info *parent_dii)
{
	constexpr int default_ftype    = SILOFS_INODEF_FTYPE2;
	const enum silofs_inodef flags = silofs_ii_flags(parent_dii);

	return make_inodef(flags, default_ftype);
}

static void inewp_reset(struct silofs_inew_params *inp)
{
	memset(inp, 0, sizeof(*inp));
}

static void inewp_set_creds(struct silofs_inew_params *inp,
                            const struct silofs_creds *creds)
{
	memcpy(&inp->creds, creds, sizeof(inp->creds));
}

static void
inewp_set_ts(struct silofs_inew_params *inp, const struct timespec *ts)
{
	memcpy(&inp->ts, ts, sizeof(inp->ts));
}

static void inewp_update_by_parent(struct silofs_inew_params *inp,
                                   const struct silofs_inode_info *parent_dii)
{
	inp->parent_ino  = parent_dii->i_ino;
	inp->parent_mode = silofs_ii_mode(parent_dii);
	if (inp->parent_mode & S_ISGID) {
		/* Inherit group from parent dir */
		inp->creds.fs_cred.gid = silofs_ii_gid(parent_dii);

		/* When creating dir, propagate the setgid bit */
		if (S_ISDIR(inp->mode)) {
			inp->mode |= S_ISGID;
		}
	}
	if (S_ISDIR(inp->mode) || S_ISREG(inp->mode)) {
		inp->flags = derive_inodef(parent_dii);
	}
}

static struct silofs_prandgen *prng_of(const struct silofs_task_ctx *task)
{
	return task->corefs->prng;
}

static void
inewp_set_seed(struct silofs_inew_params *inp, struct silofs_prandgen *prng)
{
	if (S_ISDIR(inp->mode)) {
		silofs_prandgen_take(prng, &inp->seed, sizeof(inp->seed));
	}
}

void silofs_inew_params_of(const struct silofs_task_ctx *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, dev_t rdev, uint64_t igen,
                           struct silofs_inew_params *out_inp)
{
	inewp_reset(out_inp);
	out_inp->mode       = mode;
	out_inp->rdev       = rdev;
	out_inp->generation = igen;
	inewp_set_creds(out_inp, &task->auth.creds);
	inewp_set_ts(out_inp, &task->auth.ts);
	inewp_set_seed(out_inp, prng_of(task));
	if (parent_dii != nullptr) {
		inewp_update_by_parent(out_inp, parent_dii);
	}
}

static int spawn_inode(struct silofs_task_ctx *task,
                       const struct silofs_inode_info *parent_dii, mode_t mode,
                       dev_t rdev, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp = {};
	uint64_t igen;
	int err;

	err = silofs_next_inogen(task, &igen);
	return_if_err(err);

	silofs_inew_params_of(task, parent_dii, mode, rdev, igen, &inp);
	err = silofs_spawn_inode_by(task, &inp, out_ii);
	return_if_err(err);

	return 0;
}

static int spawn_dir_inode(struct silofs_task_ctx *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, struct silofs_inode_info **out_ii)
{
	constexpr mode_t ifmt = S_IFMT;
	const mode_t dir_mode = (mode & ~ifmt) | S_IFDIR;

	return spawn_inode(task, parent_dii, dir_mode, 0, out_ii);
}

static int spawn_reg_inode(struct silofs_task_ctx *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, struct silofs_inode_info **out_ii)
{
	constexpr mode_t ifmt = S_IFMT;
	const mode_t reg_mode = (mode & ~ifmt) | S_IFREG;

	return spawn_inode(task, parent_dii, reg_mode, 0, out_ii);
}

static int spawn_lnk_inode(struct silofs_task_ctx *task,
                           const struct silofs_inode_info *parent_dii,
                           struct silofs_inode_info **out_ii)
{
	constexpr mode_t lnk_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFLNK;

	return spawn_inode(task, parent_dii, lnk_mode, 0, out_ii);
}

static int
spawn_inode_by_mode(struct silofs_task_ctx *task,
                    const struct silofs_inode_info *parent_dii, mode_t mode,
                    dev_t rdev, struct silofs_inode_info **out_ii)
{
	int err = -SILOFS_EOPNOTSUPP;

	if (S_ISREG(mode)) {
		err = spawn_reg_inode(task, parent_dii, mode, out_ii);
	} else if (S_ISLNK(mode)) {
		err = spawn_lnk_inode(task, parent_dii, out_ii);
	} else if (S_ISFIFO(mode) || S_ISSOCK(mode)) {
		err = spawn_inode(task, parent_dii, mode, rdev, out_ii);
	} else if (S_ISDIR(mode)) {
		err = -SILOFS_EISDIR;
	}
	return err;
}

static int spawn_special_inode(struct silofs_task_ctx *task,
                               struct silofs_inode_info *dir_ii, mode_t mode,
                               dev_t rdev, struct silofs_inode_info **out_ii)
{
	return spawn_inode(task, dir_ii, mode, rdev, out_ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_access_of(const struct silofs_creds *creds,
                        const struct silofs_inode_info *ii, int mode)
{
	const uid_t uid     = creds->fs_cred.uid;
	const gid_t gid     = creds->fs_cred.gid;
	const uid_t i_uid   = silofs_ii_uid(ii);
	const gid_t i_gid   = silofs_ii_gid(ii);
	const mode_t i_mode = silofs_ii_mode(ii);
	const mode_t mask   = (mode_t)mode;
	mode_t rwx          = 0;

	if (silofs_uid_isroot(uid)) {
		rwx |= R_OK | W_OK;
		if (S_ISREG(i_mode)) {
			if (i_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
				rwx |= X_OK;
			}
		} else {
			rwx |= X_OK;
		}
	} else if (silofs_uid_eq(uid, i_uid)) {
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
	} else if (silofs_gid_eq(gid, i_gid)) {
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

static int do_access(const struct silofs_task_ctx *task,
                     const struct silofs_inode_info *ii, int mode)
{
	return do_access_of(&task->auth.creds, ii, mode);
}

int silofs_do_access(const struct silofs_task_ctx *task,
                     struct silofs_inode_info *ii, int mode)
{
	int err;

	silofs_ii_incref(ii);
	err = do_access(task, ii, mode);
	silofs_ii_decref(ii);
	return err;
}

static int check_on_writable_fs(const struct silofs_task_ctx *task)
{
	const bool rdonly = silofs_test_rdonly_fs(task->corefs->fsroot);

	return rdonly ? -SILOFS_ERDONLY : 0;
}

static int
check_waccess(const struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, W_OK);
}

static int
check_xaccess(const struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, X_OK);
}

static int
check_raccess(const struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	return silofs_do_access(task, ii, R_OK);
}

static int check_dir_waccess(const struct silofs_task_ctx *task,
                             struct silofs_inode_info *ii)
{
	int err;

	err = check_on_writable_fs(task);
	return_if_err(err);

	err = check_isdir(ii);
	return_if_err(err);

	err = check_waccess(task, ii);
	return_if_err(err);

	return 0;
}

static int check_dir_and_name(const struct silofs_task_ctx *task,
                              const struct silofs_inode_info *dir_ii,
                              const struct silofs_namestr *name)
{
	int err;

	err = check_isdir(dir_ii);
	return_if_err(err);

	err = silofs_dir_check_name(dir_ii, task->corefs->uconv, name);
	return_if_err(err);

	return 0;
}

static int check_lookup(const struct silofs_task_ctx *task,
                        struct silofs_inode_info *dir_ii,
                        const struct silofs_namestr *name)
{
	int err;

	err = check_dir_and_name(task, dir_ii, name);
	return_if_err(err);

	err = check_xaccess(task, dir_ii);
	return_if_err(err);

	return 0;
}

static const struct silofs_mdigest_hd *
mdigest_of(const struct silofs_task_ctx *task)
{
	return task->corefs->md_hd;
}

static int assign_namehash(const struct silofs_task_ctx *task,
                           const struct silofs_inode_info *dir_ii,
                           const struct silofs_namestr *nstr,
                           struct silofs_namestr *out_nstr)
{
	const struct silofs_mdigest_hd *md_hd;
	int err;

	err = check_isdir(dir_ii);
	return_if_err(err);

	md_hd = mdigest_of(task);
	err   = silofs_dir_make_hname(dir_ii, md_hd, nstr, out_nstr);
	return_if_err(err);

	return 0;
}

static int
lookup_by_name(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
               const struct silofs_namestr *nstr,
               struct silofs_ino_dt *out_ino_dt)
{
	struct silofs_namestr name;
	int err;

	err = assign_namehash(task, dir_ii, nstr, &name);
	return_if_err(err);

	err = silofs_lookup_dentry(task, dir_ii, &name, out_ino_dt);
	return_if_err(err);

	return 0;
}

static int
stage_by_name(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
              const struct silofs_namestr *name, enum silofs_stg_mode stg_mode,
              struct silofs_inode_info **out_ii)
{
	struct silofs_ino_dt ino_dt = {};
	int err;

	err = lookup_by_name(task, dir_ii, name, &ino_dt);
	return_if_err(err);

	err = silofs_stage_inode_by(task, ino_dt.ino, stg_mode, out_ii);
	return_if_err(err);

	return 0;
}

static int
do_lookup(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
          const struct silofs_namestr *name, struct silofs_inode_info **out_ii)
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

int silofs_do_lookup(struct silofs_task_ctx *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info **out_ii)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_lookup(task, dir_ii, name, out_ii);
	inc_nlookup(task, *out_ii, err);
	silofs_ii_decref(dir_ii);
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

static int
check_nodent(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
             const struct silofs_namestr *name)
{
	struct silofs_ino_dt ino_dt = {};
	int err, ret;

	err = lookup_by_name(task, dir_ii, name, &ino_dt);
	if (err == 0) {
		ret = -SILOFS_EEXIST;
	} else if (err == -SILOFS_ENOENT) {
		ret = 0;
	} else {
		ret = err;
	}
	return ret;
}

static int check_spawn_inode(const struct silofs_task_ctx *task)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_curr_sbi(task, &sbi);
	return_if_err(err);

	err = silofs_sbi_check_iavail(sbi);
	return_if_err(err);

	return 0;
}

static int check_dir_add_dentry(const struct silofs_inode_info *dir_ii)
{
	if (!silofs_dir_may_add(dir_ii)) {
		return -SILOFS_EMLINK;
	}

	/* Special case for directory which is still held by open fd */
	if (silofs_ii_nlink(dir_ii) < 2) {
		return -SILOFS_ENOENT;
	}

	return 0;
}

static int check_add_dentry(const struct silofs_task_ctx *task,
                            const struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name)
{
	int err;

	err = check_dir_and_name(task, dir_ii, name);
	return_if_err(err);

	err = check_dir_add_dentry(dir_ii);
	return_if_err(err);

	return 0;
}

static int check_dir_can_add(struct silofs_task_ctx *task,
                             struct silofs_inode_info *dir_ii,
                             const struct silofs_namestr *name)
{
	int err;

	err = check_dir_waccess(task, dir_ii);
	return_if_err(err);

	err = check_nodent(task, dir_ii, name);
	return_if_err(err);

	err = check_add_dentry(task, dir_ii, name);
	return_if_err(err);

	return 0;
}

static int
check_create(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
             const struct silofs_namestr *name, mode_t mode)
{
	int err;

	err = check_on_writable_fs(task);
	return_if_err(err);

	err = check_dir_can_add(task, dir_ii, name);
	return_if_err(err);

	err = check_create_mode(mode);
	return_if_err(err);

	err = check_open_limit(task, dir_ii);
	return_if_err(err);

	return 0;
}

static int add_namehash_dentry(struct silofs_task_ctx *task,
                               struct silofs_inode_info *dir_ii,
                               const struct silofs_namestr *nstr,
                               struct silofs_inode_info *ii)
{
	struct silofs_namestr name;
	int err;

	err = assign_namehash(task, dir_ii, nstr, &name);
	return_if_err(err);

	err = silofs_add_dentry(task, dir_ii, &name, ii);
	return_if_err(err);

	return 0;
}

static int
do_remove_inode(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	return silofs_remove_inode_by(task, ii);
}

static int
do_add_dentry(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
              const struct silofs_namestr *nstr, struct silofs_inode_info *ii)
{
	int err;

	err = add_namehash_dentry(task, dir_ii, nstr, ii);
	if (err) {
		do_remove_inode(task, ii);
		return err;
	}
	return 0;
}

static void post_create_open(struct silofs_task_ctx *task,
                             struct silofs_inode_info *ii, bool kill_suidgid)
{
	update_nopen(task, ii, 1);
	if (kill_suidgid) {
		silofs_ii_kill_suidgid(ii);
	}
}

static int
do_create(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
          const struct silofs_namestr *name, mode_t mode, bool kill_suidgid,
          struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = check_create(task, dir_ii, name, mode);
	return_if_err(err);

	err = check_spawn_inode(task);
	return_if_err(err);

	err = spawn_inode_by_mode(task, dir_ii, mode, 0, &ii);
	return_if_err(err);

	err = do_add_dentry(task, dir_ii, name, ii);
	return_if_err(err);

	post_create_open(task, ii, kill_suidgid);
	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_create(struct silofs_task_ctx *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     bool kill_suidgid, struct silofs_inode_info **out_ii)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_create(task, dir_ii, name, mode, kill_suidgid, out_ii);
	inc_nlookup(task, *out_ii, err);
	silofs_ii_decref(dir_ii);
	return err;
}

static int
check_mknod(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
            const struct silofs_namestr *name, mode_t mode, dev_t rdev)
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
	if (!S_ISFIFO(mode) && !S_ISSOCK(mode) && !S_ISCHR(mode) &&
	    !S_ISBLK(mode)) {
		return -SILOFS_EOPNOTSUPP;
	}
	if (S_ISCHR(mode) || S_ISBLK(mode)) {
		if (rdev == 0) {
			return -SILOFS_EINVAL;
		}
		if (task->corefs->fsroot->ms_flags & MS_NODEV) {
			return -SILOFS_EOPNOTSUPP;
		}
	} else {
		if (rdev != 0) {
			return -SILOFS_EINVAL; /* XXX see man 3p mknod */
		}
	}
	return 0;
}

static int
do_mknod_reg(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
             const struct silofs_namestr *name, mode_t mode,
             struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_inode_info *ii = nullptr;

	err = do_create(task, dir_ii, name, mode, false, &ii);
	return_if_err(err);

	/* create reg via 'mknod' does not follow by release */
	update_nopen(task, ii, -1);
	*out_ii = ii;
	return 0;
}

static int do_mknod_special(struct silofs_task_ctx *task,
                            struct silofs_inode_info *dir_ii,
                            const struct silofs_namestr *name, mode_t mode,
                            dev_t rdev, struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = check_mknod(task, dir_ii, name, mode, rdev);
	return_if_err(err);

	err = check_spawn_inode(task);
	return_if_err(err);

	err = spawn_special_inode(task, dir_ii, mode, rdev, &ii);
	return_if_err(err);

	err = do_add_dentry(task, dir_ii, name, ii);
	return_if_err(err);

	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);

	/* can not use 'nopen' as FUSE does not sent OPEN on fifo, and
	 * therefore no RELEASE */
	ii_set_pinned(ii);

	*out_ii = ii;
	return 0;
}

int silofs_do_mknod(struct silofs_task_ctx *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii)
{
	int err;

	silofs_ii_incref(dir_ii);
	if (S_ISREG(mode)) {
		err = do_mknod_reg(task, dir_ii, name, mode, out_ii);
	} else {
		err = do_mknod_special(task, dir_ii, name, mode, dev, out_ii);
	}
	inc_nlookup(task, *out_ii, err);
	silofs_ii_decref(dir_ii);
	return err;
}

/*
 * Unlike historic UNIX (*BSD, Solaris) Linux does not have O_EXEC. On the
 * other hand, there is FMODE_EXEC internal flag, which has a value (1 << 5)
 * that is not used by other O_x flags (see comment in <asm-generic/fcntl.h>).
 * Interestingly, it is propagated via FUSE, probably unintentionally. Need
 * further investigation.
 */
#define FMODE_EXEC (1 << 5)
#ifdef O_EXEC
#error "unexpected O_EXEC define"
#endif
#define O_EXEC FMODE_EXEC

static int o_flags_to_rwx(int o_flags)
{
	int rwx = 0;
	int mask;

	if ((o_flags & O_RDWR) == O_RDWR) {
		rwx = R_OK | W_OK;
	} else if ((o_flags & O_WRONLY) == O_WRONLY) {
		rwx = W_OK;
	} else if ((o_flags & O_RDONLY) == O_RDONLY) {
		rwx = R_OK;
	}
	if ((o_flags & O_TRUNC) == O_TRUNC) {
		rwx |= W_OK;
	}
	if ((o_flags & O_APPEND) == O_APPEND) {
		rwx |= W_OK;
	}
	/* special case of Kernel's execve */
	mask = (O_LARGEFILE | O_EXEC);
	if ((o_flags & mask) == mask) {
		rwx |= X_OK;
	}
	return rwx;
}

static int check_open_flags(const struct silofs_inode_info *ii, int o_flags)
{
	if (!silofs_ii_isdir(ii) && (o_flags & O_DIRECTORY)) {
		return -SILOFS_EISDIR;
	}
	if (o_flags & (O_CREAT | O_EXCL)) {
		return -SILOFS_EEXIST; /* XXX ? */
	}
	if (silofs_ii_isreg(ii) && (o_flags & O_TRUNC) &&
	    !(o_flags & (O_WRONLY | O_RDWR))) {
		return -SILOFS_EACCES;
	}
	if (silofs_ii_isdir(ii) && (o_flags & O_DIRECT)) {
		return -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static int check_open(const struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii, int o_flags)
{
	int rwx, err;

	err = check_reg_or_fifo(ii);
	return_if_err(err);

	err = check_open_flags(ii, o_flags);
	return_if_err(err);

	rwx = o_flags_to_rwx(o_flags);
	err = silofs_do_access(task, ii, rwx);
	return_if_err(err);

	err = check_open_limit(task, ii);
	return_if_err(err);

	return 0;
}

static int trunc_data(struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii, bool kill_suidgid)
{
	int ret = 0;

	if (silofs_ii_isreg(ii)) {
		ret = silofs_do_truncate(task, ii, 0, kill_suidgid);
	}
	return ret;
}

static int
post_open(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
          int o_flags, bool kill_suidgid)
{
	int err;

	if (o_flags & O_TRUNC) {
		err = trunc_data(task, ii, kill_suidgid);
		return_if_err(err);
	}
	if (kill_suidgid) {
		silofs_ii_kill_suidgid(ii);
	}
	return 0;
}

static int do_open(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                   int o_flags, bool kill_suidgid)
{
	int err;

	err = check_open(task, ii, o_flags);
	return_if_err(err);

	err = post_open(task, ii, o_flags, kill_suidgid);
	return_if_err(err);

	post_create_open(task, ii, kill_suidgid);
	return 0;
}

int silofs_do_open(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                   int o_flags, bool kill_suidgid)
{
	int err;

	silofs_ii_incref(ii);
	err = do_open(task, ii, o_flags, kill_suidgid);
	silofs_ii_decref(ii);
	return err;
}

static void ii_cleardirty_all(struct silofs_inode_info *ii)
{
	silofs_ii_cleardirty_lnis(ii);
	silofs_ii_cleardirty(ii);
}

static int
drop_ispecific(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	int err = 0;

	if (silofs_ii_isdir(ii)) {
		err = silofs_drop_dir(task, ii);
	} else if (silofs_ii_isreg(ii)) {
		err = silofs_drop_reg(task, ii);
	} else if (silofs_ii_islnk(ii)) {
		err = silofs_drop_symlink(task, ii);
	}
	if (!err) {
		ii_cleardirty_all(ii);
	}
	return err;
}

static int
drop_unlinked(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	int err;

	err = silofs_drop_xattr(task, ii);
	return_if_err(err);

	err = drop_ispecific(task, ii);
	return_if_err(err);

	err = do_remove_inode(task, ii);
	return_if_err(err);

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
	const bool isdir    = silofs_ii_isdir(ii);
	const nlink_t nlink = silofs_ii_nlink(ii);

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

static bool ii_is_orphan(const struct silofs_inode_info *ii)
{
	return (ii->i_nopen == 0) && ii_isnlink_orphan(ii);
}

static int try_prune_loose_data(struct silofs_task_ctx *task,
                                struct silofs_inode_info *ii)
{
	/*
	 * Special case of remove-and-unlinked regular file which still has
	 * ref-count due to in-flight flush. In such case, drop its data now
	 * to release resources from within current call.
	 */
	int ret = 0;

	if (silofs_ii_isreg(ii) && silofs_ii_isloose(ii)) {
		ret = silofs_drop_reg(task, ii);
	}
	return ret;
}

static void
enqueue_if_loose(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	if (silofs_ii_isloose(ii) && !ii_ispinned(ii)) {
		silofs_enq_loose_inode(task, ii);
	}
}

static int try_prune_inode(struct silofs_task_ctx *task,
                           struct silofs_inode_info *ii, bool update_ctime)
{
	int err;

	if (ii_is_orphan(ii)) {
		ii_cleardirty_all(ii);
		silofs_ii_set_loose(ii);
	}
	if (ii_isdropable(ii)) {
		return drop_unlinked(task, ii);
	}

	err = try_prune_loose_data(task, ii);
	return_if_err(err);

	if (update_ctime) {
		silofs_update_itimes_of(task, ii, SILOFS_IATTR_CTIME);
	}
	enqueue_if_loose(task, ii);
	return 0;
}

static int
remove_dentry(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
              struct silofs_inode_info *ii, const struct silofs_namestr *name)
{
	int err;

	silofs_ii_incref(ii);
	err = silofs_remove_dentry(task, dir_ii, name);
	silofs_ii_decref(ii);
	return err;
}

static int remove_dentry_of(struct silofs_task_ctx *task,
                            struct silofs_inode_info *dir_ii,
                            struct silofs_inode_info *ii,
                            const struct silofs_namestr *nstr)
{
	struct silofs_namestr name;
	int err;

	err = assign_namehash(task, dir_ii, nstr, &name);
	return_if_err(err);

	err = remove_dentry(task, dir_ii, ii, &name);
	return_if_err(err);

	return 0;
}

static int remove_de_and_prune(struct silofs_task_ctx *task,
                               struct silofs_inode_info *dir_ii,
                               struct silofs_inode_info *ii,
                               const struct silofs_namestr *nstr)
{
	int err;

	err = remove_dentry_of(task, dir_ii, ii, nstr);
	return_if_err(err);

	err = try_prune_inode(task, ii, true);
	return_if_err(err);

	return 0;
}

static int remove_de_and_update(struct silofs_task_ctx *task,
                                struct silofs_inode_info *dir_ii,
                                struct silofs_inode_info *ii,
                                const struct silofs_namestr *nstr)
{
	int err;

	err = remove_dentry_of(task, dir_ii, ii, nstr);
	if (err) {
		return err;
	}
	silofs_update_itimes_of(task, ii, SILOFS_IATTR_CTIME);
	return 0;
}

static int check_prepare_unlink(struct silofs_task_ctx *task,
                                struct silofs_inode_info *dir_ii,
                                const struct silofs_namestr *nstr,
                                struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = check_dir_waccess(task, dir_ii);
	return_if_err(err);

	err = stage_by_name(task, dir_ii, nstr, SILOFS_STG_COW, &ii);
	return_if_err(err);

	err = check_sticky(task, dir_ii, ii);
	return_if_err(err);

	err = check_notdir(ii);
	return_if_err(err);

	*out_ii = ii;
	return 0;
}

static int
do_unlink(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
          const struct silofs_namestr *nstr)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = check_prepare_unlink(task, dir_ii, nstr, &ii);
	return_if_err(err);

	err = remove_de_and_prune(task, dir_ii, ii, nstr);
	return_if_err(err);

	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_unlink(struct silofs_task_ctx *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *nstr)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_unlink(task, dir_ii, nstr);
	silofs_ii_decref(dir_ii);
	return err;
}

static int check_nomlink(const struct silofs_inode_info *ii)
{
	const size_t link_max = SILOFS_LINK_MAX;

	return (silofs_ii_nlink(ii) < link_max) ? 0 : -SILOFS_EMLINK;
}

static int
check_link(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
           const struct silofs_namestr *name, struct silofs_inode_info *ii)
{
	int err;

	err = check_dir_waccess(task, dir_ii);
	return_if_err(err);

	err = check_notdir(ii);
	return_if_err(err);

	err = check_nodent(task, dir_ii, name);
	return_if_err(err);

	err = check_nomlink(ii);
	return_if_err(err);

	return 0;
}

static int
do_link(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
        const struct silofs_namestr *nstr, struct silofs_inode_info *ii)
{
	int err;

	err = check_link(task, dir_ii, nstr, ii);
	return_if_err(err);

	err = add_namehash_dentry(task, dir_ii, nstr, ii);
	return_if_err(err);

	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);
	silofs_update_itimes_of(task, ii, SILOFS_IATTR_CTIME);

	return 0;
}

int silofs_do_link(struct silofs_task_ctx *task,
                   struct silofs_inode_info *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info *ii)
{
	int err;

	silofs_ii_incref(dir_ii);
	silofs_ii_incref(ii);
	err = do_link(task, dir_ii, name, ii);
	inc_nlookup(task, ii, err);
	silofs_ii_decref(ii);
	silofs_ii_decref(dir_ii);
	return err;
}

static int
check_mkdir(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
            const struct silofs_namestr *name)
{
	int err;

	err = check_dir_can_add(task, dir_ii, name);
	return_if_err(err);

	err = check_nomlink(dir_ii);
	return_if_err(err);

	return 0;
}

static int
do_mkdir(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
         const struct silofs_namestr *name, mode_t mode,
         struct silofs_inode_info **out_ii)
{
	int err;

	err = check_mkdir(task, dir_ii, name);
	return_if_err(err);

	err = check_spawn_inode(task);
	return_if_err(err);

	err = spawn_dir_inode(task, dir_ii, mode, out_ii);
	return_if_err(err);

	silofs_dir_inherit_parent(*out_ii, dir_ii);

	err = do_add_dentry(task, dir_ii, name, *out_ii);
	return_if_err(err);

	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_mkdir(struct silofs_task_ctx *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_mkdir(task, dir_ii, name, mode, out_ii);
	inc_nlookup(task, *out_ii, err);
	silofs_ii_decref(dir_ii);
	return err;
}

static int check_rmdir_child(const struct silofs_task_ctx *task,
                             const struct silofs_inode_info *parent_ii,
                             const struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_on_writable_fs(task);
	if (err) {
		return err;
	}
	err = check_isdir(dir_ii);
	if (err) {
		return err;
	}
	if (!silofs_dir_isempty(dir_ii)) {
		return -SILOFS_ENOTEMPTY;
	}
	if (silofs_ii_isrootd(dir_ii)) {
		return -SILOFS_EBUSY;
	}
	err = check_sticky(task, parent_ii, dir_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_prepare_rmdir(struct silofs_task_ctx *task,
                               struct silofs_inode_info *dir_ii,
                               const struct silofs_namestr *name,
                               struct silofs_inode_info **out_ii)
{
	int err;

	err = check_dir_waccess(task, dir_ii);
	return_if_err(err);

	err = stage_by_name(task, dir_ii, name, SILOFS_STG_COW, out_ii);
	return_if_err(err);

	err = check_rmdir_child(task, dir_ii, *out_ii);
	return_if_err(err);

	return 0;
}

static int
do_rmdir(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
         const struct silofs_namestr *nstr)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = check_prepare_rmdir(task, dir_ii, nstr, &ii);
	return_if_err(err);

	err = remove_de_and_prune(task, dir_ii, ii, nstr);
	return_if_err(err);

	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);
	return 0;
}

int silofs_do_rmdir(struct silofs_task_ctx *task,
                    struct silofs_inode_info *dir_ii,
                    const struct silofs_namestr *name)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_rmdir(task, dir_ii, name);
	silofs_ii_decref(dir_ii);
	return err;
}

static int create_lnk_inode(struct silofs_task_ctx *task,
                            const struct silofs_inode_info *dir_ii,
                            const struct silofs_strview *symval,
                            struct silofs_inode_info **out_ii)
{
	int err;

	err = spawn_lnk_inode(task, dir_ii, out_ii);
	return_if_err(err);

	err = silofs_bind_symval(task, *out_ii, symval);
	if (err) {
		do_remove_inode(task, *out_ii);
		return err;
	}
	return 0;
}

static int check_symval(const struct silofs_strview *symval)
{
	const size_t symlnk_max = silofs_min(SILOFS_SYMLNK_MAX, PATH_MAX);

	if (symval->len == 0) {
		return -SILOFS_EINVAL;
	}
	if (symval->len > symlnk_max) {
		return -SILOFS_ENAMETOOLONG;
	}
	return 0;
}

static int
check_symlink(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
              const struct silofs_namestr *name,
              const struct silofs_strview *symval)
{
	int err;

	err = check_dir_can_add(task, dir_ii, name);
	return_if_err(err);

	err = check_symval(symval);
	return_if_err(err);

	return 0;
}

static int
do_symlink(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
           const struct silofs_namestr *name,
           const struct silofs_strview *symval,
           struct silofs_inode_info **out_ii)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = check_symlink(task, dir_ii, name, symval);
	return_if_err(err);

	err = check_spawn_inode(task);
	return_if_err(err);

	err = create_lnk_inode(task, dir_ii, symval, &ii);
	return_if_err(err);

	err = do_add_dentry(task, dir_ii, name, ii);
	return_if_err(err);

	silofs_update_itimes_of(task, dir_ii, SILOFS_IATTR_MCTIME);

	*out_ii = ii;
	return 0;
}

int silofs_do_symlink(struct silofs_task_ctx *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_strview *symval,
                      struct silofs_inode_info **out_ii)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_symlink(task, dir_ii, name, symval, out_ii);
	inc_nlookup(task, *out_ii, err);
	silofs_ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_opendir_flags(const struct silofs_inode_info *ii, int o_flags)
{
	const bool isdir = silofs_ii_isdir(ii);

	return (isdir && (o_flags & O_DIRECT)) ? -SILOFS_EOPNOTSUPP : 0;
}

static int check_opendir(const struct silofs_task_ctx *task,
                         struct silofs_inode_info *dir_ii, int o_flags)
{
	int err;

	err = check_isdir(dir_ii);
	return_if_err(err);

	err = check_raccess(task, dir_ii);
	return_if_err(err);

	err = check_open_limit(task, dir_ii);
	return_if_err(err);

	err = check_opendir_flags(dir_ii, o_flags);
	return_if_err(err);

	return 0;
}

static int do_opendir(struct silofs_task_ctx *task,
                      struct silofs_inode_info *dir_ii, int o_flags)
{
	int err;

	err = check_opendir(task, dir_ii, o_flags);
	return_if_err(err);

	update_nopen(task, dir_ii, 1);
	return 0;
}

int silofs_do_opendir(struct silofs_task_ctx *task,
                      struct silofs_inode_info *dir_ii, int o_flags)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_opendir(task, dir_ii, o_flags);
	silofs_ii_decref(dir_ii);

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
	return_if_err(err);

	err = check_opened(dir_ii);
	return_if_err(err);

	err = check_releasedir_flags(o_flags);
	return_if_err(err);

	return 0;
}

static int
do_releasedir_flush(struct silofs_task_ctx *task,
                    struct silofs_inode_info *dir_ii, int o_flags, bool flush)
{
	int flags = SILOFS_CTLF_RELEASE;

	if (o_flags & (O_SYNC | O_DSYNC)) {
		flags |= SILOFS_CTLF_FSYNC;
	}
	if (flush) {
		flags |= SILOFS_CTLF_NOW;
	}
	return silofs_flush_dirty_of(task, dir_ii, flags);
}

static int
do_releasedir(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
              int o_flags, bool flush)
{
	int err;

	err = check_releasedir(dir_ii, o_flags);
	return_if_err(err);

	err = do_releasedir_flush(task, dir_ii, o_flags, flush);
	return_if_err(err);

	update_nopen(task, dir_ii, -1);
	return 0;
}

int silofs_do_releasedir(struct silofs_task_ctx *task,
                         struct silofs_inode_info *dir_ii, int o_flags,
                         bool flush)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_releasedir(task, dir_ii, o_flags, flush);
	silofs_ii_decref(dir_ii);

	return !err ? try_prune_inode(task, dir_ii, false) : err;
}

static int check_isdir_and_open(const struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_isdir(dir_ii);
	return_if_err(err);

	err = check_opened(dir_ii);
	return_if_err(err);

	return 0;
}

static int check_readdir(const struct silofs_inode_info *dir_ii)
{
	return check_isdir_and_open(dir_ii);
}

int silofs_do_readdir(struct silofs_task_ctx *task,
                      struct silofs_inode_info *dir_ii,
                      struct silofs_readdir_ctx *rd_ctx)
{
	int err;

	err = check_readdir(dir_ii);
	return_if_err(err);

	err = silofs_readdir_normal(task, dir_ii, rd_ctx);
	return_if_err(err);

	return 0;
}

int silofs_do_readdirplus(struct silofs_task_ctx *task,
                          struct silofs_inode_info *dir_ii,
                          struct silofs_readdir_ctx *rd_ctx)
{
	int err;

	err = check_readdir(dir_ii);
	return_if_err(err);

	err = silofs_readdir_plus(task, dir_ii, rd_ctx);
	return_if_err(err);

	return 0;
}

static int check_notdir_and_opened(const struct silofs_inode_info *ii)
{
	int err;

	err = check_notdir(ii);
	return_if_err(err);

	err = check_opened(ii);
	return_if_err(err);

	return 0;
}

static int check_release(const struct silofs_inode_info *ii)
{
	return check_notdir_and_opened(ii);
}

static int do_release(struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii, bool flush)
{
	const int flags = flush ? SILOFS_CTLF_NOW : SILOFS_CTLF_RELEASE;
	int err;

	err = check_release(ii);
	return_if_err(err);

	err = silofs_flush_dirty_of(task, ii, flags);
	return_if_err(err);

	update_nopen(task, ii, -1);
	return 0;
}

int silofs_do_release(struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii, bool flush)
{
	int err;

	silofs_ii_incref(ii);
	err = do_release(task, ii, flush);
	silofs_ii_decref(ii);

	return !err ? try_prune_inode(task, ii, false) : err;
}

static int check_fsyncdir(const struct silofs_inode_info *dir_ii)
{
	return check_isdir_and_open(dir_ii);
}

static int
do_fsyncdir(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii)
{
	int err;

	err = check_fsyncdir(dir_ii);
	return_if_err(err);

	err = silofs_flush_dirty_of(task, dir_ii, SILOFS_CTLF_FSYNC);
	return_if_err(err);

	return 0;
}

int silofs_do_fsyncdir(struct silofs_task_ctx *task,
                       struct silofs_inode_info *dir_ii, bool dsync)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_fsyncdir(task, dir_ii);
	silofs_ii_decref(dir_ii);

	silofs_unused(dsync);
	return err;
}

static int check_fsync(const struct silofs_inode_info *ii)
{
	return check_notdir_and_opened(ii);
}

static int do_fsync(struct silofs_task_ctx *task, struct silofs_inode_info *ii)
{
	int err;

	err = check_fsync(ii);
	return_if_err(err);

	err = silofs_flush_dirty_of(task, ii, SILOFS_CTLF_FSYNC);
	return_if_err(err);

	return 0;
}

/*
 * TODO-0029: Revisit fsync semantics
 *
 * Re-think it over. See also:
 * https://lwn.net/Articles/351422/
 * https://lwn.net/Articles/322823/
 */
int silofs_do_fsync(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    bool datasync)
{
	int err;

	silofs_ii_incref(ii);
	err = do_fsync(task, ii);
	silofs_ii_decref(ii);

	silofs_unused(datasync);
	return err;
}

int silofs_do_flush(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    bool now)
{
	const int flags = now ? SILOFS_CTLF_NOW : 0;

	return silofs_flush_dirty_of(task, ii, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_dentry_ref {
	struct silofs_inode_info *dir_ii;
	const struct silofs_namestr *name;
	struct silofs_inode_info *ii;
};

static int check_add_dentry_at(const struct silofs_task_ctx *task,
                               const struct silofs_dentry_ref *dref)
{
	return check_add_dentry(task, dref->dir_ii, dref->name);
}

static int
do_add_dentry_at(struct silofs_task_ctx *task, struct silofs_dentry_ref *dref,
                 struct silofs_inode_info *ii)

{
	int err;

	err = add_namehash_dentry(task, dref->dir_ii, dref->name, ii);
	return_if_err(err);

	dref->ii = ii;
	return 0;
}

static int remove_de_and_prune_at(struct silofs_task_ctx *task,
                                  struct silofs_dentry_ref *dref)
{
	int err;

	err = remove_de_and_prune(task, dref->dir_ii, dref->ii, dref->name);
	return_if_err(err);

	dref->ii = nullptr;
	return 0;
}

static int remove_de_and_update_at(struct silofs_task_ctx *task,
                                   struct silofs_dentry_ref *dref)
{
	int err;

	err = remove_de_and_update(task, dref->dir_ii, dref->ii, dref->name);
	return_if_err(err);

	dref->ii = nullptr;
	return 0;
}

static int do_rename_move(struct silofs_task_ctx *task,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	err = check_add_dentry_at(task, new_dref);
	return_if_err(err);

	err = remove_de_and_update_at(task, cur_dref);
	return_if_err(err);

	err = do_add_dentry_at(task, new_dref, ii);
	return_if_err(err);

	return 0;
}

static int
rename_move(struct silofs_task_ctx *task, struct silofs_dentry_ref *cur_dref,
            struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	silofs_ii_incref(ii);
	err = do_rename_move(task, cur_dref, new_dref);
	silofs_ii_decref(ii);
	return err;
}

static int
rename_unlink(struct silofs_task_ctx *task, struct silofs_dentry_ref *dref)
{
	return remove_de_and_prune_at(task, dref);
}

static int do_rename_replace(struct silofs_task_ctx *task,
                             struct silofs_dentry_ref *cur_dref,
                             struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	err = remove_de_and_prune_at(task, new_dref);
	return_if_err(err);

	err = remove_de_and_update_at(task, cur_dref);
	return_if_err(err);

	err = do_add_dentry_at(task, new_dref, ii);
	return_if_err(err);

	return 0;
}

static int rename_replace(struct silofs_task_ctx *task,
                          struct silofs_dentry_ref *cur_dref,
                          struct silofs_dentry_ref *new_dref)
{
	struct silofs_inode_info *ii = cur_dref->ii;
	int err;

	silofs_ii_incref(ii);
	err = do_rename_replace(task, cur_dref, new_dref);
	silofs_ii_decref(ii);
	return err;
}

static int do_rename_exchange(struct silofs_task_ctx *task,
                              struct silofs_dentry_ref *dref1,
                              struct silofs_dentry_ref *dref2)
{
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;
	int err;

	err = remove_de_and_update_at(task, dref1);
	return_if_err(err);

	err = remove_de_and_update_at(task, dref2);
	return_if_err(err);

	err = do_add_dentry_at(task, dref2, ii1);
	return_if_err(err);

	err = do_add_dentry_at(task, dref1, ii2);
	return_if_err(err);

	return 0;
}

static int
rename_exchange(struct silofs_task_ctx *task, struct silofs_dentry_ref *dref1,
                struct silofs_dentry_ref *dref2)
{
	struct silofs_inode_info *ii1 = dref1->ii;
	struct silofs_inode_info *ii2 = dref2->ii;
	int err;

	silofs_ii_incref(ii1);
	silofs_ii_incref(ii2);
	err = do_rename_exchange(task, dref1, dref2);
	silofs_ii_decref(ii2);
	silofs_ii_decref(ii1);
	return err;
}

static int rename_specific(struct silofs_task_ctx *task,
                           struct silofs_dentry_ref *cur_dref,
                           struct silofs_dentry_ref *new_dref, int flags)
{
	int err;

	if (new_dref->ii == nullptr) {
		err = rename_move(task, cur_dref, new_dref);
	} else if (cur_dref->ii == new_dref->ii) {
		err = rename_unlink(task, cur_dref);
	} else if (flags & RENAME_EXCHANGE) {
		err = rename_exchange(task, cur_dref, new_dref);
	} else {
		err = rename_replace(task, cur_dref, new_dref);
	}
	silofs_update_itimes_of(task, cur_dref->dir_ii, SILOFS_IATTR_MCTIME);
	silofs_update_itimes_of(task, new_dref->dir_ii, SILOFS_IATTR_MCTIME);
	return err;
}

static int check_rename_exchange(const struct silofs_task_ctx *task,
                                 const struct silofs_dentry_ref *cur_dref,
                                 const struct silofs_dentry_ref *new_dref)
{
	const struct silofs_inode_info *ii     = cur_dref->ii;
	const struct silofs_inode_info *old_ii = new_dref->ii;
	int err;

	if (ii == nullptr) {
		return -SILOFS_EINVAL;
	}
	err = check_on_writable_fs(task);
	if (err) {
		return err;
	}
	if ((ii != old_ii) &&
	    (silofs_ii_isdir(ii) != silofs_ii_isdir(old_ii))) {
		if (silofs_ii_isdir(old_ii)) {
			err = check_nomlink(new_dref->dir_ii);
		} else {
			err = check_nomlink(cur_dref->dir_ii);
		}
	}
	return err;
}

static int check_rename(const struct silofs_task_ctx *task,
                        const struct silofs_dentry_ref *cur_dref,
                        const struct silofs_dentry_ref *new_dref, int flags)
{
	const struct silofs_inode_info *ii     = cur_dref->ii;
	const struct silofs_inode_info *old_ii = new_dref->ii;
	const bool old_exists                  = (old_ii != nullptr);
	int err                                = 0;

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
		return check_rename_exchange(task, cur_dref, new_dref);
	}
	if (old_exists && silofs_ii_isdir(old_ii) && (old_ii != ii)) {
		if (ii == nullptr) {
			err = check_nomlink(new_dref->dir_ii);
		} else {
			err = check_rmdir_child(task, cur_dref->dir_ii,
			                        old_ii);
		}
	}
	return err;
}

static int check_stage_rename_at(struct silofs_task_ctx *task,
                                 struct silofs_dentry_ref *dref, bool new_de)
{
	int err;

	err = check_dir_waccess(task, dref->dir_ii);
	if (err) {
		return err;
	}
	err = stage_by_name(task, dref->dir_ii, dref->name, SILOFS_STG_COW,
	                    &dref->ii);
	if (err) {
		return ((err == -SILOFS_ENOENT) && new_de) ? 0 : err;
	}
	err = check_sticky(task, dref->dir_ii, dref->ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_stage_rename_at2(struct silofs_task_ctx *task,
                                  struct silofs_dentry_ref *dref,
                                  struct silofs_dentry_ref *dalt, bool new_de)
{
	int ret;

	silofs_ii_incref(dalt->dir_ii);
	silofs_ii_incref(dalt->ii);
	ret = check_stage_rename_at(task, dref, new_de);
	silofs_ii_decref(dalt->ii);
	silofs_ii_decref(dalt->dir_ii);
	return ret;
}

static int
do_rename(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
          const struct silofs_namestr *name,
          struct silofs_inode_info *newdir_ii,
          const struct silofs_namestr *newname, int flags)
{
	struct silofs_dentry_ref cur_dref = {
		.dir_ii = dir_ii,
		.name   = name,
	};
	struct silofs_dentry_ref new_dref = {
		.dir_ii = newdir_ii,
		.name   = newname,
	};
	int err;

	err = check_stage_rename_at(task, &cur_dref, false);
	return_if_err(err);

	err = check_stage_rename_at2(task, &new_dref, &cur_dref, true);
	return_if_err(err);

	err = check_rename(task, &cur_dref, &new_dref, flags);
	return_if_err(err);

	err = rename_specific(task, &cur_dref, &new_dref, flags);
	return_if_err(err);

	return 0;
}

int silofs_do_rename(struct silofs_task_ctx *task,
                     struct silofs_inode_info *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info *newdir_ii,
                     const struct silofs_namestr *newname, int flags)
{
	int err;

	silofs_ii_incref(dir_ii);
	silofs_ii_incref(newdir_ii);
	err = do_rename(task, dir_ii, name, newdir_ii, newname, flags);
	silofs_ii_decref(newdir_ii);
	silofs_ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
fill_proc(const struct silofs_task_ctx *task, struct silofs_query_proc *qpr)
{
	struct silofs_alloc_stat alloc_stat;

	silofs_memstat(task->corefs->alloc, &alloc_stat);
	silofs_memzero(qpr, sizeof(*qpr));
	qpr->uid       = task->corefs->fsroot->owner.uid;
	qpr->gid       = task->corefs->fsroot->owner.gid;
	qpr->pid       = getpid();
	qpr->msflags   = task->corefs->fsroot->ms_flags;
	qpr->uptime    = silofs_fsroot_uptime(task->corefs->fsroot);
	qpr->iopen_max = task->corefs->fsroot->opstat.op_iopen_max;
	qpr->iopen_cur = task->corefs->fsroot->opstat.op_iopen;
	qpr->memsz_max = alloc_stat.nbytes_max;
	qpr->memsz_cur = alloc_stat.nbytes_use;
	qpr->bopen_cur = task->corefs->dstor->ds_hq.dsq_lru.sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
do_statvfs(const struct silofs_task_ctx *task, struct statvfs *out_stv)
{
	struct silofs_uber_stats ub_stats;
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	/*
	 * TODO-0068: Export uber stats via dedicated ioctl.
	 */
	silofs_ubi_collect_stats(task->corefs->fsroot->ubi, &ub_stats);

	err = get_sbi(task, &sbi);
	return_if_err(err);

	silofs_sbi_calc_statvfs(sbi, out_stv);

	put_sbi(sbi);
	return 0;
}

int silofs_do_statvfs(const struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii, struct statvfs *out_stv)
{
	int err;

	silofs_ii_incref(ii);
	err = do_statvfs(task, out_stv);
	silofs_ii_decref(ii);
	return err;
}

static void str_to_buf(const struct silofs_strview *sv, void *buf, size_t bsz)
{
	if ((sv != nullptr) && (bsz > 0)) {
		char *s = buf;

		silofs_strview_copyto(sv, s, bsz);
		s[bsz - 1] = '\0';
	}
}

static void fill_query_version(struct silofs_ioc_query *query)
{
	struct silofs_strview s = { .str = nullptr };
	const size_t bsz        = sizeof(query->u.version.string);

	silofs_strview_init(&s, silofs_sw_version_string);
	query->u.version.major    = silofs_sw_vers.major;
	query->u.version.minor    = silofs_sw_vers.minor;
	query->u.version.sublevel = silofs_sw_vers.sublevel;
	str_to_buf(&s, query->u.version.string, bsz);
}

static void fill_query_repo(const struct silofs_task_ctx *task,
                            struct silofs_ioc_query *query)
{
	struct silofs_strview strview;
	const struct silofs_fsroot *fsroot = task->corefs->fsroot;

	silofs_strview_init(&strview, fsroot->baseref.repodir);
	str_to_buf(&strview, query->u.repo.path, sizeof(query->u.repo.path));
}

static void fill_query_boot_name(const struct silofs_task_ctx *task,
                                 struct silofs_ioc_query *query)
{
	struct silofs_strview strview;
	const struct silofs_fsroot *fsroot = task->corefs->fsroot;

	silofs_strview_init(&strview, fsroot->baseref.refname);
	str_to_buf(&strview, query->u.boot.name, sizeof(query->u.boot.name));
}

static void fill_query_boot_fsref(const struct silofs_task_ctx *task,
                                  struct silofs_ioc_query *query)
{
	const struct silofs_fsroot *fsroot = task->corefs->fsroot;

	silofs_fsref_export(&query->u.boot.fsref, &fsroot->mbref);
}

static void fill_query_boot(const struct silofs_task_ctx *task,
                            struct silofs_ioc_query *query)
{
	silofs_memzero(query, sizeof(*query));
	fill_query_boot_name(task, query);
	fill_query_boot_fsref(task, query);
}

static void fill_query_proc(const struct silofs_task_ctx *task,
                            struct silofs_ioc_query *query)
{
	fill_proc(task, &query->u.proc);
}

static void fill_query_spstats(const struct silofs_task_ctx *task,
                               struct silofs_ioc_query *query)
{
	/*
	 * TODO-0069: Export space-stats properly.
	 */
	struct silofs_query_spstats *spst = &query->u.spstats;

	memset(spst, 0, sizeof(*spst));
	silofs_unused(task);
}

static int
do_query_statx(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
               struct silofs_ioc_query *query)
{
	struct silofs_stat st           = { .gen = 0 };
	const enum silofs_inodef iflags = silofs_ii_flags(ii);
	int err;

	err = silofs_do_statx(task, ii, STATX_ALL | STATX_BTIME, &st);
	if (err) {
		return err;
	}
	memcpy(&query->u.statx.stx, &st.stx, sizeof(query->u.statx.stx));
	query->u.statx.iflags = (uint32_t)iflags;
	if (silofs_ii_isdir(ii)) {
		const enum silofs_dirf dflags = silofs_dir_flags(ii);

		query->u.statx.dirflags = (uint32_t)dflags;
	}
	return 0;
}

static int
do_query_subcmd(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                enum silofs_query_type qtype, struct silofs_ioc_query *query)
{
	int err = 0;

	silofs_memzero(&query->u, sizeof(query->u));

	switch (qtype) {
	case SILOFS_QUERY_VERSION:
		fill_query_version(query);
		break;
	case SILOFS_QUERY_REPO:
		fill_query_repo(task, query);
		break;
	case SILOFS_QUERY_BOOT:
		fill_query_boot(task, query);
		break;
	case SILOFS_QUERY_PROC:
		fill_query_proc(task, query);
		break;
	case SILOFS_QUERY_SPSTATS:
		fill_query_spstats(task, query);
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

static int
do_query(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
         enum silofs_query_type qtype, struct silofs_ioc_query *query)
{
	int err;

	err = check_raccess(task, ii);
	return_if_err(err);

	err = do_query_subcmd(task, ii, qtype, query);
	return_if_err(err);

	return 0;
}

int silofs_do_query(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    enum silofs_query_type qtype,
                    struct silofs_ioc_query *out_qry)
{
	int err;

	silofs_ii_incref(ii);
	err = do_query(task, ii, qtype, out_qry);
	silofs_ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_fsowner(const struct silofs_task_ctx *task)
{
	const struct silofs_creds *creds = &task->auth.creds;
	const uid_t owner_uid            = task->corefs->fsroot->owner.uid;
	const uid_t host_uid             = creds->host_cred.uid;

	return silofs_uid_eq(host_uid, owner_uid) ? 0 : -SILOFS_EPERM;
}

static int check_clone_flags(int flags)
{
	const int allow_flags = 0;

	return (flags & ~allow_flags) ? -SILOFS_EINVAL : 0;
}

static int check_clone(const struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii, int flags)
{
	int err;

	err = check_on_writable_fs(task);
	return_if_err(err);

	err = check_isdir(ii);
	return_if_err(err);

	err = check_raccess(task, ii);
	return_if_err(err);

	err = check_fsowner(task);
	return_if_err(err);

	err = check_clone_flags(flags);
	return_if_err(err);

	return 0;
}

static int flush_and_sync(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	return_if_err(err);

	err = silofs_repo_fsync_all(task->corefs->repo);
	return_if_err(err);

	return 0;
}

static int
do_forkfs(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
          int flags, struct silofs_mbrefs *out_mbrefs)
{
	int err;

	err = check_clone(task, dir_ii, flags);
	return_if_err(err);

	err = flush_and_sync(task);
	return_if_err(err);

	err = silofs_env_forkfs(nullptr, out_mbrefs); /* XXX FIXME */
	return_if_err(err);

	err = flush_and_sync(task);
	return_if_err(err);

	return 0;
}

static void relax_post_forkfs(const struct silofs_task_ctx *task)
{
	silofs_lcache_relax(task->corefs->lcache, SILOFS_CTLF_NOW);
}

static int do_forkfs_and_relex(struct silofs_task_ctx *task,
                               struct silofs_inode_info *dir_ii, int flags,
                               struct silofs_mbrefs *out_mbrefs)
{
	int err;

	err = do_forkfs(task, dir_ii, flags, out_mbrefs);
	return_if_err(err);

	relax_post_forkfs(task);
	return 0;
}

int silofs_do_forkfs(struct silofs_task_ctx *task,
                     struct silofs_inode_info *dir_ii, int flags,
                     struct silofs_mbrefs *out_mbrefs)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_forkfs_and_relex(task, dir_ii, flags, out_mbrefs);
	silofs_ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_tune_mask(int iflags_mask)
{
	const int itune_mask = SILOFS_INODEF_FTYPE2;

	if ((iflags_mask | itune_mask) != itune_mask) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int check_tune_flags(int iflags_want, int iflags_dont)
{
	int err;

	err = check_tune_mask(iflags_want);
	return_if_err(err);

	err = check_tune_mask(iflags_dont);
	return_if_err(err);

	if (iflags_want & iflags_dont) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int
check_tune(const struct silofs_task_ctx *task, struct silofs_inode_info *ii,
           int iflags_want, int iflags_dont)
{
	int err;

	err = check_dir_waccess(task, ii);
	return_if_err(err);

	err = check_tune_flags(iflags_want, iflags_dont);
	return_if_err(err);

	return 0;
}

static int
do_tune(struct silofs_task_ctx *task, struct silofs_inode_info *dir_ii,
        int iflags_want, int iflags_dont)
{
	int err;

	err = check_tune(task, dir_ii, iflags_want, iflags_dont);
	return_if_err(err);

	silofs_ii_update_iflags(dir_ii, iflags_want, iflags_dont);
	return 0;
}

int silofs_do_tune(struct silofs_task_ctx *task,
                   struct silofs_inode_info *dir_ii, int iflags_want,
                   int iflags_dont)
{
	int err;

	silofs_ii_incref(dir_ii);
	err = do_tune(task, dir_ii, iflags_want, iflags_dont);
	silofs_ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_do_walkfs(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	return_if_err(err);

	/* TODO: FIXME */

	return 0;
}

int silofs_do_unrefs(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	return_if_err(err);

	/* TODO: FIXME */

	return 0;
}

static int check_syncfs(const struct silofs_inode_info *ii, int flags)
{
	if (!silofs_ii_isdir(ii) && !silofs_ii_isreg(ii)) {
		return -SILOFS_EINVAL;
	}
	if (flags > 2) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

int silofs_do_syncfs(struct silofs_task_ctx *task,
                     struct silofs_inode_info *ii, int flags)
{
	int err;

	err = check_syncfs(ii, flags);
	return_if_err(err);

	err = flush_and_sync(task);
	return_if_err(err);

	return 0;
}

int silofs_do_maintain(struct silofs_task_ctx *task, int flags)
{
	silofs_relax_caches(task->corefs, flags);
	return silofs_try_flush_dirty(task, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_make_xattrname(struct silofs_task_ctx *task,
                          const struct silofs_inode_info *ii, const char *s,
                          struct silofs_namestr *out_nstr)
{
	int err;

	err = silofs_namestr_init(out_nstr, s);
	if (err) {
		return err;
	}
	/* TODO: use those for extra checks */
	silofs_unused(task);
	silofs_unused(ii);
	return 0;
}

int silofs_make_linkname(struct silofs_task_ctx *task,
                         const struct silofs_inode_info *dir_ii, const char *s,
                         struct silofs_namestr *out_nstr)
{
	int err;

	if (!silofs_ii_isdir(dir_ii)) {
		return -SILOFS_ENOTDIR;
	}
	err = silofs_namestr_init(out_nstr, s);
	if (err) {
		return err;
	}
	return check_dir_and_name(task, dir_ii, out_nstr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int try_forget_cached_ii(const struct silofs_task_ctx *task,
                                struct silofs_inode_info *ii)
{
	if ((ii->i_nlookup <= 0) && ii_isevictable(ii)) {
		struct silofs_lnode_info *lni = silofs_ii_to_lni(ii);

		silofs_lcache_forget_lnode(task->corefs->lcache, lni);
	}
	return 0;
}

static int do_forget(struct silofs_task_ctx *task,
                     struct silofs_inode_info *ii, size_t nlookup)
{
	int ret;

	sub_nlookup(task, ii, (long)nlookup);

	if (ii_ispinned(ii)) {
		/* case of prune special files created by MKNOD */
		ii_unpin(ii);
		ret = try_prune_inode(task, ii, false);
	} else {
		ret = try_forget_cached_ii(task, ii);
	}
	return ret;
}

int silofs_do_forget(struct silofs_task_ctx *task,
                     struct silofs_inode_info *ii, size_t nlookup)
{
	int ret = 0;

	if (likely(ii != nullptr)) {
		/* make gcc -Werror=null-dereference happy */
		ret = do_forget(task, ii, nlookup);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_forget_loose_ii(struct silofs_task_ctx *task,
                           struct silofs_inode_info *ii)
{
	int ret = -SILOFS_EWOULDBLOCK;

	if (ii_isdropable(ii)) {
		ret = drop_unlinked(task, ii);
	}
	return ret;
}

int silofs_next_inogen(const struct silofs_task_ctx *task, uint64_t *out_igen)
{
	struct silofs_sbnode_info *sbi = nullptr;
	int err;

	err = silofs_curr_sbi(task, &sbi);
	return_if_err(err);

	*out_igen = silofs_sbi_next_igen(sbi);
	return 0;
}
