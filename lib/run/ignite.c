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
#include <dirent.h>

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/syscall.h>
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/run.h>

static void drop_caches(struct silofs_task_ctx *task)
{
	silofs_env_drop_caches(task->env);
}

static void relax_caches(struct silofs_task_ctx *task)
{
	silofs_env_relax_caches(task->env, SILOFS_CTLF_IDLE);
}

static void drop_relax_caches(struct silofs_task_ctx *task)
{
	drop_caches(task);
	relax_caches(task);
}

static int flush_destage_dirty(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
		return err;
	}
	err = silofs_destage_dirty_by(task);
	if (err) {
		log_err("failed to destage dirty: err=%d", err);
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *repodir_of(const struct silofs_task_ctx *task)
{
	return task->env->repodir;
}

static int iter_repodir(const char *repodir, size_t *out_ndes)
{
	struct dirent64 de[4];
	int dfd = -1;
	int err;

	err = silofs_sys_open(repodir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		log_dbg("opendir error: repodir=%s err=%d", repodir, err);
		goto out;
	}
	err = silofs_sys_getdents2(dfd, de, ARRAY_SIZE(de), out_ndes);
	if (err) {
		log_dbg("readdir error: repodir=%s err=%d", repodir, err);
		goto out;
	}
out:
	silofs_sys_closefd(&dfd);
	return err;
}

static int require_empty_repodir(const struct silofs_task_ctx *task)
{
	size_t ndes = 0;
	int err;

	err = iter_repodir(repodir_of(task), &ndes);
	if (err) {
		return err;
	}
	if (ndes > 2) {
		log_dbg("non empty repodir: %s", repodir_of(task));
		return -SILOFS_ENOTEMPTY;
	}
	return 0;
}

static int require_nonempty_repodir(const struct silofs_task_ctx *task)
{
	size_t ndes = 0;
	int err;

	err = iter_repodir(repodir_of(task), &ndes);
	if (err) {
		return err;
	}
	if (ndes <= 2) {
		log_dbg("bad repodir: %s", repodir_of(task));
		return -SILOFS_EBADREPO;
	}
	return 0;
}

static int pre_format_repo(const struct silofs_task_ctx *task)
{
	return require_empty_repodir(task);
}

static void post_format_repo(struct silofs_task_ctx *task)
{
	drop_relax_caches(task);
}

int silofs_exec_format_repo(struct silofs_task_ctx *task)
{
	int err;

	err = pre_format_repo(task);
	if (err) {
		return err;
	}
	err = silofs_repo_format(task->repo, task->env->repodir);
	if (err) {
		return err;
	}
	post_format_repo(task);
	return 0;
}

static int pre_reload_repo(struct silofs_task_ctx *task)
{
	return require_nonempty_repodir(task);
}

static int open_repo(struct silofs_task_ctx *task)
{
	return silofs_repo_open(task->repo, task->env->repodir,
	                        task->ubref->ctl_flags);
}

int silofs_exec_reload_repo(struct silofs_task_ctx *task)
{
	int err;

	if (task->repo->re_opened) {
		return 0; /* no-op */
	}
	err = pre_reload_repo(task);
	if (err) {
		return err;
	}
	err = open_repo(task);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int pre_format(struct silofs_task_ctx *task)
{
	return silofs_env_reinit_ciphers(task->env);
}

static int
post_format(struct silofs_task_ctx *task, const struct silofs_pnptr *pnptr)
{
	silofs_env_refresh_root(task->env, pnptr);
	return flush_destage_dirty(task);
}

int silofs_exec_format(struct silofs_task_ctx *task, size_t fs_capacity)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = pre_format(task);
	return_if_err(err);

	err = silofs_format(task, fs_capacity, &pnptr);
	return_if_err(err);

	err = post_format(task, &pnptr);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int format_super(struct silofs_task_ctx *task)
{
	return silofs_env_format_super(task->env, task->env->fscap);
}

static int
require_spmaps_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	struct silofs_vaddr vaddr;
	struct silofs_spleaf_info *sli = nullptr;

	silofs_vaddr_setup(&vaddr, vtype, 0);
	return silofs_require_spleaf_of(task, &vaddr, SILOFS_STG_COW, &sli);
}

static int
format_spmaps_of(struct silofs_task_ctx *task, enum silofs_vtype vtype)
{
	int err;

	err = require_spmaps_of(task, vtype);
	if (err) {
		log_err("format spmaps failed: vtype=%d err=%d", vtype, err);
		return err;
	}
	err = flush_destage_dirty(task);
	if (err) {
		return err;
	}
	log_dbg("format spmaps of: vtype=%d", vtype);
	return 0;
}

static int format_spmaps(struct silofs_task_ctx *task)
{
	enum silofs_vtype vtype = SILOFS_VTYPE_NONE;
	int err;

	while (++vtype < SILOFS_VTYPE_LAST) {
		if (!silofs_vtype_isvnode(vtype)) {
			continue;
		}
		if (vtype == SILOFS_VTYPE_SPNODE2) {
			continue;
		}
		if (vtype == SILOFS_VTYPE_SUPER2) {
			continue;
		}
		err = format_spmaps_of(task, vtype);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
spawn_rootdir(struct silofs_task_ctx *task, struct silofs_inode_info **out_ii)
{
	struct silofs_inew_params inp;
	struct silofs_inode_info *ii;
	int err;

	silofs_inew_params_of(task, nullptr, S_IFDIR | 0755, 0, &inp);
	err = silofs_spawn_inode_by(task, &inp, &ii);
	if (err) {
		return err;
	}
	if (ii->i_ino != SILOFS_INO_ROOT) {
		log_err("failed to format root-dir: ino=%ld", ii->i_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	*out_ii = ii;
	return 0;
}

static void update_rootdir(struct silofs_inode_info *rootd_ii, bool utf8_names)
{
	silofs_ii_fixup_as_rootdir(rootd_ii);
	if (utf8_names) {
		silofs_dir_set_flag(rootd_ii, SILOFS_DIRF_NAME_UTF8);
	} else {
		silofs_dir_unset_flag(rootd_ii, SILOFS_DIRF_NAME_UTF8);
	}
}

static bool use_utf8_names(const struct silofs_task_ctx *task)
{
	return (task->ubref->ctl_flags & SILOFS_F_UTF8NAMES) > 0;
}

static int format_rootdir(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *rootd_ii = nullptr;
	int err;

	err = spawn_rootdir(task, &rootd_ii);
	return_if_err(err);

	update_rootdir(rootd_ii, use_utf8_names(task));
	return 0;
}

static int format_fs(struct silofs_task_ctx *task)
{
	int err;

	err = format_super(task);
	return_if_err(err);

	err = format_spmaps(task);
	return_if_err(err);

	err = format_rootdir(task);
	return_if_err(err);

	return 0;
}

static int pre_format_fs(struct silofs_task_ctx *task)
{
	drop_relax_caches(task);
	return 0;
}

static int
commit_mbr(struct silofs_task_ctx *task, struct silofs_mbref *out_mbref)
{
	return silofs_env_commit_fs_mbr(task->env, out_mbref);
}

static int post_format_fs(struct silofs_task_ctx *task)
{
	return flush_destage_dirty(task);
}

int silofs_exec_format_fs(struct silofs_task_ctx *task,
                          struct silofs_mbref *out_mbref)
{
	int err;

	err = pre_format_fs(task);
	return_if_err(err);

	err = format_fs(task);
	return_if_err(err);

	err = commit_mbr(task, out_mbref);
	return_if_err(err);

	err = post_format_fs(task);
	return_if_err(err);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int resolve_root_uber(const struct silofs_task_ctx *task,
                             struct silofs_pnptr *out_pnptr)
{
	const struct silofs_env_mbis *mbis = &task->env->mbis;

	return silofs_mbi_uber_root(&mbis->fs_mbi, out_pnptr);
}

static int
reload_mbr(struct silofs_task_ctx *task, const struct silofs_mbref *mbref)
{
	return silofs_env_reload_fs_mbr(task->env, mbref);
}

int silofs_exec_reload(struct silofs_task_ctx *task,
                       const struct silofs_mbref *mbref)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = reload_mbr(task, mbref);
	return_if_err(err);

	err = resolve_root_uber(task, &pnptr);
	return_if_err(err);

	err = silofs_reload(task, &pnptr);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int reload_super(struct silofs_task_ctx *task)
{
	int err;

	err = silofs_env_reload_sb_lseg(task->env);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(task->env);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_rootd(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;
	int err;

	err = silofs_stage_inode_of(task, SILOFS_INO_ROOT, SILOFS_STG_CUR,
	                            &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!silofs_ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o",
		        silofs_ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_exec_reload_fs(struct silofs_task_ctx *task)
{
	int err;

	err = reload_super(task);
	return_if_err(err);

	err = reload_rootd(task);
	return_if_err(err);

	return 0;
}
