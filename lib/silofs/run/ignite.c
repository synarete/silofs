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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>
#include <silofs/run.h>

static void drop_caches(struct silofs_task_ctx *task)
{
	silofs_drop_caches(task->ectx);
}

static void relax_caches(struct silofs_task_ctx *task)
{
	silofs_relax_caches(task->ectx, SILOFS_CTLF_IDLE);
}

static void drop_relax_caches(struct silofs_task_ctx *task)
{
	drop_caches(task);
	relax_caches(task);
}

static int flush_dirty(struct silofs_task_ctx *task)
{
	return silofs_flush_dirty_now(task);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *repodir_of(const struct silofs_task_ctx *task)
{
	return task->ectx->fsroot->baseref.repodir;
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
	return_if_err(err);

	err = silofs_repo_format(task->ectx->repo, repodir_of(task));
	return_if_err(err);

	post_format_repo(task);
	return 0;
}

static int pre_reload_repo(struct silofs_task_ctx *task)
{
	return require_nonempty_repodir(task);
}

static int open_repo(struct silofs_task_ctx *task)
{
	return silofs_repo_open(task->ectx->repo, repodir_of(task),
	                        task->ectx->fsroot->ctl_flags);
}

int silofs_exec_reload_repo(struct silofs_task_ctx *task)
{
	int err;

	if (task->ectx->repo->re_opened) {
		return 0; /* no-op */
	}

	err = pre_reload_repo(task);
	return_if_err(err);

	err = open_repo(task);
	return_if_err(err);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int reinit_ciphers(struct silofs_task_ctx *task)
{
	return silofs_reinit_ciphers(task->ectx);
}

static int
post_format(struct silofs_task_ctx *task, const struct silofs_pnptr *pnptr)
{
	silofs_update_root_uber(task->ectx->fsroot, pnptr, &silofs_sw_vers);
	return flush_dirty(task);
}

int silofs_exec_format_meta(struct silofs_task_ctx *task, size_t fs_capacity)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = reinit_ciphers(task);
	return_if_err(err);

	err = silofs_format(task, fs_capacity, &pnptr);
	return_if_err(err);

	err = post_format(task, &pnptr);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
commit_mbr(struct silofs_task_ctx *task, struct silofs_mbref *out_mbref)
{
	return silofs_commit_mbr(task->ectx, out_mbref);
}

static int post_commit_mbr(struct silofs_task_ctx *task)
{
	return flush_dirty(task);
}

int silofs_exec_commit_mbr(struct silofs_task_ctx *task,
                           struct silofs_mbref *out_mbref)
{
	int err;

	err = commit_mbr(task, out_mbref);
	return_if_err(err);

	err = post_commit_mbr(task);
	return_if_err(err);

	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int resolve_root_uber(const struct silofs_task_ctx *task,
                             struct silofs_pnptr *out_pnptr)
{
	struct silofs_sw_version swv;

	return silofs_resolve_root_uber(task->ectx->fsroot, out_pnptr, &swv);
}

static int
reload_mbr(struct silofs_task_ctx *task, const struct silofs_mbref *mbref)
{
	return silofs_reload_mbr(task->ectx, mbref);
}

int silofs_exec_reload_meta(struct silofs_task_ctx *task,
                            const struct silofs_mbref *mbref)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = reload_mbr(task, mbref);
	return_if_err(err);

	err = reinit_ciphers(task);
	return_if_err(err);

	err = resolve_root_uber(task, &pnptr);
	return_if_err(err);

	err = silofs_reload(task, &pnptr);
	return_if_err(err);

	return 0;
}
