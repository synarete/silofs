/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include <string.h>
#include <limits.h>
#include <silofs/ioctls.h>
#include "infra.h"
#include "lnodes.h"
#include "task.h"
#include "inode.h"
#include "namei.h"
#include "stage.h"
#include "flush.h"
#include "opexec.h"
#include "repo.h"
#include "env.h"

static int reload_super(struct silofs_task *task)
{
	int err;

	err = silofs_env_reload_sb_lseg(task->t_env);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(task->t_env);
	if (err) {
		return err;
	}
	return 0;
}

static int reload_vspace(struct silofs_task *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = silofs_rescan_vspace_of(task, ltype);
		if (err) {
			log_err("failed to reload vspace: ltype=%d err=%d",
			        ltype, err);
			return err;
		}
	}
	return 0;
}

static int reload_rootd(struct silofs_task *task)
{
	struct silofs_inode_info *ii = NULL;
	const ino_t ino = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode(task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o", ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int reload_vmeta(struct silofs_task *task)
{
	int err;

	err = reload_super(task);
	if (err) {
		return err;
	}
	err = reload_vspace(task);
	if (err) {
		return err;
	}
	err = reload_rootd(task);
	if (err) {
		return err;
	}
	return 0;
}

static void relax_caches(struct silofs_task *task, bool now)
{
	const int flags = now ? SILOFS_CTLF_NOW : SILOFS_CTLF_IDLE;

	silofs_env_relax_caches(task->t_env, flags);
}

static int flush_dirty(struct silofs_task *task)
{
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		log_err("failed to flush dirty: err=%d", err);
	}
	return err;
}

static void drop_caches(struct silofs_task *task)
{
	silofs_env_drop_caches(task->t_env);
}

static void drop_relax_caches(struct silofs_task *task)
{
	drop_caches(task);
	relax_caches(task, false);
}

int silofs_appexec_resync_vmeta(struct silofs_task *task, bool drop)
{
	int err;

	relax_caches(task, drop);
	err = flush_dirty(task);
	if (err || !drop) {
		return err;
	}
	drop_relax_caches(task);
	return 0;
}

static int do_claim_reclaim(struct silofs_task *task, enum silofs_ltype ltype)
{
	struct silofs_vaddr vaddr;
	const loff_t voff_exp = 0;
	int err;

	err = silofs_claim_vspace(task, ltype, &vaddr);
	if (err) {
		log_err("vclaim failed: ltype=%d err=%d", ltype, err);
		return err;
	}
	if (vaddr.off != voff_exp) {
		log_err("bad claim: ltype=%d exp=%ld got=%ld", ltype, voff_exp,
		        vaddr.off);
		return -SILOFS_EFSCORRUPTED;
	}
	drop_caches(task);
	err = silofs_reclaim_vspace(task, &vaddr);
	if (err) {
		log_err("bad reclaim: ltype=%d voff=%ld err=%d", ltype,
		        vaddr.off, err);
	}
	return 0;
}

int silofs_appexec_retry_claim(struct silofs_task *task)
{
	enum silofs_ltype ltype = SILOFS_LTYPE_NONE;
	int err;

	while (++ltype < SILOFS_LTYPE_LAST) {
		if (!ltype_isvnode(ltype)) {
			continue;
		}
		err = do_claim_reclaim(task, ltype);
		if (err) {
			return err;
		}
		err = flush_dirty(task);
		if (err) {
			return err;
		}
		drop_relax_caches(task);
	}
	return 0;
}

static int reload_uber(const struct silofs_task *task)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_uber_caddr(task->t_env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_env_reload_uber(task->t_env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_appexec_reload_fs(struct silofs_task *task)
{
	int err;

	err = reload_uber(task);
	if (err) {
		return err;
	}
	err = reload_vmeta(task);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

static int unlink_uber(struct silofs_task *task)
{
	int err;

	err = silofs_env_unlink_uber(task->t_env);
	if (err) {
		return err;
	}
	drop_caches(task);
	return 0;
}

int silofs_appexec_fork_fs(struct silofs_task *task)
{
	struct silofs_uber_caddrs caddrs;
	int err;

	err = silofs_env_uber_caddr(task->t_env, &caddrs.curr);
	if (err) {
		return err;
	}
	err = silofs_exec_forkfs(task, SILOFS_INO_ROOT, 0, &caddrs);
	if (err) {
		return err;
	}
	err = flush_dirty(task);
	if (err) {
		return err;
	}
	drop_relax_caches(task);
	return 0;
}

static int shutdown_fs(struct silofs_task *task)
{
	struct silofs_repo *repo = silofs_task_repo(task);
	int err;

	err = silofs_repo_fsync_all(repo);
	if (err) {
		return err;
	}
	drop_relax_caches(task);

	err = silofs_env_shut(task->t_env);
	if (err) {
		return err;
	}
	drop_relax_caches(task);

	return 0;
}

int silofs_appexec_unload_fs(struct silofs_task *task)
{
	int err;

	err = flush_dirty(task);
	if (err) {
		return err;
	}
	err = shutdown_fs(task);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_appexec_remove_fs(struct silofs_task *task)
{
	int err;

	err = silofs_exec_unrefs(task);
	if (err) {
		return err;
	}
	err = unlink_uber(task);
	if (err) {
		return err;
	}
	err = shutdown_fs(task);
	if (err) {
		return err;
	}
	return 0;
}
