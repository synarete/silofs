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
#include <silofs/infra.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>

#include <silofs/run/env.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_update_creds(struct silofs_task_ctx *task, uid_t uid,
                              gid_t gid, mode_t umsk)
{
	struct silofs_creds *creds = &task->auth.creds;

	silofs_cred_setup(&creds->host_cred, uid, gid, umsk);
	silofs_cred_setup(&creds->fs_cred, uid, gid, umsk);
}

void silofs_task_update_auth(struct silofs_task_ctx *task, pid_t pid,
                             uint64_t unique, uint32_t opcode, bool exclusive)
{
	task->auth.pid    = pid;
	task->auth.unique = unique;
	task->auth.opcode = opcode;
	task->exclusive   = exclusive;
}

void silofs_task_update_umask(struct silofs_task_ctx *task, mode_t umask)
{
	struct silofs_creds *creds = &task->auth.creds;

	creds->host_cred.umask = creds->fs_cred.umask = umask;
}

void silofs_task_update_times(struct silofs_task_ctx *task, bool rt)
{
	struct timespec *ts = &task->auth.ts;

	if (rt) {
		silofs_clock_gettime_real(ts);
	} else {
		silofs_clock_gettime_mono(ts);
	}
}

static int task_apply(const struct silofs_task_ctx *task, bool all)
{
	/* TODO: is it needed? XXX */
	silofs_unused(task);
	silofs_unused(all);

	return 0;
}

void silofs_task_init(struct silofs_task_ctx *task, struct silofs_env *env)
{
	memset(task, 0, sizeof(*task));
	silofs_cred_init(&task->auth.creds.fs_cred);
	silofs_cred_init(&task->auth.creds.host_cred);

	task->env         = env;
	task->fsroot      = &env->fsroot;
	task->xrefs       = &env->xrefs;
	task->lspools     = &env->lspools;
	task->idsm        = &env->idsmap;
	task->repo        = &env->repo;
	task->looseq      = nullptr;
	task->upper_id    = 0;
	task->interrupted = 0;
	task->fs_locked   = false;
	task->rw_locked   = false;
	task->exclusive   = false;
	task->priv_op     = false;
	task->kwrite      = false;
	task->runnable    = true;
	task->internal    = false;
}

void silofs_task_fini(struct silofs_task_ctx *task)
{
	silofs_assert_null(task->looseq);
	silofs_assert_eq(task->fs_locked, false);

	memset(task, 0, sizeof(*task));
	task->runnable = false;
}

void silofs_task_enq_loose(struct silofs_task_ctx *task,
                           struct silofs_inode_info *ii)
{
	silofs_assert_null(ii->i_looseq_next);
	silofs_assert_eq(ii->i_lni.vn_flags & SILOFS_LNF_PINNED, 0);

	if (!ii->i_in_looseq) {
		ii->i_looseq_next = task->looseq;
		ii->i_in_looseq   = true;
		task->looseq      = ii;
		silofs_ii_incref(ii);
	}
}

static struct silofs_inode_info *task_deq_loose(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;

	if (task->looseq != nullptr) {
		ii                = task->looseq;
		task->looseq      = ii->i_looseq_next;
		ii->i_looseq_next = nullptr;
		ii->i_in_looseq   = false;
		silofs_ii_decref(ii);
	}
	return ii;
}

static void task_forget_looseq(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii;
	int err;

	ii = task_deq_loose(task);
	while (ii != nullptr) {
		err = silofs_forget_loose_ii(task, ii);
		if (err) {
			/* TODO: maybe have retry loop ? */
			silofs_panic("failed to forget loose inode: "
			             "ino=%ld flags=%x err=%d",
			             ii->i_ino, ii->i_lni.vn_flags, err);
		}
		ii = task_deq_loose(task);
	}
}

static void task_purge(struct silofs_task_ctx *task)
{
	if (task->looseq != nullptr) {
		if (task->fs_locked) {
			/* case 1: already fs-locked; keep it locked post op */
			task_forget_looseq(task);
		} else {
			/* case 2: need to protect with fs-lock/unlock pair */
			silofs_lock_fs_by(task);
			task_forget_looseq(task);
			silofs_unlock_fs_by(task);
		}
	}
}

void silofs_lock_fs_by(struct silofs_task_ctx *task)
{
	if (!task->fs_locked && !task->priv_op) {
		silofs_fsroot_lock(task->fsroot);
		task->fs_locked = true;
	}
}

void silofs_unlock_fs_by(struct silofs_task_ctx *task)
{
	if (task->fs_locked && !task->priv_op) {
		silofs_fsroot_unlock(task->fsroot);
		task->fs_locked = false;
	}
}

void silofs_rwlock_fs_by(struct silofs_task_ctx *task)
{
	if (!task->rw_locked) {
		silofs_fsroot_rwlock(task->fsroot, task->exclusive);
		task->rw_locked = true;
	}
}

void silofs_rwunlock_fs_by(struct silofs_task_ctx *task)
{
	if (task->rw_locked) {
		silofs_fsroot_rwunlock(task->fsroot);
		task->rw_locked = false;
	}
}

static bool task_has_looseq(const struct silofs_task_ctx *task)
{
	return (task->looseq != nullptr);
}

int silofs_task_submit(struct silofs_task_ctx *task, bool all)
{
	int ret;

	ret = task_apply(task, all || task_has_looseq(task));
	task_purge(task);
	return ret;
}

int silofs_curr_sbi(const struct silofs_task_ctx *task,
                    struct silofs_sbnode_info **out_sbi)
{
	return silofs_stage_super(task, SILOFS_STG_CUR, out_sbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flush_threshold_of(int flags)
{
	size_t threshold;

	if (flags & (SILOFS_CTLF_NOW | SILOFS_CTLF_IDLE | SILOFS_CTLF_FSYNC)) {
		threshold = 0;
	} else if (flags & SILOFS_CTLF_RELEASE) {
		threshold = SILOFS_MEGA / 2;
	} else if (flags & SILOFS_CTLF_INTERN) {
		threshold = SILOFS_MEGA;
	} else if (flags & SILOFS_CTLF_OPSTART) {
		threshold = 2 * SILOFS_MEGA;
	} else {
		threshold = 4 * SILOFS_MEGA;
	}
	return threshold;
}

static bool need_flush_now(const struct silofs_task_ctx *task, int flags)
{
	struct silofs_alloc_stat alst = {
		.nbytes_use = 0,
		.nbytes_max = 0,
	};
	size_t flush_threshold;

	if (flags & SILOFS_CTLF_NOW) {
		return true;
	}
	silofs_memstat(task->xrefs->alloc, &alst);
	if (alst.nbytes_use > (alst.nbytes_max / 2)) {
		return true;
	}
	flush_threshold = flush_threshold_of(flags); /* XXX CRAP FIXME */
	if (flush_threshold == 0) {
		return true;
	}
	return false;
}

static bool need_flush_by(const struct silofs_task_ctx *task,
                          const struct silofs_inode_info *ii, int flags)
{
	silofs_unused(ii);
	return need_flush_now(task, flags);
}

static int do_flush_dirty(struct silofs_task_ctx *task,
                          struct silofs_inode_info *ii, int flags)
{
	/* XXX TODO FIXME */
	silofs_unused(ii);
	silofs_unused(flags);

	return silofs_flush_dirty_now(task);
}

int silofs_flush_dirty(struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii, int flags)
{
	int err = 0;

	if (need_flush_by(task, ii, flags)) {
		silofs_ii_incref(ii);
		err = do_flush_dirty(task, ii, flags);
		silofs_ii_decref(ii);
	}
	return err;
}

int silofs_flush_dirty_now(struct silofs_task_ctx *task)
{
	return silofs_destage_dirty_nodes(task->xrefs);
}
