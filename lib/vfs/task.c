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
#include "infra.h"
#include "ubs.h"
#include "vfs.h"
#include "exec.h"
#include "env.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cred_init(struct silofs_cred *cred)
{
	cred->uid = (uid_t)(-1);
	cred->gid = (gid_t)(-1);
	cred->umask = (mode_t)(-1);
}

static void
cred_setup(struct silofs_cred *cred, uid_t uid, gid_t gid, mode_t umsk)
{
	cred->uid = uid;
	cred->gid = gid;
	cred->umask = umsk;
}

static void cred_update_umask(struct silofs_cred *cred, mode_t umsk)
{
	cred->umask = umsk;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_set_creds(struct silofs_task_ctx *task, uid_t uid, gid_t gid,
                           mode_t umsk)
{
	cred_setup(&task->t_auth.creds.host_cred, uid, gid, umsk);
	cred_setup(&task->t_auth.creds.fs_cred, uid, gid, umsk);
}

void silofs_task_update_umask(struct silofs_task_ctx *task, mode_t umask)
{
	cred_update_umask(&task->t_auth.creds.host_cred, umask);
	cred_update_umask(&task->t_auth.creds.fs_cred, umask);
}

void silofs_task_set_ts(struct silofs_task_ctx *task, bool rt)
{
	int err;

	err = silofs_ts_gettime(&task->t_auth.ts, rt);
	if (err && rt) {
		/* failure in clock_gettime -- fall to non-realtime */
		silofs_ts_gettime(&task->t_auth.ts, !rt);
	}
}

void silofs_task_update_by(struct silofs_task_ctx *task,
                           struct silofs_submitq_ent *sqe)
{
	if (sqe->uniq_id > task->t_upper_id) {
		task->t_upper_id = sqe->uniq_id;
	}
}

static int task_apply(const struct silofs_task_ctx *task, bool all)
{
	int ret = 0;

	if (all) {
		ret = silofs_submitq_apply(task->t_submitq, SILOFS_CID_ALL);
	} else if (task->t_upper_id) {
		ret = silofs_submitq_apply(task->t_submitq, task->t_upper_id);
	}
	return ret;
}

void silofs_task_init(struct silofs_task_ctx *task, struct silofs_env *env)
{
	memset(task, 0, sizeof(*task));
	cred_init(&task->t_auth.creds.fs_cred);
	cred_init(&task->t_auth.creds.host_cred);
	task->t_env = env;
	task->t_creds = &task->t_auth.creds;
	task->t_idsm = env->base.idsmap;
	task->t_repo = env->base.repo;
	task->t_lcache = env->base.lcache;
	task->t_submitq = env->base.submitq;
	task->t_looseq = nullptr;
	task->t_upper_id = 0;
	task->t_interrupt = 0;
	task->t_fs_locked = false;
	task->t_ex_locked = false;
	task->t_exclusive = false;
	task->t_priv_op = false;
	task->t_kwrite = false;
	task->t_runnable = true;
}

void silofs_task_fini(struct silofs_task_ctx *task)
{
	silofs_assert_null(task->t_looseq);
	silofs_assert_eq(task->t_fs_locked, false);

	task->t_env = nullptr;
	task->t_idsm = nullptr;
	task->t_repo = nullptr;
	task->t_lcache = nullptr;
	task->t_submitq = nullptr;
	task->t_runnable = false;
}

void silofs_task_enq_loose(struct silofs_task_ctx *task,
                           struct silofs_inode_info *ii)
{
	silofs_assert_null(ii->i_looseq_next);
	silofs_assert_eq(ii->i_vni.vn_lni.ln_flags & SILOFS_LNF_PINNED, 0);

	if (!ii->i_in_looseq) {
		ii->i_looseq_next = task->t_looseq;
		ii->i_in_looseq = true;
		task->t_looseq = ii;
		silofs_ii_incref(ii);
	}
}

static struct silofs_inode_info *task_deq_loose(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;

	if (task->t_looseq != nullptr) {
		ii = task->t_looseq;
		task->t_looseq = ii->i_looseq_next;
		ii->i_looseq_next = nullptr;
		ii->i_in_looseq = false;
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
			             ii->i_ino, ii->i_vni.vn_lni.ln_flags,
			             err);
		}
		ii = task_deq_loose(task);
	}
}

static void task_purge(struct silofs_task_ctx *task)
{
	if (task->t_looseq != nullptr) {
		if (task->t_fs_locked) {
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
	if (!task->t_fs_locked && !task->t_priv_op) {
		silofs_env_lock(task->t_env);
		task->t_fs_locked = true;
	}
}

void silofs_unlock_fs_by(struct silofs_task_ctx *task)
{
	if (task->t_fs_locked && !task->t_priv_op) {
		silofs_env_unlock(task->t_env);
		task->t_fs_locked = false;
	}
}

void silofs_rwlock_fs_by(struct silofs_task_ctx *task)
{
	if (!task->t_ex_locked) {
		silofs_env_rwlock(task->t_env, task->t_exclusive);
		task->t_ex_locked = true;
	}
}

void silofs_rwunlock_fs_by(struct silofs_task_ctx *task)
{
	if (task->t_ex_locked) {
		silofs_env_rwunlock(task->t_env);
		task->t_ex_locked = false;
	}
}

static bool task_has_looseq(const struct silofs_task_ctx *task)
{
	return (task->t_looseq != nullptr);
}

int silofs_task_submit(struct silofs_task_ctx *task, bool all)
{
	int ret;

	ret = task_apply(task, all || task_has_looseq(task));
	task_purge(task);
	return ret;
}

struct silofs_sb_info *silofs_get_sbi(const struct silofs_task_ctx *task)
{
	return task->t_env->sbi;
}
