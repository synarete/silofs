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
#include "infra.h"
#include "obs.h"
#include "fs.h"
#include "exec.h"
#include "env.h"
#include "exectx.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_exct_update_creds(struct silofs_exec_ctx *exct, uid_t uid,
                              gid_t gid, mode_t umsk)
{
	struct silofs_creds *creds = &exct->auth.creds;

	silofs_cred_setup(&creds->host_cred, uid, gid, umsk);
	silofs_cred_setup(&creds->fs_cred, uid, gid, umsk);
}

void silofs_exct_update_auth(struct silofs_exec_ctx *exct, pid_t pid,
                             uint64_t unique, uint32_t opcode, bool exclusive)
{
	exct->auth.pid    = pid;
	exct->auth.unique = unique;
	exct->auth.opcode = opcode;
	exct->exclusive   = exclusive;
}

void silofs_exct_update_umask(struct silofs_exec_ctx *exct, mode_t umask)
{
	struct silofs_creds *creds = &exct->auth.creds;

	creds->host_cred.umask = creds->fs_cred.umask = umask;
}

void silofs_exct_update_times(struct silofs_exec_ctx *exct, bool rt)
{
	int err;

	err = silofs_ts_gettime(&exct->auth.ts, rt);
	if (err && rt) {
		/* failure in clock_gettime -- fall to non-realtime */
		silofs_ts_gettime(&exct->auth.ts, !rt);
	}
}

void silofs_exct_update_id(struct silofs_exec_ctx *exct,
                           struct silofs_submitq_ent *sqe)
{
	if (sqe->uniq_id > exct->upper_id) {
		exct->upper_id = sqe->uniq_id;
	}
}

static int exct_apply(const struct silofs_exec_ctx *exct, bool all)
{
	int ret = 0;

	if (all) {
		ret = silofs_submitq_apply(exct->submitq, SILOFS_CID_ALL);
	} else if (exct->upper_id) {
		ret = silofs_submitq_apply(exct->submitq, exct->upper_id);
	}
	return ret;
}

void silofs_exct_init(struct silofs_exec_ctx *exct, struct silofs_env *env)
{
	memset(exct, 0, sizeof(*exct));
	silofs_cred_init(&exct->auth.creds.fs_cred);
	silofs_cred_init(&exct->auth.creds.host_cred);
	exct->env       = env;
	exct->idsm      = env->base.idsmap;
	exct->repo      = env->base.repo;
	exct->lcache    = env->base.lcache;
	exct->submitq   = env->base.submitq;
	exct->looseq    = nullptr;
	exct->upper_id  = 0;
	exct->interrupt = 0;
	exct->fs_locked = false;
	exct->rw_locked = false;
	exct->exclusive = false;
	exct->priv_op   = false;
	exct->kwrite    = false;
	exct->runnable  = true;
}

void silofs_exct_fini(struct silofs_exec_ctx *exct)
{
	silofs_assert_null(exct->looseq);
	silofs_assert_eq(exct->fs_locked, false);

	exct->env      = nullptr;
	exct->idsm     = nullptr;
	exct->repo     = nullptr;
	exct->lcache   = nullptr;
	exct->submitq  = nullptr;
	exct->runnable = false;
}

void silofs_exct_enq_loose(struct silofs_exec_ctx *exct,
                           struct silofs_inode_info *ii)
{
	silofs_assert_null(ii->i_looseq_next);
	silofs_assert_eq(ii->i_vni.vn_lni.ln_flags & SILOFS_LNF_PINNED, 0);

	if (!ii->i_in_looseq) {
		ii->i_looseq_next = exct->looseq;
		ii->i_in_looseq   = true;
		exct->looseq      = ii;
		silofs_ii_incref(ii);
	}
}

static struct silofs_inode_info *exct_deq_loose(struct silofs_exec_ctx *exct)
{
	struct silofs_inode_info *ii = nullptr;

	if (exct->looseq != nullptr) {
		ii                = exct->looseq;
		exct->looseq      = ii->i_looseq_next;
		ii->i_looseq_next = nullptr;
		ii->i_in_looseq   = false;
		silofs_ii_decref(ii);
	}
	return ii;
}

static void exct_forget_looseq(struct silofs_exec_ctx *exct)
{
	struct silofs_inode_info *ii;
	int err;

	ii = exct_deq_loose(exct);
	while (ii != nullptr) {
		err = silofs_forget_loose_ii(exct, ii);
		if (err) {
			/* TODO: maybe have retry loop ? */
			silofs_panic("failed to forget loose inode: "
			             "ino=%ld flags=%x err=%d",
			             ii->i_ino, ii->i_vni.vn_lni.ln_flags,
			             err);
		}
		ii = exct_deq_loose(exct);
	}
}

static void exct_purge(struct silofs_exec_ctx *exct)
{
	if (exct->looseq != nullptr) {
		if (exct->fs_locked) {
			/* case 1: already fs-locked; keep it locked post op */
			exct_forget_looseq(exct);
		} else {
			/* case 2: need to protect with fs-lock/unlock pair */
			silofs_lock_fs_by(exct);
			exct_forget_looseq(exct);
			silofs_unlock_fs_by(exct);
		}
	}
}

void silofs_lock_fs_by(struct silofs_exec_ctx *exct)
{
	if (!exct->fs_locked && !exct->priv_op) {
		silofs_env_lock(exct->env);
		exct->fs_locked = true;
	}
}

void silofs_unlock_fs_by(struct silofs_exec_ctx *exct)
{
	if (exct->fs_locked && !exct->priv_op) {
		silofs_env_unlock(exct->env);
		exct->fs_locked = false;
	}
}

void silofs_rwlock_fs_by(struct silofs_exec_ctx *exct)
{
	if (!exct->rw_locked) {
		silofs_env_rwlock(exct->env, exct->exclusive);
		exct->rw_locked = true;
	}
}

void silofs_rwunlock_fs_by(struct silofs_exec_ctx *exct)
{
	if (exct->rw_locked) {
		silofs_env_rwunlock(exct->env);
		exct->rw_locked = false;
	}
}

static bool exct_has_looseq(const struct silofs_exec_ctx *exct)
{
	return (exct->looseq != nullptr);
}

int silofs_exct_submit(struct silofs_exec_ctx *exct, bool all)
{
	int ret;

	ret = exct_apply(exct, all || exct_has_looseq(exct));
	exct_purge(exct);
	return ret;
}

struct silofs_sb_info *silofs_get_sbi(const struct silofs_exec_ctx *exct)
{
	return exct->env->sbi;
}
