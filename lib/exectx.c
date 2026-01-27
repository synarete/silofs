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

void silofs_ectx_update_creds(struct silofs_exec_ctx *ectx, uid_t uid,
                              gid_t gid, mode_t umsk)
{
	struct silofs_creds *creds = &ectx->ex_auth.creds;

	silofs_cred_setup(&creds->host_cred, uid, gid, umsk);
	silofs_cred_setup(&creds->fs_cred, uid, gid, umsk);
}

void silofs_ectx_update_auth(struct silofs_exec_ctx *ectx, pid_t pid,
                             uint64_t unique, uint32_t opcode, bool exclusive)
{
	ectx->ex_auth.pid    = pid;
	ectx->ex_auth.unique = unique;
	ectx->ex_auth.opcode = opcode;
	ectx->ex_exclusive   = exclusive;
}

void silofs_ectx_update_umask(struct silofs_exec_ctx *ectx, mode_t umask)
{
	struct silofs_creds *creds = &ectx->ex_auth.creds;

	creds->host_cred.umask = creds->fs_cred.umask = umask;
}

void silofs_ectx_update_times(struct silofs_exec_ctx *ectx, bool rt)
{
	int err;

	err = silofs_ts_gettime(&ectx->ex_auth.ts, rt);
	if (err && rt) {
		/* failure in clock_gettime -- fall to non-realtime */
		silofs_ts_gettime(&ectx->ex_auth.ts, !rt);
	}
}

void silofs_ectx_update_id(struct silofs_exec_ctx *ectx,
                           struct silofs_submitq_ent *sqe)
{
	if (sqe->uniq_id > ectx->ex_upper_id) {
		ectx->ex_upper_id = sqe->uniq_id;
	}
}

static int ectx_apply(const struct silofs_exec_ctx *ectx, bool all)
{
	int ret = 0;

	if (all) {
		ret = silofs_submitq_apply(ectx->ex_submitq, SILOFS_CID_ALL);
	} else if (ectx->ex_upper_id) {
		ret = silofs_submitq_apply(ectx->ex_submitq,
		                           ectx->ex_upper_id);
	}
	return ret;
}

void silofs_ectx_init(struct silofs_exec_ctx *ectx, struct silofs_env *env)
{
	memset(ectx, 0, sizeof(*ectx));
	silofs_cred_init(&ectx->ex_auth.creds.fs_cred);
	silofs_cred_init(&ectx->ex_auth.creds.host_cred);
	ectx->ex_env       = env;
	ectx->ex_creds     = &ectx->ex_auth.creds;
	ectx->ex_idsm      = env->base.idsmap;
	ectx->ex_repo      = env->base.repo;
	ectx->ex_lcache    = env->base.lcache;
	ectx->ex_submitq   = env->base.submitq;
	ectx->ex_looseq    = nullptr;
	ectx->ex_upper_id  = 0;
	ectx->ex_interrupt = 0;
	ectx->ex_fs_locked = false;
	ectx->ex_rw_locked = false;
	ectx->ex_exclusive = false;
	ectx->ex_priv_op   = false;
	ectx->ex_kwrite    = false;
	ectx->ex_runnable  = true;
}

void silofs_ectx_fini(struct silofs_exec_ctx *ectx)
{
	silofs_assert_null(ectx->ex_looseq);
	silofs_assert_eq(ectx->ex_fs_locked, false);

	ectx->ex_env      = nullptr;
	ectx->ex_idsm     = nullptr;
	ectx->ex_repo     = nullptr;
	ectx->ex_lcache   = nullptr;
	ectx->ex_submitq  = nullptr;
	ectx->ex_runnable = false;
}

void silofs_ectx_enq_loose(struct silofs_exec_ctx *ectx,
                           struct silofs_inode_info *ii)
{
	silofs_assert_null(ii->i_looseq_next);
	silofs_assert_eq(ii->i_vni.vn_lni.ln_flags & SILOFS_LNF_PINNED, 0);

	if (!ii->i_in_looseq) {
		ii->i_looseq_next = ectx->ex_looseq;
		ii->i_in_looseq   = true;
		ectx->ex_looseq   = ii;
		silofs_ii_incref(ii);
	}
}

static struct silofs_inode_info *ectx_deq_loose(struct silofs_exec_ctx *ectx)
{
	struct silofs_inode_info *ii = nullptr;

	if (ectx->ex_looseq != nullptr) {
		ii                = ectx->ex_looseq;
		ectx->ex_looseq   = ii->i_looseq_next;
		ii->i_looseq_next = nullptr;
		ii->i_in_looseq   = false;
		silofs_ii_decref(ii);
	}
	return ii;
}

static void ectx_forget_looseq(struct silofs_exec_ctx *ectx)
{
	struct silofs_inode_info *ii;
	int err;

	ii = ectx_deq_loose(ectx);
	while (ii != nullptr) {
		err = silofs_forget_loose_ii(ectx, ii);
		if (err) {
			/* TODO: maybe have retry loop ? */
			silofs_panic("failed to forget loose inode: "
			             "ino=%ld flags=%x err=%d",
			             ii->i_ino, ii->i_vni.vn_lni.ln_flags,
			             err);
		}
		ii = ectx_deq_loose(ectx);
	}
}

static void ectx_purge(struct silofs_exec_ctx *ectx)
{
	if (ectx->ex_looseq != nullptr) {
		if (ectx->ex_fs_locked) {
			/* case 1: already fs-locked; keep it locked post op */
			ectx_forget_looseq(ectx);
		} else {
			/* case 2: need to protect with fs-lock/unlock pair */
			silofs_lock_fs_by(ectx);
			ectx_forget_looseq(ectx);
			silofs_unlock_fs_by(ectx);
		}
	}
}

void silofs_lock_fs_by(struct silofs_exec_ctx *ectx)
{
	if (!ectx->ex_fs_locked && !ectx->ex_priv_op) {
		silofs_env_lock(ectx->ex_env);
		ectx->ex_fs_locked = true;
	}
}

void silofs_unlock_fs_by(struct silofs_exec_ctx *ectx)
{
	if (ectx->ex_fs_locked && !ectx->ex_priv_op) {
		silofs_env_unlock(ectx->ex_env);
		ectx->ex_fs_locked = false;
	}
}

void silofs_rwlock_fs_by(struct silofs_exec_ctx *ectx)
{
	if (!ectx->ex_rw_locked) {
		silofs_env_rwlock(ectx->ex_env, ectx->ex_exclusive);
		ectx->ex_rw_locked = true;
	}
}

void silofs_rwunlock_fs_by(struct silofs_exec_ctx *ectx)
{
	if (ectx->ex_rw_locked) {
		silofs_env_rwunlock(ectx->ex_env);
		ectx->ex_rw_locked = false;
	}
}

static bool ectx_has_looseq(const struct silofs_exec_ctx *ectx)
{
	return (ectx->ex_looseq != nullptr);
}

int silofs_ectx_submit(struct silofs_exec_ctx *ectx, bool all)
{
	int ret;

	ret = ectx_apply(ectx, all || ectx_has_looseq(ectx));
	ectx_purge(ectx);
	return ret;
}

struct silofs_sb_info *silofs_get_sbi(const struct silofs_exec_ctx *ectx)
{
	return ectx->ex_env->sbi;
}
