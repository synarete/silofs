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
#ifndef SILOFS_EXECTX_H_
#define SILOFS_EXECTX_H_

#include <silofs/types.h>
#include "infra.h"
#include "addr.h"
#include "flags.h"

struct silofs_submitq_ent;

/* execution-context authentication */
struct silofs_exec_auth {
	struct silofs_creds creds;
	struct timespec     ts;
	uint64_t            unique;
	uint32_t            opcode;
	pid_t               pid;
};

/* execution-context */
struct silofs_exec_ctx {
	struct silofs_exec_auth     auth;
	struct silofs_env          *env;
	const struct silofs_idsmap *idsm;
	struct silofs_repo         *repo;
	struct silofs_lcache       *lcache;
	struct silofs_submitq      *submitq;
	struct silofs_inode_info   *looseq;
	uint64_t                    upper_id;
	time_t                      op_start_time;
	volatile int8_t             interrupt;
	volatile bool               fs_locked;
	volatile bool               rw_locked;
	bool                        exclusive;
	bool                        priv_op;
	bool                        kwrite;
	bool                        runnable;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_exct_init(struct silofs_exec_ctx *exct, struct silofs_env *env);

void silofs_exct_fini(struct silofs_exec_ctx *exct);

void silofs_exct_update_creds(struct silofs_exec_ctx *exct, uid_t uid,
                              gid_t gid, mode_t umsk);

void silofs_exct_update_auth(struct silofs_exec_ctx *exct, pid_t pid,
                             uint64_t unique, uint32_t opcode, bool exclusive);

void silofs_exct_update_umask(struct silofs_exec_ctx *exct, mode_t umask);

void silofs_exct_update_times(struct silofs_exec_ctx *exct, bool rt);

void silofs_exct_update_id(struct silofs_exec_ctx    *exct,
                           struct silofs_submitq_ent *sqe);

int silofs_exct_submit(struct silofs_exec_ctx *exct, bool all);

void silofs_exct_enq_loose(struct silofs_exec_ctx   *exct,
                           struct silofs_inode_info *ii);

void silofs_lock_fs_by(struct silofs_exec_ctx *exct);

void silofs_unlock_fs_by(struct silofs_exec_ctx *exct);

void silofs_rwlock_fs_by(struct silofs_exec_ctx *exct);

void silofs_rwunlock_fs_by(struct silofs_exec_ctx *exct);

struct silofs_sb_info *silofs_get_sbi(const struct silofs_exec_ctx *exct);

#endif /* SILOFS_EXECTX_H_ */
