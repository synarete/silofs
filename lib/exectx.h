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
	struct silofs_exec_auth     ex_auth;
	struct silofs_env          *ex_env;
	const struct silofs_idsmap *ex_idsm;
	const struct silofs_creds  *ex_creds;
	struct silofs_repo         *ex_repo;
	struct silofs_lcache       *ex_lcache;
	struct silofs_submitq      *ex_submitq;
	struct silofs_inode_info   *ex_looseq;
	uint64_t                    ex_upper_id;
	time_t                      ex_op_start_time;
	volatile int8_t             ex_interrupt;
	volatile bool               ex_fs_locked;
	volatile bool               ex_rw_locked;
	bool                        ex_exclusive;
	bool                        ex_priv_op;
	bool                        ex_kwrite;
	bool                        ex_runnable;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ectx_init(struct silofs_exec_ctx *ectx, struct silofs_env *env);

void silofs_ectx_fini(struct silofs_exec_ctx *ectx);

void silofs_ectx_update_creds(struct silofs_exec_ctx *ectx, uid_t uid,
                              gid_t gid, mode_t umsk);

void silofs_ectx_update_auth(struct silofs_exec_ctx *ectx, pid_t pid,
                             uint64_t unique, uint32_t opcode, bool exclusive);

void silofs_ectx_update_umask(struct silofs_exec_ctx *ectx, mode_t umask);

void silofs_ectx_update_times(struct silofs_exec_ctx *ectx, bool rt);

void silofs_ectx_update_id(struct silofs_exec_ctx    *ectx,
                           struct silofs_submitq_ent *sqe);

int silofs_ectx_submit(struct silofs_exec_ctx *ectx, bool all);

void silofs_ectx_enq_loose(struct silofs_exec_ctx   *ectx,
                           struct silofs_inode_info *ii);

void silofs_lock_fs_by(struct silofs_exec_ctx *ectx);

void silofs_unlock_fs_by(struct silofs_exec_ctx *ectx);

void silofs_rwlock_fs_by(struct silofs_exec_ctx *ectx);

void silofs_rwunlock_fs_by(struct silofs_exec_ctx *ectx);

struct silofs_sb_info *silofs_get_sbi(const struct silofs_exec_ctx *ectx);

#endif /* SILOFS_EXECTX_H_ */
