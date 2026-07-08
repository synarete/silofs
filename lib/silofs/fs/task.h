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
#ifndef SILOFS_TASK_H_
#define SILOFS_TASK_H_

/* execution-context authentication parameters */
struct silofs_task_auth {
	struct silofs_creds creds;
	struct timespec     ts;
	uint64_t            unique;
	uint32_t            opcode;
	pid_t               pid;
};

/* execution-context */
struct silofs_task_ctx {
	struct silofs_task_auth     auth;
	struct silofs_pexec_ctx     pexec;
	struct silofs_lcache       *lcache;
	struct silofs_lspools      *lspools;
	struct silofs_env          *env;
	const struct silofs_idsmap *idsm;
	struct silofs_repo         *repo;
	struct silofs_inode_info   *looseq;
	uint64_t                    upper_id;
	struct timespec             op_start_time;
	volatile int8_t             interrupted;
	volatile bool               fs_locked;
	volatile bool               rw_locked;
	bool                        exclusive;
	bool                        priv_op;
	bool                        kwrite;
	bool                        runnable;
	bool                        internal;
};

void silofs_task_init(struct silofs_task_ctx *task, struct silofs_env *env);

void silofs_task_fini(struct silofs_task_ctx *task);

void silofs_task_update_creds(struct silofs_task_ctx *task, uid_t uid,
                              gid_t gid, mode_t umsk);

void silofs_task_update_auth(struct silofs_task_ctx *task, pid_t pid,
                             uint64_t unique, uint32_t opcode, bool exclusive);

void silofs_task_update_umask(struct silofs_task_ctx *task, mode_t umask);

void silofs_task_update_times(struct silofs_task_ctx *task, bool rt);

int silofs_task_submit(struct silofs_task_ctx *task, bool all);

void silofs_task_enq_loose(struct silofs_task_ctx   *task,
                           struct silofs_inode_info *ii);

void silofs_lock_fs_by(struct silofs_task_ctx *task);

void silofs_unlock_fs_by(struct silofs_task_ctx *task);

void silofs_rwlock_fs_by(struct silofs_task_ctx *task);

void silofs_rwunlock_fs_by(struct silofs_task_ctx *task);

int silofs_curr_sbi(const struct silofs_task_ctx *task,
                    struct silofs_sbnode_info   **out_sbi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_flush_dirty(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *ii, int flags);

int silofs_flush_dirty_now(struct silofs_task_ctx *task);

#endif /* SILOFS_TASK_H_ */
