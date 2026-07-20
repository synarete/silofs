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
	struct silofs_task_auth        auth;
	const struct silofs_core_refs *corefs;
	struct silofs_inode_info      *looseq;
	uint64_t                       upper_id;
	struct timespec                start_time;
	volatile int8_t                interrupted;
	volatile int8_t                fs_locked;
	volatile int8_t                rw_locked;
	volatile int8_t                exclusive;
	bool                           kwrite;
	bool                           internal;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_task_init(struct silofs_task_ctx        *task,
                      const struct silofs_core_refs *corefs);

void silofs_task_fini(struct silofs_task_ctx *task);

void silofs_task_set_creds(struct silofs_task_ctx *task, //
                           uid_t uid, gid_t gid, mode_t umsk);

void silofs_task_set_auth(struct silofs_task_ctx *task,  //
                          pid_t pid, uint64_t unique, uint32_t opcode);

void silofs_task_set_umask(struct silofs_task_ctx *task, mode_t umask);

void silofs_task_set_time(struct silofs_task_ctx *task, bool rt);

void silofs_task_set_excl(struct silofs_task_ctx *task, bool excl);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_lock_fs_by(struct silofs_task_ctx *task);

void silofs_unlock_fs_by(struct silofs_task_ctx *task);

void silofs_rwlock_fs_by(struct silofs_task_ctx *task);

void silofs_rwunlock_fs_by(struct silofs_task_ctx *task);

#endif /* SILOFS_TASK_H_ */
