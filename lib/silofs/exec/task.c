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
#include <silofs/exec.h>

void silofs_task_init(struct silofs_task_ctx *task,
                      const struct silofs_core_refs *corefs)
{
	silofs_memzero(task, sizeof(*task));
	silofs_creds_init(&task->auth.creds);
	task->corefs      = corefs;
	task->looseq      = nullptr;
	task->upper_id    = 0;
	task->interrupted = 0;
	task->fs_locked   = 0;
	task->rw_locked   = 0;
	task->exclusive   = 0;
	task->kwrite      = false;
	task->internal    = false;
}

void silofs_task_fini(struct silofs_task_ctx *task)
{
	silofs_assert_null(task->looseq);

	silofs_creds_fini(&task->auth.creds);
	task->corefs = nullptr;
	task->looseq = nullptr;
}

void silofs_task_set_creds(struct silofs_task_ctx *task, uid_t uid, gid_t gid,
                           mode_t umsk)
{
	struct silofs_creds *creds = &task->auth.creds;

	silofs_cred_setup(&creds->host_cred, uid, gid, umsk);
	silofs_cred_setup(&creds->fs_cred, uid, gid, umsk);
}

void silofs_task_set_auth(struct silofs_task_ctx *task, pid_t pid,
                          uint64_t unique, uint32_t opcode)
{
	task->auth.pid    = pid;
	task->auth.unique = unique;
	task->auth.opcode = opcode;
}

void silofs_task_set_umask(struct silofs_task_ctx *task, mode_t umask)
{
	struct silofs_creds *creds = &task->auth.creds;

	creds->host_cred.umask = creds->fs_cred.umask = umask;
}

void silofs_task_set_time(struct silofs_task_ctx *task, bool rt)
{
	struct timespec *ts = &task->auth.ts;

	if (rt) {
		silofs_clock_gettime_real(ts);
	} else {
		silofs_clock_gettime_mono(ts);
	}
}

void silofs_task_set_excl(struct silofs_task_ctx *task, bool excl)
{
	task->exclusive = excl ? 1 : 0;
}

void silofs_lock_fs_by(struct silofs_task_ctx *task)
{
	if (!task->fs_locked) {
		silofs_fsroot_lock(task->corefs->fsroot);
		task->fs_locked = 1;
	}
}

void silofs_unlock_fs_by(struct silofs_task_ctx *task)
{
	if (task->fs_locked) {
		silofs_fsroot_unlock(task->corefs->fsroot);
		task->fs_locked = 0;
	}
}

void silofs_rwlock_fs_by(struct silofs_task_ctx *task)
{
	if (!task->rw_locked) {
		silofs_fsroot_rwlock(task->corefs->fsroot, task->exclusive);
		task->rw_locked = 1;
	}
}

void silofs_rwunlock_fs_by(struct silofs_task_ctx *task)
{
	if (task->rw_locked) {
		silofs_fsroot_rwunlock(task->corefs->fsroot);
		task->rw_locked = 0;
	}
}
