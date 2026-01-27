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
#include <silofs/ondisk.h>
#include <silofs/types.h>
#include "infra.h"
#include "addr.h"
#include "fs.h"
#include "exec.h"
#include "env.h"

static int reload_uber(struct silofs_task_ctx *task)
{
	return silofs_env_reload_uber(task->t_env);
}

static int reload_super(struct silofs_task_ctx *task)
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

static int reload_vspace(struct silofs_task_ctx *task)
{
	return silofs_reload_vspace(task);
}

static int reload_rootd(struct silofs_task_ctx *task)
{
	struct silofs_inode_info *ii = nullptr;
	const ino_t ino              = SILOFS_INO_ROOT;
	int err;

	err = silofs_stage_inode(task, ino, SILOFS_STG_CUR, &ii);
	if (err) {
		log_err("failed to reload root-inode: err=%d", err);
		return err;
	}
	if (!silofs_ii_isdir(ii)) {
		log_err("root-inode is not-a-dir: mode=0%o",
		        silofs_ii_mode(ii));
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int
reload_fs_mbr(struct silofs_task_ctx *task, const struct silofs_mbref *mbref)
{
	return silofs_env_reload_fs_mbr(task->t_env, mbref);
}

int silofs_exec_reload_fs(struct silofs_task_ctx *task,
                          const struct silofs_mbref *mbref)
{
	int err;

	err = reload_fs_mbr(task, mbref);
	if (err) {
		return err;
	}
	err = reload_uber(task);
	if (err) {
		return err;
	}
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
