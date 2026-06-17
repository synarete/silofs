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
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/run.h>

static bool isock_allowed(const struct silofs_task_ctx *task)
{
	return (task->env->flags & SILOFS_F_ALLOW_ISOCK) > 0;
}

static bool ififo_allowed(const struct silofs_task_ctx *task)
{
	return (task->env->flags & SILOFS_F_ALLOW_IFIFO) > 0;
}

static int check_itype(const struct silofs_task_ctx *task, mode_t mode)
{
	/*
	 * TODO-0031: Filter supported modes based on mount flags
	 *
	 * Have explicit control in 'allow_ispecial' from mount command and
	 * by mount flags.
	 */
	const mode_t itype = mode & S_IFMT;
	int ret;

	switch (itype) {
	case S_IFDIR:
	case S_IFREG:
	case S_IFLNK:
		ret = 0;
		break;
	case S_IFSOCK:
		ret = isock_allowed(task) ? 0 : -SILOFS_EOPNOTSUPP;
		break;
	case S_IFIFO:
		ret = ififo_allowed(task) ? 0 : -SILOFS_EOPNOTSUPP;
		break;
	case S_IFCHR:
	case S_IFBLK:
	default:
		ret = -SILOFS_EOPNOTSUPP;
		break;
	}
	return ret;
}

int silofs_spawn_inode_by(struct silofs_task_ctx *task,
                          const struct silofs_inew_params *inp,
                          struct silofs_inode_info **out_ii)
{
	int err;

	err = check_itype(task, inp->mode);
	return_if_err(err);

	err = silofs_spawn_inode2(task, out_ii);
	return_if_err(err);

	silofs_ii_update_spawned(*out_ii, inp);
	return 0;
}
