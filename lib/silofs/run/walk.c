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
#include <silofs/base.h>
#include <silofs/fs.h>
#include <silofs/run.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*
 * TODO-0041: Proper space accounting
 *
 * Do full space-stats collection and export result to caller. Verify collected
 * stats against top-level space-stats accountings.
 */

/*
 * TODO-0049: Proper file-system traverse and repair
 *
 * Extend fsck logic to enable file-system repair.
 */

int silofs_traverse_fs(struct silofs_task_ctx *task)
{
	silofs_unused(task);
	return 0;
}
