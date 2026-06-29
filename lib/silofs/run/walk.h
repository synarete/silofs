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
#ifndef SILOFS_WALK_H_
#define SILOFS_WALK_H_

#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>
#include <silofs/fs.h>

int silofs_walkfs_at(struct silofs_task_ctx *task, struct silofs_sb_info *sbi);

int silofs_unrefs_at(struct silofs_task_ctx *task, struct silofs_sb_info *sbi);

#endif /* SILOFS_WALK_H_ */
