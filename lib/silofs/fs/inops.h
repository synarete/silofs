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
#ifndef SILOFS_INOPS_H_
#define SILOFS_INOPS_H_

int silofs_spawn_inode_by(struct silofs_task_ctx          *task,
                          const struct silofs_inew_params *inp,
                          struct silofs_inode_info       **out_ii);

int silofs_stage_inode_by(struct silofs_task_ctx *task, ino_t ino,
                          enum silofs_stg_mode       stg_mode,
                          struct silofs_inode_info **out_ii);

int silofs_remove_inode_by(struct silofs_task_ctx   *task,
                           struct silofs_inode_info *ii);

int silofs_lookup_cached_inode(const struct silofs_task_ctx *task, ino_t ino,
                               struct silofs_inode_info **out_ii);

int silofs_flush_dirty_of(const struct silofs_task_ctx *task,
                          struct silofs_inode_info *ii, int flags);

void silofs_enq_loose_inode(struct silofs_task_ctx   *task,
                            struct silofs_inode_info *ii);

int silofs_purge_loose_inodes(struct silofs_task_ctx *task);

#endif /* SILOFS_INOPS_H_ */
