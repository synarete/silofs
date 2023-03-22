/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_SPAWN_H_
#define SILOFS_SPAWN_H_

int silofs_spawn_vnode(struct silofs_task *task,
                       enum silofs_stype stype,
                       struct silofs_inode_info *ii,
                       struct silofs_vnode_info **out_vi);

int silofs_spawn_inode(struct silofs_task *task, ino_t parent_ino,
                       mode_t parent_mode, mode_t mode, dev_t rdev,
                       struct silofs_inode_info **out_ii);

int silofs_remove_vnode(struct silofs_task *task,
                        struct silofs_vnode_info *vi);

int silofs_remove_vnode_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr);

int silofs_remove_inode(struct silofs_task *task,
                        struct silofs_inode_info *ii);

#endif /* SILOFS_SPAWN_H_ */
