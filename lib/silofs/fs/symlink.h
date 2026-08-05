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
#ifndef SILOFS_SYMLINK_H_
#define SILOFS_SYMLINK_H_

#include <silofs/nodes.h>
#include <silofs/exec.h>

void silofs_ii_setup_symlnk(struct silofs_inode_info *lnk_ii);

int silofs_drop_symlink(const struct silofs_task_ctx *task,
                        struct silofs_inode_info     *lnk_ii);

int silofs_do_readlink(const struct silofs_task_ctx *task,
                       struct silofs_inode_info *lnk_ii, void *ptr, size_t lim,
                       size_t *out_len);

int silofs_bind_symval(const struct silofs_task_ctx *task,
                       struct silofs_inode_info     *lnk_ii,
                       const struct silofs_strview  *symval);

int silofs_verify_symval_node(const struct silofs_symval_node *svn);

#endif /* SILOFS_SYMLINK_H_ */
