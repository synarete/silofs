/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_DIR_H_
#define SILOFS_DIR_H_

#include <silofs/types.h>

size_t silofs_dir_ndentries(const struct silofs_inode_info *dir_ii);

uint64_t silofs_dir_seed(const struct silofs_inode_info *dir_ii);

enum silofs_dirf silofs_dir_flags(const struct silofs_inode_info *dir_ii);

enum silofs_dirhfn silofs_dir_hfn(const struct silofs_inode_info *dir_ii);

int silofs_verify_dir_inode(const struct silofs_inode *inode);

int silofs_verify_dtree_node(const struct silofs_dtree_node *dtn);

void silofs_setup_dir(struct silofs_inode_info *dir_ii,
                      mode_t parent_mode, nlink_t nlink);

int silofs_lookup_dentry(const struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_qstr *name,
                         struct silofs_ino_dt *out_idt);

int silofs_add_dentry(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_qstr *name,
                      struct silofs_inode_info *ii);

int silofs_remove_dentry(const struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_qstr *name);

int silofs_do_readdir(const struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      struct silofs_readdir_ctx *rd_ctx);

int silofs_do_readdirplus(const struct silofs_task *task,
                          struct silofs_inode_info *dir_ii,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_drop_dir(struct silofs_inode_info *dir_ii);


#endif /* SILOFS_DIR_H_ */
