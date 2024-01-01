/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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


/* call-back context for read-dir operations */
typedef int (*silofs_filldir_fn)(struct silofs_readdir_ctx *rd_ctx,
                                 const struct silofs_readdir_info *rdi);

struct silofs_readdir_info {
	struct silofs_stat attr;
	const char     *name;
	size_t          namelen;
	ino_t           ino;
	loff_t          off;
	mode_t          dt;
};

struct silofs_readdir_ctx {
	silofs_filldir_fn actor;
	loff_t pos;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum silofs_dirf silofs_dir_flags(const struct silofs_inode_info *dir_ii);

void silofs_setup_dir(struct silofs_inode_info *dir_ii,
                      mode_t parent_mode, nlink_t nlink);

int silofs_lookup_dentry(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name,
                         struct silofs_ino_dt *out_idt);

int silofs_add_dentry(struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      const struct silofs_namestr *name,
                      struct silofs_inode_info *ii);

int silofs_remove_dentry(struct silofs_task *task,
                         struct silofs_inode_info *dir_ii,
                         const struct silofs_namestr *name);

int silofs_do_readdir(struct silofs_task *task,
                      struct silofs_inode_info *dir_ii,
                      struct silofs_readdir_ctx *rd_ctx);

int silofs_do_readdirplus(struct silofs_task *task,
                          struct silofs_inode_info *dir_ii,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_drop_dir(struct silofs_task *task,
                    struct silofs_inode_info *dir_ii);

bool silofs_dir_isempty(const struct silofs_inode_info *dir_ii);

bool silofs_dir_may_add(const struct silofs_inode_info *dir_ii);


bool silofs_dir_has_flags(const struct silofs_inode_info *dir_ii,
                          enum silofs_dirf mask);

int silofs_dir_check_name(const struct silofs_inode_info *dir_ii,
                          const struct silofs_namestr *nstr);

int silofs_dir_make_hname(const struct silofs_inode_info *dir_ii,
                          const struct silofs_namestr *nstr,
                          struct silofs_namestr *out_nstr);

int silofs_verify_dir_inode(const struct silofs_inode *inode);

int silofs_verify_dtree_node(const struct silofs_dtree_node *dtn);

#endif /* SILOFS_DIR_H_ */
