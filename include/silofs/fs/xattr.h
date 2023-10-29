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
#ifndef SILOFS_XATTR_H_
#define SILOFS_XATTR_H_

void silofs_ii_setup_xattr(struct silofs_inode_info *ii);

int silofs_do_getxattr(struct silofs_task *task,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name,
                       void *buf, size_t size, size_t *out_size);

int silofs_do_setxattr(struct silofs_task *task,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name,
                       const void *value, size_t size,
                       int flags, bool kill_sgid);

int silofs_do_removexattr(struct silofs_task *task,
                          struct silofs_inode_info *ii,
                          const struct silofs_namestr *name);

int silofs_do_listxattr(struct silofs_task *task,
                        struct silofs_inode_info *ii,
                        struct silofs_listxattr_ctx *lxa_ctx);

int silofs_drop_xattr(struct silofs_task *task,
                      struct silofs_inode_info *ii);

int silofs_verify_inode_xattr(const struct silofs_inode *inode);

int silofs_verify_xattr_node(const struct silofs_xattr_node *xan);


#endif /* SILOFS_XATTR_H_ */
