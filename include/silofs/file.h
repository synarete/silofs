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
#ifndef SILOFS_FILE_H_
#define SILOFS_FILE_H_

#include <unistd.h>
#include <stdlib.h>

void silofs_setup_reg(struct silofs_inode_info *ii);

int silofs_drop_reg(struct silofs_inode_info *ii);

int silofs_do_write(const struct silofs_task *task,
                    struct silofs_inode_info *ii,
                    const void *buf, size_t len,
                    loff_t off, size_t *out_len);

int silofs_do_write_iter(const struct silofs_task *task,
                         struct silofs_inode_info *ii,
                         struct silofs_rwiter_ctx *rwi_ctx);

int silofs_do_read_iter(const struct silofs_task *task,
                        struct silofs_inode_info *ii,
                        struct silofs_rwiter_ctx *rwi_ctx);

int silofs_do_read(const struct silofs_task *task,
                   struct silofs_inode_info *ii,
                   void *buf, size_t len, loff_t off, size_t *out_len);

int silofs_do_lseek(const struct silofs_task *task,
                    struct silofs_inode_info *ii,
                    loff_t off, int whence, loff_t *out_off);

int silofs_do_fallocate(const struct silofs_task *task,
                        struct silofs_inode_info *ii,
                        int mode, loff_t off, loff_t length);

int silofs_do_truncate(const struct silofs_task *task,
                       struct silofs_inode_info *ii, loff_t off);

int silofs_do_fiemap(const struct silofs_task *task,
                     struct silofs_inode_info *ii, struct fiemap *fm);

int silofs_do_copy_file_range(const struct silofs_task *task,
                              struct silofs_inode_info *ii_in,
                              struct silofs_inode_info *ii_out,
                              loff_t off_in, loff_t off_out, size_t len,
                              int flags, size_t *out_ncp);

int silofs_do_rdwr_post(const struct silofs_task *task,
                        const struct silofs_iovec *iov, size_t cnt);


int silofs_verify_ftree_node(const struct silofs_ftree_node *ftn);


#endif /* SILOFS_FILE_H_ */
