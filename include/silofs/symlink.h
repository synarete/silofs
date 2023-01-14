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
#ifndef SILOFS_SYMLINK_H_
#define SILOFS_SYMLINK_H_

#include <stdlib.h>

void silofs_setup_symlnk(struct silofs_inode_info *lnk_ii);

int silofs_drop_symlink(struct silofs_task *task,
                        struct silofs_inode_info *lnk_ii);

int silofs_do_readlink(struct silofs_task *task,
                       struct silofs_inode_info *lnk_ii,
                       void *ptr, size_t lim, size_t *out_len);

int silofs_setup_symlink(struct silofs_task *task,
                         struct silofs_inode_info *lnk_ii,
                         const struct silofs_str *symval);

int silofs_verify_symlnk_value(const struct silofs_symlnk_value *lnv);

#endif /* SILOFS_SYMLINK_H_ */
