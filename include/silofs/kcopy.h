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
#ifndef SILOFS_KCOPY_H_
#define SILOFS_KCOPY_H_

int silofs_kcopy_by_splice(struct silofs_fs_uber *uber,
                           int fd_src, loff_t off_src,
                           int fd_dst, loff_t off_dst, size_t len);

int silofs_kcopy_by_iovec(struct silofs_fs_uber *uber,
                          const struct silofs_iovec *iov_src,
                          const struct silofs_iovec *iov_dst, size_t len);

#endif /* SILOFS_KCOPY_H_ */
