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
#include <silofs/configs.h>
#include <silofs/fs.h>


int silofs_kcopy_by_splice(struct silofs_fs_uber *uber,
                           int fd_src, loff_t off_src,
                           int fd_dst, loff_t off_dst, size_t len)
{
	struct silofs_piper *piper = &uber->ub_piper;
	int err;

	err = silofs_piper_kcopy(piper, fd_src, &off_src,
	                         fd_dst, &off_dst, len, 0);
	if (err) {
		silofs_piper_dispose(piper);
	}
	return err;
}

int silofs_kcopy_by_iovec(struct silofs_fs_uber *uber,
                          const struct silofs_iovec *iov_src,
                          const struct silofs_iovec *iov_dst, size_t len)
{
	return silofs_kcopy_by_splice(uber, iov_src->iov_fd, iov_src->iov_off,
	                              iov_dst->iov_fd, iov_dst->iov_off, len);
}
