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
#ifndef SILOFS_IOVEC_H_
#define SILOFS_IOVEC_H_

#include <sys/uio.h>

/* read-only I/O vector (pointer-to-data + length) */
struct silofs_rovec {
	const void *rov_base;
	size_t rov_len;
};

/* extension to standard scatter/gather I/O vector with optional
 * file-descriptor and back-reference. */
struct silofs_iovec {
	struct iovec iov;
	void  *iov_backref;
	loff_t iov_off;
	int    iov_fd;
};

void silofs_iovec_reset(struct silofs_iovec *iov);

void silofs_iovec_assign(struct silofs_iovec *iov,
                         const struct silofs_iovec *other);

int silofs_iovec_copy_into(const struct silofs_iovec *iov, void *buf);

int silofs_iovec_copy_from(const struct silofs_iovec *iov, const void *buf);

int silofs_iovec_copy_mem(const struct silofs_iovec *iov_src,
                          const struct silofs_iovec *iov_dst, size_t len);

#endif /* SILOFS_IOVEC_H_ */
