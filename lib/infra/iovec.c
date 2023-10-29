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
#include <silofs/configs.h>
#include <silofs/syscall.h>
#include <silofs/errors.h>
#include <silofs/infra/iovec.h>
#include <string.h>
#include <errno.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_iovec_copy_into(const struct silofs_iovec *iov, void *buf)
{
	int err;

	if (iov->iov_base != NULL) {
		memcpy(buf, iov->iov_base, iov->iov_len);
		err = 0;
	} else if (iov->iov_fd > 0) {
		err = silofs_sys_preadn(iov->iov_fd, buf,
		                        iov->iov_len, iov->iov_off);
	} else {
		err = -SILOFS_EIO;
	}
	return err;
}

int silofs_iovec_copy_from(const struct silofs_iovec *iov, const void *buf)
{
	int err;

	if (iov->iov_base != NULL) {
		memcpy(iov->iov_base, buf, iov->iov_len);
		err = 0;
	} else if (iov->iov_fd > 0) {
		err = silofs_sys_pwriten(iov->iov_fd, buf,
		                         iov->iov_len, iov->iov_off);
	} else {
		err = -SILOFS_EIO;
	}
	return err;
}

int silofs_iovec_copy_mem(const struct silofs_iovec *iov_src,
                          const struct silofs_iovec *iov_dst, size_t len)
{
	memcpy(iov_dst->iov_base, iov_src->iov_base, len);
	return 0;
}
