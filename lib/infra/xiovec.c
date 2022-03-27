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
#include <silofs/infra/xiovec.h>
#include <silofs/infra/syscall.h>
#include <string.h>
#include <errno.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_xiovec_copy_into(const struct silofs_xiovec *xiov, void *buf)
{
	int err;

	if (xiov->xiov_base != NULL) {
		memcpy(buf, xiov->xiov_base, xiov->xiov_len);
		err = 0;
	} else if (xiov->xiov_fd > 0) {
		err = silofs_sys_preadn(xiov->xiov_fd, buf,
		                        xiov->xiov_len, xiov->xiov_off);
	} else {
		err = -EIO;
	}
	return err;
}

int silofs_xiovec_copy_from(const struct silofs_xiovec *xiov, const void *buf)
{
	int err;

	if (xiov->xiov_base != NULL) {
		memcpy(xiov->xiov_base, buf, xiov->xiov_len);
		err = 0;
	} else if (xiov->xiov_fd > 0) {
		err = silofs_sys_pwriten(xiov->xiov_fd, buf,
		                         xiov->xiov_len, xiov->xiov_off);
	} else {
		err = -EIO;
	}
	return err;
}

int silofs_xiovec_copy_mem(const struct silofs_xiovec *xiov_src,
                           const struct silofs_xiovec *xiov_dst, size_t len)
{
	memcpy(xiov_dst->xiov_base, xiov_src->xiov_base, len);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_xiovref_init(struct silofs_xiovref *xior,
                         silofs_xiovref_fn pre, silofs_xiovref_fn post)
{
	xior->pre = pre;
	xior->post = post;
}

void silofs_xiovref_fini(struct silofs_xiovref *xior)
{
	xior->pre = NULL;
	xior->post = NULL;
}

void silofs_xiovref_pre(struct silofs_xiovref *xior)
{
	if (xior && xior->pre) {
		xior->pre(xior);
	}
}

void silofs_xiovref_post(struct silofs_xiovref *xior)
{
	if (xior && xior->post) {
		xior->post(xior);
	}
}
