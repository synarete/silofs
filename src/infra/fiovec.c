/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/infra/fiovec.h>
#include <silofs/infra/syscall.h>
#include <string.h>
#include <errno.h>

void silofs_fiovref_init(struct silofs_fiovref *fir,
                         silofs_fiovref_fn pre, silofs_fiovref_fn post)
{
	fir->pre = pre;
	fir->post = post;
}

void silofs_fiovref_fini(struct silofs_fiovref *fir)
{
	fir->pre = NULL;
	fir->post = NULL;
}

void silofs_fiovref_pre(struct silofs_fiovref *fir)
{
	if (fir && fir->pre) {
		fir->pre(fir);
	}
}

void silofs_fiovref_post(struct silofs_fiovref *fir)
{
	if (fir && fir->post) {
		fir->post(fir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_fiovec_copy_into(const struct silofs_fiovec *fiov, void *buf)
{
	int err;

	if (fiov->fv_base != NULL) {
		memcpy(buf, fiov->fv_base, fiov->fv_len);
		err = 0;
	} else if (fiov->fv_fd > 0) {
		err = silofs_sys_preadn(fiov->fv_fd, buf,
		                        fiov->fv_len, fiov->fv_off);
	} else {
		err = -EIO;
	}
	return err;
}

int silofs_fiovec_copy_from(const struct silofs_fiovec *fiov, const void *buf)
{
	int err;

	if (fiov->fv_base != NULL) {
		memcpy(fiov->fv_base, buf, fiov->fv_len);
		err = 0;
	} else if (fiov->fv_fd > 0) {
		err = silofs_sys_pwriten(fiov->fv_fd, buf,
		                         fiov->fv_len, fiov->fv_off);
	} else {
		err = -EIO;
	}
	return err;
}

int silofs_fiovec_copy_mem(const struct silofs_fiovec *fiov_src,
                           const struct silofs_fiovec *fiov_dst, size_t len)
{
	memcpy(fiov_dst->fv_base, fiov_src->fv_base, len);
	return 0;
}
