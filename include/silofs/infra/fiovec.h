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
#ifndef SILOFS_FIOVEC_H_
#define SILOFS_FIOVEC_H_

#include <stdlib.h>

struct silofs_fiovref;
struct silofs_fiovec;

typedef void (*silofs_fiovref_fn)(struct silofs_fiovref *fvr);

struct silofs_fiovref {
	silofs_fiovref_fn pre;
	silofs_fiovref_fn post;
};

struct silofs_fiovec {
	void  *fv_base;
	size_t fv_len;
	loff_t fv_off;
	int    fv_fd;
	struct silofs_fiovref *fv_ref;
};


void silofs_fiovref_init(struct silofs_fiovref *fir,
                         silofs_fiovref_fn pre, silofs_fiovref_fn post);

void silofs_fiovref_fini(struct silofs_fiovref *fir);

void silofs_fiovref_pre(struct silofs_fiovref *fir);

void silofs_fiovref_post(struct silofs_fiovref *fir);


int silofs_fiovec_copy_into(const struct silofs_fiovec *fiov, void *buf);

int silofs_fiovec_copy_from(const struct silofs_fiovec *fiov, const void *buf);

int silofs_fiovec_copy_mem(const struct silofs_fiovec *fiov_src,
                           const struct silofs_fiovec *fiov_dst, size_t len);

#endif /* SILOFS_FIOVEC_H_ */
