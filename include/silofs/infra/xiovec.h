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
#ifndef SILOFS_XIOVEC_H_
#define SILOFS_XIOVEC_H_

#include <stdlib.h>

struct silofs_xiovref;
struct silofs_xiovec;

typedef void (*silofs_xiovref_fn)(struct silofs_xiovref *fvr);

/* extended iovec with optional back-reference */
struct silofs_xiovec {
	struct silofs_xiovref *xiov_ref;
	void  *xiov_base;
	size_t xiov_len;
	loff_t xiov_off;
	int    xiov_fd;
};

struct silofs_xiovref {
	silofs_xiovref_fn pre;
	silofs_xiovref_fn post;
};


int silofs_xiovec_copy_into(const struct silofs_xiovec *xiov, void *buf);

int silofs_xiovec_copy_from(const struct silofs_xiovec *xiov, const void *buf);

int silofs_xiovec_copy_mem(const struct silofs_xiovec *xiov_src,
                           const struct silofs_xiovec *xiov_dst, size_t len);


void silofs_xiovref_init(struct silofs_xiovref *xior,
                         silofs_xiovref_fn pre, silofs_xiovref_fn post);

void silofs_xiovref_fini(struct silofs_xiovref *xior);

void silofs_xiovref_pre(struct silofs_xiovref *xior);

void silofs_xiovref_post(struct silofs_xiovref *xior);

#endif /* SILOFS_XIOVEC_H_ */
