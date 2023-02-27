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
#ifndef SILOFS_IOVEC_H_
#define SILOFS_IOVEC_H_

#include <stdlib.h>

struct silofs_iovref;
struct silofs_iovec;

typedef void (*silofs_iovref_fn)(struct silofs_iovref *);

/* extended iovec with optional file and back-context references */
struct silofs_iovec {
	struct silofs_iovref *iov_ref;
	void  *iov_base;
	size_t iov_len;
	loff_t iov_off;
	int    iov_fd;
};

struct silofs_iovref {
	silofs_iovref_fn pre;
	silofs_iovref_fn post;
};


int silofs_iovec_copy_into(const struct silofs_iovec *iov, void *buf);

int silofs_iovec_copy_from(const struct silofs_iovec *iov, const void *buf);

int silofs_iovec_copy_mem(const struct silofs_iovec *iov_src,
                          const struct silofs_iovec *iov_dst, size_t len);


void silofs_iovref_init(struct silofs_iovref *iovr,
                        silofs_iovref_fn pre, silofs_iovref_fn post);

void silofs_iovref_fini(struct silofs_iovref *iovr);

void silofs_iovref_pre(struct silofs_iovref *iovr);

void silofs_iovref_post(struct silofs_iovref *iovr);

#endif /* SILOFS_IOVEC_H_ */
