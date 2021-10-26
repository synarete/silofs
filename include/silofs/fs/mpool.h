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
#ifndef SILOFS_MPOOL_H_
#define SILOFS_MPOOL_H_

#include <silofs/fs/types.h>

/* pool of chained free memory-chunks of equal size */
struct silofs_mpoolq {
	struct silofs_listq     mpq_fls;
	struct silofs_qalloc   *mpq_qal;
	size_t mpq_obj_size;
};

/* pool-based memory-allocator */
struct silofs_mpool {
	struct silofs_alloc_if  mp_alif;
	struct silofs_qalloc   *mp_qal;
	unsigned long           mp_nbytes_alloc;
	struct silofs_mpoolq    mpq[11];
};

void silofs_mpool_init(struct silofs_mpool *mpool, struct silofs_qalloc *qal);

void silofs_mpool_fini(struct silofs_mpool *mpool);

#endif /* SILOFS_MPOOL_H_ */
