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
#ifndef SILOFS_BSTORE_H_
#define SILOFS_BSTORE_H_

#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/pcache.h>

/* persistent storage's current active range */
struct silofs_prange {
	struct silofs_pvid pvid;
	uint32_t           base_index;
	uint32_t           curr_index;
	loff_t             pos_in_curr;
};

/* blobs storage state: a pair of active range and mapping tree root */
struct silofs_bstate {
	struct silofs_prange prange;
	struct silofs_paddr  btree_root;
};

/* blobs-storage control object */
struct silofs_bstore {
	struct silofs_repo  *repo;
	struct silofs_pcache pcache;
	struct silofs_bstate bstate;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_prange_assign(struct silofs_prange       *prange,
                          const struct silofs_prange *other);

void silofs_prange64b_htox(struct silofs_prange64b    *prange64,
                           const struct silofs_prange *prange);

void silofs_prange64b_xtoh(const struct silofs_prange64b *prange64,
                           struct silofs_prange          *prange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_init(struct silofs_bstore *bstore, struct silofs_repo *repo);

void silofs_bstore_fini(struct silofs_bstore *bstore);

int silofs_bstore_dropall(struct silofs_bstore *bstore);

int silofs_bstore_format(struct silofs_bstore *bstore);

int silofs_bstore_reload(struct silofs_bstore       *bstore,
                         const struct silofs_prange *prange);

int silofs_bstore_close(struct silofs_bstore *bstore);

int silofs_bstore_flush_dirty(struct silofs_bstore *bstore);

void silofs_bstore_curr_prange(const struct silofs_bstore *bstore,
                               struct silofs_prange       *out_prange);

#endif /* SILOFS_BSTORE_H_ */
