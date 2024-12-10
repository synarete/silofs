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
#ifndef SILOFS_PSTORE_H_
#define SILOFS_PSTORE_H_

#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/addr.h>
#include <silofs/ps/repo.h>
#include <silofs/ps/bcache.h>

struct silofs_prange {
	struct silofs_pvid pvid;
	uint32_t           base_index;
	uint32_t           curr_index;
	loff_t             pos_in_curr;
};

struct silofs_pstate {
	struct silofs_prange prange;
	struct silofs_paddr  btree_root;
};

struct silofs_pstore {
	struct silofs_repo  *repo;
	struct silofs_bcache bcache;
	struct silofs_pstate pstate;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_prange_assign(struct silofs_prange       *prange,
                          const struct silofs_prange *other);

void silofs_prange64b_htox(struct silofs_prange64b    *prange64,
                           const struct silofs_prange *prange);

void silofs_prange64b_xtoh(const struct silofs_prange64b *prange64,
                           struct silofs_prange          *prange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pstore_init(struct silofs_pstore *pstore, struct silofs_repo *repo);

void silofs_pstore_fini(struct silofs_pstore *pstore);

int silofs_pstore_dropall(struct silofs_pstore *pstore);

int silofs_pstore_format(struct silofs_pstore *pstore);

int silofs_pstore_open(struct silofs_pstore       *pstore,
                       const struct silofs_prange *prange);

int silofs_pstore_close(struct silofs_pstore *pstore);

int silofs_pstore_flush_dirty(struct silofs_pstore *pstore);

void silofs_pstore_curr_prange(const struct silofs_pstore *pstore,
                               struct silofs_prange       *out_prange);

#endif /* SILOFS_PSTORE_H_ */
