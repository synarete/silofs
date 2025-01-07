/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include <silofs/addr.h>
#include <silofs/repo.h>
#include <silofs/pcache.h>
#include <silofs/btree.h>

/* persistent volume range (current address-space state) */
struct silofs_pvrange {
	struct silofs_pvid pvid;
	uint32_t           base_index;
	uint32_t           curr_index;
	loff_t             curr_pos;
};

/* blobs-storage control object */
struct silofs_bstore {
	struct silofs_pvrange pvrange;
	struct silofs_pcache  pcache;
	struct silofs_btree   btree;
	struct silofs_repo   *repo;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvrange_assign(struct silofs_pvrange       *pvrange,
                           const struct silofs_pvrange *other);

void silofs_pvrange64b_htox(struct silofs_pvrange64b    *pvrange64,
                            const struct silofs_pvrange *pvrange);

void silofs_pvrange64b_xtoh(const struct silofs_pvrange64b *pvrange64,
                            struct silofs_pvrange          *pvrange);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bstore_init(struct silofs_bstore *bstore, struct silofs_repo *repo);

void silofs_bstore_fini(struct silofs_bstore *bstore);

int silofs_bstore_dropall(struct silofs_bstore *bstore);

int silofs_bstore_format(struct silofs_bstore *bstore);

int silofs_bstore_reload(struct silofs_bstore        *bstore,
                         const struct silofs_pvrange *pvrange);

int silofs_bstore_close(struct silofs_bstore *bstore);

int silofs_bstore_flush_dirty(struct silofs_bstore *bstore);

void silofs_bstore_curr_pvrange(const struct silofs_bstore *bstore,
                                struct silofs_pvrange      *out_pvrange);

int silofs_bstore_resolve(struct silofs_bstore      *bstore,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_paddr       *out_paddr);

int silofs_bstore_remap(struct silofs_bstore      *bstore,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_paddr *paddr);

#endif /* SILOFS_BSTORE_H_ */
