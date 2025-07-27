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
#ifndef SILOFS_UBER_H_
#define SILOFS_UBER_H_

#include "pnode.h"

/* uber-block in-memory state */
struct silofs_ub_info {
	struct silofs_pnode_info  ub_pni;
	struct silofs_uber_block *ub;
};

/* blob-descriptor cursor */
struct silofs_bdcur {
	struct silofs_paddr paddr;
	size_t              blobsz;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_ub_info *
silofs_ubi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_ubi_del(struct silofs_ub_info *ubi, struct silofs_alloc *alloc);

void silofs_ubi_set_dq(struct silofs_ub_info *ubi, struct silofs_dirtyq *dq);

void silofs_ubi_dirtify(struct silofs_ub_info *ubi);

void silofs_ubi_undirtify(struct silofs_ub_info *ubi);

void silofs_ubi_setup_spawned(struct silofs_ub_info *ubi);

int silofs_ubi_bdcur_of(const struct silofs_ub_info *ubi,
                        enum silofs_mtype            mtype,
                        struct silofs_bdcur         *out_bdcur);

int silofs_ubi_update_bdcur(struct silofs_ub_info     *ubi,
                            enum silofs_mtype          mtype,
                            const struct silofs_bdcur *bdcur);

#endif /* SILOFS_UBER_H_ */
