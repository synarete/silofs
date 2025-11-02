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

#include "bnode.h"

/* uber-block in-memory state */
struct silofs_ub_info {
	struct silofs_bnode_info  ub_bni;
	struct silofs_uber_block *ub;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_ub_info *
silofs_ubi_new(const struct silofs_baddr *baddr, struct silofs_alloc *alloc);

void silofs_ubi_del(struct silofs_ub_info *ubi, struct silofs_alloc *alloc);

void silofs_ubi_set_dq(struct silofs_ub_info *ubi, struct silofs_dirtyq *dq);

void silofs_ubi_dirtify(struct silofs_ub_info *ubi);

void silofs_ubi_undirtify(struct silofs_ub_info *ubi);

void silofs_ubi_setup_spawned(struct silofs_ub_info *ubi);

int silofs_ubi_bcursor_of(const struct silofs_ub_info *ubi,
                          enum silofs_mtype            mtype,
                          struct silofs_bcursor       *out_bcursor);

int silofs_ubi_update_bcursor(struct silofs_ub_info       *ubi,
                              enum silofs_mtype            mtype,
                              const struct silofs_bcursor *bcursor);

#endif /* SILOFS_UBER_H_ */
