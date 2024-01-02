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
#ifndef SILOFS_BCACHE_H_
#define SILOFS_BCACHE_H_


struct silofs_bcache {
	struct silofs_alloc            *bc_alloc;
	struct silofs_listq             bc_lru;
	struct silofs_list_head        *bc_htbl;
	size_t                          bc_htbl_cap;
	size_t                          bc_htbl_sz;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc);

void silofs_bcache_fini(struct silofs_bcache *bcache);

#endif /* SILOFS_BCACHE_H_ */
