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
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/pv.h>


int silofs_bcache_init(struct silofs_bcache *bcache,
                       struct silofs_alloc *alloc)
{
	const unsigned int cap = 8191; /* TODO: cap based on memory size */

	silofs_memzero(bcache, sizeof(*bcache));
	silofs_listq_init(&bcache->bc_lru);
	bcache->bc_htbl = silofs_lista_new(alloc, cap);
	if (bcache->bc_htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	bcache->bc_htbl_cap = cap;
	bcache->bc_htbl_sz = 0;
	bcache->bc_alloc = alloc;
	return 0;
}

void silofs_bcache_fini(struct silofs_bcache *bcache)
{
	silofs_listq_fini(&bcache->bc_lru);
	silofs_lista_del(bcache->bc_htbl,
	                 bcache->bc_htbl_cap, bcache->bc_alloc);
	bcache->bc_htbl_cap = 0;
	bcache->bc_htbl_sz = 0;
	bcache->bc_alloc = NULL;
}
