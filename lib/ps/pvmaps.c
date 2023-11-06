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
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/ps.h>


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_pvmap_init(struct silofs_pvmap *pvmap, struct silofs_alloc *alloc)
{
	const unsigned int cap = 8191; /* TODO: cap based on memory size */

	silofs_memzero(pvmap, sizeof(*pvmap));
	silofs_listq_init(&pvmap->pvm_lru);
	pvmap->pvm_htbl = silofs_lista_new(alloc, cap);
	if (pvmap->pvm_htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	pvmap->pvm_htbl_cap = cap;
	pvmap->pvm_htbl_sz = 0;
	pvmap->pvm_alloc = alloc;
	return 0;
}

void silofs_pvmap_fini(struct silofs_pvmap *pvmap)
{
	silofs_listq_fini(&pvmap->pvm_lru);
	if (pvmap->pvm_htbl != NULL) {
		silofs_lista_del(pvmap->pvm_htbl,
		                 pvmap->pvm_htbl_cap, pvmap->pvm_alloc);
		pvmap->pvm_htbl_cap = 0;
		pvmap->pvm_htbl_sz = 0;
	}
	pvmap->pvm_alloc = NULL;
}
