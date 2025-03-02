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
#ifndef SILOFS_PVLOGS_H_
#define SILOFS_PVLOGS_H_

#include <stdint.h>
#include <silofs/infra.h>
#include "addr.h"

/* persistent volume segments range */
struct silofs_pvsegr {
	struct silofs_volid volid;
	uint32_t            base_index;
	uint32_t            curr_index;
	loff_t              curr_pos;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvsegr_init(struct silofs_pvsegr *pvsegr);

void silofs_pvsegr_fini(struct silofs_pvsegr *pvsegr);

int silofs_pvsegr_validate(const struct silofs_pvsegr *pvsegr);

void silofs_pvsegr_assign(struct silofs_pvsegr       *pvsegr,
                          const struct silofs_pvsegr *other);

bool silofs_pvsegr_has_paddr(const struct silofs_pvsegr *pvsegr,
                             const struct silofs_paddr  *paddr);

void silofs_pvsegr_next_chkpt(struct silofs_pvsegr *pvsegr,
                              struct silofs_paddr  *out_paddr);

void silofs_pvsegr_last_chkpt(const struct silofs_pvsegr *pvsegr,
                              struct silofs_paddr        *out_paddr);

void silofs_pvsegr_next_btnode(struct silofs_pvsegr *pvsegr,
                               struct silofs_paddr  *out_paddr);

void silofs_pvsegr64b_htox(struct silofs_pvsegr64b    *pvsegr64,
                           const struct silofs_pvsegr *pvsegr);

void silofs_pvsegr64b_xtoh(const struct silofs_pvsegr64b *pvsegr64,
                           struct silofs_pvsegr          *pvsegr);

#endif /* SILOFS_PVLOGS_H_ */
