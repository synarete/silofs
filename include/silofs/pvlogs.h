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

#include <silofs/infra.h>
#include <silofs/addr.h>

/* persistent volume address-space descriptor */
struct silofs_pvasd {
	struct silofs_pvid pvid;
	uint32_t           base_index;
	uint32_t           curr_index;
	loff_t             curr_pos;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pvasd_init(struct silofs_pvasd *pvasd);

void silofs_pvasd_fini(struct silofs_pvasd *pvasd);

int silofs_pvasd_validate(const struct silofs_pvasd *pvasd);

void silofs_pvasd_assign(struct silofs_pvasd       *pvasd,
			   const struct silofs_pvasd *other);

bool silofs_pvasd_has_paddr(const struct silofs_pvasd *pvasd,
			      const struct silofs_paddr   *paddr);

void silofs_pvasd_next_chkpt(struct silofs_pvasd *pvasd,
			       struct silofs_paddr   *out_paddr);

void silofs_pvasd_last_chkpt(const struct silofs_pvasd *pvasd,
			       struct silofs_paddr         *out_paddr);

void silofs_pvasd_next_btnode(struct silofs_pvasd *pvasd,
				struct silofs_paddr   *out_paddr);

void silofs_pvasd64b_htox(struct silofs_pvasd64b    *pvasd64,
			    const struct silofs_pvasd *pvasd);

void silofs_pvasd64b_xtoh(const struct silofs_pvasd64b *pvasd64,
			    struct silofs_pvasd          *pvasd);

#endif /* SILOFS_PVLOGS_H_ */
