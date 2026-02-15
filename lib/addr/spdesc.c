/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/configs.h>
#include "htox.h"
#include "spdesc.h"

static const struct silofs_spdesc s_spdesc_none = {
	.beg.pos = SILOFS_OFF_NULL,
	.end.pos = SILOFS_OFF_NULL,
};

const struct silofs_spdesc *silofs_spdesc_none(void)
{
	return &s_spdesc_none;
}

void silofs_spdesc_setup(struct silofs_spdesc *spdesc,
                         const struct silofs_paddr *beg,
                         const struct silofs_paddr *end)
{
	silofs_paddr_assign(&spdesc->beg, beg);
	silofs_paddr_assign(&spdesc->end, end);
}

void silofs_spdesc_setup1(struct silofs_spdesc *spdesc,
                          const struct silofs_paddr *beg)
{
	struct silofs_paddr nxt;

	silofs_paddr_next(beg, &nxt);
	silofs_spdesc_setup(spdesc, beg, &nxt);
}

void silofs_spdesc_htox(struct silofs_spdesc128b *spdesc128,
                        const struct silofs_spdesc *spdesc)
{
	silofs_paddr64b_htox(&spdesc128->spd_beg, &spdesc->beg);
	silofs_paddr64b_htox(&spdesc128->spd_end, &spdesc->end);
}

void silofs_spdesc_xtoh(const struct silofs_spdesc128b *spdesc128,
                        struct silofs_spdesc *spdesc)
{
	silofs_paddr64b_xtoh(&spdesc128->spd_beg, &spdesc->beg);
	silofs_paddr64b_xtoh(&spdesc128->spd_end, &spdesc->end);
}
