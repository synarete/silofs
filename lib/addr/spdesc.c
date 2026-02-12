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
	.btns_head.pos = SILOFS_OFF_NULL,
	.btns_tail.pos = SILOFS_OFF_NULL,
	.vns_head.pos  = SILOFS_OFF_NULL,
	.vns_tail.pos  = SILOFS_OFF_NULL,
};

const struct silofs_spdesc *silofs_spdesc_none(void)
{
	return &s_spdesc_none;
}

void silofs_spdesc_htox(struct silofs_spdesc256b *spdesc256,
                        const struct silofs_spdesc *spdesc)
{
	silofs_paddr64b_htox(&spdesc256->spd_btns_head, &spdesc->btns_head);
	silofs_paddr64b_htox(&spdesc256->spd_btns_tail, &spdesc->btns_tail);
	silofs_paddr64b_htox(&spdesc256->spd_vns_head, &spdesc->vns_head);
	silofs_paddr64b_htox(&spdesc256->spd_vns_tail, &spdesc->vns_tail);
}

void silofs_spdesc_xtoh(const struct silofs_spdesc256b *spdesc256,
                        struct silofs_spdesc *spdesc)
{
	silofs_paddr64b_xtoh(&spdesc256->spd_btns_head, &spdesc->btns_head);
	silofs_paddr64b_xtoh(&spdesc256->spd_btns_tail, &spdesc->btns_tail);
	silofs_paddr64b_xtoh(&spdesc256->spd_vns_head, &spdesc->vns_head);
	silofs_paddr64b_xtoh(&spdesc256->spd_vns_tail, &spdesc->vns_tail);
}
