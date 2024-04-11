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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/vol.h>
#include <silofs/fs.h>
#include <silofs/pack.h>

void silofs_pkdesc_init(struct silofs_pack_desc *pd,
                        const struct silofs_laddr *laddr)
{
	silofs_memzero(pd, sizeof(*pd));
	silofs_laddr_assign(&pd->pd_laddr, laddr);
}

void silofs_pkdesc_fini(struct silofs_pack_desc *pd)
{
	silofs_laddr_reset(&pd->pd_laddr);
}

void silofs_pkdesc_to_name(const struct silofs_pack_desc *pd,
                           struct silofs_strbuf *out_name)
{
	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(pd->pd_hash.hash, sizeof(pd->pd_hash.hash),
	                    out_name->str, sizeof(out_name->str) - 1);
}

static void calc_hash_of(const struct silofs_mdigest *md,
                         const void *buf, size_t bsz,
                         struct silofs_hash256 *out_hash)
{
	silofs_sha256_of(md, buf, bsz, out_hash);
}

void silofs_pkdesc_update_hash(struct silofs_pack_desc *pd,
                               const struct silofs_mdigest *md,
                               const void *buf, size_t bsz)
{
	calc_hash_of(md, buf, bsz, &pd->pd_hash);
}


static void silofs_pack_desc128b_reset(struct silofs_pack_desc128b *pdx)
{
	memset(pdx, 0, sizeof(*pdx));
}

void silofs_pkdesc128b_htox(struct silofs_pack_desc128b *pdx,
                            const struct silofs_pack_desc *pd)
{
	silofs_pack_desc128b_reset(pdx);
	silofs_hash256_assign(&pdx->pd_hash, &pd->pd_hash);
	silofs_laddr48b_htox(&pdx->pd_laddr, &pd->pd_laddr);
}

void silofs_pkdesc128b_xtoh(const struct silofs_pack_desc128b *pdx,
                            struct silofs_pack_desc *pd)
{
	silofs_hash256_assign(&pd->pd_hash, &pdx->pd_hash);
	silofs_laddr48b_xtoh(&pdx->pd_laddr, &pd->pd_laddr);
}
