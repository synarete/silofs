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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pstor.h>

static void calc_aad_by_paddr(const struct silofs_mdigest_hd *md_hd,
                              const struct silofs_paddr *paddr,
                              struct silofs_caad *out_caad)
{
	struct silofs_hash256 hash;
	struct silofs_paddr64b paddr64;

	STATICASSERT_EQ(sizeof(hash.hash), sizeof(out_caad->aad));

	silofs_paddr64b_htox(&paddr64, paddr);
	silofs_sha3_256_of(md_hd, &paddr64, sizeof(paddr64), &hash);
	memcpy(out_caad->aad, hash.hash, sizeof(out_caad->aad));
}

static void
calc_aad_of(const struct silofs_core_refs *corefs,
            const struct silofs_pnptr *pnptr, struct silofs_caad *out_caad)
{
	calc_aad_by_paddr(corefs->md_hd, &pnptr->paddr, out_caad);
}

static const struct silofs_caad *
caad_by(const struct silofs_core_refs *corefs,
        const struct silofs_pnptr *pnptr, const struct silofs_ctag *ctag,
        struct silofs_caad *caad)
{
	if (ctag == nullptr) {
		caad = nullptr;
	} else {
		calc_aad_of(corefs, pnptr, caad);
	}
	return caad;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t pni_pview_len(const struct silofs_pnode_info *pni)
{
	return silofs_ni_view_size(&pni->pn_ni);
}

static const struct silofs_pview * //
pni_pview(const struct silofs_pnode_info *pni)
{
	const struct silofs_pview *pview = silofs_pni_pview(pni);

	silofs_assume_not_null(pview);
	return pview;
}

static struct silofs_pview * //
pni_mut_pview(const struct silofs_pnode_info *pni)
{
	struct silofs_pview *pview = silofs_pni_pview(pni);

	silofs_assume_not_null(pview);
	return pview;
}

static const struct silofs_pview * //
pni_pviewx(const struct silofs_pnode_info *pni)
{
	const struct silofs_pview *pviewx = silofs_pni_pviewx(pni);

	silofs_assume_not_null(pviewx);
	return pviewx;
}

static struct silofs_pview * //
pni_mut_pviewx(const struct silofs_pnode_info *pni)
{
	struct silofs_pview *pviewx = silofs_pni_pviewx(pni);

	silofs_assume_not_null(pviewx);
	return pviewx;
}

static const struct silofs_pnptr * //
pni_self(const struct silofs_pnode_info *pni)
{
	return silofs_pni_self(pni);
}

int silofs_encrypt_pnode(const struct silofs_core_refs *corefs,
                         const struct silofs_pnode_info *pni,
                         struct silofs_ctag *out_ctag)
{
	struct silofs_caad caad;
	const struct silofs_pnptr *pnptr      = pni_self(pni);
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = corefs->enc_ci_hd,
		.civ      = &pnptr->nmeta.civkey.iv,
		.ckey     = &pnptr->nmeta.civkey.key,
		.caad     = caad_by(corefs, pnptr, out_ctag, &caad),
		.ctag_in  = nullptr,
		.ctag_out = out_ctag,
		.data_in  = pni_pview(pni),
		.data_out = pni_mut_pviewx(pni),
		.data_len = pni_pview_len(pni),
	};

	return silofs_encrypt(&ed_ctx);
}

int silofs_decrypt_pnode(const struct silofs_core_refs *corefs,
                         const struct silofs_pnode_info *pni,
                         const struct silofs_ctag *ctag)
{
	struct silofs_caad caad;
	const struct silofs_pnptr *pnptr      = pni_self(pni);
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = corefs->dec_ci_hd,
		.civ      = &pnptr->nmeta.civkey.iv,
		.ckey     = &pnptr->nmeta.civkey.key,
		.caad     = caad_by(corefs, pnptr, ctag, &caad),
		.ctag_in  = ctag,
		.ctag_out = nullptr,
		.data_in  = pni_pviewx(pni),
		.data_out = pni_mut_pview(pni),
		.data_len = pni_pview_len(pni),
	};

	return silofs_decrypt(&ed_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t lni_lview_len(const struct silofs_lnode_info *lni)
{
	return silofs_ni_view_size(&lni->ln_ni);
}

static const struct silofs_lview * //
lni_lview(const struct silofs_lnode_info *lni)
{
	const struct silofs_lview *lview = silofs_lni_lview(lni);

	silofs_assume_not_null(lview);
	return lview;
}

static struct silofs_lview * //
lni_mut_lview(const struct silofs_lnode_info *lni)
{
	struct silofs_lview *lview = silofs_lni_lview(lni);

	silofs_assume_not_null(lview);
	return lview;
}

static const struct silofs_lview * //
lni_lviewx(const struct silofs_lnode_info *lni)
{
	const struct silofs_lview *lviewx = silofs_lni_lviewx(lni);

	silofs_assume_not_null(lviewx);
	return lviewx;
}

static struct silofs_lview * //
lni_mut_lviewx(const struct silofs_lnode_info *lni)
{
	struct silofs_lview *lviewx = silofs_lni_lviewx(lni);

	silofs_assume_not_null(lviewx);
	return lviewx;
}

int silofs_encrypt_lnode(const struct silofs_core_refs *corefs,
                         const struct silofs_lnode_info *lni,
                         const struct silofs_pnptr *pnptr,
                         struct silofs_ctag *out_ctag)
{
	struct silofs_caad caad;
	struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = corefs->enc_ci_hd,
		.civ      = &pnptr->nmeta.civkey.iv,
		.ckey     = &pnptr->nmeta.civkey.key,
		.caad     = caad_by(corefs, pnptr, out_ctag, &caad),
		.ctag_in  = nullptr,
		.ctag_out = out_ctag,
		.data_in  = lni_lview(lni),
		.data_out = lni_mut_lviewx(lni),
		.data_len = lni_lview_len(lni),
	};

	return silofs_encrypt(&ed_ctx);
}

int silofs_decrypt_lnode(const struct silofs_core_refs *corefs,
                         const struct silofs_lnode_info *lni,
                         const struct silofs_pnptr *pnptr,
                         const struct silofs_ctag *ctag)
{
	struct silofs_caad caad;
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = corefs->dec_ci_hd,
		.civ      = &pnptr->nmeta.civkey.iv,
		.ckey     = &pnptr->nmeta.civkey.key,
		.caad     = caad_by(corefs, pnptr, ctag, &caad),
		.ctag_in  = ctag,
		.ctag_out = nullptr,
		.data_in  = lni_lviewx(lni),
		.data_out = lni_mut_lview(lni),
		.data_len = lni_lview_len(lni),
	};

	return silofs_decrypt(&ed_ctx);
}
