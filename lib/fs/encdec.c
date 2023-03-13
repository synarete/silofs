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
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <limits.h>


static uint64_t bk_view_mask_of(loff_t off, size_t len)
{
	const ssize_t kb_size = SILOFS_KB_SIZE;
	const loff_t  pos = silofs_off_in_bk(off);
	const ssize_t idx = pos / kb_size;
	const ssize_t nkb = (ssize_t)len / kb_size;
	const uint64_t zeros = 0;
	uint64_t mask;

	STATICASSERT_EQ(8 * sizeof(mask), SILOFS_NKB_IN_BK);
	silofs_assert_ge(len, SILOFS_KB_SIZE);
	silofs_assert_le(len, SILOFS_BK_SIZE);

	if (nkb == SILOFS_NKB_IN_BK) {
		silofs_assert_eq(idx, 0);
		mask = ~zeros;
	} else {
		mask = ((1UL << nkb) - 1) << idx;
	}
	return mask;
}

static bool bki_has_view_at(const struct silofs_bk_info *bki,
                            loff_t view_pos, size_t view_len)
{
	const uint64_t view_mask = bk_view_mask_of(view_pos, view_len);

	return ((bki->bk_view & view_mask) == view_mask);
}

static void bki_set_view_at(struct silofs_bk_info *bki,
                            loff_t view_pos, size_t view_len)
{
	const uint64_t view_mask = bk_view_mask_of(view_pos, view_len);

	bki->bk_view |= view_mask;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool si_has_bkview(const struct silofs_snode_info *si)
{
	const struct silofs_bk_info *bki = si->s_bki;

	silofs_assert_not_null(bki);
	return bki_has_view_at(bki, si->s_view_pos, si->s_view_len);
}

static void si_set_bkview(const struct silofs_snode_info *si)
{
	struct silofs_bk_info *bki = si->s_bki;

	silofs_assert_not_null(bki);
	bki_set_view_at(bki, si->s_view_pos, si->s_view_len);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void update_iv_of(struct silofs_ivkey *ivkey,
                         const struct silofs_oaddr *oaddr)
{
	struct silofs_iv iv;

	memset(&iv, 0, sizeof(iv));
	silofs_iv_of_oaddr(&iv, oaddr);
	silofs_iv_xor_with(&ivkey->iv, &iv);
}

static void resolve_ivkey_of(const struct silofs_uber *uber,
                             const struct silofs_oaddr *oaddr,
                             struct silofs_ivkey *ivkey)
{
	silofs_ivkey_copyto(uber->ub.ivkey, ivkey);
	update_iv_of(ivkey, oaddr);
}

int silofs_encrypt_view(const struct silofs_uber *uber,
                        const struct silofs_oaddr *oaddr,
                        const union silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;

	resolve_ivkey_of(uber, oaddr, &ivkey);
	return silofs_encrypt_buf(&uber->ub_crypto.ci, &ivkey,
	                          view, ptr, oaddr->len);
}

static int
silofs_decrypt_view(const struct silofs_uber *uber,
                    const struct silofs_oaddr *oaddr,
                    const union silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;

	resolve_ivkey_of(uber, oaddr, &ivkey);
	return silofs_decrypt_buf(&uber->ub_crypto.ci, &ivkey,
	                          view, ptr, oaddr->len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ui_has_bkview(const struct silofs_unode_info *ui)
{
	return si_has_bkview(&ui->u_si);
}

static void ui_set_bkview(struct silofs_unode_info *ui)
{
	si_set_bkview(&ui->u_si);
}

static int decrypt_ui_view_inplace(const struct silofs_uber *uber,
                                   struct silofs_unode_info *ui)
{
	union silofs_view *view = ui->u_si.s_view;

	return silofs_decrypt_view(uber, ui_oaddr(ui), view, view);
}

int silofs_restore_ui_view(const struct silofs_uber *uber,
                           struct silofs_unode_info *ui)
{
	int err;

	if (ui_has_bkview(ui)) {
		return 0;
	}
	err = decrypt_ui_view_inplace(uber, ui);
	if (err) {
		return err;
	}
	ui_set_bkview(ui);
	return 0;
}

void silofs_ui_set_bkview(struct silofs_unode_info *ui)
{
	si_set_bkview(&ui->u_si);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_has_bkview(const struct silofs_vnode_info *vi)
{
	return si_has_bkview(&vi->v_si);
}

static void vi_set_bkview(struct silofs_vnode_info *vi)
{
	si_set_bkview(&vi->v_si);
}

static int decrypt_vi_view_inplace(const struct silofs_uber *uber,
                                   struct silofs_vnode_info *vi)
{
	union silofs_view *view = vi->v_si.s_view;

	return silofs_decrypt_view(uber, &vi->v_oaddr, view, view);
}

int silofs_restore_vi_view(const struct silofs_uber *uber,
                           struct silofs_vnode_info *vi, bool has_enc_view)
{
	int err;

	if (vi_has_bkview(vi)) {
		return 0;
	}
	if (has_enc_view) {
		err = decrypt_vi_view_inplace(uber, vi);
		if (err) {
			return err;
		}
	}
	vi_set_bkview(vi);
	return 0;
}


