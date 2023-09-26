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


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool lni_has_bkview(const struct silofs_lnode_info *lni)
{
	return silofs_lbki_has_view_at(lni->lbki, lni->view_pos,
	                               lni->view_len);
}

static void lni_set_bkview(const struct silofs_lnode_info *lni)
{
	struct silofs_lbk_info *bki = lni->lbki;

	silofs_assert_not_null(bki);
	silofs_lbki_set_view_at(bki, lni->view_pos, lni->view_len);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void resolve_ivkey_of(const struct silofs_uber *uber,
                             const struct silofs_paddr *paddr,
                             const struct silofs_iv *seediv,
                             struct silofs_ivkey *out_ivkey)
{
	struct silofs_iv oadiv;

	silofs_paddr_as_iv(paddr, &oadiv);
	silofs_ivkey_assign(out_ivkey, uber->ub.ivkey);
	silofs_iv_xor_with(&out_ivkey->iv, seediv);
	silofs_iv_xor_with(&out_ivkey->iv, &oadiv);
}

static int encrypt_view_with(const struct silofs_uber *uber,
                             const struct silofs_ivkey *ivkey,
                             const union silofs_view *view,
                             void *ptr, size_t len)
{
	return silofs_encrypt_buf(&uber->ub_crypto.ci, ivkey, view, ptr, len);
}

int silofs_encrypt_view(const struct silofs_uber *uber,
                        const struct silofs_paddr *paddr,
                        const struct silofs_iv *seediv,
                        const union silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;

	resolve_ivkey_of(uber, paddr, seediv, &ivkey);
	return encrypt_view_with(uber, &ivkey, view, ptr, paddr->len);
}

static int decrypt_view_with(const struct silofs_uber *uber,
                             const struct silofs_ivkey *ivkey,
                             const union silofs_view *view,
                             void *ptr, size_t len)
{
	return silofs_decrypt_buf(&uber->ub_crypto.ci, ivkey, view, ptr, len);
}

static int decrypt_view(const struct silofs_uber *uber,
                        const struct silofs_plink *plink,
                        const union silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;

	resolve_ivkey_of(uber, &plink->paddr, &plink->riv, &ivkey);
	return decrypt_view_with(uber, &ivkey, view, ptr, plink->paddr.len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ui_set_bkview(struct silofs_unode_info *ui)
{
	lni_set_bkview(&ui->u);
}

static bool ui_has_bkview(const struct silofs_unode_info *ui)
{
	return lni_has_bkview(&ui->u);
}

static void ui_set_bkview(struct silofs_unode_info *ui)
{
	lni_set_bkview(&ui->u);
}

static int decrypt_ui_view_inplace(const struct silofs_uber *uber,
                                   struct silofs_unode_info *ui)
{
	struct silofs_plink plink;
	union silofs_view *view = ui->u.view;

	silofs_ulink_as_plink(ui_ulink(ui), &plink);
	return decrypt_view(uber, &plink, view, view);
}

int silofs_restore_uview(const struct silofs_uber *uber,
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_has_bkview(const struct silofs_vnode_info *vi)
{
	return lni_has_bkview(&vi->v);
}

static void vi_set_bkview(struct silofs_vnode_info *vi)
{
	lni_set_bkview(&vi->v);
}

static int decrypt_vi_view_inplace(const struct silofs_uber *uber,
                                   struct silofs_vnode_info *vi)
{
	union silofs_view *view = vi->v.view;

	return decrypt_view(uber, &vi->v_plink, view, view);
}

int silofs_restore_vview(const struct silofs_uber *uber,
                         struct silofs_vnode_info *vi, bool raw)
{
	int err;

	if (vi_has_bkview(vi)) {
		return 0;
	}
	if (!raw) {
		err = decrypt_vi_view_inplace(uber, vi);
		if (err) {
			return err;
		}
	}
	vi_set_bkview(vi);
	return 0;
}
