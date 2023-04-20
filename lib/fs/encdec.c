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
	return lni_has_bkview(&ui->u);
}

static void ui_set_bkview(struct silofs_unode_info *ui)
{
	lni_set_bkview(&ui->u);
}

static int decrypt_ui_view_inplace(const struct silofs_uber *uber,
                                   struct silofs_unode_info *ui)
{
	union silofs_view *view = ui->u.view;

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
	lni_set_bkview(&ui->u);
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

	return silofs_decrypt_view(uber, &vi->v_oaddr, view, view);
}

int silofs_restore_vi_view(const struct silofs_uber *uber,
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


