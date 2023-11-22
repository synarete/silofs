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


static void resolve_ivkey_of(const struct silofs_fsenv *fsenv,
                             const struct silofs_laddr *laddr,
                             const struct silofs_iv *seediv,
                             struct silofs_ivkey *out_ivkey)
{
	struct silofs_iv iv;

	silofs_laddr_as_iv(laddr, &iv);
	silofs_ivkey_assign(out_ivkey, fsenv->fse.main_ivkey);
	silofs_iv_xor_with(&out_ivkey->iv, seediv);
	silofs_iv_xor_with(&out_ivkey->iv, &iv);
}

static int encrypt_view_with(const struct silofs_fsenv *fsenv,
                             const struct silofs_ivkey *ivkey,
                             const struct silofs_view *view,
                             void *ptr, size_t len)
{
	return silofs_encrypt_buf(&fsenv->fse_crypto.ci,
	                          ivkey, view, ptr, len);
}

int silofs_encrypt_view(const struct silofs_fsenv *fsenv,
                        const struct silofs_laddr *laddr,
                        const struct silofs_iv *seediv,
                        const struct silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;

	resolve_ivkey_of(fsenv, laddr, seediv, &ivkey);
	return encrypt_view_with(fsenv, &ivkey, view, ptr, laddr->len);
}

static int decrypt_view_with(const struct silofs_fsenv *fsenv,
                             const struct silofs_ivkey *ivkey,
                             const struct silofs_view *view,
                             void *ptr, size_t len)
{
	return silofs_decrypt_buf(&fsenv->fse_crypto.ci,
	                          ivkey, view, ptr, len);
}

static int decrypt_view(const struct silofs_fsenv *fsenv,
                        const struct silofs_llink *llink,
                        const struct silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;
	int ret;

	resolve_ivkey_of(fsenv, &llink->laddr, &llink->riv, &ivkey);
	ret = decrypt_view_with(fsenv, &ivkey, view, ptr, llink->laddr.len);
	silofs_assert_ok(ret);
	return ret;
}

static int decrypt_view_inplace(const struct silofs_fsenv *fsenv,
                                const struct silofs_llink *llink,
                                struct silofs_view *view)
{
	return decrypt_view(fsenv, llink, view, view);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_decrypt_ui_view(const struct silofs_fsenv *fsenv,
                           struct silofs_unode_info *ui)
{
	struct silofs_llink llink;

	silofs_ulink_as_llink(ui_ulink(ui), &llink);
	return decrypt_view_inplace(fsenv, &llink, ui->u_lni.l_view);
}

int silofs_decrypt_vi_view(const struct silofs_fsenv *fsenv,
                           struct silofs_vnode_info *vi)
{
	return decrypt_view_inplace(fsenv, &vi->v_llink, vi->v_lni.l_view);
}
