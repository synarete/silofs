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
#include "configs.h"
#include "infra.h"
#include "bootrec.h"
#include "lnodes.h"
#include "encdec.h"
#include "env.h"

static void resolve_ivkey_of(const struct silofs_env *env,
                             const struct silofs_laddr *laddr,
                             const struct silofs_iv *seediv,
                             struct silofs_ivkey *out_ivkey)
{
	struct silofs_iv laddriv;
	const struct silofs_ivkey *ivkey = &env->bootrec.main_ivkey;

	silofs_laddr_as_iv(laddr, &laddriv);
	silofs_ivkey_assign(out_ivkey, ivkey);
	silofs_iv_xor_with2(&out_ivkey->iv, &laddriv, seediv);
}

static int
encrypt_view_with(const struct silofs_env *env,
                  const struct silofs_ivkey *ivkey,
                  const struct silofs_view *view, void *ptr, size_t len)
{
	return silofs_encrypt_buf(&env->enc_cipher, ivkey, view, ptr, len);
}

int silofs_encrypt_view(const struct silofs_env *env,
                        const struct silofs_laddr *laddr,
                        const struct silofs_iv *seediv,
                        const struct silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;

	resolve_ivkey_of(env, laddr, seediv, &ivkey);
	return encrypt_view_with(env, &ivkey, view, ptr, laddr->len);
}

static int
decrypt_view_with(const struct silofs_env *env,
                  const struct silofs_ivkey *ivkey,
                  const struct silofs_view *view, void *ptr, size_t len)
{
	return silofs_decrypt_buf(&env->dec_cipher, ivkey, view, ptr, len);
}

static int
decrypt_view(const struct silofs_env *env, const struct silofs_llink *llink,
             const struct silofs_view *view, void *ptr)
{
	struct silofs_ivkey ivkey;
	int ret;

	resolve_ivkey_of(env, &llink->laddr, &llink->iv, &ivkey);
	ret = decrypt_view_with(env, &ivkey, view, ptr, llink->laddr.len);
	silofs_assert_ok(ret);
	return ret;
}

static int decrypt_view_inplace(const struct silofs_env *env,
                                const struct silofs_llink *llink,
                                struct silofs_view *view)
{
	return decrypt_view(env, llink, view, view);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_decrypt_uni_view(const struct silofs_env *env,
                            struct silofs_unode_info *uni)
{
	struct silofs_llink llink;

	silofs_ulink_as_llink(uni_ulink(uni), &llink);
	return decrypt_view_inplace(env, &llink, uni->un_lni.ln_view);
}

int silofs_decrypt_vni_view(const struct silofs_env *env,
                            struct silofs_vnode_info *vni)
{
	const struct silofs_llink *llink = &vni->vn_llink;

	return decrypt_view_inplace(env, llink, vni->vn_lni.ln_view);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t iov_length(const struct iovec *iov, size_t iov_cnt)
{
	return (uint32_t)silofs_iov_length(iov, iov_cnt);
}

void silofs_calc_caddr_of(const struct silofs_env *env,
                          const struct iovec *iov, size_t iov_cnt,
                          enum silofs_ctype ctype,
                          struct silofs_caddr *out_caddr)
{
	struct silofs_hash256 hash;

	silofs_sha256_ofv(&env->mdigest, iov, iov_cnt, &hash);
	silofs_caddr_setup(out_caddr, &hash, iov_length(iov, iov_cnt), ctype);
}
