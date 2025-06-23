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
#include "bootrec.h"
#include "fs.h"
#include "env.h"

static int
encrypt_view_with(const struct silofs_env *env,
                  const struct silofs_ivkey *ivkey,
                  const struct silofs_view *view, void *ptr, size_t len)
{
	return silofs_encrypt_buf(&env->enc_cipher, ivkey, view, ptr, len);
}

int silofs_encrypt_view(const struct silofs_env *env,
                        const struct silofs_llink *llink,
                        const struct silofs_view *view, void *ptr)
{
	const struct silofs_ivkey *ivkey = &llink->ivkey;
	const size_t len = silofs_laddr_len(&llink->laddr);

	return encrypt_view_with(env, ivkey, view, ptr, len);
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
	const struct silofs_ivkey *ivkey = &llink->ivkey;
	const size_t len = silofs_laddr_len(&llink->laddr);

	return decrypt_view_with(env, ivkey, view, ptr, len);
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

	silofs_llink_of_uni(env->base.bootrec, uni, &llink);
	return decrypt_view_inplace(env, &llink, uni->un_lni.ln_view);
}

int silofs_decrypt_vni_view(const struct silofs_env *env,
                            struct silofs_vnode_info *vni)
{
	struct silofs_llink llink;

	silofs_llink_of_vni(env->base.bootrec, vni, &llink);
	return decrypt_view_inplace(env, &llink, vni->vn_lni.ln_view);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_of_uni(const struct silofs_bootrec *bootrec,
                         const struct silofs_unode_info *uni,
                         struct silofs_llink *out_llink)
{
	const struct silofs_laddr *laddr = silofs_uni_laddr(uni);
	const struct silofs_ivkey *ivkey = &bootrec->main_ivkey;

	silofs_llink_setup2(out_llink, laddr, &ivkey->key, &ivkey->iv);
}

void silofs_llink_of_vni(const struct silofs_bootrec *bootrec,
                         const struct silofs_vnode_info *vni,
                         struct silofs_llink *out_llink)
{
	silofs_unused(bootrec);
	silofs_llink_assign(out_llink, &vni->vn_llink);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_calc_caddr_of(const struct silofs_mdigest *md,
                          const struct iovec *iov, size_t iov_cnt,
                          enum silofs_ctype ctype,
                          struct silofs_caddr *out_caddr)
{
	struct silofs_hash256 hash;
	uint32_t iov_len;

	silofs_sha256_ofv(md, iov, iov_cnt, &hash);
	iov_len = (uint32_t)silofs_iov_length(iov, iov_cnt);
	silofs_caddr_setup(out_caddr, &hash, iov_len, ctype);
}
