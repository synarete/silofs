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
#include "addr.h"
#include "nodes.h"
#include "env.h"

static enum silofs_mtype llink_mtype(const struct silofs_llink *llink)
{
	return silofs_laddr_mtype(&llink->laddr);
}

int silofs_encrypt_lview(const struct silofs_env *env,
                         const struct silofs_llink *llink,
                         const struct silofs_view *view, void *ptr)
{
	return silofs_encrypt_view(&env->enc_cipher, &llink->ivkey, view,
	                           llink_mtype(llink), ptr);
}

static int decrypt_lview_inplace(const struct silofs_env *env,
                                 const struct silofs_llink *llink,
                                 struct silofs_view *view)
{
	return silofs_decrypt_view_inplace(&env->dec_cipher, &llink->ivkey,
	                                   view, llink_mtype(llink));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_decrypt_uni_view(const struct silofs_env *env,
                            struct silofs_unode_info *uni)
{
	struct silofs_llink llink;

	silofs_llink_of_uni(&env->mbri.fs_mbr, uni, &llink);
	return decrypt_lview_inplace(env, &llink, uni->un_lni.ln_view);
}

int silofs_decrypt_vni_view(const struct silofs_env *env,
                            struct silofs_vnode_info *vni)
{
	struct silofs_llink llink;

	silofs_llink_of_vni(&env->mbri.fs_mbr, vni, &llink);
	return decrypt_lview_inplace(env, &llink, vni->vn_lni.ln_view);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_of_uni(const struct silofs_mbr *mbr,
                         const struct silofs_unode_info *uni,
                         struct silofs_llink *out_llink)
{
	const struct silofs_laddr *laddr = silofs_uni_laddr(uni);
	const struct silofs_ivkey *ivkey = &mbr->main_ivkey;

	silofs_llink_setup(out_llink, laddr, &ivkey->key, &ivkey->iv);
}

void silofs_llink_of_vni(const struct silofs_mbr *mbr,
                         const struct silofs_vnode_info *vni,
                         struct silofs_llink *out_llink)
{
	silofs_unused(mbr);
	silofs_llink_assign(out_llink, &vni->vn_llink);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_calc_cas_baddr(const struct silofs_mdigest *md,
                           enum silofs_mtype mtype, const struct iovec *iov,
                           size_t iov_cnt, struct silofs_baddr *out_baddr)
{
	struct silofs_hash256 hash;
	struct silofs_blobid blobid;

	silofs_assert_ne(mtype, 0);

	silofs_sha3_256_ofv(md, iov, iov_cnt, &hash);
	silofs_blobid_setup_cas(&blobid, silofs_svolid_none(), &hash, mtype);
	silofs_baddr_init(out_baddr, &blobid, 0);
}
