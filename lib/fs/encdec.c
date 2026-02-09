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
	return silofs_encrypt_view(&env->enc_ci_hd, &llink->civkey, view,
	                           llink_mtype(llink), ptr);
}

static int decrypt_lview_inplace(const struct silofs_env *env,
                                 const struct silofs_llink *llink,
                                 struct silofs_view *view)
{
	return silofs_decrypt_view_inplace(&env->dec_ci_hd, &llink->civkey,
	                                   view, llink_mtype(llink));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_resolve_unode_nmeta(const struct silofs_env *env,
                                struct silofs_nmeta *out_nmeta)
{
	struct silofs_nodeptr nodeptr;
	const struct silofs_mbr_info *fs_mbi = &env->mbis.fs_mbi;

	silofs_mbi_uber_root(fs_mbi, &nodeptr);
	silofs_nmeta_assign(out_nmeta, &nodeptr.nmeta);
}

int silofs_decrypt_uni_view(const struct silofs_env *env,
                            struct silofs_unode_info *uni)
{
	struct silofs_llink llink;
	struct silofs_nmeta nmeta;

	silofs_resolve_unode_nmeta(env, &nmeta);
	silofs_llink_of_uni(uni, &nmeta, &llink);
	return decrypt_lview_inplace(env, &llink, uni->un_lni.ln_view);
}

int silofs_decrypt_vni_view(const struct silofs_env *env,
                            struct silofs_vnode_info *vni)
{
	struct silofs_llink llink;

	silofs_llink_of_vni(vni, &llink);
	return decrypt_lview_inplace(env, &llink, vni->vn_lni.ln_view);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_llink_of_uni(const struct silofs_unode_info *uni,
                         const struct silofs_nmeta *nmeta,
                         struct silofs_llink *out_llink)
{
	const struct silofs_laddr *laddr   = silofs_uni_laddr(uni);
	const struct silofs_civkey *civkey = &nmeta->civkey;

	silofs_llink_setup(out_llink, laddr, &civkey->key, &civkey->iv);
}

void silofs_llink_of_vni(const struct silofs_vnode_info *vni,
                         struct silofs_llink *out_llink)
{
	silofs_llink_assign(out_llink, &vni->vn_llink);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_calc_cas_paddr(const struct silofs_mdigest_hd *md_hd,
                           enum silofs_mtype mtype, const struct iovec *iov,
                           size_t iov_cnt, struct silofs_paddr *out_paddr)
{
	struct silofs_hash256 hash;
	struct silofs_blobid blobid;

	silofs_assert_ne(mtype, 0);

	silofs_sha3_256_ofv(md_hd, iov, iov_cnt, &hash);
	silofs_blobid_setup_cas(&blobid, silofs_layerid_none(), &hash, mtype);
	silofs_paddr_init(out_paddr, &blobid, 0);
}
