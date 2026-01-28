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
#include "infra.h"
#include "obs.h"
#include "fs.h"
#include "exectx.h"
#include "env.h"
#include "walk.h"
#include "index.h"
#include "arre.h"

struct silofs_re_ctx {
	struct silofs_exec_ctx *ectx;
	struct silofs_env *env;
	struct silofs_arnode_info *ari;
	struct silofs_alloc *alloc;
	struct silofs_repo *repo;
	struct silofs_dstor *dstor;
	struct silofs_laddr sb_laddr;
};

static void
rec_rebind_ari(struct silofs_re_ctx *re_ctx, struct silofs_arnode_info *ari)
{
	if (re_ctx->ari != nullptr) {
		silofs_ari_del(re_ctx->ari, re_ctx->alloc);
		re_ctx->ari = nullptr;
	}
	if (ari != nullptr) {
		re_ctx->ari = ari;
	}
}

static int rec_renew_ari(struct silofs_re_ctx *re_ctx,
                         const struct silofs_pnodeptr *pnodeptr)
{
	struct silofs_arnode_info *ari = nullptr;

	ari = silofs_ari_new(re_ctx->alloc, pnodeptr);
	if (ari == nullptr) {
		return -SILOFS_ENOMEM;
	}
	rec_rebind_ari(re_ctx, ari);
	return 0;
}

static int rec_init(struct silofs_re_ctx *re_ctx, struct silofs_exec_ctx *ectx)
{
	silofs_memzero(re_ctx, sizeof(*re_ctx));
	silofs_laddr_reset(&re_ctx->sb_laddr);
	re_ctx->ectx  = ectx;
	re_ctx->env   = ectx->ex_env;
	re_ctx->ari   = nullptr;
	re_ctx->alloc = re_ctx->env->base.alloc;
	re_ctx->repo  = re_ctx->env->base.repo;
	re_ctx->dstor = &re_ctx->env->base.repo->re_dstor;
	return 0;
}

static void rec_fini(struct silofs_re_ctx *re_ctx)
{
	rec_rebind_ari(re_ctx, nullptr);
	re_ctx->ectx  = nullptr;
	re_ctx->env   = nullptr;
	re_ctx->alloc = nullptr;
	re_ctx->repo  = nullptr;
}

static int
rec_recv_from_repo(const struct silofs_re_ctx *re_ctx,
                   const struct silofs_paddr *paddr, void *dat, size_t len)
{
	return silofs_dstor_read_blob_at(re_ctx->dstor, &paddr->blobid,
	                                 paddr->pos, dat, len);
}

static int
rec_recv_pack(const struct silofs_re_ctx *re_ctx,
              const struct silofs_paddr *paddr, void *dat, size_t len)
{
	return rec_recv_from_repo(re_ctx, paddr, dat, len);
}

static int
rec_save_seg(const struct silofs_re_ctx *re_ctx,
             const struct silofs_laddr *laddr, void *seg, size_t len)
{
	const enum silofs_mtype mtype = silofs_laddr_mtype(laddr);
	int err;

	err = silofs_repo_require_lseg(re_ctx->repo, &laddr->lsid);
	if (err) {
		log_err("failed to require lseg: mtype=%d", (int)mtype);
		return err;
	}
	err = silofs_repo_require_laddr(re_ctx->repo, laddr);
	if (err) {
		log_err("failed to require laddr: mtype=%d err=%d", (int)mtype,
		        err);
		return err;
	}
	err = silofs_repo_write_at(re_ctx->repo, laddr, seg, len);
	if (err) {
		log_err("failed to write: mtype=%d err=%d", (int)mtype, err);
		return err;
	}
	return 0;
}

static int rec_restore_segdata(const struct silofs_re_ctx *re_ctx,
                               const struct silofs_ar_desc *ard)
{
	const size_t len = ard->len;
	void *seg        = nullptr;
	int err;

	seg = silofs_memalloc(re_ctx->alloc, len, 0);
	if (seg == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = rec_recv_pack(re_ctx, &ard->paddr, seg, len);
	if (err) {
		goto out;
	}
	/* TODO: recheck paddr by content */
	err = rec_save_seg(re_ctx, &ard->laddr, seg, len);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(re_ctx->alloc, seg, len, 0);
	return err;
}

static int rec_arix_nmeta(const struct silofs_re_ctx *re_ctx,
                          struct silofs_nmeta *out_nmeta)
{
	const struct silofs_mbr_info *ar_mbi = &re_ctx->env->mbis.ar_mbi;

	/* For now, using top-level nmeta for all arix nodes */
	silofs_nmeta_assign(out_nmeta, &ar_mbi->mb_meta.nmeta);
	return 0;
}

static const struct silofs_mdigest_hd *
rec_mdigest(const struct silofs_re_ctx *re_ctx)
{
	return &re_ctx->env->md_hd;
}

static int rec_arix_cargs(const struct silofs_re_ctx *re_ctx,
                          struct silofs_ar_cargs *out_ar_cargs)
{
	out_ar_cargs->ci_hd = &re_ctx->env->enc_ci_hd;
	out_ar_cargs->md_hd = rec_mdigest(re_ctx);
	return rec_arix_nmeta(re_ctx, &out_ar_cargs->nmeta);
}

static struct silofs_arix_node *rec_new_arix_node(struct silofs_re_ctx *re_ctx)
{
	struct silofs_arix_node *arn = nullptr;

	arn = silofs_memalloc(re_ctx->alloc, sizeof(*arn),
	                      SILOFS_ALLOCF_BZERO);
	return arn;
}

static void
rec_del_arix_node(struct silofs_re_ctx *re_ctx, struct silofs_arix_node *arn)
{
	silofs_memfree(re_ctx->alloc, arn, sizeof(*arn), 0);
}

static int rec_fetch_arix_node(struct silofs_re_ctx *re_ctx)
{
	struct silofs_ar_cargs ar_cargs;
	struct silofs_paddr paddr;
	struct silofs_arix_node *arn_enc;
	int err = -SILOFS_ENOMEM;

	arn_enc = rec_new_arix_node(re_ctx);
	if (arn_enc == nullptr) {
		goto out;
	}
	err = rec_arix_cargs(re_ctx, &ar_cargs);
	if (err) {
		return err;
	}
	silofs_ari_get_paddr(re_ctx->ari, &paddr);
	err = silofs_load_arix_node(re_ctx->dstor, &paddr, arn_enc);
	if (err) {
		goto out;
	}
	err = silofs_verify_arix_paddr(arn_enc, rec_mdigest(re_ctx), &paddr);
	if (err) {
		goto out;
	}
	err = silofs_import_arix_node(re_ctx->ari, &ar_cargs, arn_enc);
	if (err) {
		goto out;
	}
out:
	rec_del_arix_node(re_ctx, arn_enc);
	return err;
}

static int rec_resolve_root(struct silofs_re_ctx *re_ctx,
                            struct silofs_pnodeptr *out_pnodeptr)
{
	const struct silofs_mbr_info *ar_mbi = &re_ctx->env->mbis.ar_mbi;

	return silofs_mbi_arix_root(ar_mbi, out_pnodeptr);
}

static int rec_restore_arix(struct silofs_re_ctx *re_ctx,
                            const struct silofs_pnodeptr *pnodeptr)
{
	int err;

	err = rec_renew_ari(re_ctx, pnodeptr);
	if (err) {
		return err;
	}
	err = rec_fetch_arix_node(re_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_apex(struct silofs_re_ctx *re_ctx)
{
	struct silofs_pnodeptr pnodeptr;
	int err;

	err = rec_resolve_root(re_ctx, &pnodeptr);
	if (err) {
		return err;
	}
	err = rec_restore_arix(re_ctx, &pnodeptr);
	if (err) {
		return err;
	}
	return 0;
}

static bool is_super(const struct silofs_ar_desc *ard)
{
	enum silofs_mtype mtype;

	mtype = silofs_blobid_get_mtype(&ard->laddr.lsid.blobid);
	return (mtype == SILOFS_MTYPE_SUPER);
}

static int rec_update_by_desc(struct silofs_re_ctx *re_ctx,
                              const struct silofs_ar_desc *ard)
{
	struct silofs_laddr *laddr = &re_ctx->sb_laddr;

	if (!is_super(ard)) {
		return 0;
	}
	if (!silofs_laddr_isnull(laddr)) {
		/* err -- more then single sb */
		return -SILOFS_EBADARIX;
	}
	silofs_laddr_assign(laddr, &ard->laddr);
	return 0;
}

static int rec_restore_descs(struct silofs_re_ctx *re_ctx)
{
	struct silofs_ar_desc ard;
	const struct silofs_arnode_info *ari = re_ctx->ari;
	const size_t ndescs                  = silofs_ari_ndescs(ari);
	int err;

	for (size_t slot = 0; slot < ndescs; ++slot) {
		ard.len = 0;
		err     = silofs_ari_fetch_desc(ari, slot, &ard);
		if (err) {
			return err;
		}
		err = rec_restore_segdata(re_ctx, &ard);
		if (err) {
			return err;
		}
		err = rec_update_by_desc(re_ctx, &ard);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int rec_restore_next(struct silofs_re_ctx *re_ctx)
{
	struct silofs_pnodeptr pnodeptr;
	int err;

	silofs_ari_get_next(re_ctx->ari, &pnodeptr);
	if (silofs_pnodeptr_isnull(&pnodeptr)) {
		rec_rebind_ari(re_ctx, nullptr);
		return 0; /* end-of-chain */
	}
	err = rec_restore_arix(re_ctx, &pnodeptr);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_fs(struct silofs_re_ctx *re_ctx)
{
	int err;

	while (re_ctx->ari != nullptr) {
		err = rec_restore_descs(re_ctx);
		if (err) {
			return err;
		}
		err = rec_restore_next(re_ctx);
		if (err) {
			return err;
		}
	}
	return 0;
}

/* XXX: Crap, move it elsewhere */
static void
sb_uaddr_of(const struct silofs_laddr *laddr, struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(laddr->pos, 0);
	silofs_uaddr_setup(out_uaddr, &laddr->lsid, 0, 0);
}

static int rec_restore_sb_addr(struct silofs_re_ctx *re_ctx)
{
	const struct silofs_laddr *sb_laddr = &re_ctx->sb_laddr;
	struct silofs_uaddr sb_uaddr        = { .voff = -1 };

	if (silofs_laddr_isnull(sb_laddr)) {
		return -SILOFS_EBADARIX;
	}
	sb_uaddr_of(sb_laddr, &sb_uaddr);
	silofs_mbi_set_sbaddr(&re_ctx->env->mbis.fs_mbi, &sb_uaddr);
	return 0;
}

static int rec_restore_sb(struct silofs_re_ctx *re_ctx)
{
	int err;

	err = rec_restore_sb_addr(re_ctx);
	if (err) {
		return err;
	}
	err = silofs_env_reload_super(re_ctx->env);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_fs_mbr(const struct silofs_re_ctx *re_ctx,
                              struct silofs_mbref *out_fs_mbref)
{
	return silofs_env_commit_fs_mbr(re_ctx->env, out_fs_mbref);
}

static int rec_restore_post(struct silofs_re_ctx *re_ctx,
                            struct silofs_mbref *out_fs_mbref)
{
	int err;

	err = rec_restore_sb(re_ctx);
	if (err) {
		return err;
	}
	err = rec_restore_fs_mbr(re_ctx, out_fs_mbref);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_prep(struct silofs_re_ctx *re_ctx,
                            const struct silofs_mbref *ar_mbref)
{
	return silofs_env_reload_ar_mbr(re_ctx->env, ar_mbref);
}

static int rec_do_restore(struct silofs_re_ctx *re_ctx,
                          const struct silofs_mbref *ar_mbref,
                          struct silofs_mbref *out_fs_mbref)
{
	int err;

	err = rec_restore_prep(re_ctx, ar_mbref);
	if (err) {
		return err;
	}
	err = rec_restore_apex(re_ctx);
	if (err) {
		return err;
	}
	err = rec_restore_fs(re_ctx);
	if (err) {
		return err;
	}
	err = rec_restore_post(re_ctx, out_fs_mbref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_restore_fs(struct silofs_exec_ctx *ectx,
                         const struct silofs_mbref *ar_mbref,
                         struct silofs_mbref *out_fs_mbref)
{
	struct silofs_re_ctx re_ctx;
	int err;

	err = silofs_flush_dirty_now(ectx);
	if (err) {
		return err;
	}
	err = rec_init(&re_ctx, ectx);
	if (err) {
		goto out;
	}
	err = rec_do_restore(&re_ctx, ar_mbref, out_fs_mbref);
	if (err) {
		goto out;
	}
out:
	rec_fini(&re_ctx);
	return err;
}
