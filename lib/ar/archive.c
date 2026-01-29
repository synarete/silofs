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

struct silofs_ar_ctx {
	struct timespec now;
	struct silofs_exec_ctx *exct;
	struct silofs_env *env;
	struct silofs_alloc *alloc;
	struct silofs_arnode_info *ari;
	struct silofs_repo *repo;
	struct silofs_dstor *dstor;
};

static int arc_arix_nmeta(const struct silofs_ar_ctx *ar_ctx,
                          struct silofs_nmeta *out_nmeta)
{
	const struct silofs_mbr_info *ar_mbi = &ar_ctx->env->mbis.ar_mbi;

	/* For now, using top-level nmeta for all arix nodes */
	silofs_nmeta_assign(out_nmeta, &ar_mbi->mb_meta.nmeta);
	return 0;
}

static int arc_default_arix_pnodeptr(const struct silofs_ar_ctx *ar_ctx,
                                     struct silofs_pnodeptr *out_pnodeptr)
{
	int err;

	err = arc_arix_nmeta(ar_ctx, &out_pnodeptr->nmeta);
	if (err) {
		return err;
	}
	silofs_paddr_reset(&out_pnodeptr->paddr);
	return 0;
}

static const struct silofs_mdigest_hd *
arc_mdigest(const struct silofs_ar_ctx *ar_ctx)
{
	return &ar_ctx->env->md_hd;
}

static int arc_arix_cargs(const struct silofs_ar_ctx *ar_ctx,
                          struct silofs_ar_cargs *out_ar_cargs)
{
	out_ar_cargs->ci_hd = &ar_ctx->env->enc_ci_hd;
	out_ar_cargs->md_hd = arc_mdigest(ar_ctx);
	return arc_arix_nmeta(ar_ctx, &out_ar_cargs->nmeta);
}

static void
arc_rebind_ari(struct silofs_ar_ctx *ar_ctx, struct silofs_arnode_info *abi)
{
	if (ar_ctx->ari != nullptr) {
		silofs_ari_del(ar_ctx->ari, ar_ctx->alloc);
		ar_ctx->ari = nullptr;
	}
	if (abi != nullptr) {
		ar_ctx->ari = abi;
	}
}

static int arc_renew_ari(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_pnodeptr pnodeptr;
	struct silofs_arnode_info *ari = nullptr;

	arc_default_arix_pnodeptr(ar_ctx, &pnodeptr);
	ari = silofs_ari_new(ar_ctx->alloc, &pnodeptr);
	if (ari == nullptr) {
		return -SILOFS_ENOMEM;
	}
	silofs_ari_set_btime(ari, &ar_ctx->now);
	if (ar_ctx->ari != nullptr) {
		silofs_ari_set_next(ari, &ar_ctx->ari->arn_pnodeptr);
	}

	arc_rebind_ari(ar_ctx, ari);
	return 0;
}

static int arc_init(struct silofs_ar_ctx *ar_ctx, struct silofs_exec_ctx *exct)
{
	silofs_memzero(ar_ctx, sizeof(*ar_ctx));
	silofs_clock_real_now(&ar_ctx->now);
	ar_ctx->exct  = exct;
	ar_ctx->env   = exct->env;
	ar_ctx->ari   = nullptr;
	ar_ctx->alloc = ar_ctx->env->alloc;
	ar_ctx->repo  = ar_ctx->env->base.repo;
	ar_ctx->dstor = &ar_ctx->env->base.repo->re_dstor;

	return arc_renew_ari(ar_ctx);
}

static void arc_fini(struct silofs_ar_ctx *ar_ctx)
{
	arc_rebind_ari(ar_ctx, nullptr);
	ar_ctx->exct  = nullptr;
	ar_ctx->env   = nullptr;
	ar_ctx->repo  = nullptr;
	ar_ctx->dstor = nullptr;
	ar_ctx->alloc = nullptr;
}

static int arc_stat_pack(const struct silofs_ar_ctx *ar_ctx,
                         const struct silofs_paddr *paddr, size_t *out_sz)
{
	struct stat st;
	int err;

	err = silofs_dstor_stat_blob(ar_ctx->dstor, &paddr->blobid, &st);
	if (err) {
		return err;
	}
	*out_sz = (size_t)st.st_size;
	return 0;
}

static int
arc_send_blob(const struct silofs_ar_ctx *ar_ctx,
              const struct silofs_paddr *paddr, const void *dat, size_t len)
{
	int err;

	err = silofs_dstor_require_blob(ar_ctx->dstor, &paddr->blobid);
	if (err) {
		log_err("failed to create archive blob: err=%d", err);
		return err;
	}
	err = silofs_dstor_write_blob_at(ar_ctx->dstor, &paddr->blobid,
	                                 paddr->pos, dat, len);
	if (err) {
		log_err("failed to save blob: err=%d", err);
		return err;
	}
	return 0;
}

static int
arc_send_pack(const struct silofs_ar_ctx *ar_ctx,
              const struct silofs_paddr *paddr, const void *dat, size_t len)
{
	size_t sz = 0;
	int err;

	err = arc_stat_pack(ar_ctx, paddr, &sz);
	if ((err == -ENOENT) || (!err && (sz != len))) {
		err = arc_send_blob(ar_ctx, paddr, dat, len);
	}
	return err;
}

static int
arc_load_seg(const struct silofs_ar_ctx *ar_ctx,
             const struct silofs_laddr *laddr, void *seg, size_t len)
{
	int err;

	err = silofs_repo_read_at(ar_ctx->repo, laddr, seg, len);
	if (err) {
		log_err("failed to read: mtype=%d pos=%ld len=%zu err=%d",
		        silofs_laddr_mtype(laddr), laddr->pos, len, err);
	}
	return err;
}

static void
arc_calc_seg_desc(const struct silofs_ar_ctx *ar_ctx,
                  const struct silofs_laddr *laddr, const void *seg,
                  size_t seg_len, struct silofs_ar_desc *out_ard)
{
	const struct silofs_rovec rovec = {
		.rov_base = seg,
		.rov_len  = seg_len,
	};

	silofs_calc_ar_desc(&ar_ctx->env->md_hd, laddr, &rovec, out_ard);
}

static int arc_archive_segdata(const struct silofs_ar_ctx *ar_ctx,
                               const struct silofs_laddr *laddr, size_t len,
                               struct silofs_ar_desc *out_ard)
{
	void *seg = nullptr;
	int err;

	seg = silofs_memalloc(ar_ctx->alloc, len, 0);
	if (seg == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = arc_load_seg(ar_ctx, laddr, seg, len);
	if (err) {
		goto out;
	}
	arc_calc_seg_desc(ar_ctx, laddr, seg, len, out_ard);

	err = arc_send_pack(ar_ctx, &out_ard->paddr, seg, len);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(ar_ctx->alloc, seg, len, 0);
	return err;
}

static struct silofs_arix_node *arc_new_arix_node(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_arix_node *arn = nullptr;

	arn = silofs_memalloc(ar_ctx->alloc, sizeof(*arn),
	                      SILOFS_ALLOCF_BZERO);
	return arn;
}

static void
arc_del_arix_node(struct silofs_ar_ctx *ar_ctx, struct silofs_arix_node *arn)
{
	silofs_memfree(ar_ctx->alloc, arn, sizeof(*arn), 0);
}

static int arc_store_arix_node(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_ar_cargs ar_cargs;
	struct silofs_paddr paddr;
	struct silofs_arix_node *arn_enc;
	int err = -SILOFS_ENOMEM;

	arn_enc = arc_new_arix_node(ar_ctx);
	if (arn_enc == nullptr) {
		goto out;
	}
	err = arc_arix_cargs(ar_ctx, &ar_cargs);
	if (err) {
		goto out;
	}
	err = silofs_export_arix_node(ar_ctx->ari, &ar_cargs, arn_enc);
	if (err) {
		goto out;
	}
	silofs_calc_arix_paddr(arn_enc, arc_mdigest(ar_ctx), &paddr);

	err = silofs_save_arix_node(ar_ctx->dstor, &paddr, arn_enc);
	if (err) {
		goto out;
	}
	silofs_ari_set_paddr(ar_ctx->ari, &paddr);
out:
	arc_del_arix_node(ar_ctx, arn_enc);
	return err;
}

static int arc_require_room(struct silofs_ar_ctx *ar_ctx)
{
	int err;

	if (!silofs_ari_isfull(ar_ctx->ari)) {
		return 0;
	}
	err = arc_store_arix_node(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_renew_ari(ar_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int
arc_append_desc(struct silofs_ar_ctx *ar_ctx, const struct silofs_ar_desc *ard)
{
	return silofs_ari_append_desc(ar_ctx->ari, ard);
}

static int arc_archive_by_laddr(struct silofs_ar_ctx *ar_ctx,
                                const struct silofs_laddr *laddr, size_t len)
{
	struct silofs_ar_desc ard;
	int err;

	err = arc_require_room(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_archive_segdata(ar_ctx, laddr, len, &ard);
	if (err) {
		return err;
	}
	err = arc_append_desc(ar_ctx, &ard);
	if (err) {
		return err;
	}
	return 0;
}

static int
arc_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr, size_t len)
{
	struct silofs_ar_ctx *ar_ctx = ctx;

	return arc_archive_by_laddr(ar_ctx, laddr, len);
}

static int arc_archive_fs(struct silofs_ar_ctx *ar_ctx)
{
	const struct silofs_laddr_visitor lvis = {
		.hook  = arc_visit_laddr_cb,
		.userp = ar_ctx,
	};
	struct silofs_exec_ctx *exct = ar_ctx->exct;

	return silofs_walkfs_at(exct, silofs_get_sbi(exct), &lvis);
}

static int arc_archive_head_arix(struct silofs_ar_ctx *ar_ctx,
                                 struct silofs_pnodeptr *out_pnodeptr)
{
	int err;

	err = arc_store_arix_node(ar_ctx);
	if (err) {
		return err;
	}
	silofs_pnodeptr_assign(out_pnodeptr, &ar_ctx->ari->arn_pnodeptr);
	return 0;
}

static int arc_export_ar_mbr(const struct silofs_ar_ctx *ar_ctx,
                             struct silofs_mbref *out_mbref,
                             struct silofs_mbr1k *out_mbr1k)
{
	return silofs_env_export_ar_mbr(ar_ctx->env, out_mbref, out_mbr1k);
}

static int arc_send_mbr1k(const struct silofs_ar_ctx *ar_ctx,
                          const struct silofs_mbref *mbref,
                          const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = silofs_dstor_save_mbr(ar_ctx->dstor, mbref, mbr1k,
	                            sizeof(*mbr1k));
	if (err) {
		log_err("failed to create save mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int arc_archive_mbr(const struct silofs_ar_ctx *ar_ctx,
                           struct silofs_mbref *out_mbref)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 0xff };
	int err;

	err = arc_export_ar_mbr(ar_ctx, out_mbref, &mbr1k);
	if (err) {
		return err;
	}
	err = arc_send_mbr1k(ar_ctx, out_mbref, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_set_mbr_root(struct silofs_ar_ctx *ar_ctx,
                            const struct silofs_pnodeptr *pnodeptr)
{
	struct silofs_mbr_info *ar_mbi = &ar_ctx->env->mbis.ar_mbi;

	return silofs_mbi_set_root(ar_mbi, pnodeptr);
}

static int arc_archive_post(struct silofs_ar_ctx *ar_ctx,
                            const struct silofs_pnodeptr *pnodeptr,
                            struct silofs_mbref *out_mbref)
{
	int err;

	err = arc_set_mbr_root(ar_ctx, pnodeptr);
	if (err) {
		return err;
	}
	err = arc_archive_mbr(ar_ctx, out_mbref);
	if (err) {
		return err;
	}
	return 0;
}

static void arc_archive_prep(struct silofs_ar_ctx *ar_ctx)
{
	unused(ar_ctx);
}

static int
arc_do_archive(struct silofs_ar_ctx *ar_ctx, struct silofs_mbref *out_mbref)
{
	struct silofs_pnodeptr pnodeptr;
	int err;

	arc_archive_prep(ar_ctx);

	err = arc_archive_fs(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_archive_head_arix(ar_ctx, &pnodeptr);
	if (err) {
		return err;
	}
	err = arc_archive_post(ar_ctx, &pnodeptr, out_mbref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_archive_fs(struct silofs_exec_ctx *exct,
                         struct silofs_mbref *out_ar_mbref)
{
	struct silofs_ar_ctx ar_ctx;
	int err;

	err = silofs_flush_dirty_now(exct);
	if (err) {
		return err;
	}
	err = arc_init(&ar_ctx, exct);
	if (err) {
		goto out;
	}
	err = arc_do_archive(&ar_ctx, out_ar_mbref);
	if (err) {
		goto out;
	}
out:
	arc_fini(&ar_ctx);
	return err;
}
