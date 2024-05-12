/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/vol.h>
#include <silofs/fs.h>
#include <silofs/pack.h>


struct silofs_pack_export_ctx {
	struct silofs_catalog   pex_catalog;
	struct silofs_task     *pex_task;
	struct silofs_alloc    *pex_alloc;
	struct silofs_repo     *pex_repo;
	long pad;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pec_init(struct silofs_pack_export_ctx *pe_ctx,
                    struct silofs_task *task)
{
	silofs_memzero(pe_ctx, sizeof(*pe_ctx));
	pe_ctx->pex_task = task;
	pe_ctx->pex_alloc = task->t_fsenv->fse.alloc;
	pe_ctx->pex_repo = task->t_fsenv->fse.repo;
	return silofs_catalog_init(&pe_ctx->pex_catalog, pe_ctx->pex_alloc);
}

static void pec_fini(struct silofs_pack_export_ctx *pe_ctx)
{
	silofs_catalog_fini(&pe_ctx->pex_catalog);
	pe_ctx->pex_task = NULL;
	pe_ctx->pex_alloc = NULL;
	pe_ctx->pex_repo = NULL;
}

static int
pec_stat_pack(const struct silofs_pack_export_ctx *pe_ctx,
              const struct silofs_caddr *caddr, ssize_t *out_sz)
{
	return silofs_repo_stat_pack(pe_ctx->pex_repo, caddr, out_sz);
}

static int pec_send_to_repo(const struct silofs_pack_export_ctx *pe_ctx,
                            const struct silofs_caddr *caddr,
                            const struct silofs_bytebuf *bb)
{
	return silofs_repo_save_pack(pe_ctx->pex_repo, caddr, bb);
}

static int pec_send_pack(const struct silofs_pack_export_ctx *pe_ctx,
                         const struct silofs_pack_desc_info *pdi,
                         const void *dat)
{
	const struct silofs_caddr *caddr = &pdi->pd.pd_caddr;
	const struct silofs_laddr *laddr = &pdi->pd.pd_laddr;
	struct silofs_bytebuf bb;
	ssize_t sz = -1;
	int err;

	err = pec_stat_pack(pe_ctx, caddr, &sz);
	if ((err == -ENOENT) || (!err && ((size_t)sz != laddr->len))) {
		silofs_bytebuf_init2(&bb, unconst(dat), laddr->len);
		err = pec_send_to_repo(pe_ctx, caddr, &bb);
	}
	return err;
}

static int pec_load_seg(const struct silofs_pack_export_ctx *pe_ctx,
                        const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(pe_ctx->pex_repo, laddr, seg);
	if (err) {
		log_err("failed to read: ltype=%d len=%zu err=%d",
		        laddr->ltype, laddr->len, err);
	}
	return err;
}

static int pec_load_brec(const struct silofs_pack_export_ctx *pe_ctx,
                         const struct silofs_laddr *laddr,
                         struct silofs_bootrec1k *out_brec1k)
{
	int err;

	err = silofs_repo_load_lobj(pe_ctx->pex_repo, laddr, out_brec1k);
	if (err) {
		log_err("failed to load: ltype=%d len=%zu err=%d",
		        laddr->ltype, laddr->len, err);
	}
	return err;
}

static int
pec_update_hash_of(const struct silofs_pack_export_ctx *pe_ctx,
                   struct silofs_pack_desc_info *pdi, const void *dat)
{
	const struct silofs_mdigest *md = &pe_ctx->pex_catalog.cat_mdigest;
	const size_t len = pdi->pd.pd_laddr.len;

	silofs_pkdesc_update_id(&pdi->pd, md, dat, len);
	return 0;
}

static int pec_export_segdata(const struct silofs_pack_export_ctx *pe_ctx,
                              struct silofs_pack_desc_info *pdi)
{
	const size_t seg_len = pdi->pd.pd_laddr.len;
	void *seg = NULL;
	int err = -SILOFS_ENOMEM;

	seg = silofs_memalloc(pe_ctx->pex_alloc, seg_len, 0);
	if (seg == NULL) {
		goto out;
	}
	err = pec_load_seg(pe_ctx, &pdi->pd.pd_laddr, seg);
	if (err) {
		goto out;
	}
	err = pec_update_hash_of(pe_ctx, pdi, seg);
	if (err) {
		goto out;
	}
	err = pec_send_pack(pe_ctx, pdi, seg);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(pe_ctx->pex_alloc, seg, seg_len, 0);
	return err;
}

static int pec_export_bootrec(const struct silofs_pack_export_ctx *pe_ctx,
                              struct silofs_pack_desc_info *pdi)
{
	struct silofs_bootrec1k brec = { .br_magic = 0xFFFFFFFF };
	int err;

	err = pec_load_brec(pe_ctx, &pdi->pd.pd_laddr, &brec);
	if (err) {
		return err;
	}
	err = pec_update_hash_of(pe_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	err = pec_send_pack(pe_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	return 0;
}

static int pec_process_pdi(struct silofs_pack_export_ctx *pe_ctx,
                           struct silofs_pack_desc_info *pdi)
{
	int err;

	if (silofs_pdi_isbootrec(pdi)) {
		err = pec_export_bootrec(pe_ctx, pdi);
	} else {
		err = pec_export_segdata(pe_ctx, pdi);
	}
	return err;
}

static int pec_process_by_laddr(struct silofs_pack_export_ctx *pe_ctx,
                                const struct silofs_laddr *laddr)
{
	struct silofs_pack_desc_info *pdi = NULL;
	int err;

	pdi = silofs_catalog_add_desc(&pe_ctx->pex_catalog, laddr);
	if (pdi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pec_process_pdi(pe_ctx, pdi);
	if (err) {
		silofs_catalog_rm_desc(&pe_ctx->pex_catalog, pdi);
		return err;
	}
	return 0;
}

static int pec_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr)
{
	struct silofs_pack_export_ctx *pe_ctx = ctx;

	return pec_process_by_laddr(pe_ctx, laddr);
}

static int pec_export_catalog(struct silofs_pack_export_ctx *pe_ctx)
{
	struct silofs_catalog *cat = &pe_ctx->pex_catalog;
	int err;

	err = silofs_catalog_encode(cat);
	if (err) {
		return err;
	}
	err = pec_send_to_repo(pe_ctx, &cat->cat_caddr, &cat->cat_bbuf);
	if (err) {
		return err;
	}
	return 0;
}

static int pec_export_fs(struct silofs_pack_export_ctx *pe_ctx)
{
	int err;

	err = silofs_fs_inspect(pe_ctx->pex_task, pec_visit_laddr_cb, pe_ctx);
	if (err) {
		return err;
	}
	err = pec_export_catalog(pe_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static void pec_catalog_id(const struct silofs_pack_export_ctx *pe_ctx,
                           struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &pe_ctx->pex_catalog.cat_caddr);
}

int silofs_fs_pack(struct silofs_task *task,
                   struct silofs_caddr *out_caddr)
{
	struct silofs_pack_export_ctx pe_ctx = {
		.pad = -1,
	};
	int err;

	err = pec_init(&pe_ctx, task);
	if (err) {
		return err;
	}
	err = pec_export_fs(&pe_ctx);
	if (err) {
		goto out;
	}
	pec_catalog_id(&pe_ctx, out_caddr);
out:
	pec_fini(&pe_ctx);
	return err;
}
