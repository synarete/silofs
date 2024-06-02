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


struct silofs_pack_ctx {
	struct silofs_catalog   pac_catalog;
	struct silofs_task     *pac_task;
	struct silofs_alloc    *pac_alloc;
	struct silofs_repo     *pac_repo;
	long pad;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_acquire_buf(const struct silofs_pack_ctx *pa_ctx, size_t len,
                           struct silofs_bytebuf *out_bbuf)
{
	void *dat;

	dat = silofs_memalloc(pa_ctx->pac_alloc, len, SILOFS_ALLOCF_BZERO);
	if (dat == NULL) {
		return -SILOFS_ENOMEM;
	}
	silofs_bytebuf_init2(out_bbuf, dat, len);
	return 0;
}

static void pac_release_buf(const struct silofs_pack_ctx *pa_ctx,
                            struct silofs_bytebuf *bbuf)
{
	if (bbuf && bbuf->cap) {
		silofs_memfree(pa_ctx->pac_alloc, bbuf->ptr, bbuf->cap, 0);
		silofs_bytebuf_fini(bbuf);
	}
}

static int pac_init(struct silofs_pack_ctx *pa_ctx,
                    struct silofs_task *task)
{
	silofs_memzero(pa_ctx, sizeof(*pa_ctx));
	pa_ctx->pac_task = task;
	pa_ctx->pac_alloc = task->t_fsenv->fse.alloc;
	pa_ctx->pac_repo = task->t_fsenv->fse.repo;
	return silofs_catalog_init(&pa_ctx->pac_catalog, pa_ctx->pac_alloc);
}

static void pac_fini(struct silofs_pack_ctx *pa_ctx)
{
	silofs_catalog_fini(&pa_ctx->pac_catalog);
	pa_ctx->pac_task = NULL;
	pa_ctx->pac_alloc = NULL;
	pa_ctx->pac_repo = NULL;
}

static int
pac_stat_pack(const struct silofs_pack_ctx *pa_ctx,
              const struct silofs_caddr *caddr, size_t *out_sz)
{
	ssize_t sz = -1;
	int err;

	err = silofs_repo_stat_pack(pa_ctx->pac_repo, caddr, &sz);
	if (err) {
		return err;
	}
	if ((sz < SILOFS_CATALOG_SIZE_MIN) ||
	    (sz > SILOFS_CATALOG_SIZE_MAX)) {
		log_warn("illegal pack-catalog: size=%zu", sz);
		return -SILOFS_EINVAL;
	}
	*out_sz = (size_t)sz;
	return 0;
}

static int pac_send_to_repo(const struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            const struct silofs_rovec *rov)
{
	return silofs_repo_save_pack(pa_ctx->pac_repo, caddr, rov);
}

static int pac_recv_from_repo(const struct silofs_pack_ctx *pa_ctx,
                              const struct silofs_caddr *caddr,
                              const struct silofs_rwvec *rwv)
{
	return silofs_repo_load_pack(pa_ctx->pac_repo, caddr, rwv);
}

static int pac_send_pack(const struct silofs_pack_ctx *pa_ctx,
                         const struct silofs_pack_desc_info *pdi,
                         const void *dat)
{
	const struct silofs_caddr *caddr = &pdi->pd.pd_caddr;
	const struct silofs_laddr *laddr = &pdi->pd.pd_laddr;
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = laddr->len
	};
	size_t sz = 0;
	int err;

	err = pac_stat_pack(pa_ctx, caddr, &sz);
	if ((err == -ENOENT) || (!err && (sz != laddr->len))) {
		err = pac_send_to_repo(pa_ctx, caddr, &rov);
	}
	return err;
}

static int pac_load_seg(const struct silofs_pack_ctx *pa_ctx,
                        const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(pa_ctx->pac_repo, laddr, seg);
	if (err) {
		log_err("failed to read: ltype=%d len=%zu err=%d",
		        laddr->ltype, laddr->len, err);
	}
	return err;
}

static int pac_load_bootrec(const struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_caddr *caddr,
                            struct silofs_bootrec1k *out_brec1k)
{
	struct silofs_bootrec brec = { .flags = 0 };
	const struct silofs_fsenv *fsenv = pa_ctx->pac_task->t_fsenv;
	int err;

	err = silofs_load_bootrec(fsenv, caddr, &brec);
	if (err) {
		log_err("failed to load bootrec: err=%d", err);
		return err;
	}
	err = silofs_encode_bootrec(fsenv, &brec, out_brec1k);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	return 0;
}

static int
pac_update_hash_of(const struct silofs_pack_ctx *pa_ctx,
                   struct silofs_pack_desc_info *pdi, const void *dat)
{
	const struct silofs_rovec rov = {
		.rov_base = dat,
		.rov_len = pdi->pd.pd_laddr.len
	};
	const struct silofs_mdigest *md = &pa_ctx->pac_catalog.cat_mdigest;

	silofs_pkdesc_update_caddr_by(&pdi->pd, md, &rov);
	return 0;
}

static int pac_export_segdata(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_pack_desc_info *pdi)
{
	const size_t seg_len = pdi->pd.pd_laddr.len;
	void *seg = NULL;
	int err = -SILOFS_ENOMEM;

	seg = silofs_memalloc(pa_ctx->pac_alloc, seg_len, 0);
	if (seg == NULL) {
		goto out;
	}
	err = pac_load_seg(pa_ctx, &pdi->pd.pd_laddr, seg);
	if (err) {
		goto out;
	}
	err = pac_update_hash_of(pa_ctx, pdi, seg);
	if (err) {
		goto out;
	}
	err = pac_send_pack(pa_ctx, pdi, seg);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(pa_ctx->pac_alloc, seg, seg_len, 0);
	return err;
}

static const struct silofs_caddr *
pac_bootrec_caddr(const struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_fsenv *fsenv = pa_ctx->pac_task->t_fsenv;

	return &fsenv->fse_boot_ref;
}

static int pac_export_bootrec(const struct silofs_pack_ctx *pa_ctx,
                              struct silofs_pack_desc_info *pdi)
{
	struct silofs_bootrec1k brec = { .br_magic = 0xFFFFFFFF };
	const struct silofs_caddr *boot_caddr = NULL;
	int err;

	boot_caddr = pac_bootrec_caddr(pa_ctx);
	err = pac_load_bootrec(pa_ctx, boot_caddr, &brec);
	if (err) {
		return err;
	}
	err = pac_update_hash_of(pa_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	err = pac_send_pack(pa_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_process_pdi(struct silofs_pack_ctx *pa_ctx,
                           struct silofs_pack_desc_info *pdi)
{
	int err;

	if (silofs_pdi_isbootrec(pdi)) {
		err = pac_export_bootrec(pa_ctx, pdi);
	} else {
		err = pac_export_segdata(pa_ctx, pdi);
	}
	return err;
}

static int pac_process_by_laddr(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_laddr *laddr)
{
	struct silofs_pack_desc_info *pdi = NULL;
	int err;

	pdi = silofs_catalog_add_desc(&pa_ctx->pac_catalog, laddr);
	if (pdi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pac_process_pdi(pa_ctx, pdi);
	if (err) {
		silofs_catalog_rm_desc(&pa_ctx->pac_catalog, pdi);
		return err;
	}
	return 0;
}

static int pac_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr)
{
	struct silofs_pack_ctx *pa_ctx = ctx;

	return pac_process_by_laddr(pa_ctx, laddr);
}

static int pac_export_fs(struct silofs_pack_ctx *pa_ctx)
{
	return silofs_fs_inspect(pa_ctx->pac_task, pac_visit_laddr_cb, pa_ctx);
}

static int pac_encode_save_catalog(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_bytebuf *bb)
{
	struct silofs_catalog *cat = &pa_ctx->pac_catalog;
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = silofs_catalog_encode(cat, &rwv);
	if (err) {
		return err;
	}
	err = pac_send_to_repo(pa_ctx, &cat->cat_caddr, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_acquire_enc_buf(const struct silofs_pack_ctx *pa_ctx,
                               struct silofs_bytebuf *out_bbuf)
{
	size_t bsz = 0;
	int err;

	err = silofs_catalog_encsize(&pa_ctx->pac_catalog, &bsz);
	if (!err) {
		err = pac_acquire_buf(pa_ctx, bsz, out_bbuf);
	}
	return err;
}

static int pac_export_catalog(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	int err;

	err = pac_acquire_enc_buf(pa_ctx, &bb);
	if (err) {
		goto out;
	}
	err = pac_encode_save_catalog(pa_ctx, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

static void pac_catalog_id(const struct silofs_pack_ctx *pa_ctx,
                           struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &pa_ctx->pac_catalog.cat_caddr);
}

int silofs_fs_pack(struct silofs_task *task,
                   struct silofs_caddr *out_caddr)
{
	struct silofs_pack_ctx pa_ctx = {
		.pad = -1,
	};
	int err;

	err = pac_init(&pa_ctx, task);
	if (err) {
		return err;
	}
	err = pac_export_fs(&pa_ctx);
	if (err) {
		goto out;
	}
	err = pac_export_catalog(&pa_ctx);
	if (err) {
		goto out;
	}
	pac_catalog_id(&pa_ctx, out_caddr);
out:
	pac_fini(&pa_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void pac_set_catalog_id(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_caddr *caddr)
{
	silofs_caddr_assign(&pa_ctx->pac_catalog.cat_caddr, caddr);
}

static int pac_acquire_dec_buf(const struct silofs_pack_ctx *pa_ctx, size_t sz,
                               struct silofs_bytebuf *out_bbuf)
{
	return pac_acquire_buf(pa_ctx, sz, out_bbuf);
}

static int pac_load_decode_catalog(struct silofs_pack_ctx *pa_ctx,
                                   struct silofs_bytebuf *bb)
{
	struct silofs_catalog *cat = &pa_ctx->pac_catalog;
	struct silofs_rwvec rwv = {
		.rwv_base = bb->ptr,
		.rwv_len = bb->len
	};
	struct silofs_rovec rov = {
		.rov_base = bb->ptr,
		.rov_len = bb->len
	};
	int err;

	err = pac_recv_from_repo(pa_ctx, &cat->cat_caddr, &rwv);
	if (err) {
		return err;
	}
	err = silofs_catalog_decode(cat, &rov);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_import_catalog(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_catalog *cat = &pa_ctx->pac_catalog;
	struct silofs_bytebuf bb = { .ptr = NULL, .cap = 0 };
	size_t sz;
	int err;

	err = pac_stat_pack(pa_ctx, &cat->cat_caddr, &sz);
	if (err) {
		goto out;
	}
	err = pac_acquire_dec_buf(pa_ctx, sz, &bb);
	if (err) {
		goto out;
	}
	err = pac_load_decode_catalog(pa_ctx, &bb);
	if (err) {
		goto out;
	}
out:
	pac_release_buf(pa_ctx, &bb);
	return err;
}

int silofs_fs_unpack(struct silofs_task *task,
                     const struct silofs_caddr *caddr)
{
	struct silofs_pack_ctx pa_ctx = {
		.pad = -1,
	};
	int err;

	err = pac_init(&pa_ctx, task);
	if (err) {
		return err;
	}
	pac_set_catalog_id(&pa_ctx, caddr);
	if (err) {
		goto out;
	}
	err = pac_import_catalog(&pa_ctx);
	if (err) {
		goto out;
	}
out:
	pac_fini(&pa_ctx);
	return err;
}
