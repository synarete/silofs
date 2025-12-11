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
#include "bstore.h"
#include "fs.h"
#include "env.h"
#include "walk.h"
#include "index.h"
#include "arre.h"

struct silofs_ar_ctx {
	struct timespec            now;
	struct silofs_task_ctx    *task;
	struct silofs_env         *env;
	struct silofs_alloc       *alloc;
	struct silofs_arnode_info *abi;
	struct silofs_repo        *repo;
	struct silofs_filos       *filos;
};

static void
arc_rebind_ari(struct silofs_ar_ctx *ar_ctx, struct silofs_arnode_info *abi)
{
	if (ar_ctx->abi != nullptr) {
		silofs_ari_del(ar_ctx->abi, ar_ctx->alloc);
		ar_ctx->abi = nullptr;
	}
	if (abi != nullptr) {
		ar_ctx->abi = abi;
	}
}

static int arc_renew_abi(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_arnode_info *ari = nullptr;

	ari = silofs_ari_new(ar_ctx->alloc);
	if (ari == nullptr) {
		return -SILOFS_ENOMEM;
	}
	silofs_ari_set_btime(ari, &ar_ctx->now);
	silofs_ari_set_next(ari, ar_ctx->abi);

	arc_rebind_ari(ar_ctx, ari);
	return 0;
}

static int arc_init(struct silofs_ar_ctx *ar_ctx, struct silofs_task_ctx *task)
{
	silofs_memzero(ar_ctx, sizeof(*ar_ctx));
	silofs_clock_real_now(&ar_ctx->now);
	ar_ctx->task  = task;
	ar_ctx->env   = task->t_env;
	ar_ctx->abi   = nullptr;
	ar_ctx->alloc = ar_ctx->env->base.alloc;
	ar_ctx->repo  = ar_ctx->env->base.repo;
	ar_ctx->filos = &ar_ctx->env->base.repo->re_filos;

	return arc_renew_abi(ar_ctx);
}

static void arc_fini(struct silofs_ar_ctx *ar_ctx)
{
	arc_rebind_ari(ar_ctx, nullptr);
	ar_ctx->task  = nullptr;
	ar_ctx->env   = nullptr;
	ar_ctx->repo  = nullptr;
	ar_ctx->filos = nullptr;
	ar_ctx->alloc = nullptr;
}

static int arc_stat_pack(const struct silofs_ar_ctx *ar_ctx,
                         const struct silofs_paddr *paddr, size_t *out_sz)
{
	struct stat st;
	int         err;

	err = silofs_repo_stat_blob(ar_ctx->repo, &paddr->blobid, &st);
	if (err) {
		return err;
	}
	*out_sz = (size_t)st.st_size;
	return 0;
}

static int arc_send_to_repo(const struct silofs_ar_ctx *ar_ctx,
                            const struct silofs_paddr  *paddr,
                            const struct silofs_rovec  *rov)
{
	int err;

	err = silofs_repo_spawn_blob(ar_ctx->repo, &paddr->blobid);
	if (err) {
		log_err("failed to create archive blob: err=%d", err);
		return err;
	}
	err = silofs_repo_save_bseg(ar_ctx->repo, paddr, rov);
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
	const struct silofs_rovec rov = { .rov_base = dat, .rov_len = len };
	size_t                    sz  = 0;
	int                       err;

	err = arc_stat_pack(ar_ctx, paddr, &sz);
	if ((err == -ENOENT) || (!err && (sz != len))) {
		err = arc_send_to_repo(ar_ctx, paddr, &rov);
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

	silofs_calc_ar_desc(&ar_ctx->env->mdigest, laddr, &rovec, out_ard);
}

static int arc_archive_segdata(const struct silofs_ar_ctx *ar_ctx,
                               const struct silofs_laddr *laddr, size_t len,
                               struct silofs_ar_desc *out_ard)
{
	void *seg = nullptr;
	int   err;

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

static void arc_arix_nmeta(const struct silofs_ar_ctx *ar_ctx,
                           struct silofs_nmeta        *out_nmeta)
{
	struct silofs_pmeta pmeta;

	silofs_mbi_arix_root(&ar_ctx->env->mbis.ar_mbi, &pmeta);
	silofs_nmeta_assign(out_nmeta, &pmeta.nmeta);
}

static int arc_store_arix_node(struct silofs_ar_ctx *ar_ctx)
{
	struct silofs_ar_cargs ar_cargs = {
		.cipher  = &ar_ctx->env->enc_cipher,
		.mdigest = &ar_ctx->env->mdigest,
	};
	int err;

	arc_arix_nmeta(ar_ctx, &ar_cargs.nmeta);
	err = silofs_export_arix_node(ar_ctx->abi, &ar_cargs);
	if (err) {
		return err;
	}
	err = silofs_save_arix_node(ar_ctx->abi, ar_ctx->filos);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_require_room(struct silofs_ar_ctx *ar_ctx)
{
	int err;

	if (!silofs_ari_isfull(ar_ctx->abi)) {
		return 0;
	}
	err = arc_store_arix_node(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_renew_abi(ar_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int
arc_append_desc(struct silofs_ar_ctx *ar_ctx, const struct silofs_ar_desc *ard)
{
	return silofs_ari_append_desc(ar_ctx->abi, ard);
}

static int arc_archive_by_laddr(struct silofs_ar_ctx      *ar_ctx,
                                const struct silofs_laddr *laddr, size_t len)
{
	struct silofs_ar_desc ard;
	int                   err;

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
	struct silofs_task_ctx *task = ar_ctx->task;

	return silofs_walkfs_at(task, silofs_get_sbi(task), &lvis);
}

static int arc_archive_apex(struct silofs_ar_ctx *ar_ctx,
                            struct silofs_paddr  *out_arix_addr)
{
	int err;

	err = arc_store_arix_node(ar_ctx);
	if (err) {
		return err;
	}
	silofs_ari_get_paddr(ar_ctx->abi, out_arix_addr);
	return 0;
}

static int arc_export_ar_mbr(const struct silofs_ar_ctx *ar_ctx,
                             struct silofs_paddr        *out_paddr,
                             struct silofs_mbr1k        *out_mbr1k)
{
	const struct silofs_mbr_info *ar_mbi = &ar_ctx->env->mbis.ar_mbi;

	return silofs_mbi_export(ar_mbi, out_paddr, out_mbr1k);
}

static int arc_archive_mbr(const struct silofs_ar_ctx *ar_ctx,
                           struct silofs_paddr        *out_paddr)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = 0xff };
	int                 err;

	err = arc_export_ar_mbr(ar_ctx, out_paddr, &mbr1k);
	if (err) {
		return err;
	}
	err = arc_send_pack(ar_ctx, out_paddr, &mbr1k, sizeof(mbr1k));
	if (err) {
		return err;
	}
	return 0;
}

static int arc_update_mbr_root(struct silofs_ar_ctx      *ar_ctx,
                               const struct silofs_paddr *paddr)
{
	struct silofs_mbr_info *ar_mbi = &ar_ctx->env->mbis.ar_mbi;

	return silofs_mbi_update_root(ar_mbi, paddr);
}

static int arc_archive_post(struct silofs_ar_ctx      *ar_ctx,
                            const struct silofs_paddr *paddr,
                            struct silofs_paddr       *out_paddr)
{
	int err;

	err = arc_update_mbr_root(ar_ctx, paddr);
	if (err) {
		return err;
	}
	err = arc_archive_mbr(ar_ctx, out_paddr);
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
arc_do_archive(struct silofs_ar_ctx *ar_ctx, struct silofs_paddr *out_mbref)
{
	struct silofs_paddr arix_addr;
	int                 err;

	arc_archive_prep(ar_ctx);

	err = arc_archive_fs(ar_ctx);
	if (err) {
		return err;
	}
	err = arc_archive_apex(ar_ctx, &arix_addr);
	if (err) {
		return err;
	}
	err = arc_archive_post(ar_ctx, &arix_addr, out_mbref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_archive_fs(struct silofs_task_ctx *task,
                         struct silofs_paddr    *out_ar_mbref)
{
	struct silofs_ar_ctx ar_ctx;
	int                  err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = arc_init(&ar_ctx, task);
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
