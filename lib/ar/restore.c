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
#include "bs.h"
#include "fs.h"
#include "env.h"
#include "walk.h"
#include "index.h"
#include "arre.h"

struct silofs_re_ctx {
	struct silofs_task_ctx *task;
	struct silofs_env *env;
	struct silofs_ab_info *abi;
	struct silofs_alloc *alloc;
	struct silofs_repo *repo;
	struct silofs_laddr sb_laddr;
};

static void
rec_rebind_abi(struct silofs_re_ctx *re_ctx, struct silofs_ab_info *abi)
{
	if (re_ctx->abi != nullptr) {
		silofs_abi_del(re_ctx->abi, re_ctx->alloc);
		re_ctx->abi = nullptr;
	}
	if (abi != nullptr) {
		re_ctx->abi = abi;
	}
}

static void rec_setup_ab_meta(struct silofs_re_ctx *re_ctx,
                              struct silofs_ab_base *out_ab_meta)
{
	struct silofs_env *env = re_ctx->env;

	out_ab_meta->enc_cipher = &env->enc_cipher;
	out_ab_meta->dec_cipher = &env->dec_cipher;
	out_ab_meta->mdigest = &env->mdigest;
	out_ab_meta->repo = re_ctx->repo;
}

static int
rec_renew_abi(struct silofs_re_ctx *re_ctx, const struct silofs_baddr *baddr)
{
	struct silofs_ab_base ab_meta;
	struct silofs_ab_info *abi = nullptr;

	rec_setup_ab_meta(re_ctx, &ab_meta);
	abi = silofs_abi_new(re_ctx->alloc, &ab_meta);
	if (abi == nullptr) {
		return -SILOFS_ENOMEM;
	}
	silofs_abi_set_baddr(abi, baddr);

	rec_rebind_abi(re_ctx, abi);
	return 0;
}

static int rec_init(struct silofs_re_ctx *re_ctx, struct silofs_task_ctx *task)
{
	silofs_memzero(re_ctx, sizeof(*re_ctx));
	silofs_laddr_reset(&re_ctx->sb_laddr);
	re_ctx->task = task;
	re_ctx->env = task->t_env;
	re_ctx->abi = nullptr;
	re_ctx->alloc = re_ctx->env->base.alloc;
	re_ctx->repo = re_ctx->env->base.repo;
	return 0;
}

static void rec_fini(struct silofs_re_ctx *re_ctx)
{
	rec_rebind_abi(re_ctx, nullptr);
	re_ctx->task = nullptr;
	re_ctx->env = nullptr;
	re_ctx->alloc = nullptr;
	re_ctx->repo = nullptr;
}

static int
rec_recv_from_repo(const struct silofs_re_ctx *re_ctx,
                   const struct silofs_baddr *baddr, struct silofs_rwvec *rwv)
{
	return silofs_repo_load_cobj(re_ctx->repo, baddr, rwv);
}

static int
rec_recv_pack(const struct silofs_re_ctx *re_ctx,
              const struct silofs_baddr *baddr, void *dat, size_t len)
{
	struct silofs_rwvec rwv = { .rwv_base = dat, .rwv_len = len };

	return rec_recv_from_repo(re_ctx, baddr, &rwv);
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
	void *seg = nullptr;
	int err;

	seg = silofs_memalloc(re_ctx->alloc, len, 0);
	if (seg == nullptr) {
		return -SILOFS_ENOMEM;
	}
	err = rec_recv_pack(re_ctx, &ard->baddr, seg, len);
	if (err) {
		goto out;
	}
	/* TODO: recheck baddr by content */
	err = rec_save_seg(re_ctx, &ard->laddr, seg, len);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(re_ctx->alloc, seg, len, 0);
	return err;
}

static const struct silofs_ivkey *
rec_arix_ivkey(const struct silofs_re_ctx *re_ctx)
{
	const struct silofs_mbrinfo *mbri = &re_ctx->env->mbri;

	return &mbri->ar_mbr.main_ivkey;
}

static int rec_fetch_arix_block(struct silofs_re_ctx *re_ctx)
{
	const struct silofs_ivkey *ivkey = rec_arix_ivkey(re_ctx);

	return silofs_fetch_arix_block(re_ctx->abi, ivkey);
}

static int
rec_resolve_apex(struct silofs_re_ctx *re_ctx, struct silofs_baddr *out_baddr)
{
	return silofs_mbri_arix_addr(&re_ctx->env->mbri, out_baddr);
}

static int rec_restore_arix(struct silofs_re_ctx *re_ctx,
                            const struct silofs_baddr *baddr)
{
	int err;

	err = rec_renew_abi(re_ctx, baddr);
	if (err) {
		return err;
	}
	err = rec_fetch_arix_block(re_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_apex(struct silofs_re_ctx *re_ctx)
{
	struct silofs_baddr baddr = { .pos = -1 };
	int err;

	err = rec_resolve_apex(re_ctx, &baddr);
	if (err) {
		return err;
	}
	err = rec_restore_arix(re_ctx, &baddr);
	if (err) {
		return err;
	}
	return 0;
}

static bool is_super(const struct silofs_ar_desc *ard)
{
	return (ard->laddr.lsid.mtype == SILOFS_MTYPE_SUPER);
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
	const struct silofs_ab_info *abi = re_ctx->abi;
	const size_t ndescs = silofs_abi_ndescs(abi);
	int err;

	for (size_t slot = 0; slot < ndescs; ++slot) {
		ard.len = 0;
		err = silofs_abi_fetch_desc(abi, slot, &ard);
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
	struct silofs_baddr baddr = { .pos = -1 };
	int err;

	silofs_assert_not_null(re_ctx->abi);

	silofs_abi_get_next(re_ctx->abi, &baddr);
	if (silofs_baddr_isnull(&baddr)) {
		rec_rebind_abi(re_ctx, nullptr);
		return 0; /* end-of-chain */
	}
	err = rec_restore_arix(re_ctx, &baddr);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_fs(struct silofs_re_ctx *re_ctx)
{
	int err;

	while (re_ctx->abi != nullptr) {
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
	const struct silofs_lsid *lsid = &laddr->lsid;

	silofs_assert_eq(laddr->pos, 0);
	silofs_assert_eq(lsid->height, SILOFS_HEIGHT_SUPER);
	silofs_assert_eq(lsid->mtype, SILOFS_MTYPE_SUPER);

	silofs_uaddr_setup(out_uaddr, lsid, 0, 0);
}

static int rec_restore_sb_addr(struct silofs_re_ctx *re_ctx)
{
	const struct silofs_laddr *sb_laddr = &re_ctx->sb_laddr;
	struct silofs_uaddr sb_uaddr = { .voff = -1 };

	if (silofs_laddr_isnull(sb_laddr)) {
		return -SILOFS_EBADARIX;
	}
	sb_uaddr_of(sb_laddr, &sb_uaddr);
	silofs_mbri_update_sb_addr(&re_ctx->env->mbri, &sb_uaddr);
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
                              struct silofs_baddr *out_fs_mref)
{
	return silofs_env_commit_fs_mbr(re_ctx->env, out_fs_mref);
}

static int rec_restore_post(struct silofs_re_ctx *re_ctx,
                            struct silofs_baddr *out_fs_mref)
{
	int err;

	err = rec_restore_sb(re_ctx);
	if (err) {
		return err;
	}
	err = rec_restore_fs_mbr(re_ctx, out_fs_mref);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_restore_prep(struct silofs_re_ctx *re_ctx,
                            const struct silofs_baddr *ar_mref)
{
	struct silofs_env *env = re_ctx->env;
	int err;

	err = silofs_env_reload_ar_mbr(env, ar_mref);
	if (err) {
		return err;
	}
	err = silofs_mbri_sync_mbrs(&env->mbri, SILOFS_MBR_FS);
	if (err) {
		return err;
	}
	return 0;
}

static int rec_do_restore(struct silofs_re_ctx *re_ctx,
                          const struct silofs_baddr *ar_mref,
                          struct silofs_baddr *out_fs_mref)
{
	int err;

	err = rec_restore_prep(re_ctx, ar_mref);
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
	err = rec_restore_post(re_ctx, out_fs_mref);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_restore_fs(struct silofs_task_ctx *task,
                         const struct silofs_baddr *ar_mref,
                         struct silofs_baddr *out_fs_mref)
{
	struct silofs_re_ctx re_ctx;
	int err;

	err = silofs_flush_dirty_now(task);
	if (err) {
		return err;
	}
	err = rec_init(&re_ctx, task);
	if (err) {
		goto out;
	}
	err = rec_do_restore(&re_ctx, ar_mref, out_fs_mref);
	if (err) {
		goto out;
	}
out:
	rec_fini(&re_ctx);
	return err;
}
