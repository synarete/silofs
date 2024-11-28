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
#include <silofs/fs.h>
#include <silofs/fs-private.h>

/*
 * TODO-0041: Proper space accounting
 *
 * Do full space-stats collection and export result to caller. Verify collected
 * stats against top-level space-stats accountings.
 */

/*
 * TODO-0049: Proper file-system traverse and repair
 *
 * Extend fsck logic to enable file-system repair.
 */

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_inspect_ctx {
	struct silofs_visitor vis;
	struct silofs_spacestats sp_st;
	struct silofs_spmap_lmap lmap;
	struct silofs_task *task;
	struct silofs_sb_info *sbi;
	silofs_visit_laddr_fn cb;
	void *user_ctx;
};

static int inspc_exec_lmap(const struct silofs_inspect_ctx *insp_ctx)
{
	const struct silofs_laddr *laddr = NULL;
	int err;

	for (size_t i = 0; i < insp_ctx->lmap.cnt; ++i) {
		laddr = &insp_ctx->lmap.laddr[i];
		err = insp_ctx->cb(insp_ctx->user_ctx, laddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int inspc_exec_at_super(struct silofs_inspect_ctx *insp_ctx,
                               const struct silofs_sb_info *sbi)
{
	silofs_sbi_resolve_lmap(sbi, &insp_ctx->lmap);
	return inspc_exec_lmap(insp_ctx);
}

static int inspc_exec_at_spnode(struct silofs_inspect_ctx *insp_ctx,
                                const struct silofs_spnode_info *sni)
{
	silofs_sni_resolve_lmap(sni, &insp_ctx->lmap);
	return inspc_exec_lmap(insp_ctx);
}

static int inspc_exec_at_spleaf(struct silofs_inspect_ctx *insp_ctx,
                                const struct silofs_spleaf_info *sli)
{
	silofs_sli_resolve_lmap(sli, &insp_ctx->lmap);
	return inspc_exec_lmap(insp_ctx);
}

static int inspc_exec_at(struct silofs_inspect_ctx *insp_ctx,
                         const struct silofs_walk_iter *witr)
{
	int ret = 0;

	switch (witr->height) {
	case SILOFS_HEIGHT_BOOT:
		break;
	case SILOFS_HEIGHT_SUPER:
		break;
	case SILOFS_HEIGHT_SPNODE4:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni4);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni3);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni2);
		break;
	case SILOFS_HEIGHT_SPNODE1:
		insp_ctx->sp_st.objs.nspnode++;
		ret = inspc_exec_at_spnode(insp_ctx, witr->sni1);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		insp_ctx->sp_st.objs.nspleaf++;
		ret = inspc_exec_at_spleaf(insp_ctx, witr->sli);
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		break;
	}
	return ret;
}

static struct silofs_inspect_ctx *inspc_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_inspect_ctx, vis);
}

static int inspc_exec_hook(struct silofs_visitor *vis,
                           const struct silofs_walk_iter *witr)
{
	return inspc_exec_at(inspc_of(vis), witr);
}

static int noop_callback(void *ctx, const struct silofs_laddr *laddr)
{
	silofs_unused(laddr);
	silofs_unused(ctx);
	return 0;
}

static void inspc_init(struct silofs_inspect_ctx *insp_ctx,
                       struct silofs_task *task, struct silofs_sb_info *sbi,
                       silofs_visit_laddr_fn cb, void *user_ctx)
{
	silofs_memzero(insp_ctx, sizeof(*insp_ctx));
	insp_ctx->vis.post_hook = inspc_exec_hook;
	insp_ctx->task = task;
	insp_ctx->sbi = sbi;
	insp_ctx->cb = cb ? cb : noop_callback;
	insp_ctx->user_ctx = user_ctx;
}

static void inspc_fini(struct silofs_inspect_ctx *insp_ctx)
{
	silofs_memzero(insp_ctx, sizeof(*insp_ctx));
}

static struct silofs_inspect_ctx *
inspc_new(struct silofs_alloc *alloc, struct silofs_task *task,
          struct silofs_sb_info *sbi, silofs_visit_laddr_fn cb, void *user_ctx)
{
	struct silofs_inspect_ctx *insp_ctx = NULL;

	insp_ctx = silofs_memalloc(alloc, sizeof(*insp_ctx), 0);
	if (insp_ctx != NULL) {
		inspc_init(insp_ctx, task, sbi, cb, user_ctx);
	}
	return insp_ctx;
}

static void
inspc_del(struct silofs_inspect_ctx *insp_ctx, struct silofs_alloc *alloc)
{
	inspc_fini(insp_ctx);
	silofs_memfree(alloc, insp_ctx, sizeof(*insp_ctx), 0);
}

static int inspc_walk_spmaps(struct silofs_inspect_ctx *insp_ctx)
{
	return silofs_walk_space_tree(insp_ctx->task, insp_ctx->sbi,
	                              &insp_ctx->vis);
}

static int inspc_walk_super(struct silofs_inspect_ctx *insp_ctx)
{
	const struct silofs_laddr *sb_laddr = sbi_laddr(insp_ctx->sbi);
	int err;

	insp_ctx->sp_st.objs.nsuper++;
	err = inspc_exec_at_super(insp_ctx, insp_ctx->sbi);
	if (err) {
		return err;
	}
	err = insp_ctx->cb(insp_ctx->user_ctx, sb_laddr);
	if (err) {
		return err;
	}
	return 0;
}

static int inspc_walk_boot(struct silofs_inspect_ctx *insp_ctx)
{
	struct silofs_uaddr brec_uaddr = { .voff = -1 };
	const struct silofs_laddr *sb_laddr = sbi_laddr(insp_ctx->sbi);

	silofs_make_bootrec_uaddr(&sb_laddr->lsid.lvid, &brec_uaddr);
	return insp_ctx->cb(insp_ctx->user_ctx, &brec_uaddr.laddr);
}

static int inspc_walk_fs(struct silofs_inspect_ctx *insp_ctx)
{
	int err;

	err = inspc_walk_spmaps(insp_ctx);
	if (err) {
		return err;
	}
	err = inspc_walk_super(insp_ctx);
	if (err) {
		return err;
	}
	err = inspc_walk_boot(insp_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_walk_inspect_fs(struct silofs_task *task,
                           struct silofs_sb_info *sbi,
                           silofs_visit_laddr_fn cb, void *user_ctx)
{
	struct silofs_alloc *alloc = task->t_fsenv->fse.alloc;
	struct silofs_inspect_ctx *insp_ctx = NULL;
	int ret;

	insp_ctx = inspc_new(alloc, task, sbi, cb, user_ctx);
	if (insp_ctx == NULL) {
		return -SILOFS_ENOMEM;
	}
	ret = inspc_walk_fs(insp_ctx);
	inspc_del(insp_ctx, alloc);
	return ret;
}
