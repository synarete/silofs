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
	struct silofs_visitor           vis;
	struct silofs_spacestats        sp_st;
	struct silofs_spmap_lmap        lmap;
	struct silofs_task             *task;
	struct silofs_sb_info          *sbi;
	silofs_visit_laddr_fn           cb;
};

static void
inspc_exec_lmap(const struct silofs_inspect_ctx *insp_ctx, loff_t voff)
{
	const struct silofs_laddr *laddr = NULL;

	for (size_t i = 0; i < insp_ctx->lmap.cnt; ++i) {
		laddr = &insp_ctx->lmap.laddr[i];
		insp_ctx->cb(laddr, voff);
		voff = off_end(voff, laddr->len);
	}
}

static void
inspc_exec_at_super(struct silofs_inspect_ctx *insp_ctx,
                    const struct silofs_sb_info *sbi, loff_t voff)
{
	silofs_sbi_resolve_lmap(sbi, &insp_ctx->lmap);
	inspc_exec_lmap(insp_ctx, voff);
}

static void
inspc_exec_at_spnode(struct silofs_inspect_ctx *insp_ctx,
                     const struct silofs_spnode_info *sni, loff_t voff)
{
	silofs_sni_resolve_lmap(sni, &insp_ctx->lmap);
	inspc_exec_lmap(insp_ctx, voff);
}

static void
inspc_exec_at_spleaf(struct silofs_inspect_ctx *insp_ctx,
                     const struct silofs_spleaf_info *sli, loff_t voff)
{
	silofs_sli_resolve_lmap(sli, &insp_ctx->lmap);
	inspc_exec_lmap(insp_ctx, voff);
}

static int inspc_exec_at(struct silofs_inspect_ctx *insp_ctx,
                         const struct silofs_walk_iter *witr)
{
	switch (witr->height) {
	case SILOFS_HEIGHT_BOOT:
		break;
	case SILOFS_HEIGHT_SUPER:
		inspc_exec_at_super(insp_ctx, witr->sbi, witr->voff);
		insp_ctx->sp_st.objs.nsuper++;
		break;
	case SILOFS_HEIGHT_SPNODE4:
		inspc_exec_at_spnode(insp_ctx, witr->sni4, witr->voff);
		insp_ctx->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPNODE3:
		inspc_exec_at_spnode(insp_ctx, witr->sni3, witr->voff);
		insp_ctx->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPNODE2:
		inspc_exec_at_spnode(insp_ctx, witr->sni2, witr->voff);
		insp_ctx->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPNODE1:
		inspc_exec_at_spnode(insp_ctx, witr->sni1, witr->voff);
		insp_ctx->sp_st.objs.nspnode++;
		break;
	case SILOFS_HEIGHT_SPLEAF:
		inspc_exec_at_spleaf(insp_ctx, witr->sli, witr->voff);
		insp_ctx->sp_st.objs.nspleaf++;
		break;
	case SILOFS_HEIGHT_NONE:
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	default:
		break;
	}
	return 0;
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

static void noop_callback(const struct silofs_laddr *laddr, loff_t voff)
{
	silofs_unused(laddr);
	silofs_unused(voff);
}

static void inspc_init(struct silofs_inspect_ctx *insp_ctx,
                       struct silofs_task *task,
                       struct silofs_sb_info *sbi,
                       silofs_visit_laddr_fn cb)
{
	silofs_memzero(insp_ctx, sizeof(*insp_ctx));
	insp_ctx->vis.post_hook = inspc_exec_hook;
	insp_ctx->task = task;
	insp_ctx->sbi = sbi;
	insp_ctx->cb = cb ? cb : noop_callback;
}

static void inspc_fini(struct silofs_inspect_ctx *insp_ctx)
{
	silofs_memzero(insp_ctx, sizeof(*insp_ctx));
}

static struct silofs_inspect_ctx *
inspc_new(struct silofs_alloc *alloc,
          struct silofs_task *task,
          struct silofs_sb_info *sbi,
          silofs_visit_laddr_fn cb)
{
	struct silofs_inspect_ctx *insp_ctx = NULL;

	insp_ctx = silofs_memalloc(alloc, sizeof(*insp_ctx), 0);
	if (insp_ctx != NULL) {
		inspc_init(insp_ctx, task, sbi, cb);
	}
	return insp_ctx;
}

static void inspc_del(struct silofs_inspect_ctx *insp_ctx,
                      struct silofs_alloc *alloc)
{
	inspc_fini(insp_ctx);
	silofs_memfree(alloc, insp_ctx, sizeof(*insp_ctx), 0);
}

static int inspc_walk_fs(struct silofs_inspect_ctx *insp_ctx)
{
	struct silofs_sb_info *sbi = insp_ctx->sbi;
	int err;

	err = silofs_walk_space_tree(insp_ctx->task, sbi, &insp_ctx->vis);
	if (!err) {
		insp_ctx->cb(sbi_laddr(sbi), 0);
	}
	return err;
}

int silofs_walk_inspect_fs(struct silofs_task *task,
                           struct silofs_sb_info *sbi,
                           silofs_visit_laddr_fn cb)
{
	struct silofs_alloc *alloc = task->t_fsenv->fse.alloc;
	struct silofs_inspect_ctx *insp_ctx = NULL;
	int ret;

	insp_ctx = inspc_new(alloc, task, sbi, cb);
	if (insp_ctx == NULL) {
		return -SILOFS_ENOMEM;
	}
	ret = inspc_walk_fs(insp_ctx);
	inspc_del(insp_ctx, alloc);
	return ret;
}
