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
#include <silofs/configs.h>
#include <silofs/ioctls.h>
#include "infra.h"
#include "bstore.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"
#include "walk.h"

struct silofs_delfs_ctx {
	struct silofs_visitor vis;
	struct silofs_env    *env;
	struct silofs_repo   *repo;
	struct silofs_uaddr   sb_uaddr;
};

static int sli_resolve_lseg_of(const struct silofs_spleaf_info *sli,
                               off_t voff, struct silofs_lsid *out_lsid)
{
	struct silofs_laddr laddr;
	int                 err;

	err = silofs_sli_resolve_child(sli, voff, &laddr);
	if (err) {
		return err;
	}
	silofs_lsid_assign(out_lsid, &laddr.lsid);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool delfc_is_silofs_lsid_of(const struct silofs_delfs_ctx *delf_ctx,
                                    const struct silofs_lsid      *lsid)
{
	const struct silofs_uaddr  *sb_uaddr = &delf_ctx->sb_uaddr;
	const struct silofs_blobid *blobid   = &sb_uaddr->laddr.lsid.blobid;

	return silofs_lsid_has_blobid(lsid, blobid);
}

static int delfc_exec_unrefs_at(struct silofs_delfs_ctx       *delf_ctx,
                                const struct silofs_walk_iter *witr)
{
	silofs_unused(delf_ctx);
	silofs_unused(witr);
	return 0;
}

static int delfc_try_remove_lseg_of(const struct silofs_delfs_ctx *delf_ctx,
                                    const struct silofs_lsid      *lsid)
{
	struct stat st = { .st_size = -1 };
	int         err;

	if (!delfc_is_silofs_lsid_of(delf_ctx, lsid)) {
		return 0;
	}
	err = silofs_repo_stat_lseg(delf_ctx->repo, lsid, false, &st);
	if (err) {
		return (err == -SILOFS_ENOENT) ? 0 : err;
	}
	err = silofs_repo_remove_lseg(delf_ctx->repo, lsid);
	if (err) {
		silofs_assert_ne(err, -ENOENT);
		return err;
	}
	return 0;
}

static int
delfc_post_at_lseg_of(struct silofs_delfs_ctx         *delf_ctx,
                      const struct silofs_spleaf_info *sli, off_t voff)
{
	struct silofs_lsid lsid;
	int                err;

	err = sli_resolve_lseg_of(sli, voff, &lsid);
	if (err) {
		return err;
	}
	err = delfc_try_remove_lseg_of(delf_ctx, &lsid);
	if (err) {
		return err;
	}
	return 0;
}

static int delfc_post_at_spleaf(struct silofs_delfs_ctx         *delf_ctx,
                                const struct silofs_spleaf_info *sli)
{
	struct silofs_lrange lrange = { .beg = -1 };
	off_t                voff   = -1;
	int                  err;

	silofs_sli_get_lrange(sli, &lrange);
	voff = lrange.beg;
	while (voff < lrange.end) {
		err = delfc_post_at_lseg_of(delf_ctx, sli, voff);
		if (err) {
			return err;
		}
		voff = silofs_lrange_next(&lrange, voff);
	}
	return 0;
}

static const struct silofs_lsid *
silofs_lsid_of(const struct silofs_uaddr *uaddr)
{
	return silofs_uaddr_lsid(uaddr);
}

static int delfc_post_at_spnode(struct silofs_delfs_ctx         *delf_ctx,
                                const struct silofs_spnode_info *sni)
{
	struct silofs_uaddr  uaddr;
	struct silofs_lrange lrange;
	off_t                voff;
	int                  err;

	silofs_sni_vspace_range(sni, &lrange);
	voff = lrange.beg;
	while (voff < lrange.end) {
		err = silofs_sni_resolve_child(sni, voff, &uaddr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		err = delfc_try_remove_lseg_of(delf_ctx,
		                               silofs_lsid_of(&uaddr));
		if (err) {
			return err;
		}
		voff = silofs_lrange_next(&lrange, voff);
	}
	return 0;
}

static int delfc_post_at_super(struct silofs_delfs_ctx       *delf_ctx,
                               const struct silofs_walk_iter *witr)
{
	struct silofs_uaddr uaddr;
	int                 err;

	err = silofs_sbi_sproot_of(witr->sbi, witr->vspace, &uaddr);
	if (err) {
		return err;
	}
	err = delfc_try_remove_lseg_of(delf_ctx, silofs_uaddr_lsid(&uaddr));
	if (err) {
		return err;
	}
	return 0;
}

static int delfc_post_at(struct silofs_delfs_ctx       *delf_ctx,
                         const struct silofs_walk_iter *witr)
{
	int err;

	switch (witr->height) {
	case SILOFS_HEIGHT_BOOT:
		err = 0;
		break;
	case SILOFS_HEIGHT_SUPER:
		err = delfc_post_at_super(delf_ctx, witr);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = delfc_post_at_spnode(delf_ctx, witr->sni4);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = delfc_post_at_spnode(delf_ctx, witr->sni3);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = delfc_post_at_spnode(delf_ctx, witr->sni2);
		break;
	case SILOFS_HEIGHT_SPNODE1:
		err = delfc_post_at_spnode(delf_ctx, witr->sni1);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = delfc_post_at_spleaf(delf_ctx, witr->sli);
		break;
	case SILOFS_HEIGHT_VDATA:
	case SILOFS_HEIGHT_LAST:
	case SILOFS_HEIGHT_NONE:
	default:
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_delfs_ctx *delf_ctx_of(struct silofs_visitor *vis)
{
	return silofs_container_of(vis, struct silofs_delfs_ctx, vis);
}

static int delfc_visit_exec_hook(struct silofs_visitor         *vis,
                                 const struct silofs_walk_iter *witr)
{
	return delfc_exec_unrefs_at(delf_ctx_of(vis), witr);
}

static int delfc_visit_post_hook(struct silofs_visitor         *vis,
                                 const struct silofs_walk_iter *witr)
{
	return delfc_post_at(delf_ctx_of(vis), witr);
}

static void
delfc_init(struct silofs_delfs_ctx *delf_ctx, struct silofs_task_ctx *task,
           const struct silofs_sb_info *sbi)
{
	silofs_memzero(delf_ctx, sizeof(*delf_ctx));
	delf_ctx->vis.exec_hook = delfc_visit_exec_hook;
	delf_ctx->vis.post_hook = delfc_visit_post_hook;
	delf_ctx->env           = task->t_env;
	delf_ctx->repo          = task->t_env->base.repo;
	silofs_uaddr_assign(&delf_ctx->sb_uaddr, silofs_sbi_uaddr(sbi));
}

static void delfc_fini(struct silofs_delfs_ctx *delf_ctx)
{
	silofs_memffff(delf_ctx, sizeof(*delf_ctx));
	delf_ctx->env  = nullptr;
	delf_ctx->repo = nullptr;
}

static int delfc_remove_super(const struct silofs_delfs_ctx *delf_ctx)
{
	const struct silofs_lsid *lsid =
		silofs_uaddr_lsid(&delf_ctx->sb_uaddr);

	return delfc_try_remove_lseg_of(delf_ctx, lsid);
}

int silofs_unrefs_at(struct silofs_task_ctx *task, struct silofs_sb_info *sbi)
{
	struct silofs_delfs_ctx delf_ctx;
	int                     err;

	delfc_init(&delf_ctx, task, sbi);
	err = silofs_visit_sptree(task, sbi, &delf_ctx.vis);
	if (!err) {
		err = delfc_remove_super(&delf_ctx);
	}
	delfc_fini(&delf_ctx);
	return err;
}
