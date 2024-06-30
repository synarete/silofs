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

struct silofs_delfs_ctx {
	struct silofs_visitor   vis;
	struct silofs_fsenv    *fsenv;
	struct silofs_repo     *repo;
	struct silofs_uaddr     sb_uaddr;
};


static int sli_resolve_lseg_of(const struct silofs_spleaf_info *sli,
                               loff_t voff, struct silofs_lsegid *out_lsegid)
{
	struct silofs_llink llink;
	int ret;

	ret = silofs_sli_resolve_child(sli, voff, &llink);
	if (ret == 0) {
		lsegid_assign(out_lsegid, &llink.laddr.lsegid);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool delfc_is_lsegid_of(const struct silofs_delfs_ctx *delf_ctx,
                               const struct silofs_lsegid *lsegid)
{
	const struct silofs_uaddr *sb_uaddr = &delf_ctx->sb_uaddr;
	const struct silofs_lvid *lvid = &sb_uaddr->laddr.lsegid.lvid;

	return silofs_lsegid_has_lvid(lsegid, lvid);
}

static int delfc_exec_unrefs_at(struct silofs_delfs_ctx *delf_ctx,
                                const struct silofs_walk_iter *witr)
{
	silofs_unused(delf_ctx);
	silofs_unused(witr);
	return 0;
}

static int delfc_try_remove_lseg_of(const struct silofs_delfs_ctx *delf_ctx,
                                    const struct silofs_lsegid *lsegid)
{
	struct stat st = { .st_size = -1 };
	int err;

	if (!delfc_is_lsegid_of(delf_ctx, lsegid)) {
		return 0;
	}
	err = silofs_repo_stat_lseg(delf_ctx->repo, lsegid, false, &st);
	if (err) {
		return (err == -SILOFS_ENOENT) ? 0 : err;
	}
	err = silofs_repo_remove_lseg(delf_ctx->repo, lsegid);
	if (err) {
		silofs_assert_ne(err, -ENOENT);
		return err;
	}
	return 0;
}

static int
delfc_post_at_lseg_of(struct silofs_delfs_ctx *delf_ctx,
                      const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_lsegid lsegid;
	int err;

	err = sli_resolve_lseg_of(sli, voff, &lsegid);
	if (err) {
		return err;
	}
	err = delfc_try_remove_lseg_of(delf_ctx, &lsegid);
	if (err) {
		return err;
	}
	return 0;
}

static int delfc_post_at_spleaf(struct silofs_delfs_ctx *delf_ctx,
                                const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	int err;

	sli_vrange(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = delfc_post_at_lseg_of(delf_ctx, sli, voff);
		if (err) {
			return err;
		}
		voff = silofs_vrange_next(&vrange, voff);
	}
	return 0;
}

static const struct silofs_lsegid *
lsegid_of(const struct silofs_ulink *ulink)
{
	return uaddr_lsegid(&ulink->uaddr);
}

static int delfc_post_at_spnode(struct silofs_delfs_ctx *delf_ctx,
                                const struct silofs_spnode_info *sni)
{
	struct silofs_ulink ulink;
	struct silofs_vrange vrange;
	loff_t voff;
	int err;

	sni_vrange(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = silofs_sni_resolve_child(sni, voff, &ulink);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		err = delfc_try_remove_lseg_of(delf_ctx, lsegid_of(&ulink));
		if (err) {
			return err;
		}
		voff = silofs_vrange_next(&vrange, voff);
	}
	return 0;
}

static int delfc_post_at_super(struct silofs_delfs_ctx *delf_ctx,
                               const struct silofs_walk_iter *witr)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_sproot_of(witr->sbi, witr->vspace, &uaddr);
	if (err) {
		return err;
	}
	err = delfc_try_remove_lseg_of(delf_ctx, uaddr_lsegid(&uaddr));
	if (err) {
		return err;
	}
	return 0;
}

static int delfc_post_at(struct silofs_delfs_ctx *delf_ctx,
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
	return container_of(vis, struct silofs_delfs_ctx, vis);
}

static int delfc_visit_exec_hook(struct silofs_visitor *vis,
                                 const struct silofs_walk_iter *witr)
{
	return delfc_exec_unrefs_at(delf_ctx_of(vis), witr);
}

static int delfc_visit_post_hook(struct silofs_visitor *vis,
                                 const struct silofs_walk_iter *witr)
{
	return delfc_post_at(delf_ctx_of(vis), witr);
}

static void delfc_init(struct silofs_delfs_ctx *delf_ctx,
                       const struct silofs_sb_info *sbi)
{
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);

	silofs_memzero(delf_ctx, sizeof(*delf_ctx));
	delf_ctx->vis.exec_hook = delfc_visit_exec_hook;
	delf_ctx->vis.post_hook = delfc_visit_post_hook;
	delf_ctx->fsenv = sbi_fsenv(sbi);
	delf_ctx->repo = delf_ctx->fsenv->fse.repo;
	uaddr_assign(&delf_ctx->sb_uaddr, uaddr);
}

static void delfc_fini(struct silofs_delfs_ctx *delf_ctx)
{
	silofs_memffff(delf_ctx, sizeof(*delf_ctx));
	delf_ctx->fsenv = NULL;
	delf_ctx->repo = NULL;
}

static int delfc_remove_super(const struct silofs_delfs_ctx *delf_ctx)
{
	const struct silofs_lsegid *lsegid = uaddr_lsegid(&delf_ctx->sb_uaddr);

	return delfc_try_remove_lseg_of(delf_ctx, lsegid);
}

int silofs_walk_unref_fs(struct silofs_task *task,
                         struct silofs_sb_info *sbi)
{
	struct silofs_delfs_ctx delf_ctx;
	int err;

	delfc_init(&delf_ctx, sbi);
	err = silofs_walk_space_tree(task, sbi, &delf_ctx.vis);
	if (!err) {
		err = delfc_remove_super(&delf_ctx);
	}
	delfc_fini(&delf_ctx);
	return err;
}
