/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

struct silofs_unref_ctx {
	struct silofs_visitor   vis;
	struct silofs_uber     *uber;
	struct silofs_uaddr     sb_uaddr;
};


static int sli_resolve_blob_of(const struct silofs_spleaf_info *sli,
                               loff_t voff, struct silofs_blobid *out_blobid)
{
	struct silofs_blink blink;
	int ret;

	ret = silofs_sli_resolve_child(sli, voff, &blink);
	if (ret == 0) {
		blobid_assign(out_blobid, &blink.bka.blobid);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *unrc_repo(const struct silofs_unref_ctx *unr_ctx)
{
	return unr_ctx->uber->ub.repo;
}

static bool unrc_is_blobid_of(const struct silofs_unref_ctx *unr_ctx,
                              const struct silofs_blobid *blobid)
{
	const struct silofs_treeid *treeid =
		        &unr_ctx->sb_uaddr.oaddr.bka.blobid.treeid;

	return silofs_blobid_has_treeid(blobid, treeid);
}

static int unrc_exec_unrefs_at(struct silofs_unref_ctx *unr_ctx,
                               const struct silofs_space_iter *spit)
{
	silofs_unused(unr_ctx);
	silofs_unused(spit);
	return 0;
}

static int unrc_try_remove_blob_of(const struct silofs_unref_ctx *unr_ctx,
                                   const struct silofs_blobid *blobid)
{
	struct stat st = { .st_size = -1 };
	struct silofs_repo *repo;
	int err;

	if (!unrc_is_blobid_of(unr_ctx, blobid)) {
		return 0;
	}
	repo = unrc_repo(unr_ctx);
	err = silofs_repo_stat_blob(repo, blobid, &st);
	if (err) {
		return (err == -SILOFS_ENOENT) ? 0 : err;
	}
	err = silofs_repo_remove_blob(repo, blobid);
	if (err) {
		silofs_assert_ne(err, -ENOENT);
		return err;
	}
	return 0;
}

static int
unrc_post_unrefs_at_blob_of(struct silofs_unref_ctx *unr_ctx,
                            const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_blobid blobid;
	int err;

	err = sli_resolve_blob_of(sli, voff, &blobid);
	if (err) {
		return err;
	}
	err = unrc_try_remove_blob_of(unr_ctx, &blobid);
	if (err) {
		return err;
	}
	return 0;
}

static int unrc_post_unrefs_at_spleaf(struct silofs_unref_ctx *unr_ctx,
                                      const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange = { .beg = -1 };
	loff_t voff = -1;
	int err;

	sli_vrange(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = unrc_post_unrefs_at_blob_of(unr_ctx, sli, voff);
		if (err) {
			return err;
		}
		voff = vrange_next(&vrange, voff);
	}
	return 0;
}

static const struct silofs_blobid *
blobid_of(const struct silofs_ulink *ulink)
{
	return uaddr_blobid(&ulink->uaddr);
}

static int
unrc_post_unrefs_at_spnode(struct silofs_unref_ctx *unr_ctx,
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
		err = unrc_try_remove_blob_of(unr_ctx, blobid_of(&ulink));
		if (err) {
			return err;
		}
		voff = vrange_next(&vrange, voff);
	}
	return 0;
}

static int
unrc_post_unrefs_at_super(struct silofs_unref_ctx *unr_ctx,
                          const struct silofs_space_iter *spit)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_sproot_of(spit->sbi, spit->vspace, &uaddr);
	if (err) {
		return err;
	}
	err = unrc_try_remove_blob_of(unr_ctx, uaddr_blobid(&uaddr));
	if (err) {
		return err;
	}
	return 0;
}

static int unrc_post_unrefs_at(struct silofs_unref_ctx *unr_ctx,
                               const struct silofs_space_iter *spit)
{
	int err;

	switch (spit->height) {
	case SILOFS_HEIGHT_SUPER:
		err = unrc_post_unrefs_at_super(unr_ctx, spit);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = unrc_post_unrefs_at_spnode(unr_ctx, spit->sni4);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = unrc_post_unrefs_at_spnode(unr_ctx, spit->sni3);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = unrc_post_unrefs_at_spnode(unr_ctx, spit->sni2);
		break;
	case SILOFS_HEIGHT_SPNODE1:
		err = unrc_post_unrefs_at_spnode(unr_ctx, spit->sni1);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = unrc_post_unrefs_at_spleaf(unr_ctx, spit->sli);
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

static struct silofs_unref_ctx *unr_ctx_of(struct silofs_visitor *vis)
{
	return container_of(vis, struct silofs_unref_ctx, vis);
}

static int unrc_visit_exec_hook(struct silofs_visitor *vis,
                                const struct silofs_space_iter *uit)
{
	return unrc_exec_unrefs_at(unr_ctx_of(vis), uit);
}

static int unrc_visit_post_hook(struct silofs_visitor *vis,
                                const struct silofs_space_iter *uit)
{
	return unrc_post_unrefs_at(unr_ctx_of(vis), uit);
}

static void unrc_init(struct silofs_unref_ctx *unr_ctx,
                      const struct silofs_sb_info *sbi)
{
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);

	silofs_memzero(unr_ctx, sizeof(*unr_ctx));
	unr_ctx->vis.exec_hook = unrc_visit_exec_hook;
	unr_ctx->vis.post_hook = unrc_visit_post_hook;
	unr_ctx->uber = sbi_uber(sbi);
	uaddr_assign(&unr_ctx->sb_uaddr, uaddr);
}

static void unrc_fini(struct silofs_unref_ctx *unr_ctx)
{
	silofs_memffff(unr_ctx, sizeof(*unr_ctx));
	unr_ctx->uber = NULL;
}

static int unrc_remove_super(const struct silofs_unref_ctx *unr_ctx)
{
	const struct silofs_blobid *blobid = uaddr_blobid(&unr_ctx->sb_uaddr);

	return unrc_try_remove_blob_of(unr_ctx, blobid);
}

int silofs_walk_unref_fs(struct silofs_task *task,
                         struct silofs_sb_info *sbi)
{
	struct silofs_unref_ctx unr_ctx;
	int err;

	unrc_init(&unr_ctx, sbi);
	err = silofs_walk_space_tree(task, sbi, &unr_ctx.vis);
	if (!err) {
		err = unrc_remove_super(&unr_ctx);
	}
	unrc_fini(&unr_ctx);
	return err;
}
