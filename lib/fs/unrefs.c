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
	struct silofs_fsenv     *fsenv;
	struct silofs_uaddr     sb_uaddr;
};


static int sli_resolve_lext_of(const struct silofs_spleaf_info *sli,
                               loff_t voff, struct silofs_lextid *out_lextid)
{
	struct silofs_blink blink;
	int ret;

	ret = silofs_sli_resolve_child(sli, voff, &blink);
	if (ret == 0) {
		lextid_assign(out_lextid, &blink.bka.laddr.lextid);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_repo *unrc_repo(const struct silofs_unref_ctx *unr_ctx)
{
	return unr_ctx->fsenv->fse.repo;
}

static bool unrc_is_lextid_of(const struct silofs_unref_ctx *unr_ctx,
                              const struct silofs_lextid *lextid)
{
	const struct silofs_volid *volid =
		        &unr_ctx->sb_uaddr.laddr.lextid.volid;

	return silofs_lextid_has_volid(lextid, volid);
}

static int unrc_exec_unrefs_at(struct silofs_unref_ctx *unr_ctx,
                               const struct silofs_walk_iter *witr)
{
	silofs_unused(unr_ctx);
	silofs_unused(witr);
	return 0;
}

static int unrc_try_remove_lext_of(const struct silofs_unref_ctx *unr_ctx,
                                   const struct silofs_lextid *lextid)
{
	struct stat st = { .st_size = -1 };
	struct silofs_repo *repo;
	int err;

	if (!unrc_is_lextid_of(unr_ctx, lextid)) {
		return 0;
	}
	repo = unrc_repo(unr_ctx);
	err = silofs_repo_stat_lext(repo, lextid, false, &st);
	if (err) {
		return (err == -SILOFS_ENOENT) ? 0 : err;
	}
	err = silofs_repo_remove_lext(repo, lextid);
	if (err) {
		silofs_assert_ne(err, -ENOENT);
		return err;
	}
	return 0;
}

static int
unrc_post_unrefs_at_lext_of(struct silofs_unref_ctx *unr_ctx,
                            const struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_lextid lextid;
	int err;

	err = sli_resolve_lext_of(sli, voff, &lextid);
	if (err) {
		return err;
	}
	err = unrc_try_remove_lext_of(unr_ctx, &lextid);
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
		err = unrc_post_unrefs_at_lext_of(unr_ctx, sli, voff);
		if (err) {
			return err;
		}
		voff = silofs_vrange_next(&vrange, voff);
	}
	return 0;
}

static const struct silofs_lextid *
lextid_of(const struct silofs_ulink *ulink)
{
	return uaddr_lextid(&ulink->uaddr);
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
		err = unrc_try_remove_lext_of(unr_ctx, lextid_of(&ulink));
		if (err) {
			return err;
		}
		voff = silofs_vrange_next(&vrange, voff);
	}
	return 0;
}

static int
unrc_post_unrefs_at_super(struct silofs_unref_ctx *unr_ctx,
                          const struct silofs_walk_iter *witr)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_sproot_of(witr->sbi, witr->vspace, &uaddr);
	if (err) {
		return err;
	}
	err = unrc_try_remove_lext_of(unr_ctx, uaddr_lextid(&uaddr));
	if (err) {
		return err;
	}
	return 0;
}

static int unrc_post_unrefs_at(struct silofs_unref_ctx *unr_ctx,
                               const struct silofs_walk_iter *witr)
{
	int err;

	switch (witr->height) {
	case SILOFS_HEIGHT_BOOT:
		err = 0;
		break;
	case SILOFS_HEIGHT_SUPER:
		err = unrc_post_unrefs_at_super(unr_ctx, witr);
		break;
	case SILOFS_HEIGHT_SPNODE4:
		err = unrc_post_unrefs_at_spnode(unr_ctx, witr->sni4);
		break;
	case SILOFS_HEIGHT_SPNODE3:
		err = unrc_post_unrefs_at_spnode(unr_ctx, witr->sni3);
		break;
	case SILOFS_HEIGHT_SPNODE2:
		err = unrc_post_unrefs_at_spnode(unr_ctx, witr->sni2);
		break;
	case SILOFS_HEIGHT_SPNODE1:
		err = unrc_post_unrefs_at_spnode(unr_ctx, witr->sni1);
		break;
	case SILOFS_HEIGHT_SPLEAF:
		err = unrc_post_unrefs_at_spleaf(unr_ctx, witr->sli);
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
                                const struct silofs_walk_iter *witr)
{
	return unrc_exec_unrefs_at(unr_ctx_of(vis), witr);
}

static int unrc_visit_post_hook(struct silofs_visitor *vis,
                                const struct silofs_walk_iter *witr)
{
	return unrc_post_unrefs_at(unr_ctx_of(vis), witr);
}

static void unrc_init(struct silofs_unref_ctx *unr_ctx,
                      const struct silofs_sb_info *sbi)
{
	const struct silofs_uaddr *uaddr = sbi_uaddr(sbi);

	silofs_memzero(unr_ctx, sizeof(*unr_ctx));
	unr_ctx->vis.exec_hook = unrc_visit_exec_hook;
	unr_ctx->vis.post_hook = unrc_visit_post_hook;
	unr_ctx->fsenv = sbi_fsenv(sbi);
	uaddr_assign(&unr_ctx->sb_uaddr, uaddr);
}

static void unrc_fini(struct silofs_unref_ctx *unr_ctx)
{
	silofs_memffff(unr_ctx, sizeof(*unr_ctx));
	unr_ctx->fsenv = NULL;
}

static int unrc_remove_super(const struct silofs_unref_ctx *unr_ctx)
{
	const struct silofs_lextid *lextid = uaddr_lextid(&unr_ctx->sb_uaddr);

	return unrc_try_remove_lext_of(unr_ctx, lextid);
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
