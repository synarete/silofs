/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as penvlnhed by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/nodes.h>
#include <silofs/vfs.h>
#include <silofs/fs.h>

struct silofs_symval_desc {
	struct silofs_strview head;
	struct silofs_strview parts[SILOFS_SYMLNK_NPARTS];
	size_t nparts;
};

struct silofs_symlnk_ctx {
	struct silofs_task_ctx *task;
	struct silofs_inode_info *lnk_ii;
	const struct silofs_strview *symval;
	enum silofs_stg_mode stg_mode;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *next_part(const char *val, size_t len)
{
	silofs_assert_not_null(val);
	return silofs_nextof2(val, len);
}

static size_t head_size(size_t len)
{
	return silofs_min(len, SILOFS_SYMLNK_HEAD_MAX);
}

static size_t part_size(size_t len)
{
	return silofs_min(len, SILOFS_SYMVAL_PART_MAX);
}

static int symval_desc_setup(struct silofs_symval_desc *sv_dsc,
                             const char *val, size_t len)
{
	struct silofs_strview *sv;
	size_t rem;

	silofs_memzero(sv_dsc, sizeof(*sv_dsc));
	sv_dsc->nparts = 0;

	sv = &sv_dsc->head;
	silofs_strview_initn(sv, val, head_size(len));

	if (val != nullptr) {
		val = next_part(val, sv->len);
	}
	rem = len - sv->len;
	while (rem > 0) {
		if (sv_dsc->nparts == ARRAY_SIZE(sv_dsc->parts)) {
			return -SILOFS_ENAMETOOLONG;
		}
		sv = &sv_dsc->parts[sv_dsc->nparts++];
		silofs_strview_initn(sv, val, part_size(rem));

		if (val != nullptr) {
			val = next_part(val, sv->len);
		}
		rem -= sv->len;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t svn_parent(const struct silofs_symval_node *svn)
{
	return silofs_ino_to_cpu(svn->svn_parent);
}

static void svn_set_parent(struct silofs_symval_node *svn, ino_t parent)
{
	svn->svn_parent = silofs_cpu_to_ino(parent);
}

static size_t svn_length(const struct silofs_symval_node *svn)
{
	return silofs_le16_to_cpu(svn->svn_length);
}

static void svn_set_length(struct silofs_symval_node *svn, size_t length)
{
	svn->svn_length = silofs_cpu_to_le16((uint16_t)length);
}

static const void *svn_value(const struct silofs_symval_node *svn)
{
	return svn->svn_value;
}

static void svn_set_value(struct silofs_symval_node *svn, //
                          const void *value, size_t length)
{
	memcpy(svn->svn_value, value, length);
}

static void svn_init(struct silofs_symval_node *svn, ino_t parent,
                     const char *value, size_t length)
{
	svn_set_parent(svn, parent);
	svn_set_length(svn, length);
	svn_set_value(svn, value, length);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const void *lnkin_head_value(const struct silofs_inode_lnk *lnkin)
{
	return lnkin->l_head;
}

static void lnkin_set_head_value(struct silofs_inode_lnk *lnkin,
                                 const void *value, size_t length)
{
	memcpy(lnkin->l_head, value, length);
}

static void lnkin_tail_part(const struct silofs_inode_lnk *lnkin, size_t slot,
                            struct silofs_laddr *out_laddr)
{
	silofs_laddr64_xtoh(&lnkin->l_tail[slot], out_laddr);
}

static void lnkin_set_tail_part(struct silofs_inode_lnk *lnkin, size_t slot,
                                const struct silofs_laddr *laddr)
{
	silofs_laddr64_htox(&lnkin->l_tail[slot], laddr);
}

static void lnkin_reset_tail_part(struct silofs_inode_lnk *lnkin, size_t slot)
{
	lnkin_set_tail_part(lnkin, slot, silofs_laddr_none());
}

static void lnkin_setup(struct silofs_inode_lnk *lnkin)
{
	memset(lnkin->l_head, 0, sizeof(lnkin->l_head));
	for (size_t slot = 0; slot < ARRAY_SIZE(lnkin->l_tail); ++slot) {
		lnkin_reset_tail_part(lnkin, slot);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_lnk *lnkin_of(const struct silofs_inode_info *ii)
{
	struct silofs_inode *inode = ii->inode;

	return &inode->i_ta.l;
}

static size_t lnk_value_length(const struct silofs_inode_info *lnk_ii)
{
	return (size_t)silofs_ii_size(lnk_ii);
}

static const void *lnk_value_head(const struct silofs_inode_info *lnk_ii)
{
	return lnkin_head_value(lnkin_of(lnk_ii));
}

static void lnk_assign_value_head(const struct silofs_inode_info *lnk_ii,
                                  const void *val, size_t len)
{
	lnkin_set_head_value(lnkin_of(lnk_ii), val, len);
}

static int lnk_get_value_part(const struct silofs_inode_info *lnk_ii,
                              size_t slot, struct silofs_laddr *out_laddr)
{
	lnkin_tail_part(lnkin_of(lnk_ii), slot, out_laddr);
	return !silofs_laddr_isnull(out_laddr) ? 0 : -SILOFS_ENOENT;
}

static void lnk_set_value_part(struct silofs_inode_info *lnk_ii, size_t slot,
                               const struct silofs_laddr *laddr)
{
	lnkin_set_tail_part(lnkin_of(lnk_ii), slot, laddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr *
svi_laddr(const struct silofs_symval_info *svi)
{
	return silofs_lni_laddr(&svi->svn_lni);
}

static void
svi_setdirty(struct silofs_symval_info *svi, struct silofs_inode_info *ii)
{
	silofs_lni_setdirty(&svi->svn_lni, ii);
}

static void
svi_setup_by(struct silofs_symval_info *svi, struct silofs_inode_info *ii,
             const struct silofs_strview *sv)
{
	svn_init(svi->svn, ii->i_ino, sv->str, sv->len);
	svi_setdirty(svi, ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int slc_check_symlnk(const struct silofs_symlnk_ctx *sl_ctx)
{
	if (silofs_ii_isdir(sl_ctx->lnk_ii)) {
		return -SILOFS_EISDIR;
	}
	if (!silofs_ii_islnk(sl_ctx->lnk_ii)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int slc_do_recheck_symval(const struct silofs_symlnk_ctx *sl_ctx,
                                 const struct silofs_symval_info *svi)
{
	const ino_t parent_ino = svn_parent(svi->svn);
	const ino_t owner_ino  = sl_ctx->lnk_ii->i_ino;
	size_t len;

	if (parent_ino != owner_ino) {
		log_err("bad symval ino: owner_ino=%lu parent_ino=%lu",
		        owner_ino, parent_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	len = svn_length(svi->svn);
	if (!len || (len > SILOFS_SYMVAL_PART_MAX)) {
		log_err("bad symval length: owner_ino=%lu len=%zu", owner_ino,
		        len);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int slc_recheck_symval(const struct silofs_symlnk_ctx *sl_ctx,
                              struct silofs_symval_info *svi)
{
	int err;

	if (silofs_lni_need_recheck(&svi->svn_lni)) {
		err = slc_do_recheck_symval(sl_ctx, svi);
		return_if_err(err);

		silofs_lni_set_rechecked(&svi->svn_lni);
	}
	return 0;
}

static int slc_stage_symval(const struct silofs_symlnk_ctx *sl_ctx,
                            const struct silofs_laddr *laddr,
                            struct silofs_symval_info **out_svi)
{
	int err;

	err = silofs_stage_symval(sl_ctx->task, laddr, sl_ctx->lnk_ii,
	                          sl_ctx->stg_mode, out_svi);
	return_if_err(err);

	err = slc_recheck_symval(sl_ctx, *out_svi);
	if (err) {
		return err;
	}
	return 0;
}

static int slc_extern_symval_head(const struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_symval_desc *sv_dsc,
                                  struct silofs_bytebuf *buf)
{
	const struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;
	size_t len, ncp;

	len = sv_dsc->head.len;
	ncp = silofs_bytebuf_append(buf, lnk_value_head(lnk_ii), len);
	return (ncp != len) ? -SILOFS_ERANGE : 0;
}

static int slc_extern_symval_parts(const struct silofs_symlnk_ctx *sl_ctx,
                                   const struct silofs_symval_desc *sv_dsc,
                                   struct silofs_bytebuf *bbuf)
{
	const struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;
	int err;

	for (size_t i = 0; i < sv_dsc->nparts; ++i) {
		struct silofs_laddr laddr      = { .off = -1 };
		struct silofs_symval_info *svi = nullptr;
		size_t len, ncp;

		err = lnk_get_value_part(lnk_ii, i, &laddr);
		return_if_err(err);

		err = slc_stage_symval(sl_ctx, &laddr, &svi);
		return_if_err(err);

		len = sv_dsc->parts[i].len;
		ncp = silofs_bytebuf_append(bbuf, svn_value(svi->svn), len);
		if (ncp != len) {
			return -SILOFS_ERANGE;
		}
	}
	return 0;
}

static int slc_extern_symval(const struct silofs_symlnk_ctx *sl_ctx,
                             struct silofs_bytebuf *bbuf)
{
	struct silofs_symval_desc sv_dsc;
	size_t len;
	int err;

	len = lnk_value_length(sl_ctx->lnk_ii);
	err = symval_desc_setup(&sv_dsc, nullptr, len);
	return_if_err(err);

	err = slc_extern_symval_head(sl_ctx, &sv_dsc, bbuf);
	return_if_err(err);

	err = slc_extern_symval_parts(sl_ctx, &sv_dsc, bbuf);
	return_if_err(err);

	return 0;
}

static int slc_readlink_of(const struct silofs_symlnk_ctx *sl_ctx,
                           struct silofs_bytebuf *bbuf)
{
	int err;

	err = slc_check_symlnk(sl_ctx);
	return_if_err(err);

	err = slc_extern_symval(sl_ctx, bbuf);
	return_if_err(err);

	return 0;
}

int silofs_do_readlink(struct silofs_task_ctx *task,
                       struct silofs_inode_info *lnk_ii, void *ptr, size_t lim,
                       size_t *out_len)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task     = task,
		.lnk_ii   = lnk_ii,
		.stg_mode = SILOFS_STG_CUR,
	};
	struct silofs_bytebuf bbuf;
	int err;

	silofs_bytebuf_init(&bbuf, ptr, lim);
	silofs_ii_incref(lnk_ii);
	err = slc_readlink_of(&sl_ctx, &bbuf);
	silofs_ii_decref(lnk_ii);
	*out_len = bbuf.len;
	silofs_bytebuf_fini(&bbuf);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int slc_spawn_symval(const struct silofs_symlnk_ctx *sl_ctx,
                            struct silofs_symval_info **out_svi)
{
	return silofs_spawn_symval(sl_ctx->task, sl_ctx->lnk_ii, out_svi);
}

static int slc_remove_symval_at(const struct silofs_symlnk_ctx *sl_ctx,
                                const struct silofs_laddr *laddr)
{
	return silofs_remove_symval(sl_ctx->task, laddr, sl_ctx->lnk_ii);
}

static int slc_create_symval(const struct silofs_symlnk_ctx *sl_ctx,
                             const struct silofs_strview *sv,
                             struct silofs_symval_info **out_svi)
{
	int err;

	err = slc_spawn_symval(sl_ctx, out_svi);
	return_if_err(err);

	svi_setup_by(*out_svi, sl_ctx->lnk_ii, sv);
	return 0;
}

static int slc_assign_symval_head(const struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_symval_desc *sv_dsc)
{
	struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;

	lnk_assign_value_head(lnk_ii, sv_dsc->head.str, sv_dsc->head.len);
	silofs_ii_setdirty(lnk_ii);
	return 0;
}

static void slc_update_iblocks_by(const struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_laddr *laddr)
{

	silofs_update_iblocks(sl_ctx->task, sl_ctx->lnk_ii, laddr->ltype, 1);
}

static void
slc_bind_symval_part(const struct silofs_symlnk_ctx *sl_ctx, size_t slot,
                     const struct silofs_symval_info *syi)
{
	const struct silofs_laddr *laddr = svi_laddr(syi);

	lnk_set_value_part(sl_ctx->lnk_ii, slot, laddr);
	slc_update_iblocks_by(sl_ctx, laddr);
}

static int slc_assign_symval_parts(const struct silofs_symlnk_ctx *sl_ctx,
                                   const struct silofs_symval_desc *sv_dsc)
{
	int err;

	for (size_t slot = 0; slot < sv_dsc->nparts; ++slot) {
		struct silofs_symval_info *syi = nullptr;

		err = slc_create_symval(sl_ctx, &sv_dsc->parts[slot], &syi);
		return_if_err(err);

		slc_bind_symval_part(sl_ctx, slot, syi);
	}
	return 0;
}

static int slc_assign_symval(const struct silofs_symlnk_ctx *sl_ctx)
{
	const struct silofs_strview *symval = sl_ctx->symval;
	struct silofs_symval_desc sv_dsc    = {
		.nparts = 0,
	};
	int err;

	err = symval_desc_setup(&sv_dsc, symval->str, symval->len);
	return_if_err(err);

	err = slc_assign_symval_head(sl_ctx, &sv_dsc);
	return_if_err(err);

	err = slc_assign_symval_parts(sl_ctx, &sv_dsc);
	return_if_err(err);

	return 0;
}

static ssize_t symval_length(const struct silofs_strview *symval)
{
	return (ssize_t)symval->len;
}

static void slc_update_post_symlink(const struct silofs_symlnk_ctx *sl_ctx)
{
	struct silofs_iattr iattr = {
		.ia_flags = SILOFS_IATTR_NONE,
		.ia_size  = -1,
	};
	struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;

	silofs_make_iattr_of(lnk_ii, &iattr);
	iattr.ia_size  = symval_length(sl_ctx->symval);
	iattr.ia_flags = SILOFS_IATTR_MCTIME | SILOFS_IATTR_SIZE;
	silofs_update_iattrs(sl_ctx->task, lnk_ii, &iattr);
}

static int slc_do_symlink(const struct silofs_symlnk_ctx *sl_ctx)
{
	int err;

	err = slc_check_symlnk(sl_ctx);
	return_if_err(err);

	err = slc_assign_symval(sl_ctx);
	return_if_err(err);

	slc_update_post_symlink(sl_ctx);
	return 0;
}

static int slc_symlink(const struct silofs_symlnk_ctx *sl_ctx)
{
	int ret;

	silofs_ii_incref(sl_ctx->lnk_ii);
	ret = slc_do_symlink(sl_ctx);
	silofs_ii_decref(sl_ctx->lnk_ii);
	return ret;
}

int silofs_bind_symval(struct silofs_task_ctx *task,
                       struct silofs_inode_info *lnk_ii,
                       const struct silofs_strview *symval)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task     = task,
		.lnk_ii   = lnk_ii,
		.symval   = symval,
		.stg_mode = SILOFS_STG_COW,
	};

	return slc_symlink(&sl_ctx);
}

static int slc_drop_symval(const struct silofs_symlnk_ctx *sl_ctx)
{
	struct silofs_laddr laddr;
	int err;

	for (size_t i = 0; i < SILOFS_SYMLNK_NPARTS; ++i) {
		err = lnk_get_value_part(sl_ctx->lnk_ii, i, &laddr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		err = slc_remove_symval_at(sl_ctx, &laddr);
		return_if_err(err);
	}
	return 0;
}

int silofs_drop_symlink(struct silofs_task_ctx *task,
                        struct silofs_inode_info *lnk_ii)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task     = task,
		.lnk_ii   = lnk_ii,
		.stg_mode = SILOFS_STG_COW,
	};
	int err;

	silofs_ii_incref(lnk_ii);
	err = slc_drop_symval(&sl_ctx);
	silofs_ii_decref(lnk_ii);
	return err;
}

void silofs_ii_setup_symlnk(struct silofs_inode_info *lnk_ii)
{
	lnkin_setup(lnkin_of(lnk_ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int svn_verify_parent(const struct silofs_symval_node *svn)
{
	const ino_t parent = svn_parent(svn);

	return silofs_verify_ino(parent);
}

static int svn_verify_length(const struct silofs_symval_node *svn)
{
	const size_t len = svn_length(svn);

	if ((len == 0) || (len > SILOFS_SYMVAL_PART_MAX)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

int silofs_verify_symval_node(const struct silofs_symval_node *svn)
{
	int err;

	err = svn_verify_parent(svn);
	return_if_err(err);

	err = svn_verify_length(svn);
	return_if_err(err);

	return 0;
}
