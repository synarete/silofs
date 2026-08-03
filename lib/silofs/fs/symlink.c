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

struct silofs_symlnk_ctx {
	const struct silofs_task_ctx *task;
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
	return silofs_min(len, SILOFS_SYMVAL_HEAD_MAX);
}

static size_t tail_size(size_t len)
{
	return silofs_min(len, SILOFS_SYMVAL_TAIL_MAX);
}

static void
split_symval(const struct silofs_strview *symval,
             struct silofs_strview *out_head, struct silofs_strview *out_tail)
{
	const char *val  = symval->str;
	const size_t len = symval->len;
	size_t rem;

	silofs_strview_initn(out_head, val, head_size(len));

	val = next_part(val, out_head->len);
	rem = len - out_head->len;

	silofs_strview_initn(out_tail, val, tail_size(rem));
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

static void lnkin_tail_laddr(const struct silofs_inode_lnk *lnkin,
                             struct silofs_laddr *out_laddr)
{
	silofs_laddr64_xtoh(&lnkin->l_tail, out_laddr);
}

static void lnkin_set_tail_laddr(struct silofs_inode_lnk *lnkin,
                                 const struct silofs_laddr *laddr)
{
	silofs_laddr64_htox(&lnkin->l_tail, laddr);
}

static void lnkin_reset_tail_laddr(struct silofs_inode_lnk *lnkin)
{
	lnkin_set_tail_laddr(lnkin, silofs_laddr_none());
}

static void lnkin_setup(struct silofs_inode_lnk *lnkin)
{
	silofs_memzero(lnkin->l_head, sizeof(lnkin->l_head));
	lnkin_reset_tail_laddr(lnkin);
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

static const void *lnk_symval_head(const struct silofs_inode_info *lnk_ii)
{
	return lnkin_head_value(lnkin_of(lnk_ii));
}

static void lnk_assign_symval_head(const struct silofs_inode_info *lnk_ii,
                                   const void *val, size_t len)
{
	lnkin_set_head_value(lnkin_of(lnk_ii), val, len);
}

static int lnk_get_symval_tail(const struct silofs_inode_info *lnk_ii,
                               struct silofs_laddr *out_laddr)
{
	lnkin_tail_laddr(lnkin_of(lnk_ii), out_laddr);
	return !silofs_laddr_isnull(out_laddr) ? 0 : -SILOFS_ENOENT;
}

static void lnk_set_symval_tail(struct silofs_inode_info *lnk_ii,
                                const struct silofs_laddr *laddr)
{
	lnkin_set_tail_laddr(lnkin_of(lnk_ii), laddr);
}

static void lnk_reset_symval_tail(struct silofs_inode_info *lnk_ii)
{
	lnk_set_symval_tail(lnk_ii, silofs_laddr_none());
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr *
svi_laddr(const struct silofs_symval_info *svi)
{
	return silofs_lni_laddr(&svi->svn_lni);
}

static void
svi_setup_by(struct silofs_symval_info *svi, struct silofs_inode_info *ii,
             const struct silofs_strview *sv)
{
	svn_init(svi->svn, ii->i_ino, sv->str, sv->len);
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
	constexpr size_t head_max = SILOFS_SYMVAL_HEAD_MAX;
	constexpr size_t tail_max = SILOFS_SYMVAL_TAIL_MAX;
	const ino_t parent_ino    = svn_parent(svi->svn);
	const ino_t owner_ino     = sl_ctx->lnk_ii->i_ino;
	size_t tail_len, value_len;

	if (parent_ino != owner_ino) {
		log_err("bad symval ino: owner_ino=%lu parent_ino=%lu",
		        owner_ino, parent_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	tail_len = svn_length(svi->svn);
	if (!tail_len || (tail_len > tail_max)) {
		log_err("bad symval length: owner_ino=%lu symval_len=%zu",
		        owner_ino, tail_len);
		return -SILOFS_EFSCORRUPTED;
	}
	value_len = lnk_value_length(sl_ctx->lnk_ii);
	if ((value_len <= head_max) || ((head_max + tail_len) != value_len)) {
		log_err("symval length mismatch: owner_ino=%lu value_len=%zu "
		        "tail_len=%zu head_max=%zu",
		        owner_ino, value_len, tail_len, head_max);
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

static int slc_stage_symval_at(const struct silofs_symlnk_ctx *sl_ctx,
                               const struct silofs_laddr *laddr,
                               struct silofs_symval_info **out_svi)
{
	return silofs_stage_symval(sl_ctx->task, laddr, sl_ctx->lnk_ii,
	                           sl_ctx->stg_mode, out_svi);
}

static int slc_stage_symval(const struct silofs_symlnk_ctx *sl_ctx,
                            const struct silofs_laddr *laddr,
                            struct silofs_symval_info **out_svi)
{
	int err;

	err = slc_stage_symval_at(sl_ctx, laddr, out_svi);
	return_if_err(err);

	err = slc_recheck_symval(sl_ctx, *out_svi);
	return_if_err(err);

	return 0;
}

static int
append_symval(struct silofs_bytebuf *bbuf, const void *val, size_t len)
{
	const size_t ncp = silofs_bytebuf_append(bbuf, val, len);

	return (ncp != len) ? -SILOFS_ERANGE : 0;
}

static size_t slc_symval_head_length(const struct silofs_symlnk_ctx *sl_ctx)
{
	const size_t symval_len = lnk_value_length(sl_ctx->lnk_ii);

	return silofs_min(symval_len, SILOFS_SYMVAL_HEAD_MAX);
}

static int slc_extern_symval_head(const struct silofs_symlnk_ctx *sl_ctx,
                                  struct silofs_bytebuf *bbuf)
{
	const void *val  = lnk_symval_head(sl_ctx->lnk_ii);
	const size_t len = slc_symval_head_length(sl_ctx);

	return append_symval(bbuf, val, len);
}

static bool slc_has_symval_tail(const struct silofs_symlnk_ctx *sl_ctx)
{
	const size_t len = lnk_value_length(sl_ctx->lnk_ii);

	return (len > SILOFS_SYMVAL_HEAD_MAX);
}

static int slc_resolve_symval_tail(const struct silofs_symlnk_ctx *sl_ctx,
                                   struct silofs_laddr *out_laddr)
{
	int err;

	err = lnk_get_symval_tail(sl_ctx->lnk_ii, out_laddr);
	return (err == -SILOFS_ENOENT) ? -SILOFS_EFSCORRUPTED : 0;
}

static int slc_extern_symval_tail(const struct silofs_symlnk_ctx *sl_ctx,
                                  struct silofs_bytebuf *bbuf)
{
	struct silofs_laddr laddr;
	struct silofs_symval_info *svi = nullptr;
	size_t len;
	int err;

	if (slc_has_symval_tail(sl_ctx)) {
		err = slc_resolve_symval_tail(sl_ctx, &laddr);
		return_if_err(err);

		err = slc_stage_symval(sl_ctx, &laddr, &svi);
		return_if_err(err);

		len = svn_length(svi->svn);
		err = append_symval(bbuf, svn_value(svi->svn), len);
		return_if_err(err);
	}
	return 0;
}

static int slc_extern_symval(const struct silofs_symlnk_ctx *sl_ctx,
                             struct silofs_bytebuf *bbuf)
{
	int err;

	err = slc_extern_symval_head(sl_ctx, bbuf);
	return_if_err(err);

	err = slc_extern_symval_tail(sl_ctx, bbuf);
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

int silofs_do_readlink(const struct silofs_task_ctx *task,
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

static void slc_add_svi_to_predq(const struct silofs_symlnk_ctx *sl_ctx,
                                 struct silofs_symval_info *svi)
{
	const struct silofs_core_refs *corefs = sl_ctx->task->corefs;

	silofs_add_to_predq(corefs->iis_predq, sl_ctx->lnk_ii, &svi->svn_lni);
}

static int slc_create_symval(const struct silofs_symlnk_ctx *sl_ctx,
                             const struct silofs_strview *sv,
                             struct silofs_symval_info **out_svi)
{
	int err;

	err = slc_spawn_symval(sl_ctx, out_svi);
	return_if_err(err);

	svi_setup_by(*out_svi, sl_ctx->lnk_ii, sv);
	slc_add_svi_to_predq(sl_ctx, *out_svi);
	return 0;
}

static int slc_assign_symval_head(const struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_strview *sv_head)
{
	struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;

	lnk_assign_symval_head(lnk_ii, sv_head->str, sv_head->len);
	silofs_ii_setdirty(lnk_ii);
	return 0;
}

static void slc_update_iblocks_by(const struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_laddr *laddr)
{

	silofs_update_iblocks(sl_ctx->task, sl_ctx->lnk_ii, laddr->ltype, 1);
}

static void slc_bind_tail_symval(const struct silofs_symlnk_ctx *sl_ctx,
                                 const struct silofs_symval_info *svi)
{
	if (svi != nullptr) {
		const struct silofs_laddr *laddr = svi_laddr(svi);

		lnk_set_symval_tail(sl_ctx->lnk_ii, laddr);
		slc_update_iblocks_by(sl_ctx, laddr);
	} else {
		lnk_reset_symval_tail(sl_ctx->lnk_ii);
	}
}

static int slc_assign_symval_tail(const struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_strview *sv_tail)
{
	struct silofs_symval_info *svi = nullptr;
	int err;

	if (sv_tail->len > 0) {
		err = slc_create_symval(sl_ctx, sv_tail, &svi);
		return_if_err(err);
	}

	slc_bind_tail_symval(sl_ctx, svi);
	return 0;
}

static int slc_assign_symval(const struct silofs_symlnk_ctx *sl_ctx)
{
	struct silofs_strview head, tail;
	int err;

	split_symval(sl_ctx->symval, &head, &tail);

	err = slc_assign_symval_head(sl_ctx, &head);
	return_if_err(err);

	err = slc_assign_symval_tail(sl_ctx, &tail);
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

int silofs_bind_symval(const struct silofs_task_ctx *task,
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

static int slc_drop_symval_tail(const struct silofs_symlnk_ctx *sl_ctx)
{
	struct silofs_laddr laddr;
	int err;

	if (slc_has_symval_tail(sl_ctx)) {
		err = slc_resolve_symval_tail(sl_ctx, &laddr);
		return_if_err(err);

		err = slc_remove_symval_at(sl_ctx, &laddr);
		return_if_err(err);
	}
	return 0;
}

int silofs_drop_symlink(const struct silofs_task_ctx *task,
                        struct silofs_inode_info *lnk_ii)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task     = task,
		.lnk_ii   = lnk_ii,
		.stg_mode = SILOFS_STG_COW,
	};
	int err;

	silofs_ii_incref(lnk_ii);
	err = slc_drop_symval_tail(&sl_ctx);
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
	const size_t symval_len = svn_length(svn);

	if ((symval_len == 0) || (symval_len > SILOFS_SYMVAL_TAIL_MAX)) {
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
