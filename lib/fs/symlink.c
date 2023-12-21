/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as pfsenvlnhed by
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

struct silofs_symval_desc {
	struct silofs_substr head;
	struct silofs_substr parts[SILOFS_SYMLNK_NPARTS];
	size_t nparts;
};

struct silofs_symlnk_ctx {
	struct silofs_task             *task;
	struct silofs_sb_info          *sbi;
	struct silofs_inode_info       *lnk_ii;
	const struct silofs_substr     *symval;
	enum silofs_stg_mode            stg_mode;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *next_part(const char *val, size_t len)
{
	return (val != NULL) ? (val + len) : NULL;
}

static size_t head_size(size_t len)
{
	return min(len, SILOFS_SYMLNK_HEAD_MAX);
}

static size_t part_size(size_t len)
{
	return min(len, SILOFS_SYMLNK_PART_MAX);
}

static int symval_desc_setup(struct silofs_symval_desc *sv_dsc,
                             const char *val, size_t len)
{
	struct silofs_substr *str;
	size_t rem;

	silofs_memzero(sv_dsc, sizeof(*sv_dsc));
	sv_dsc->nparts = 0;

	str = &sv_dsc->head;
	silofs_substr_init_rd(str, val, head_size(len));

	val = next_part(val, str->len);
	rem = len - str->len;
	while (rem > 0) {
		if (sv_dsc->nparts == ARRAY_SIZE(sv_dsc->parts)) {
			return -SILOFS_ENAMETOOLONG;
		}
		str = &sv_dsc->parts[sv_dsc->nparts++];
		silofs_substr_init_rd(str, val, part_size(rem));

		val = next_part(val, str->len);
		rem -= str->len;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t symv_parent(const struct silofs_symlnk_value *symv)
{
	return silofs_ino_to_cpu(symv->sy_parent);
}

static void symv_set_parent(struct silofs_symlnk_value *symv, ino_t parent)
{
	symv->sy_parent = silofs_cpu_to_ino(parent);
}

static void symv_set_length(struct silofs_symlnk_value *symv, size_t length)
{
	symv->sy_length = silofs_cpu_to_le16((uint16_t)length);
}

static const void *symv_value(const struct silofs_symlnk_value *symv)
{
	return symv->sy_value;
}

static void symv_set_value(struct silofs_symlnk_value *symv,
                           const void *value, size_t length)
{
	memcpy(symv->sy_value, value, length);
}

static void symv_init(struct silofs_symlnk_value *symv, ino_t parent,
                      const char *value, size_t length)
{
	symv_set_parent(symv, parent);
	symv_set_length(symv, length);
	symv_set_value(symv, value, length);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const void *inln_head_value(const struct silofs_inode_lnk *inln)
{
	return inln->l_head;
}

static void inln_set_head_value(struct silofs_inode_lnk *inln,
                                const void *value, size_t length)
{
	memcpy(inln->l_head, value, length);
}

static void inln_tail_part(const struct silofs_inode_lnk *inln, size_t slot,
                           struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_xtoh(&inln->l_tail[slot], out_vaddr);
}

static void inln_set_tail_part(struct silofs_inode_lnk *inln, size_t slot,
                               const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_htox(&inln->l_tail[slot], vaddr);
}

static void inln_reset_tail_part(struct silofs_inode_lnk *inln, size_t slot)
{
	inln_set_tail_part(inln, slot, vaddr_none());
}

static void inln_setup(struct silofs_inode_lnk *inln)
{
	memset(inln->l_head, 0, sizeof(inln->l_head));
	for (size_t slot = 0; slot < ARRAY_SIZE(inln->l_tail); ++slot) {
		inln_reset_tail_part(inln, slot);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_lnk *inln_of(const struct silofs_inode_info *ii)
{
	struct silofs_inode *inode = ii->inode;

	return &inode->i_ta.l;
}

static size_t lnk_value_length(const struct silofs_inode_info *lnk_ii)
{
	return (size_t)ii_size(lnk_ii);
}

static const void *lnk_value_head(const struct silofs_inode_info *lnk_ii)
{
	return inln_head_value(inln_of(lnk_ii));
}

static void lnk_assign_value_head(const struct silofs_inode_info *lnk_ii,
                                  const void *val, size_t len)
{
	inln_set_head_value(inln_of(lnk_ii), val, len);
}

static int lnk_get_value_part(const struct silofs_inode_info *lnk_ii,
                              size_t slot, struct silofs_vaddr *out_vaddr)
{
	inln_tail_part(inln_of(lnk_ii), slot, out_vaddr);
	return !vaddr_isnull(out_vaddr) ? 0 : -SILOFS_ENOENT;
}

static void lnk_set_value_part(struct silofs_inode_info *lnk_ii, size_t slot,
                               const struct silofs_vaddr *vaddr)
{
	inln_set_tail_part(inln_of(lnk_ii), slot, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_vaddr *
syi_vaddr(const struct silofs_symval_info *syi)
{
	return vi_vaddr(&syi->sy_vi);
}

static void syi_dirtify(struct silofs_symval_info *syi,
                        struct silofs_inode_info *ii)
{
	vi_dirtify(&syi->sy_vi, ii);
}

static int syi_recheck_symval(struct silofs_symval_info *syi)
{
	if (syi->sy_vi.v_lni.l_flags & SILOFS_LNF_RECHECK) {
		return 0;
	}
	/* TODO: recheck */
	syi->sy_vi.v_lni.l_flags |= SILOFS_LNF_RECHECK;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int slc_check_symlnk(const struct silofs_symlnk_ctx *sl_ctx)
{
	if (ii_isdir(sl_ctx->lnk_ii)) {
		return -SILOFS_EISDIR;
	}
	if (!ii_islnk(sl_ctx->lnk_ii)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int slc_do_stage_symval(const struct silofs_symlnk_ctx *sl_ctx,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_symval_info **out_syi)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_symval_info *syi = NULL;
	int err;

	err = silofs_stage_vnode(sl_ctx->task, sl_ctx->lnk_ii,
	                         vaddr, sl_ctx->stg_mode, &vi);
	if (err) {
		return err;
	}
	syi = silofs_syi_from_vi(vi);
	err = syi_recheck_symval(syi);
	if (err) {
		return err;
	}
	*out_syi = syi;
	return 0;
}

static int slc_stage_symval(const struct silofs_symlnk_ctx *sl_ctx,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_symval_info **out_syi)
{
	int ret;

	ii_incref(sl_ctx->lnk_ii);
	ret = slc_do_stage_symval(sl_ctx, vaddr, out_syi);
	ii_decref(sl_ctx->lnk_ii);
	return ret;
}

static int
slc_extern_symval_head(const struct silofs_symlnk_ctx *sl_ctx,
                       const struct silofs_symval_desc *sv_dsc,
                       struct silofs_bytebuf *buf)
{
	const struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;

	silofs_bytebuf_append(buf, lnk_value_head(lnk_ii), sv_dsc->head.len);
	return 0;
}

static int
slc_extern_symval_parts(const struct silofs_symlnk_ctx *sl_ctx,
                        const struct silofs_symval_desc *sv_dsc,
                        struct silofs_bytebuf *buf)
{
	struct silofs_vaddr vaddr = { .off = -1 };
	struct silofs_symval_info *syi = NULL;
	const struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;
	size_t len;
	int err;

	for (size_t i = 0; i < sv_dsc->nparts; ++i) {
		err = lnk_get_value_part(lnk_ii, i, &vaddr);
		if (err) {
			return err;
		}
		err = slc_stage_symval(sl_ctx, &vaddr, &syi);
		if (err) {
			return err;
		}
		len = sv_dsc->parts[i].len;
		silofs_bytebuf_append(buf, symv_value(syi->syv), len);
	}
	return 0;
}


static int slc_extern_symval(const struct silofs_symlnk_ctx *sl_ctx,
                             struct silofs_bytebuf *buf)
{
	struct silofs_symval_desc sv_dsc;
	const struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;
	size_t len;
	int err;

	len = lnk_value_length(lnk_ii);
	err = symval_desc_setup(&sv_dsc, NULL, len);
	if (err) {
		return err;
	}
	err = slc_extern_symval_head(sl_ctx, &sv_dsc, buf);
	if (err) {
		return err;
	}
	err = slc_extern_symval_parts(sl_ctx, &sv_dsc, buf);
	if (err) {
		return err;
	}
	return 0;
}

static int slc_readlink_of(const struct silofs_symlnk_ctx *sl_ctx,
                           struct silofs_bytebuf *buf)
{
	int err;

	err = slc_check_symlnk(sl_ctx);
	if (err) {
		return err;
	}
	err = slc_extern_symval(sl_ctx, buf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_do_readlink(struct silofs_task *task,
                       struct silofs_inode_info *lnk_ii,
                       void *ptr, size_t lim, size_t *out_len)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.lnk_ii = lnk_ii,
		.stg_mode = SILOFS_STG_CUR,
	};
	struct silofs_bytebuf sl;
	int err;

	silofs_bytebuf_init(&sl, ptr, lim);
	ii_incref(lnk_ii);
	err = slc_readlink_of(&sl_ctx, &sl);
	ii_decref(lnk_ii);
	*out_len = sl.len;
	silofs_bytebuf_fini(&sl);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int slc_spawn_symval(const struct silofs_symlnk_ctx *sl_ctx,
                            struct silofs_symval_info **out_syi)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_symval_info *syi = NULL;
	int err;

	err = silofs_spawn_vnode(sl_ctx->task, sl_ctx->lnk_ii,
	                         SILOFS_STYPE_SYMVAL, &vi);
	if (err) {
		return err;
	}
	syi = silofs_syi_from_vi(vi);
	syi_dirtify(syi, sl_ctx->lnk_ii);
	*out_syi = syi;
	return 0;
}

static int slc_remove_symval_at(const struct silofs_symlnk_ctx *sl_ctx,
                                const struct silofs_vaddr *vaddr)
{
	return silofs_remove_vnode_at(sl_ctx->task, vaddr);
}

static int slc_create_symval(struct silofs_symlnk_ctx *sl_ctx,
                             const struct silofs_substr *str,
                             struct silofs_symval_info **out_syi)
{
	struct silofs_symval_info *syi = NULL;
	const ino_t parent = ii_ino(sl_ctx->lnk_ii);
	int err;

	err = slc_spawn_symval(sl_ctx, &syi);
	if (err) {
		return err;
	}
	symv_init(syi->syv, parent, str->str, str->len);
	*out_syi = syi;
	return 0;
}

static int slc_assign_symval_head(struct silofs_symlnk_ctx *sl_ctx,
                                  const struct silofs_symval_desc *sv_dsc)
{
	struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;

	lnk_assign_value_head(lnk_ii, sv_dsc->head.str, sv_dsc->head.len);
	ii_dirtify(lnk_ii);
	return 0;
}

static void
slc_bind_symval_part(struct silofs_symlnk_ctx *sl_ctx, size_t slot,
                     const struct silofs_symval_info *syi)
{
	struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;
	const struct silofs_vaddr *vaddr = syi_vaddr(syi);
	const struct silofs_creds *creds = task_creds(sl_ctx->task);

	lnk_set_value_part(lnk_ii, slot, vaddr);
	ii_update_iblocks(lnk_ii, creds, vaddr->stype, 1);
}

static int slc_assign_symval_parts(struct silofs_symlnk_ctx *sl_ctx,
                                   const struct silofs_symval_desc *sv_dsc)
{
	struct silofs_symval_info *syi = NULL;
	int err;

	for (size_t slot = 0; slot < sv_dsc->nparts; ++slot) {
		err = slc_create_symval(sl_ctx, &sv_dsc->parts[slot], &syi);
		if (err) {
			return err;
		}
		slc_bind_symval_part(sl_ctx, slot, syi);
	}
	return 0;
}

static int slc_assign_symval(struct silofs_symlnk_ctx *sl_ctx)
{
	const struct silofs_substr *symval = sl_ctx->symval;
	struct silofs_symval_desc sv_dsc = { .nparts = 0 };
	int err;

	err = symval_desc_setup(&sv_dsc, symval->str, symval->len);
	if (err) {
		return err;
	}
	err = slc_assign_symval_head(sl_ctx, &sv_dsc);
	if (err) {
		return err;
	}
	err = slc_assign_symval_parts(sl_ctx, &sv_dsc);
	if (err) {
		return err;
	}
	return 0;
}

static ssize_t symval_length(const struct silofs_substr *symval)
{
	return (ssize_t)symval->len;
}

static void slc_update_post_symlink(const struct silofs_symlnk_ctx *sl_ctx)
{
	struct silofs_iattr iattr = { .ia_flags = 0 };
	struct silofs_inode_info *lnk_ii = sl_ctx->lnk_ii;
	const struct silofs_creds *creds = task_creds(sl_ctx->task);

	silofs_setup_iattr_of(&iattr, ii_ino(lnk_ii));
	iattr.ia_size = symval_length(sl_ctx->symval);
	iattr.ia_flags = SILOFS_IATTR_MCTIME | SILOFS_IATTR_SIZE;
	ii_update_iattrs(lnk_ii, creds, &iattr);
}

static int slc_symlink(struct silofs_symlnk_ctx *sl_ctx)
{
	int ret;

	ii_incref(sl_ctx->lnk_ii);
	ret = slc_check_symlnk(sl_ctx);
	if (ret) {
		goto out;
	}
	ret = slc_assign_symval(sl_ctx);
	if (ret) {
		goto out;
	}
	slc_update_post_symlink(sl_ctx);
out:
	ii_decref(sl_ctx->lnk_ii);
	return ret;
}

int silofs_setup_symlink(struct silofs_task *task,
                         struct silofs_inode_info *lnk_ii,
                         const struct silofs_substr *symval)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.lnk_ii = lnk_ii,
		.symval = symval,
		.stg_mode = SILOFS_STG_COW
	};

	return slc_symlink(&sl_ctx);
}

static int slc_drop_symval(const struct silofs_symlnk_ctx *sl_ctx)
{
	struct silofs_vaddr vaddr;
	int err;

	for (size_t i = 0; i < SILOFS_SYMLNK_NPARTS; ++i) {
		err = lnk_get_value_part(sl_ctx->lnk_ii, i, &vaddr);
		if (err == -SILOFS_ENOENT) {
			break;
		}
		err = slc_remove_symval_at(sl_ctx, &vaddr);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_drop_symlink(struct silofs_task *task,
                        struct silofs_inode_info *lnk_ii)
{
	struct silofs_symlnk_ctx sl_ctx = {
		.task = task,
		.sbi = task_sbi(task),
		.lnk_ii = lnk_ii,
	};
	int err;

	ii_incref(lnk_ii);
	err = slc_drop_symval(&sl_ctx);
	ii_decref(lnk_ii);
	return err;
}

void silofs_setup_symlnk(struct silofs_inode_info *lnk_ii)
{
	inln_setup(inln_of(lnk_ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_symlnk_value(const struct silofs_symlnk_value *symv)
{
	ino_t parent;
	int err;

	parent = symv_parent(symv);
	err = silofs_verify_ino(parent);
	if (err) {
		return err;
	}
	return 0;
}

