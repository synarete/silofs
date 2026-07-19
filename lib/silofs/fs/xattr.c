/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <limits.h>
#include <inttypes.h>

#include <silofs/nodes.h>
#include <silofs/fs.h>

#define XATTR_DATA_MAX (SILOFS_NAME_MAX + 1 + SILOFS_XATTR_VALUE_MAX)

#define XATTRF_DISABLE (0x01)
#define XATTRF_ACL     (0x02)

#define XATTR_PREFIX_(p_, n_, f_) \
	{                         \
		.prefix = (p_),   \
		.ns = (n_),       \
		.flags = (f_),    \
	}

#define XATTR_PREFIX_NORMAL(p_, n_) XATTR_PREFIX_(p_, n_, 0)

#define XATTR_PREFIX_ACL(p_, n_) XATTR_PREFIX_(p_, n_, XATTRF_ACL)

#define XATTR_PREFIX_DISABLED(p_, n_) XATTR_PREFIX_(p_, n_, XATTRF_DISABLE)

struct silofs_xentry_view {
	struct silofs_xattr_entry xe;
	uint8_t xe_data[XATTR_DATA_MAX];
} silofs_attr_aligned8;

struct silofs_xattr_prefix {
	const char *prefix;
	enum silofs_xattr_ns ns;
	int flags;
};

struct silofs_xentry_info {
	struct silofs_xanode_info *xai;
	struct silofs_xattr_entry *xe;
};

struct silofs_xattr_ctx {
	struct silofs_task_ctx *task;
	struct silofs_listxattr_ctx *lxa_ctx;
	struct silofs_inode_info *ii;
	const struct silofs_namestr *name;
	struct silofs_bytebuf value;
	size_t size;
	int flags;
	enum silofs_stg_mode stg_mode;
	bool kill_sgid;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO: For well-known xattr prefix, do not store the prefix-part as string
 * but as 'enum silofs_xattr_ns' value within 'xe_namespace'.
 */
static const struct silofs_xattr_prefix s_xattr_prefix[] = {
	XATTR_PREFIX_ACL(XATTR_SECURITY_PREFIX, SILOFS_XATTR_SECURITY),
	XATTR_PREFIX_ACL(XATTR_SYSTEM_PREFIX, SILOFS_XATTR_SYSTEM),
	XATTR_PREFIX_ACL(XATTR_TRUSTED_PREFIX, SILOFS_XATTR_TRUSTED),
	XATTR_PREFIX_NORMAL(XATTR_USER_PREFIX, SILOFS_XATTR_USER),
	XATTR_PREFIX_DISABLED(XATTR_HURD_PREFIX, SILOFS_XATTR_GNU),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t xe_aligned_size(size_t size)
{
	const size_t align = sizeof(struct silofs_xattr_entry);

	return (align * silofs_div_round_up(size, align));
}

static size_t xe_calc_payload_nents(size_t name_len, size_t value_size)
{
	const size_t payload_size =
		xe_aligned_size(name_len) + xe_aligned_size(value_size);

	return payload_size / sizeof(struct silofs_xattr_entry);
}

static size_t xe_calc_nents(size_t name_len, size_t value_size)
{
	return 1 + xe_calc_payload_nents(name_len, value_size);
}

static size_t xe_calc_nents_of(const struct silofs_strview *name,
                               const struct silofs_bytebuf *value)
{
	return xe_calc_nents(name->len, value->len);
}

static size_t xe_diff(const struct silofs_xattr_entry *beg,
                      const struct silofs_xattr_entry *end)
{
	return (size_t)(end - beg);
}

static struct silofs_xattr_entry *
xe_unconst(const struct silofs_xattr_entry *xe)
{
	return silofs_unconst(xe);
}

static struct silofs_xentry_view *
xe_view_of(const struct silofs_xattr_entry *xe)
{
	const struct silofs_xentry_view *xe_view =
		container_of(xe, struct silofs_xentry_view, xe);

	return silofs_unconst(xe_view);
}

static size_t xe_name_len(const struct silofs_xattr_entry *xe)
{
	return silofs_le16_to_cpu(xe->xe_name_len);
}

static void xe_set_name_len(struct silofs_xattr_entry *xe, size_t name_len)
{
	xe->xe_name_len = silofs_cpu_to_le16((uint16_t)name_len);
}

static size_t xe_value_size(const struct silofs_xattr_entry *xe)
{
	return silofs_le32_to_cpu(xe->xe_value_size);
}

static void xe_set_value_size(struct silofs_xattr_entry *xe, size_t value_size)
{
	xe->xe_value_size = silofs_cpu_to_le32((uint32_t)value_size);
}

static char *xe_name(const struct silofs_xattr_entry *xe)
{
	struct silofs_xentry_view *xeview = xe_view_of(xe);

	return (char *)xeview->xe_data;
}

static void *xe_value(const struct silofs_xattr_entry *xe)
{
	struct silofs_xentry_view *xeview = xe_view_of(xe);
	size_t name_len, aligned_size;

	name_len     = xe_name_len(xe);
	aligned_size = xe_aligned_size(name_len);

	return silofs_nextof(xeview->xe_data, aligned_size);
}

static bool xe_has_name(const struct silofs_xattr_entry *xe,
                        const struct silofs_strview *name)
{
	return (name->len == xe_name_len(xe)) &&
	       !memcmp(xe_name(xe), name->str, name->len);
}

static size_t xe_nents(const struct silofs_xattr_entry *xe)
{
	return xe_calc_nents(xe_name_len(xe), xe_value_size(xe));
}

static struct silofs_xattr_entry *xe_next(const struct silofs_xattr_entry *xe)
{
	return xe_unconst(xe + xe_nents(xe));
}

static void
xe_assign(struct silofs_xattr_entry *xe, const struct silofs_strview *name,
          const struct silofs_bytebuf *value)
{
	xe_set_name_len(xe, name->len);
	xe_set_value_size(xe, value->len);
	memcpy(xe_name(xe), name->str, name->len);
	if ((value->len > 0) && (value->ptr != nullptr)) {
		memcpy(xe_value(xe), value->ptr, value->len);
	}
}

static void xe_reset(struct silofs_xattr_entry *xe)
{
	silofs_memzero(xe, sizeof(*xe));
}

static void xe_reset_arr(struct silofs_xattr_entry *xe, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		xe_reset(&xe[i]);
	}
}

static void xe_squeeze(struct silofs_xattr_entry *xe,
                       const struct silofs_xattr_entry *last)
{
	const struct silofs_xattr_entry *next = xe_next(xe);
	size_t nshift, nclear;

	nshift = xe_diff(next, last);
	nclear = xe_diff(xe, next);
	memmove(xe, next, nshift * sizeof(*xe));
	memset(xe + nshift, 0, nclear * sizeof(*xe));
}

static void
xe_copy_value(const struct silofs_xattr_entry *xe, struct silofs_bytebuf *buf)
{
	silofs_bytebuf_append(buf, xe_value(xe), xe_value_size(xe));
}

static struct silofs_xattr_entry *
xe_search(const struct silofs_xattr_entry *itr,
          const struct silofs_xattr_entry *end,
          const struct silofs_strview *name)
{
	while (itr < end) {
		if (xe_has_name(itr, name)) {
			return silofs_unconst(itr);
		}
		itr = xe_next(itr);
	}
	return nullptr;
}

static bool xe_may_append(const struct silofs_xattr_entry *xe,
                          const struct silofs_xattr_entry *end,
                          const struct silofs_strview *name,
                          const struct silofs_bytebuf *value)
{
	const size_t nfree = xe_diff(xe, end);
	const size_t nents = xe_calc_nents_of(name, value);

	return (nfree >= nents);
}

static struct silofs_xattr_entry *
xe_append(struct silofs_xattr_entry *xe, const struct silofs_xattr_entry *end,
          const struct silofs_strview *name,
          const struct silofs_bytebuf *value)
{
	const size_t nfree = xe_diff(xe, end);
	const size_t nents = xe_calc_nents_of(name, value);

	if (nfree < nents) {
		return nullptr;
	}
	xe_assign(xe, name, value);
	return xe;
}

static int xe_verify(const struct silofs_xattr_entry *xe)
{
	size_t name_len;
	size_t value_size;

	name_len = xe_name_len(xe);
	if (!name_len || (name_len > SILOFS_NAME_MAX)) {
		return -SILOFS_EFSCORRUPTED;
	}
	value_size = xe_value_size(xe);
	if (value_size > SILOFS_XATTR_VALUE_MAX) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int xe_verify_range(const struct silofs_xattr_entry *xe,
                           const struct silofs_xattr_entry *end)
{
	const struct silofs_xattr_entry *itr = xe;
	size_t nents;
	int err;

	while (itr < end) {
		err = xe_verify(itr);
		if (err) {
			return err;
		}
		nents = xe_nents(itr);
		if (!nents || ((itr + nents) > end)) {
			return -SILOFS_EFSCORRUPTED;
		}
		itr += nents;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t xan_ino(const struct silofs_xattr_node *xan)
{
	return silofs_ino_to_cpu(xan->xa_ino);
}

static void xan_set_ino(struct silofs_xattr_node *xan, ino_t ino)
{
	xan->xa_ino = silofs_cpu_to_ino(ino);
}

static size_t xan_nents(const struct silofs_xattr_node *xan)
{
	return silofs_le16_to_cpu(xan->xa_nents);
}

static void xan_set_nents(struct silofs_xattr_node *xan, size_t n)
{
	xan->xa_nents = silofs_cpu_to_le16((uint16_t)n);
}

static void xan_inc_nents(struct silofs_xattr_node *xan, size_t n)
{
	xan_set_nents(xan, xan_nents(xan) + n);
}

static void xan_dec_nents(struct silofs_xattr_node *xan, size_t n)
{
	xan_set_nents(xan, xan_nents(xan) - n);
}

static void xan_setup(struct silofs_xattr_node *xan, ino_t ino)
{
	xan_set_ino(xan, ino);
	xan_set_nents(xan, 0);
	xe_reset_arr(xan->xe, ARRAY_SIZE(xan->xe));
}

static struct silofs_xattr_entry *xan_beg(const struct silofs_xattr_node *xan)
{
	return xe_unconst(xan->xe);
}

static const struct silofs_xattr_entry *
xan_end(const struct silofs_xattr_node *xan)
{
	return xan->xe + ARRAY_SIZE(xan->xe);
}

static struct silofs_xattr_entry *xan_tip(const struct silofs_xattr_node *xan)
{
	return xe_unconst(xan->xe) + xan_nents(xan);
}

static struct silofs_xattr_entry *
xan_search(const struct silofs_xattr_node *xan,
           const struct silofs_strview *str)
{
	struct silofs_xattr_entry *xe = nullptr;
	size_t nmin;

	nmin = xe_calc_nents(str->len, 0);
	if (xan_nents(xan) >= nmin) {
		xe = xe_search(xan_beg(xan), xan_tip(xan), str);
	}
	return xe;
}

static struct silofs_xattr_entry *
xan_insert(struct silofs_xattr_node *xan, const struct silofs_strview *name,
           const struct silofs_bytebuf *value)
{
	struct silofs_xattr_entry *xe        = xan_tip(xan);
	const struct silofs_xattr_entry *end = xan_end(xan);

	if (!xe_may_append(xe, end, name, value)) {
		return nullptr;
	}
	xe_append(xe, end, name, value);
	xan_inc_nents(xan, xe_nents(xe));
	return xe;
}

static void
xan_remove(struct silofs_xattr_node *xan, struct silofs_xattr_entry *xe)
{
	const size_t nents = xe_nents(xe);

	xe_squeeze(xe, xan_tip(xan));
	xan_dec_nents(xan, nents);
}

static int xan_verify(const struct silofs_xattr_node *xan)
{
	int err = -SILOFS_EFSCORRUPTED;

	if (xan_nents(xan) <= ARRAY_SIZE(xan->xe)) {
		err = xe_verify_range(xan_beg(xan), xan_tip(xan));
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_inode_xattr *
inode_xattr_of(const struct silofs_inode *inode)
{
	const struct silofs_inode_xattr *ixa = &inode->i_xa;

	return silofs_unconst(ixa);
}

static struct silofs_inode_xattr *ixa_of(const struct silofs_inode_info *ii)
{
	return inode_xattr_of(ii->inode);
}

static void ixa_laddr(const struct silofs_inode_xattr *ixa, size_t slot,
                      struct silofs_laddr *out_laddr)
{
	silofs_laddr64_xtoh(&ixa->ix_laddr[slot], out_laddr);
}

static void ixa_set_laddr(struct silofs_inode_xattr *ixa, size_t slot,
                          const struct silofs_laddr *laddr)
{
	silofs_laddr64_htox(&ixa->ix_laddr[slot], laddr);
}

static void ixa_reset_laddr(struct silofs_inode_xattr *ixa, size_t slot)
{
	ixa_set_laddr(ixa, slot, silofs_laddr_none());
}

static size_t ixa_nslots_max(const struct silofs_inode_xattr *ixa)
{
	return ARRAY_SIZE(ixa->ix_laddr);
}

static void ixa_reset_slots(struct silofs_inode_xattr *ixa)
{
	const size_t nslots = ixa_nslots_max(ixa);

	for (size_t slot = 0; slot < nslots; ++slot) {
		ixa_reset_laddr(ixa, slot);
	}
}

static void ixa_setup(struct silofs_inode_xattr *ixa)
{
	ixa_reset_slots(ixa);
}

static int ixa_verify(const struct silofs_inode_xattr *ixa)
{
	int err;

	for (size_t slot = 0; slot < ARRAY_SIZE(ixa->ix_laddr); ++slot) {
		struct silofs_laddr laddr = { .off = -1 };

		ixa_laddr(ixa, slot, &laddr);
		if (!silofs_off_isnull(laddr.off)) {
			err = silofs_verify_off(laddr.off);
			return_if_err(err);

			if (laddr.ltype != SILOFS_LTYPE_XANODE) {
				return -SILOFS_EFSCORRUPTED;
			}
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t ii_xa_nslots_max(const struct silofs_inode_info *ii)
{
	return ixa_nslots_max(ixa_of(ii));
}

static void ii_xa_unset_at(struct silofs_inode_info *ii, size_t sloti)
{
	ixa_reset_laddr(ixa_of(ii), sloti);
}

static void ii_xa_get_at(const struct silofs_inode_info *ii, size_t sloti,
                         struct silofs_laddr *out_laddr)
{
	ixa_laddr(ixa_of(ii), sloti, out_laddr);
}

static void ii_xa_set_at(const struct silofs_inode_info *ii, size_t sloti,
                         const struct silofs_laddr *laddr)
{
	ixa_set_laddr(ixa_of(ii), sloti, laddr);
}

void silofs_ii_setup_xattr(struct silofs_inode_info *ii)
{
	ixa_setup(ixa_of(ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_laddr *
xai_laddr(const struct silofs_xanode_info *xai)
{
	return silofs_lni_laddr(&xai->xan_lni);
}

static void
xai_setdirty(struct silofs_xanode_info *xai, struct silofs_inode_info *ii)
{
	if (xai != nullptr) {
		silofs_lni_setdirty(&xai->xan_lni, ii);
	}
}

static void xai_incref(struct silofs_xanode_info *xai)
{
	if (likely(xai != nullptr)) {
		silofs_lni_incref(&xai->xan_lni);
	}
}

static void xai_decref(struct silofs_xanode_info *xai)
{
	if (likely(xai != nullptr)) {
		silofs_lni_decref(&xai->xan_lni);
	}
}

static void xai_setup_node(struct silofs_xanode_info *xai, ino_t ino)
{
	/* TODO: investigate this -- why gcc15.2 complains here? */
	if ((xai == nullptr) || (xai->xan == nullptr)) {
		silofs_panic("null xanode: ino=%ld", (long)ino);
	}
	xan_setup(xai->xan, ino);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void xei_discard_entry(const struct silofs_xentry_info *xei)
{
	struct silofs_xanode_info *xai = xei->xai;

	if (xai != nullptr) {
		xan_remove(xai->xan, xei->xe);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int xac_recheck_node(const struct silofs_xattr_ctx *xa_ctx,
                            struct silofs_xanode_info *xai)
{
	const ino_t owner_ino = xa_ctx->ii->i_ino;
	ino_t xanode_ino;

	if (!silofs_lni_need_recheck(&xai->xan_lni)) {
		return 0;
	}
	xanode_ino = xan_ino(xai->xan);
	if (owner_ino != xanode_ino) {
		log_err("bad xanode ino: owner_ino=%lu xanode_ino=%lu",
		        owner_ino, xanode_ino);
		return -SILOFS_EFSCORRUPTED;
	}
	silofs_lni_set_rechecked(&xai->xan_lni);
	return 0;
}
static int xac_do_stage_xanode(const struct silofs_xattr_ctx *xa_ctx,
                               const struct silofs_laddr *laddr,
                               struct silofs_xanode_info **out_xai)
{
	int err;

	err = silofs_stage_xanode2(xa_ctx->task, laddr, xa_ctx->ii,
	                           xa_ctx->stg_mode, out_xai);
	return_if_err(err);

	err = xac_recheck_node(xa_ctx, *out_xai);
	return_if_err(err);

	return 0;
}

static int xac_stage_xanode(const struct silofs_xattr_ctx *xa_ctx,
                            const struct silofs_laddr *laddr,
                            struct silofs_xanode_info **out_xai)
{
	int ret;

	silofs_ii_incref(xa_ctx->ii);
	ret = xac_do_stage_xanode(xa_ctx, laddr, out_xai);
	silofs_ii_decref(xa_ctx->ii);
	return ret;
}

static bool is_valid_xflags(int flags)
{
	return !flags || (flags == XATTR_CREATE) || (flags == XATTR_REPLACE);
}

static bool has_xattr_prefix(const struct silofs_namestr *name,
                             const struct silofs_xattr_prefix *xap)
{
	const char *prefix = xap->prefix;
	const size_t len   = silofs_str_length(prefix);
	size_t npr         = 0;
	bool ret           = false;

	if (name->sv.len > len) {
		npr = silofs_strview_ncommon_prefix(&name->sv, prefix, len);
		ret = (npr == len);
	}
	return ret;
}

static const struct silofs_xattr_prefix *
search_prefix(const struct silofs_namestr *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(s_xattr_prefix); ++i) {
		const struct silofs_xattr_prefix *xap = &s_xattr_prefix[i];

		if (has_xattr_prefix(name, xap)) {
			return xap;
		}
	}
	return nullptr;
}

static bool xac_allow_acl(const struct silofs_xattr_ctx *xa_ctx)
{
	const enum silofs_flags ctl_flags =
		xa_ctx->task->corefs->fsroot->ctl_flags;

	return (ctl_flags & SILOFS_F_ALLOW_XACL) > 0;
}

static int
xac_check_xattr_name(const struct silofs_xattr_ctx *xa_ctx, int w_mode)
{
	const struct silofs_namestr *name = xa_ctx->name;
	const struct silofs_xattr_prefix *xap;
	const size_t namelen_max = silofs_min(SILOFS_NAME_MAX, NAME_MAX);

	if (!name) {
		return 0;
	}
	if (name->sv.len > namelen_max) {
		return -SILOFS_ENAMETOOLONG;
	}
	xap = search_prefix(name);
	if (xap == nullptr)
		return 0;
	if (xap->flags & XATTRF_DISABLE)
		return -SILOFS_EINVAL;
	if (!w_mode)
		return 0;
	if ((xap->flags & XATTRF_ACL) && !xac_allow_acl(xa_ctx)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int xac_check_imode(const struct silofs_xattr_ctx *xa_ctx)
{
	const mode_t mode = silofs_ii_mode(xa_ctx->ii);

	return (S_ISCHR(mode) || S_ISBLK(mode)) ? -SILOFS_EINVAL : 0;
}

static int xac_check_size_flags(const struct silofs_xattr_ctx *xa_ctx)
{
	if (xa_ctx->size > SILOFS_XATTR_VALUE_MAX) {
		return -SILOFS_EINVAL;
	}
	if (!is_valid_xflags(xa_ctx->flags)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int xac_check_op(const struct silofs_xattr_ctx *xa_ctx, int access_mode)
{
	struct silofs_inode_info *ii = xa_ctx->ii;
	int err;

	err = xac_check_imode(xa_ctx);
	return_if_err(err);

	err = xac_check_xattr_name(xa_ctx, access_mode & W_OK);
	return_if_err(err);

	err = xac_check_size_flags(xa_ctx);
	return_if_err(err);

	err = silofs_do_access(xa_ctx->task, ii, access_mode);
	return_if_err(err);

	return 0;
}

static int xac_lookup_entry_at_node(const struct silofs_xattr_ctx *xa_ctx,
                                    const struct silofs_laddr *laddr,
                                    struct silofs_xentry_info *out_xei)
{
	struct silofs_xattr_entry *xe  = nullptr;
	struct silofs_xanode_info *xai = nullptr;
	int err;

	if (silofs_laddr_isnull(laddr)) {
		return -SILOFS_ENOENT;
	}
	err = xac_stage_xanode(xa_ctx, laddr, &xai);
	if (err) {
		return err;
	}
	xe = xan_search(xai->xan, &xa_ctx->name->sv);
	if (xe == nullptr) {
		return -SILOFS_ENOENT;
	}
	out_xei->xai = xai;
	out_xei->xe  = xe;
	return 0;
}

static int
xac_lookup_entry_at_nodes_slot(struct silofs_xattr_ctx *xa_ctx, size_t sloti,
                               struct silofs_xentry_info *out_xei)
{
	struct silofs_laddr laddr;

	ii_xa_get_at(xa_ctx->ii, sloti, &laddr);
	return xac_lookup_entry_at_node(xa_ctx, &laddr, out_xei);
}

static int xac_lookup_entry_at_nodes(struct silofs_xattr_ctx *xa_ctx,
                                     struct silofs_xentry_info *out_xei)
{
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);
	int err;

	err = -SILOFS_ENOENT;
	for (size_t sloti = 0; sloti < nslots_max; ++sloti) {
		err = xac_lookup_entry_at_nodes_slot(xa_ctx, sloti, out_xei);
		if (err != -SILOFS_ENOENT) {
			break;
		}
	}
	return err;
}

static int xac_lookup_entry_at_inode(struct silofs_xattr_ctx *xa_ctx,
                                     struct silofs_xentry_info *xei)
{
	unused(xa_ctx);
	unused(xei);
	return -SILOFS_ENOENT;
}

static int xac_lookup_entry(struct silofs_xattr_ctx *xa_ctx,
                            struct silofs_xentry_info *xei)
{
	int err;

	err = xac_lookup_entry_at_inode(xa_ctx, xei);
	if (err == -SILOFS_ENOENT) {
		err = xac_lookup_entry_at_nodes(xa_ctx, xei);
	}
	return (err == -SILOFS_ENOENT) ? -SILOFS_ENODATA : err;
}

static int xac_do_getxattr(struct silofs_xattr_ctx *xa_ctx, size_t *out_size)
{
	struct silofs_xentry_info xei = { .xe = nullptr };
	struct silofs_bytebuf *buf    = &xa_ctx->value;
	int err;

	err = xac_check_op(xa_ctx, R_OK);
	return_if_err(err);

	err = xac_lookup_entry(xa_ctx, &xei);
	return_if_err(err);

	*out_size = xe_value_size(xei.xe);
	if ((buf->cap == 0) || (buf->ptr == nullptr)) {
		return 0; /* getxattr-size only */
	}
	if ((buf->cap - buf->len) < *out_size) {
		return -SILOFS_ERANGE;
	}
	xe_copy_value(xei.xe, buf);
	return 0;
}

static int xac_getxattr(struct silofs_xattr_ctx *xa_ctx, size_t *out_size)
{
	int ret;

	silofs_ii_incref(xa_ctx->ii);
	ret = xac_do_getxattr(xa_ctx, out_size);
	silofs_ii_decref(xa_ctx->ii);
	return ret;
}

int silofs_do_getxattr(struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name, void *buf,
                       size_t size, size_t *out_size)
{
	struct silofs_xattr_ctx xa_ctx = {
		.task      = task,
		.ii        = ii,
		.name      = name,
		.value.ptr = buf,
		.value.len = 0,
		.value.cap = size,
		.stg_mode  = SILOFS_STG_CUR,
	};

	return xac_getxattr(&xa_ctx, out_size);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int xac_spawn_xanode(const struct silofs_xattr_ctx *xa_ctx,
                            struct silofs_xanode_info **out_xai)
{
	int err;

	err = silofs_spawn_xanode2(xa_ctx->task, xa_ctx->ii, out_xai);
	return_if_err(err);

	xai_setdirty(*out_xai, xa_ctx->ii);
	return 0;
}

static int
xac_spawn_bind_xanode(const struct silofs_xattr_ctx *xa_ctx, size_t slot,
                      struct silofs_xanode_info **out_xai)
{
	struct silofs_inode_info *ii   = xa_ctx->ii;
	struct silofs_xanode_info *xai = nullptr;
	int err;

	err = xac_spawn_xanode(xa_ctx, &xai);
	return_if_err(err);

	xai_setup_node(xai, ii->i_ino);

	ii_xa_set_at(ii, slot, xai_laddr(xai));
	silofs_ii_setdirty(ii);

	*out_xai = xai;
	return 0;
}

static int xac_remove_xanode_at(const struct silofs_xattr_ctx *xa_ctx,
                                const struct silofs_laddr *laddr)
{
	return silofs_remove_xanode2(xa_ctx->task, laddr, xa_ctx->ii);
}

static int xac_require_xanode(const struct silofs_xattr_ctx *xa_ctx,
                              size_t slot, struct silofs_xanode_info **out_xai)
{
	struct silofs_laddr laddr    = { .off = -1 };
	struct silofs_inode_info *ii = xa_ctx->ii;
	int err;

	ii_xa_get_at(ii, slot, &laddr);
	if (!silofs_laddr_isnull(&laddr)) {
		err = xac_stage_xanode(xa_ctx, &laddr, out_xai);
	} else {
		err = xac_spawn_bind_xanode(xa_ctx, slot, out_xai);
	}
	return err;
}

static int xac_try_insert_at(const struct silofs_xattr_ctx *xa_ctx,
                             struct silofs_xanode_info *xai,
                             struct silofs_xentry_info *xei)
{
	struct silofs_xattr_entry *xe;

	xe = xan_insert(xai->xan, &xa_ctx->name->sv, &xa_ctx->value);
	if (xe == nullptr) {
		return -SILOFS_ENOSPC;
	}
	xei->xai = xai;
	xei->xe  = xe;
	xai_setdirty(xai, xa_ctx->ii);
	return 0;
}

static int xac_try_insert_at_nodes(const struct silofs_xattr_ctx *xa_ctx,
                                   struct silofs_xentry_info *xei)
{
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);
	int err;

	for (size_t sloti = 0; sloti < nslots_max; ++sloti) {
		struct silofs_xanode_info *xai = nullptr;

		err = xac_require_xanode(xa_ctx, sloti, &xai);
		return_if_err(err);

		err = xac_try_insert_at(xa_ctx, xai, xei);
		return_if_not_err(err);
	}
	return -SILOFS_ENOSPC;
}

static int xac_try_insert_at_inode(const struct silofs_xattr_ctx *xa_ctx,
                                   struct silofs_xentry_info *xei)
{
	/*
	 * TODO-0036: Consider using short-xatts embedded within inode.
	 *
	 * Allow having fast-access to short-xattr.
	 */
	(void)xa_ctx;
	(void)xei;
	return -SILOFS_ENOSPC;
}

static int xac_setxattr_create(struct silofs_xattr_ctx *xa_ctx,
                               struct silofs_xentry_info *xei)
{
	int err;

	if ((xa_ctx->flags == XATTR_CREATE) && (xei->xe != nullptr)) {
		return -SILOFS_EEXIST;
	}
	err = xac_try_insert_at_inode(xa_ctx, xei);
	if (err != -SILOFS_ENOSPC) {
		return err;
	}

	err = xac_try_insert_at_nodes(xa_ctx, xei);
	return_if_err(err);

	return 0;
}

/*
 * TODO-0007: XATTR_REPLACE in-place
 *
 * When possible in term of space, do simple replace-overwrite.
 */
static int xac_setxattr_replace(struct silofs_xattr_ctx *xa_ctx,
                                struct silofs_xentry_info *xei)
{
	const struct silofs_xentry_info xei_cur = {
		.xai = xei->xai,
		.xe  = xei->xe,
	};
	int err;

	/* TODO: Try replace in-place */
	if ((xa_ctx->flags == XATTR_REPLACE) && (xei->xe == nullptr)) {
		return -SILOFS_ENODATA;
	}

	err = xac_setxattr_create(xa_ctx, xei);
	return_if_err(err);

	if (xei_cur.xe != nullptr) {
		xei_discard_entry(&xei_cur);
		xai_setdirty(xei_cur.xai, xa_ctx->ii);
	}
	xai_setdirty(xei->xai, xa_ctx->ii);
	return 0;
}

static int xac_setxattr_do_apply_on(struct silofs_xattr_ctx *xa_ctx,
                                    struct silofs_xentry_info *xei)
{
	if (xa_ctx->flags == XATTR_REPLACE) {
		/* explicit replace */
		return xac_setxattr_replace(xa_ctx, xei);
	}
	if (!xa_ctx->flags && xei->xe) {
		/* implicit replace */
		xa_ctx->flags = XATTR_REPLACE;
		return xac_setxattr_replace(xa_ctx, xei);
	}
	/* by-default, create */
	return xac_setxattr_create(xa_ctx, xei);
}

static int xac_setxattr_apply_on(struct silofs_xattr_ctx *xa_ctx,
                                 struct silofs_xentry_info *xei)
{
	struct silofs_xanode_info *xai = xei->xai;
	int ret;

	xai_incref(xai);
	ret = xac_setxattr_do_apply_on(xa_ctx, xei);
	xai_decref(xai);
	return ret;
}

static int xac_setxattr_apply(struct silofs_xattr_ctx *xa_ctx)
{
	struct silofs_xentry_info xei = { .xe = nullptr };
	int err;

	err = xac_lookup_entry(xa_ctx, &xei);
	if ((err == 0) || (err == -SILOFS_ENODATA)) {
		err = xac_setxattr_apply_on(xa_ctx, &xei);
	}
	return err;
}

static void xac_update_post_setxattr(const struct silofs_xattr_ctx *xa_ctx)
{
	struct silofs_iattr iattr = {
		.ia_flags = SILOFS_IATTR_NONE,
		.ia_size  = -1,
	};
	struct silofs_inode_info *ii = xa_ctx->ii;

	silofs_make_iattr_of(ii, &iattr);
	iattr.ia_flags |= SILOFS_IATTR_CTIME;
	iattr.ia_flags |= (xa_ctx->kill_sgid ? SILOFS_IATTR_KILL_SGID : 0);
	silofs_update_iattrs_of(xa_ctx->task, ii, &iattr);
}

static int xac_do_setxattr(struct silofs_xattr_ctx *xa_ctx)
{
	int err;

	err = xac_check_op(xa_ctx, W_OK);
	return_if_err(err);

	err = xac_setxattr_apply(xa_ctx);
	return_if_err(err);

	xac_update_post_setxattr(xa_ctx);
	return 0;
}

static int xac_setxattr(struct silofs_xattr_ctx *xa_ctx)
{
	int ret;

	silofs_ii_incref(xa_ctx->ii);
	ret = xac_do_setxattr(xa_ctx);
	silofs_ii_decref(xa_ctx->ii);
	return ret;
}

int silofs_do_setxattr(struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii,
                       const struct silofs_namestr *name, const void *value,
                       size_t size, int flags, bool kill_sgid)
{
	struct silofs_xattr_ctx xa_ctx = {
		.task      = task,
		.ii        = ii,
		.name      = name,
		.value.ptr = silofs_unconst(value),
		.value.len = size,
		.value.cap = size,
		.size      = size,
		.flags     = flags,
		.kill_sgid = kill_sgid,
		.stg_mode  = SILOFS_STG_COW,
	};

	return xac_setxattr(&xa_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * The special extended attributes names of "system.posix_acl_access" and
 * "system.posix_acl_default" should return 0 upon REMOVEXATTR even if they do
 * not exist on the referenced inode.
 */
static bool is_posix_acl_name(const struct silofs_namestr *name)
{
	const char *posix_acl_access  = XATTR_NAME_POSIX_ACL_ACCESS;
	const char *posix_acl_default = XATTR_NAME_POSIX_ACL_DEFAULT;

	return silofs_strview_isequal(&name->sv, posix_acl_access) ||
	       silofs_strview_isequal(&name->sv, posix_acl_default);
}

static int
xac_removexattr_retval(const struct silofs_xattr_ctx *xa_ctx, int err)
{
	int ret;

	if ((err == -SILOFS_ENODATA) && is_posix_acl_name(xa_ctx->name)) {
		ret = 0;
	} else {
		ret = err;
	}
	return ret;
}

/*
 * TODO-0003: Delete node if empty
 *
 * Free xattr-node upon last-entry remvoal and update parent-slot.
 */
static int xac_do_removexattr(struct silofs_xattr_ctx *xa_ctx)
{
	struct silofs_xentry_info xei = { .xe = nullptr };
	int err;

	err = xac_check_op(xa_ctx, W_OK);
	if (err) {
		return err;
	}
	err = xac_lookup_entry(xa_ctx, &xei);
	if (err) {
		return xac_removexattr_retval(xa_ctx, err);
	}
	xei_discard_entry(&xei);
	xai_setdirty(xei.xai, xa_ctx->ii);
	silofs_update_itimes_of(xa_ctx->task, xa_ctx->ii, SILOFS_IATTR_CTIME);
	return 0;
}

static int xac_removexattr(struct silofs_xattr_ctx *xa_ctx)
{
	int ret;

	silofs_ii_incref(xa_ctx->ii);
	ret = xac_do_removexattr(xa_ctx);
	silofs_ii_decref(xa_ctx->ii);
	return ret;
}

int silofs_do_removexattr(struct silofs_task_ctx *task,
                          struct silofs_inode_info *ii,
                          const struct silofs_namestr *name)
{
	struct silofs_xattr_ctx xa_ctx = {
		.task     = task,
		.ii       = ii,
		.name     = name,
		.stg_mode = SILOFS_STG_COW,
	};

	return xac_removexattr(&xa_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
xac_emit_name(struct silofs_xattr_ctx *xa_ctx, const char *name, size_t nlen)
{
	return xa_ctx->lxa_ctx->actor(xa_ctx->lxa_ctx, name, nlen);
}

static int xac_emit_xentry(struct silofs_xattr_ctx *xa_ctx,
                           const struct silofs_xattr_entry *xe)
{
	return xac_emit_name(xa_ctx, xe_name(xe), xe_name_len(xe));
}

static int xac_emit_range(struct silofs_xattr_ctx *xa_ctx,
                          const struct silofs_xattr_entry *itr,
                          const struct silofs_xattr_entry *lst)
{
	int err = 0;

	while ((itr < lst) && !err) {
		err = xac_emit_xentry(xa_ctx, itr);
		itr = xe_next(itr);
	}
	return err;
}

static int xac_emit_inode(struct silofs_xattr_ctx *xa_ctx)
{
	(void)xa_ctx;
	return 0;
}

static int xac_emit_node(struct silofs_xattr_ctx *xa_ctx,
                         const struct silofs_xanode_info *xai)
{
	return xac_emit_range(xa_ctx, xan_beg(xai->xan), xan_tip(xai->xan));
}

static int xac_emit_node_at(struct silofs_xattr_ctx *xa_ctx, size_t sloti)
{
	struct silofs_laddr laddr;
	struct silofs_xanode_info *xai = nullptr;
	int err;

	ii_xa_get_at(xa_ctx->ii, sloti, &laddr);
	if (silofs_laddr_isnull(&laddr)) {
		return 0;
	}

	err = xac_stage_xanode(xa_ctx, &laddr, &xai);
	return_if_err(err);

	err = xac_emit_node(xa_ctx, xai);
	return_if_err(err);

	return 0;
}

static int xac_emit_by_nodes(struct silofs_xattr_ctx *xa_ctx)
{
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);
	int err;

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		err = xac_emit_node_at(xa_ctx, slot);
		return_if_err(err);
	}
	return 0;
}

static int xac_emit_by_inode(struct silofs_xattr_ctx *xa_ctx)
{
	return xac_emit_inode(xa_ctx);
}

static int xac_emit_names(struct silofs_xattr_ctx *xa_ctx)
{
	int err;

	err = xac_emit_by_inode(xa_ctx);
	return_if_err(err);

	err = xac_emit_by_nodes(xa_ctx);
	return_if_err(err);

	return 0;
}

static int xac_do_listxattr(struct silofs_xattr_ctx *xa_ctx)
{
	int err;

	err = xac_check_op(xa_ctx, R_OK);
	return_if_err(err);

	err = xac_emit_names(xa_ctx);
	return_if_err(err);

	return 0;
}

static int xac_listxattr(struct silofs_xattr_ctx *xa_ctx)
{
	int ret;

	silofs_ii_incref(xa_ctx->ii);
	ret = xac_do_listxattr(xa_ctx);
	silofs_ii_decref(xa_ctx->ii);
	return ret;
}

int silofs_do_listxattr(struct silofs_task_ctx *task,
                        struct silofs_inode_info *ii,
                        struct silofs_listxattr_ctx *lxa_ctx)
{
	struct silofs_xattr_ctx xa_ctx = {
		.task     = task,
		.ii       = ii,
		.lxa_ctx  = lxa_ctx,
		.stg_mode = SILOFS_STG_CUR,
	};

	return xac_listxattr(&xa_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int xac_drop_node_at(struct silofs_xattr_ctx *xa_ctx, size_t sloti)
{
	int err;
	struct silofs_laddr laddr;

	ii_xa_get_at(xa_ctx->ii, sloti, &laddr);
	if (silofs_laddr_isnull(&laddr)) {
		return 0;
	}

	err = xac_remove_xanode_at(xa_ctx, &laddr);
	return_if_err(err);

	ii_xa_unset_at(xa_ctx->ii, sloti);
	return 0;
}

static int xac_do_drop_slots(struct silofs_xattr_ctx *xa_ctx)
{
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);
	int err;

	for (size_t i = 0; i < nslots_max; ++i) {
		err = xac_drop_node_at(xa_ctx, i);
		return_if_err(err);
	}
	return 0;
}

static int xac_drop_slots(struct silofs_xattr_ctx *xa_ctx)
{
	int ret;

	silofs_ii_incref(xa_ctx->ii);
	ret = xac_do_drop_slots(xa_ctx);
	silofs_ii_decref(xa_ctx->ii);
	return ret;
}

int silofs_drop_xattr(struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii)
{
	struct silofs_xattr_ctx xa_ctx = {
		.task     = task,
		.ii       = ii,
		.stg_mode = SILOFS_STG_COW,
	};

	return xac_drop_slots(&xa_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_inode_xattr(const struct silofs_inode *inode)
{
	return ixa_verify(inode_xattr_of(inode));
}

int silofs_verify_xattr_node(const struct silofs_xattr_node *xan)
{
	int err;

	err = silofs_verify_ino(xan_ino(xan));
	return_if_err(err);

	err = xan_verify(xan);
	return_if_err(err);

	return 0;
}
