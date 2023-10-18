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
#ifndef SILOFS_PRIVATE_H_
#define SILOFS_PRIVATE_H_

#ifndef SILOFS_HAVE_PRIVATE
#error "internal library header -- do not include!"
#endif

#include <silofs/infra.h>
#include <silofs/defs.h>
#include <silofs/types.h>
#include <silofs/nodes.h>

/* common macros */
#define likely(x_)                      silofs_likely(x_)
#define unlikely(x_)                    silofs_unlikely(x_)

#define STATICASSERT(expr_)             SILOFS_STATICASSERT(expr_)
#define STATICASSERT_EQ(a_, b_)         SILOFS_STATICASSERT_EQ(a_, b_)
#define STATICASSERT_LT(a_, b_)         SILOFS_STATICASSERT_LT(a_, b_)
#define STATICASSERT_LE(a_, b_)         SILOFS_STATICASSERT_LE(a_, b_)
#define STATICASSERT_GT(a_, b_)         SILOFS_STATICASSERT_GT(a_, b_)
#define STATICASSERT_GE(a_, b_)         SILOFS_STATICASSERT_GE(a_, b_)
#define STATICASSERT_SIZEOF(t_, s_)     SILOFS_STATICASSERT_EQ(sizeof(t_), s_)

/* aliases */
#define ARRAY_SIZE(x)                   SILOFS_ARRAY_SIZE(x)
#define container_of(p, t, m)           silofs_container_of(p, t, m)
#define container_of2(p, t, m)          silofs_container_of2(p, t, m)
#define unconst(p)                      silofs_unconst(p)
#define unused(x)                       silofs_unused(x)

#define min(x, y)                       silofs_min(x, y)
#define min3(x, y, z)                   silofs_min3(x, y, z)
#define max(x, y)                       silofs_max(x, y)
#define clamp(x, y, z)                  silofs_clamp(x, y, z)
#define div_round_up(n, d)              silofs_div_round_up(n, d)

#define log_dbg(fmt, ...)               silofs_log_debug(fmt, __VA_ARGS__)
#define log_info(fmt, ...)              silofs_log_info(fmt, __VA_ARGS__)
#define log_warn(fmt, ...)              silofs_log_warn(fmt, __VA_ARGS__)
#define log_err(fmt, ...)               silofs_log_error(fmt, __VA_ARGS__)
#define log_crit(fmt, ...)              silofs_log_crit(fmt, __VA_ARGS__)

#define list_head_init(lh)              silofs_list_head_init(lh)
#define list_head_initn(lh, n)          silofs_list_head_initn(lh, n)
#define list_head_fini(lh)              silofs_list_head_fini(lh)
#define list_head_finin(lh, n)          silofs_list_head_finin(lh, n)
#define list_head_remove(lh)            silofs_list_head_remove(lh)
#define list_head_insert_after(p, q)    silofs_list_head_insert_after(p, q)
#define list_head_insert_before(p, q)   silofs_list_head_insert_before(p, q)

#define list_init(ls)                   silofs_list_init(ls)
#define list_fini(ls)                   silofs_list_fini(ls)
#define list_isempty(ls)                silofs_list_isempty(ls)
#define list_push_back(ls, lh)          silofs_list_push_back(ls, lh)
#define list_push_front(ls, lh)         silofs_list_push_front(ls, lh)
#define list_pop_front(ls)              silofs_list_pop_front(ls)
#define list_front(ls)                  silofs_list_front(ls)

#define listq_init(lq)                  silofs_listq_init(lq)
#define listq_initn(lq, n)              silofs_listq_initn(lq, n)
#define listq_fini(lq)                  silofs_listq_fini(lq)
#define listq_finin(lq, n)              silofs_listq_finin(lq, n)
#define listq_size(lq)                  silofs_listq_size(lq)
#define listq_isempty(lq)               silofs_listq_isempty(lq)
#define listq_push_back(lq, lh)         silofs_listq_push_back(lq, lh)
#define listq_push_front(lq, lh)        silofs_listq_push_front(lq, lh)
#define listq_pop_back(lq)              silofs_listq_pop_back(lq)
#define listq_pop_front(lq)             silofs_listq_pop_front(lq)
#define listq_remove(lq, lh)            silofs_listq_remove(lq, lh)
#define listq_front(lq)                 silofs_listq_front(lq)
#define listq_back(lq)                  silofs_listq_back(lq)
#define listq_next(lq, lh)              silofs_listq_next(lq, lh)
#define listq_prev(lq, lh)              silofs_listq_prev(lq, lh)

#define stype_nkbs(st)                  silofs_stype_nkbs(st)
#define stype_size(st)                  silofs_stype_size(st)
#define stype_ssize(st)                 silofs_stype_ssize(st)
#define stype_isequal(st1, st2)         silofs_stype_isequal(st1, st2)
#define stype_isnone(st)                silofs_stype_isnone(st)
#define stype_issuper(st)               silofs_stype_issuper(st)
#define stype_isspnode(st)              silofs_stype_isspnode(st)
#define stype_isspleaf(st)              silofs_stype_isspleaf(st)
#define stype_isunode(st)               silofs_stype_isunode(st)
#define stype_isvnode(st)               silofs_stype_isvnode(st)
#define stype_isinode(st)               silofs_stype_isinode(st)
#define stype_isxanode(st)              silofs_stype_isxanode(st)
#define stype_issymval(st)              silofs_stype_issymval(st)
#define stype_isdtnode(st)              silofs_stype_isdtnode(st)
#define stype_isftnode(st)              silofs_stype_isftnode(st)
#define stype_isdata(st)                silofs_stype_isdata(st)
#define stype_isdatabk(st)              silofs_stype_isdatabk(st)

#define lextid_reset(lid)               silofs_lextid_reset(lid)
#define lextid_assign(lid, oth)         silofs_lextid_assign(lid, oth)
#define lextid_isequal(lid, oth)        silofs_lextid_isequal(lid, oth)
#define lextid_isnull(lid)              silofs_lextid_isnull(lid)
#define lextid_size(lid)                silofs_lextid_size(lid)

#define bkaddr_reset(ba)                silofs_bkaddr_reset(ba)
#define bkaddr_setup(ba, bid, l)        silofs_bkaddr_setup(ba, bid, l)
#define bkaddr_by_laddr(ba, pa)         silofs_bkaddr_by_laddr(ba, pa)
#define bkaddr_isnull(ba)               silofs_bkaddr_isnull(ba)

#define laddr_reset(la)                 silofs_laddr_reset(la)
#define laddr_assign(la, oth)           silofs_laddr_assign(la, oth)
#define laddr_setup(la, bid, o, l)      silofs_laddr_setup(la, bid, o, l)
#define laddr_setup_by(la, bid, va)     silofs_laddr_setup_by(la, bid, va)
#define laddr_isvalid(la)               silofs_laddr_isvalid(la)
#define laddr_isnull(la)                silofs_laddr_isnull(la)

#define uaddr_none()                    silofs_uaddr_none()
#define uaddr_isnull(ua)                silofs_uaddr_isnull(ua)
#define uaddr_assign(ua, oth)           silofs_uaddr_assign(ua, oth)
#define uaddr_reset(ua)                 silofs_uaddr_reset(ua)
#define uaddr_isequal(ua1, ua2)         silofs_uaddr_isequal(ua1, ua2)
#define uaddr_setup(ua, b, p, s, o)     silofs_uaddr_setup(ua, b, p, s, o)
#define uaddr_treeid(ua)                silofs_uaddr_treeid(ua)
#define uaddr_lextid(ua)                silofs_uaddr_lextid(ua)
#define uaddr_height(ua)                silofs_uaddr_height(ua)

#define ulink_assign(ul, oth)           silofs_ulink_assign(ul, oth)
#define ulink_assign2(ul, ua, iv)       silofs_ulink_assign2(ul, ua, iv)
#define ulink_reset(ul)                 silofs_ulink_reset(ul)

#define vaddr_none()                    silofs_vaddr_none()
#define vaddr_isnull(va)                silofs_vaddr_isnull(va)
#define vaddr_isdata(va)                silofs_vaddr_isdata(va)
#define vaddr_isdatabk(va)              silofs_vaddr_isdatabk(va)
#define vaddr_isinode(va)               silofs_vaddr_isinode(va)
#define vaddr_reset(va)                 silofs_vaddr_reset(va)
#define vaddr_assign(va, oth)           silofs_vaddr_assign(va, oth)
#define vaddr_setup(va, t, o)           silofs_vaddr_setup(va, t, o)
#define vaddr_compare(va1, va2)         silofs_vaddr_compare(va1, va2)
#define vaddr_isequal(va1, va2)         silofs_vaddr_isequal(va1, va2)

#define task_sbi(t)                     silofs_task_sbi(t)
#define task_cache(t)                   silofs_task_cache(t)
#define task_repo(t)                    silofs_task_repo(t)
#define task_idsmap(t)                  silofs_task_idsmap(t)
#define task_creds(t)                   silofs_task_creds(t)

#define sbi_uber(sbi)                   silofs_sbi_uber(sbi)
#define sbi_cache(sbi)                  silofs_sbi_cache(sbi)
#define sbi_ulink(sbi)                  silofs_sbi_ulink(sbi)
#define sbi_uaddr(sbi)                  silofs_sbi_uaddr(sbi)
#define sbi_laddr(sbi)                  silofs_sbi_laddr(sbi)
#define sbi_lextid(sbi)                 silofs_sbi_lextid(sbi)
#define sbi_incref(sbi)                 silofs_sbi_incref(sbi)
#define sbi_decref(sbi)                 silofs_sbi_decref(sbi)
#define sbi_dirtify(sbi)                silofs_sbi_dirtify(sbi)

#define sni_ulink(sni)                  silofs_sni_ulink(sni)
#define sni_uaddr(sni)                  silofs_sni_uaddr(sni)
#define sni_laddr(sni)                  silofs_sni_laddr(sni)
#define sni_incref(sni)                 silofs_sni_incref(sni)
#define sni_decref(sni)                 silofs_sni_decref(sni)
#define sni_vrange(sni, vrng)           silofs_sni_vspace_range(sni, vrng)
#define sni_slot_of(sni, o)             silofs_sni_slot_of(sni, o)
#define sni_base_voff(sni)              silofs_sni_base_voff(sni)

#define sli_ulink(sli)                  silofs_sli_ulink(sli)
#define sli_uaddr(sli)                  silofs_sli_uaddr(sli)
#define sli_laddr(sli)                  silofs_sli_laddr(sli)
#define sli_incref(sli)                 silofs_sli_incref(sli)
#define sli_decref(sli)                 silofs_sli_decref(sli)
#define sli_vrange(sli, vrng)           silofs_sli_vspace_range(sli, vrng)
#define sli_base_voff(sli)              silofs_sli_base_voff(sli)

#define ui_incref(ui)                   silofs_ui_incref(ui)
#define ui_decref(ui)                   silofs_ui_decref(ui)
#define ui_dirtify(ui)                  silofs_ui_dirtify(ui)
#define ui_stype(ui)                    silofs_ui_stype(ui)
#define ui_ulink(ui)                    silofs_ui_ulink(ui)
#define ui_uaddr(ui)                    silofs_ui_uaddr(ui)
#define ui_laddr(ui)                    silofs_ui_laddr(ui)
#define ui_riv(ui)                      silofs_ui_riv(ui)

#define vi_stype(vi)                    silofs_vi_stype(vi)
#define vi_vaddr(vi)                    silofs_vi_vaddr(vi)
#define vi_uber(vi)                     silofs_vi_uber(vi)
#define vi_sbi(vi)                      silofs_vi_sbi(vi)
#define vi_refcnt(vi)                   silofs_vi_refcnt(vi)
#define vi_incref(vi)                   silofs_vi_incref(vi)
#define vi_decref(vi)                   silofs_vi_decref(vi)
#define vi_dirtify(vi, ii)              silofs_vi_dirtify(vi, ii)
#define vi_isdata(vi)                   silofs_vi_isdata(vi)

#define ii_unconst(ii)                  silofs_ii_unconst(ii)
#define ii_to_vi(ii)                    silofs_ii_to_vi(ii)
#define ii_ino(ii)                      silofs_ii_ino(ii)
#define ii_vaddr(ii)                    silofs_ii_vaddr(ii)
#define ii_sbi(ii)                      silofs_ii_sbi(ii)
#define ii_uber(ii)                     silofs_ii_uber(ii)
#define ii_cache(ii)                    silofs_ii_cache(ii)
#define ii_refcnt(ii)                   silofs_ii_refcnt(ii)
#define ii_incref(ii)                   silofs_ii_incref(ii)
#define ii_decref(ii)                   silofs_ii_decref(ii)
#define ii_dirtify(ii)                  silofs_ii_dirtify(ii)
#define ii_xino(ii)                     silofs_ii_xino_of(ii)
#define ii_parent(ii)                   silofs_ii_parent(ii)
#define ii_uid(ii)                      silofs_ii_uid(ii)
#define ii_gid(ii)                      silofs_ii_gid(ii)
#define ii_mode(ii)                     silofs_ii_mode(ii)
#define ii_nlink(ii)                    silofs_ii_nlink(ii)
#define ii_size(ii)                     silofs_ii_size(ii)
#define ii_flags(ii)                    silofs_ii_flags(ii)
#define ii_span(ii)                     silofs_ii_span(ii)
#define ii_blocks(ii)                   silofs_ii_blocks(ii)
#define ii_generation(ii)               silofs_ii_generation(ii)
#define ii_isrootd(ii)                  silofs_ii_isrootd(ii)
#define ii_isdir(ii)                    silofs_ii_isdir(ii)
#define ii_isreg(ii)                    silofs_ii_isreg(ii)
#define ii_islnk(ii)                    silofs_ii_islnk(ii)
#define ii_isfifo(ii)                   silofs_ii_isfifo(ii)
#define ii_issock(ii)                   silofs_ii_issock(ii)
#define ii_update_itimes(ii, cr, f)     silofs_ii_update_itimes(ii, cr, f)
#define ii_update_iattrs(ii, cr, a)     silofs_ii_update_iattrs(ii, cr, a)
#define ii_update_isize(ii, cr, sz)     silofs_ii_update_isize(ii, cr, sz)
#define ii_update_iblocks(ii, cr, vt, d) \
	silofs_ii_update_iblocks(ii, cr, vt, d)

#define uid_eq(uid1, uid2)              silofs_uid_eq(uid1, uid2)
#define uid_isroot(uid)                 silofs_uid_isroot(uid)
#define gid_eq(gid1, gid2)              silofs_gid_eq(gid1, gid2)
#define ino_isnull(ino)                 silofs_ino_isnull(ino)
#define ino_to_dqid(ino)                silofs_ino_to_dqid(ino)

#define off_isnull(off)                 silofs_off_isnull(off)
#define off_min(off1, off2)             silofs_off_min(off1, off2)
#define off_max(off1, off2)             silofs_off_max(off1, off2)
#define off_max3(off1, off2, off3)      silofs_off_max3(off1, off2, off3)
#define off_end(off, len)               silofs_off_end(off, len)
#define off_clamp(off1, off2, off3)     silofs_off_clamp(off1, off2, off3)
#define off_align(off, align)           silofs_off_align(off, align)
#define off_align_to_lbk(off)           silofs_off_align_to_lbk(off)
#define off_next(off, len)              silofs_off_next(off, len)
#define off_next_lbk(off)               silofs_off_next_lbk(off)
#define off_to_lba(off)                 silofs_off_to_lba(off)
#define off_diff(off, end)              silofs_off_diff(off, end)
#define off_len(beg, end)               silofs_off_len(beg, end)
#define off_ulen(beg, end)              silofs_off_ulen(beg, end)
#define off_iswithin(off, beg, end)     silofs_off_iswithin(off, beg, end)

#define lba_align(lba, align)           silofs_lba_align(lba, align)
#define lba_isequal(lba1, lba2)         silofs_lba_isequal(lba1, lba2)
#define lba_isnull(lba)                 silofs_lba_isnull(lba)
#define lba_to_off(lba)                 silofs_lba_to_off(lba)
#define lba_plus(lba, cnt)              silofs_lba_plus(lba, cnt)

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static inline const struct silofs_ulink *
silofs_ui_ulink(const struct silofs_unode_info *ui)
{
	return &ui->u_ulink;
}

static inline const struct silofs_iv *
silofs_ui_riv(const struct silofs_unode_info *ui)
{
	return &ui->u_ulink.riv;
}

static inline const struct silofs_uaddr *
silofs_ui_uaddr(const struct silofs_unode_info *ui)
{
	return &ui->u_ulink.uaddr;
}

static inline const struct silofs_laddr *
silofs_ui_laddr(const struct silofs_unode_info *ui)
{
	return &ui->u_ulink.uaddr.laddr;
}

static inline enum silofs_stype
silofs_ui_stype(const struct silofs_unode_info *ui) {
	return ui->u_ulink.uaddr.stype;
}

static inline bool
silofs_ui_has_stype(const struct silofs_unode_info *ui,
                    enum silofs_stype stype)
{
	return stype == silofs_ui_stype(ui);
}

static inline
enum silofs_stype silofs_vi_stype(const struct silofs_vnode_info *vi)
{
	return vi->v_vaddr.stype;
}

static inline const struct silofs_vaddr *
silofs_vi_vaddr(const struct silofs_vnode_info *vi)
{
	return &vi->v_vaddr;
}

static inline struct silofs_uber *
silofs_vi_uber(const struct silofs_vnode_info *vi)
{
	return vi->v.uber;
}

static inline struct silofs_sb_info *
silofs_vi_sbi(const struct silofs_vnode_info *vi)
{
	return vi->v.uber->ub_sbi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline struct silofs_inode_info *
silofs_ii_unconst(const struct silofs_inode_info *ii)
{
	union {
		const struct silofs_inode_info *p;
		struct silofs_inode_info *q;
	} u = {
		.p = ii
	};
	return u.q;
}

static inline struct silofs_vnode_info *
silofs_ii_to_vi(const struct silofs_inode_info *ii)
{
	return silofs_unconst(&ii->i_vi);
}

static inline ino_t silofs_ii_ino(const struct silofs_inode_info *ii)
{
	return ii->i_ino;
}

static inline const struct silofs_vaddr *
silofs_ii_vaddr(const struct silofs_inode_info *ii)
{
	return silofs_vi_vaddr(silofs_ii_to_vi(ii));
}

static inline struct silofs_sb_info *
silofs_ii_sbi(const struct silofs_inode_info *ii)
{
	return silofs_vi_sbi(silofs_ii_to_vi(ii));
}

static inline struct silofs_uber *
silofs_ii_uber(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v.uber;
}

static inline struct silofs_cache *
silofs_ii_cache(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v.ce.ce_cache;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline struct silofs_uber *
silofs_sbi_uber(const struct silofs_sb_info *sbi)
{
	return sbi->sb_ui.u.uber;
}

static inline struct silofs_cache *
silofs_sbi_cache(const struct silofs_sb_info *sbi)
{
	return sbi->sb_ui.u.ce.ce_cache;
}

static inline const struct silofs_ulink *
silofs_sbi_ulink(const struct silofs_sb_info *sbi)
{
	return silofs_ui_ulink(&sbi->sb_ui);
}

static inline const struct silofs_uaddr *
silofs_sbi_uaddr(const struct silofs_sb_info *sbi)
{
	return silofs_ui_uaddr(&sbi->sb_ui);
}

static inline const struct silofs_laddr *
silofs_sbi_laddr(const struct silofs_sb_info *sbi)
{
	return silofs_ui_laddr(&sbi->sb_ui);
}

static inline const struct silofs_laddr *
silofs_sni_laddr(const struct silofs_spnode_info *sni)
{
	return silofs_ui_laddr(&sni->sn_ui);
}

static inline const struct silofs_laddr *
silofs_sli_laddr(const struct silofs_spleaf_info *sli)
{
	return silofs_ui_laddr(&sli->sl_ui);
}

#endif /* SILOFS_PRIVATE_H_ */
