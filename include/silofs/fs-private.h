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
#ifndef SILOFS_FS_PRIVATE_H_
#define SILOFS_FS_PRIVATE_H_

#ifndef SILOFS_HAVE_PRIVATE
#error "internal library header -- do not include!"
#endif

#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/ps.h>
#include <silofs/fs/types.h>
#include <silofs/fs/nodes.h>

/* types */
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

#define bkaddr_reset(ba)                silofs_bkaddr_reset(ba)
#define bkaddr_setup(ba, bid, l)        silofs_bkaddr_setup(ba, bid, l)
#define bkaddr_by_laddr(ba, pa)         silofs_bkaddr_by_laddr(ba, pa)
#define bkaddr_isnull(ba)               silofs_bkaddr_isnull(ba)

#define uaddr_none()                    silofs_uaddr_none()
#define uaddr_isnull(ua)                silofs_uaddr_isnull(ua)
#define uaddr_assign(ua, oth)           silofs_uaddr_assign(ua, oth)
#define uaddr_reset(ua)                 silofs_uaddr_reset(ua)
#define uaddr_isequal(ua1, ua2)         silofs_uaddr_isequal(ua1, ua2)
#define uaddr_setup(ua, b, p, s, o)     silofs_uaddr_setup(ua, b, p, s, o)
#define uaddr_pvid(ua)                silofs_uaddr_pvid(ua)
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

#define sbi_fsenv(sbi)                   silofs_sbi_fsenv(sbi)
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
#define vi_fsenv(vi)                     silofs_vi_fsenv(vi)
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
#define ii_fsenv(ii)                     silofs_ii_fsenv(ii)
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

static inline struct silofs_fsenv *
silofs_vi_fsenv(const struct silofs_vnode_info *vi)
{
	return vi->v.fsenv;
}

static inline struct silofs_sb_info *
silofs_vi_sbi(const struct silofs_vnode_info *vi)
{
	return vi->v.fsenv->fse_sbi;
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

static inline struct silofs_fsenv *
silofs_ii_fsenv(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v.fsenv;
}

static inline struct silofs_cache *
silofs_ii_cache(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v.ce.ce_cache;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline struct silofs_fsenv *
silofs_sbi_fsenv(const struct silofs_sb_info *sbi)
{
	return sbi->sb_ui.u.fsenv;
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

#endif /* SILOFS_FS_PRIVATE_H_ */
