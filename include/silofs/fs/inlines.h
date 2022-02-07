/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_INLINES_H_
#define SILOFS_INLINES_H_

#ifndef SILOFS_USE_PRIVATE
#error "internal library header -- do not include!"
#endif


static inline bool silofs_ino_isnull(ino_t ino)
{
	return (ino == SILOFS_INO_NULL);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool silofs_off_isnull(loff_t off)
{
	return (off < 0);
}

static inline loff_t silofs_off_min(loff_t off1, loff_t off2)
{
	return (off1 < off2) ? off1 : off2;
}

static inline loff_t silofs_off_max(loff_t off1, loff_t off2)
{
	return (off1 > off2) ? off1 : off2;
}

static inline loff_t silofs_off_end(loff_t off, size_t len)
{
	return off + (loff_t)len;
}

static inline loff_t silofs_off_align(loff_t off, ssize_t align)
{
	return (off / align) * align;
}

static inline loff_t silofs_off_align_to_bk(loff_t off)
{
	return silofs_off_align(off, SILOFS_BK_SIZE);
}

static inline loff_t silofs_off_next(loff_t off, ssize_t len)
{
	return silofs_off_align(off + len, len);
}

static inline loff_t silofs_off_next_bk(loff_t off)
{
	return silofs_off_next(off, SILOFS_BK_SIZE);
}

static inline silofs_lba_t silofs_off_to_lba(loff_t off)
{
	return !silofs_off_isnull(off) ?
	       (off / SILOFS_BK_SIZE) : SILOFS_LBA_NULL;
}

static inline ssize_t silofs_off_diff(loff_t beg, loff_t end)
{
	return end - beg;
}

static inline ssize_t silofs_off_len(loff_t beg, loff_t end)
{
	return silofs_off_diff(beg, end);
}

static inline size_t silofs_off_ulen(loff_t beg, loff_t end)
{
	return (size_t)silofs_off_len(beg, end);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline silofs_lba_t silofs_lba_align(silofs_lba_t lba, ssize_t align)
{
	return (lba / align) * align;
}

static inline bool silofs_lba_isequal(silofs_lba_t lba1, silofs_lba_t lba2)
{
	return (lba1 == lba2);
}

static inline bool silofs_lba_isnull(silofs_lba_t lba)
{
	return silofs_lba_isequal(lba, SILOFS_LBA_NULL);
}

static inline loff_t silofs_lba_to_off(silofs_lba_t lba)
{
	return !silofs_lba_isnull(lba) ?
	       (lba * SILOFS_BK_SIZE) : SILOFS_OFF_NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool silofs_uid_eq(uid_t uid1, uid_t uid2)
{
	return (uid1 == uid2);
}

static inline bool silofs_uid_isroot(uid_t uid)
{
	return silofs_uid_eq(uid, 0);
}

static inline bool silofs_gid_eq(gid_t gid1, gid_t gid2)
{
	return (gid1 == gid2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline bool silofs_stype_isequal(enum silofs_stype stype1,
                                        enum silofs_stype stype2)
{
	return (stype1 == stype2);
}

static inline bool silofs_stype_isnone(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_NONE);
}

static inline bool silofs_stype_issuper(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SUPER);
}

static inline bool silofs_stype_isspnode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SPNODE);
}

static inline bool silofs_stype_isspleaf(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_SPLEAF);
}

static inline bool silofs_stype_isitnode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_ITNODE);
}

static inline bool silofs_stype_isinode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_INODE);
}

static inline bool silofs_stype_isftnode(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_FTNODE);
}

static inline bool silofs_stype_isdatabk(enum silofs_stype stype)
{
	return silofs_stype_isequal(stype, SILOFS_STYPE_DATABK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline const struct silofs_uaddr *
silofs_ui_uaddr(const struct silofs_unode_info *ui)
{
	return &ui->u_uaddr;
}

static inline const struct silofs_oaddr *
silofs_ui_oaddr(const struct silofs_unode_info *ui)
{
	return &ui->u_uaddr.oaddr;
}

static inline enum silofs_stype
silofs_ui_stype(const struct silofs_unode_info *ui) {
	return ui->u_uaddr.stype;
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

static inline struct silofs_fs_apex *
silofs_vi_apex(const struct silofs_vnode_info *vi)
{
	return vi->v_ti.t_apex;
}

static inline struct silofs_sb_info *
silofs_vi_sbi(const struct silofs_vnode_info *vi)
{
	return vi->v_ti.t_apex->ap_sbi;
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

static inline struct silofs_fs_apex *
silofs_ii_apex(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v_ti.t_apex;
}

static inline struct silofs_cache *
silofs_ii_cache(const struct silofs_inode_info *ii)
{
	return ii->i_vi.v_ti.t_ce.ce_cache;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline struct silofs_fs_apex *
silofs_sbi_apex(const struct silofs_sb_info *sbi)
{
	return sbi->s_ui.u_ti.t_apex;
}

static inline struct silofs_cache *
silofs_sbi_cache(const struct silofs_sb_info *sbi)
{
	return sbi->s_ui.u_ti.t_ce.ce_cache;
}

static inline const struct silofs_uaddr *
silofs_sbi_uaddr(const struct silofs_sb_info *sbi)
{
	return &sbi->s_ui.u_uaddr;
}

static inline const struct silofs_oaddr *
silofs_sbi_oaddr(const struct silofs_sb_info *sbi)
{
	return &sbi->s_ui.u_uaddr.oaddr;
}

#endif /* SILOFS_INLINES_H_ */
