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
#ifndef SILOFS_ADDR_PRIVATE_H_
#define SILOFS_ADDR_PRIVATE_H_

#ifndef SILOFS_HAVE_PRIVATE
#error "internal library header -- do not include!"
#endif

#define off_isnull(off)                 silofs_off_isnull(off)
#define off_min(off1, off2)             silofs_off_min(off1, off2)
#define off_max(off1, off2)             silofs_off_max(off1, off2)
#define off_end(off, len)               silofs_off_end(off, len)
#define off_align(off, align)           silofs_off_align(off, align)
#define off_align_to_lbk(off)           silofs_off_align_to_lbk(off)
#define off_next(off, len)              silofs_off_next(off, len)
#define off_next_lbk(off)               silofs_off_next_lbk(off)
#define off_to_lba(off)                 silofs_off_to_lba(off)
#define off_diff(off, end)              silofs_off_diff(off, end)
#define off_len(beg, end)               silofs_off_len(beg, end)
#define off_ulen(beg, end)              silofs_off_ulen(beg, end)

#define oaddr_none()                    silofs_oaddr_none()
#define oaddr_reset(pa)                 silofs_oaddr_reset(pa)
#define oaddr_assign(pa, oth)           silofs_oaddr_assign(pa, oth)
#define oaddr_isnull(pa)                silofs_oaddr_isnull(pa)

#define ltype_nkbs(lt)                  silofs_ltype_nkbs(lt)
#define ltype_size(lt)                  silofs_ltype_size(lt)
#define ltype_ssize(lt)                 silofs_ltype_ssize(lt)
#define ltype_isnone(lt)                silofs_ltype_isnone(lt)
#define ltype_issuper(lt)               silofs_ltype_issuper(lt)
#define ltype_isspnode(lt)              silofs_ltype_isspnode(lt)
#define ltype_isspleaf(lt)              silofs_ltype_isspleaf(lt)
#define ltype_isunode(lt)               silofs_ltype_isunode(lt)
#define ltype_isvnode(lt)               silofs_ltype_isvnode(lt)
#define ltype_isinode(lt)               silofs_ltype_isinode(lt)
#define ltype_isxanode(lt)              silofs_ltype_isxanode(lt)
#define ltype_issymval(lt)              silofs_ltype_issymval(lt)
#define ltype_isdtnode(lt)              silofs_ltype_isdtnode(lt)
#define ltype_isftnode(lt)              silofs_ltype_isftnode(lt)
#define ltype_isdata(lt)                silofs_ltype_isdata(lt)
#define ltype_isdata1k(lt)              silofs_ltype_isdata1k(lt)
#define ltype_isdata4k(lt)              silofs_ltype_isdata4k(lt)
#define ltype_isdatabk(lt)              silofs_ltype_isdatabk(lt)

#define lsegid_reset(lid)               silofs_lsegid_reset(lid)
#define lsegid_assign(lid, oth)         silofs_lsegid_assign(lid, oth)
#define lsegid_isequal(lid, oth)        silofs_lsegid_isequal(lid, oth)
#define lsegid_isnull(lid)              silofs_lsegid_isnull(lid)
#define lsegid_size(lid)                silofs_lsegid_size(lid)

#define laddr_none()                    silofs_laddr_none()
#define laddr_reset(la)                 silofs_laddr_reset(la)
#define laddr_assign(la, oth)           silofs_laddr_assign(la, oth)
#define laddr_isvalid(la)               silofs_laddr_isvalid(la)
#define laddr_isnull(la)                silofs_laddr_isnull(la)
#define laddr_isnext(la, oth)           silofs_laddr_isnext(la, oth)

#define uaddr_none()                    silofs_uaddr_none()
#define uaddr_isnull(ua)                silofs_uaddr_isnull(ua)
#define uaddr_assign(ua, oth)           silofs_uaddr_assign(ua, oth)
#define uaddr_reset(ua)                 silofs_uaddr_reset(ua)
#define uaddr_isequal(ua1, ua2)         silofs_uaddr_isequal(ua1, ua2)
#define uaddr_setup(ua, b, p, s, o)     silofs_uaddr_setup(ua, b, p, s, o)
#define uaddr_lvid(ua)                  silofs_uaddr_lvid(ua)
#define uaddr_lsegid(ua)                silofs_uaddr_lsegid(ua)
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
#define vaddr_setup(va, st, o)          silofs_vaddr_setup(va, st, o)
#define vaddr_compare(va1, va2)         silofs_vaddr_compare(va1, va2)
#define vaddr_isequal(va1, va2)         silofs_vaddr_isequal(va1, va2)

#define caddr_isnone(ca)                silofs_caddr_isnone(ca)
#define caddr_isequal(ca, oth)          silofs_caddr_isequal(ca, oth)

#endif /* SILOFS_ADDR_PRIVATE_H_ */
