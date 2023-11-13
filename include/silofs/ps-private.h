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
#ifndef SILOFS_PS_PRIVATE_H_
#define SILOFS_PS_PRIVATE_H_

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

#define lsegid_reset(lid)               silofs_lsegid_reset(lid)
#define lsegid_assign(lid, oth)         silofs_lsegid_assign(lid, oth)
#define lsegid_isequal(lid, oth)        silofs_lsegid_isequal(lid, oth)
#define lsegid_isnull(lid)              silofs_lsegid_isnull(lid)
#define lsegid_size(lid)                silofs_lsegid_size(lid)

#define laddr_reset(la)                 silofs_laddr_reset(la)
#define laddr_assign(la, oth)           silofs_laddr_assign(la, oth)
#define laddr_setup(la, bid, o, l)      silofs_laddr_setup(la, bid, o, l)
#define laddr_setup_by(la, bid, va)     silofs_laddr_setup_by(la, bid, va)
#define laddr_isvalid(la)               silofs_laddr_isvalid(la)
#define laddr_isnull(la)                silofs_laddr_isnull(la)

#define paddr_reset(pa)                 silofs_paddr_reset(pa)
#define paddr_assign(pa, oth)           silofs_paddr_assign(pa, oth)


#endif /* SILOFS_PS_PRIVATE_H_ */
