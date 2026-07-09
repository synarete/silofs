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
#ifndef SILOFS_VIEW_H_
#define SILOFS_VIEW_H_

void silofs_hdr_setup(struct silofs_header      *hdr,
                      const struct silofs_stype *stype,
                      enum silofs_hdrf           flags);

int silofs_hdr_verify(const struct silofs_header *hdr,
                      const struct silofs_stype  *stype,
                      enum silofs_hdrf            flags);

void silofs_hdr_seal(struct silofs_header *hdr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_lview_setup(struct silofs_lview *lview, enum silofs_ltype ltype);

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_ltype ltype, int flags);

void silofs_lview_del(struct silofs_lview *lview, struct silofs_alloc *alloc,
                      enum silofs_ltype ltype, int flags);

void silofs_lview_seal(struct silofs_lview *lview);

int silofs_lview_verify(const struct silofs_lview *lview,
                        enum silofs_ltype          ltype);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_pview_setup(struct silofs_pview       *pview,
                        const struct silofs_stype *stype);

void silofs_pview_seal(struct silofs_pview *pview);

int silofs_pview_verify(const struct silofs_pview *pview,
                        const struct silofs_stype *stype);

#endif /* SILOFS_VIEW_H_ */
