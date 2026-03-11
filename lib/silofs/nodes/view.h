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

#include <silofs/ondisk.h>
#include <silofs/crypto.h>
#include <silofs/addr.h>

void silofs_hdr_setup(struct silofs_header *hdr, uint8_t stype,
                      enum silofs_hdrf flags);

int silofs_hdr_verify(const struct silofs_header *hdr, uint8_t stype,
                      enum silofs_hdrf flags);

void silofs_hdr_seal(struct silofs_header *hdr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_vtype vtype, int flags);

void silofs_lview_del(struct silofs_lview *lview, struct silofs_alloc *alloc,
                      enum silofs_vtype vtype, int flags);

void silofs_seal_lview(struct silofs_lview *lview);

int silofs_verify_lview(const struct silofs_lview *lview,
                        enum silofs_vtype          vtype);

int silofs_encrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_lview     *lview,
                         enum silofs_vtype vtype, void *ptr);

int silofs_decrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_lview     *lview,
                         enum silofs_vtype vtype, void *ptr);

int silofs_decrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey    *civkey,
                          const struct silofs_lview     *lview_enc,
                          struct silofs_lview *lview, size_t len);

int silofs_decrypt_view_inplace(const struct silofs_cipher_hd *ci_hd,
                                const struct silofs_civkey    *civkey,
                                struct silofs_lview           *view,
                                enum silofs_vtype              vtype);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_pview *
silofs_pview_new(struct silofs_alloc *alloc, enum silofs_ptype ptype);

void silofs_pview_del(struct silofs_pview *pview, struct silofs_alloc *alloc,
                      enum silofs_ptype ptype);

void silofs_seal_pview(struct silofs_pview *pview);

int silofs_verify_pview(const struct silofs_pview *pview,
                        enum silofs_ptype          ptype);

int silofs_encrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_pview     *pview,
                         struct silofs_pview *pview_enc, size_t len);

int silofs_decrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_pview     *pview_enc,
                         struct silofs_pview *pview, size_t len);

#endif /* SILOFS_VIEW_H_ */
