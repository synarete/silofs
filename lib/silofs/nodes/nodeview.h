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
#ifndef SILOFS_NODEVIEW_H_
#define SILOFS_NODEVIEW_H_

void silofs_hdr_setup(struct silofs_header      *hdr,
                      const struct silofs_stype *stype,
                      enum silofs_hdrf           flags);

int silofs_hdr_verify(const struct silofs_header *hdr,
                      const struct silofs_stype  *stype,
                      enum silofs_hdrf            flags);

void silofs_hdr_seal(struct silofs_header *hdr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_lview_setup(struct silofs_lview *lview, enum silofs_ltype ltype);

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_ltype ltype, int flags);

void silofs_lview_del(struct silofs_lview *lview, struct silofs_alloc *alloc,
                      enum silofs_ltype ltype, int flags);

void silofs_lview_seal(struct silofs_lview *lview);

int silofs_lview_verify(const struct silofs_lview *lview,
                        enum silofs_ltype          ltype);

int silofs_encrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_lview     *lview,
                         enum silofs_ltype ltype, void *ptr);

int silofs_decrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_lview     *lview,
                         enum silofs_ltype ltype, void *ptr);

int silofs_encrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey    *civkey,
                          const struct silofs_lview     *lview,
                          struct silofs_lview *lview_enc, size_t len);

int silofs_decrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey    *civkey,
                          const struct silofs_lview     *lview_enc,
                          struct silofs_lview *lview, size_t len);

int silofs_decrypt_view_inplace(const struct silofs_cipher_hd *ci_hd,
                                const struct silofs_civkey    *civkey,
                                struct silofs_lview           *lview,
                                enum silofs_ltype              ltype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pview_setup(struct silofs_pview       *pview,
                        const struct silofs_stype *stype);

void silofs_pview_seal(struct silofs_pview *pview);

int silofs_pview_verify(const struct silofs_pview *pview,
                        const struct silofs_stype *stype);

int silofs_encrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_caad      *caad,
                         const struct silofs_pview     *pview_in,
                         struct silofs_pview           *pview_out,
                         struct silofs_ctag *ctag_out, size_t pview_len);

int silofs_decrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_caad      *caad,
                         const struct silofs_ctag      *ctag_in,
                         const struct silofs_pview     *pview_in,
                         struct silofs_pview *pview_out, size_t pview_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* de-stage queue */
struct silofs_dstgq {
	struct silofs_listq dq;
};

/* union of all sub view */
union silofs_view {
	struct silofs_pview *pview;
	struct silofs_lview *lview;
	void                *opaque_view;
};

/* base of all in-memory node representations */
struct silofs_node_info {
	struct silofs_hmapq_elem hmqe;
	struct silofs_dq_elem    dqe;
	union silofs_view        view;
	union silofs_view        viewx;
};

void silofs_ni_init(struct silofs_node_info *ni, size_t view_size);

void silofs_ni_fini(struct silofs_node_info *ni);

void silofs_ni_incref(struct silofs_node_info *ni);

void silofs_ni_decref(struct silofs_node_info *ni);

size_t silofs_ni_refcnt(const struct silofs_node_info *ni);

bool silofs_ni_ispinned(const struct silofs_node_info *ni);

size_t silofs_ni_view_size(const struct silofs_node_info *ni);

int silofs_ni_attach_view(struct silofs_node_info *ni,  //
                          struct silofs_alloc *alloc, bool bzero);

void silofs_ni_detach_view(struct silofs_node_info *ni, //
                           struct silofs_alloc *alloc, bool bzero);

int silofs_ni_attach_viewx(struct silofs_node_info *ni,
                           struct silofs_alloc     *alloc);

void silofs_ni_detach_viewx(struct silofs_node_info *ni,
                            struct silofs_alloc     *alloc);

const struct silofs_node_info * //
silofs_ni_from_hmqe(const struct silofs_hmapq_elem *hmqe);

struct silofs_node_info *       //
silofs_ni_from_mut_hmqe(struct silofs_hmapq_elem *hmqe);

const struct silofs_node_info * //
silofs_ni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_node_info *       //
silofs_ni_from_mut_dqe(struct silofs_dq_elem *dqe);

#endif                          /* SILOFS_NODEVIEW_H_ */
