/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_MREC_H_
#define SILOFS_MREC_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "bs.h"

struct silofs_env;

/* main boot-record, in-memory representation */
struct silofs_mrec {
	struct silofs_ivkey main_ivkey;
	struct silofs_uuid  uuid;
	struct silofs_uaddr sb_addr;
	struct silofs_caddr ar_addr;
	enum silofs_mrecf   flags;
	int                 cipher_algo;
	int                 cipher_mode;
};

/* a tuple of content-addressable references to main boot-records */
struct silofs_mrefs {
	struct silofs_caddr main;
	struct silofs_caddr base;
	struct silofs_caddr fork;
};

/* main boot-record controller */
struct silofs_mrecinfo {
	struct silofs_mrec    mrec;
	struct silofs_cipher  cipher;
	struct silofs_mdigest mdigest;
	struct silofs_ivkey   ivkey;
	struct silofs_caddr   mref;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mrec_init(struct silofs_mrec *mrec);

void silofs_mrec_fini(struct silofs_mrec *mrec);

void silofs_mrec_assign(struct silofs_mrec       *mrec,
                        const struct silofs_mrec *other);

void silofs_mrec_gen_uuid(struct silofs_mrec *mrec);

void silofs_mrec_set_ivkey(struct silofs_mrec        *mrec,
                           const struct silofs_ivkey *ivkey);

int silofs_mrec_gen_ivkey(struct silofs_mrec          *mrec,
                          const struct silofs_mdigest *md);

void silofs_mrec_set_sb_addr(struct silofs_mrec        *mrec,
                             const struct silofs_uaddr *sb_uaddr);

void silofs_mrec_set_ar_addr(struct silofs_mrec        *mrec,
                             const struct silofs_caddr *caddr);

void silofs_make_mrec_uaddr(const struct silofs_blobid *blobid,
                            struct silofs_uaddr        *out_uaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mrecinfo_init(struct silofs_mrecinfo *mreci);

void silofs_mrecinfo_fini(struct silofs_mrecinfo *mreci);

int silofs_mrecinfo_regen(struct silofs_mrecinfo *mreci);

int silofs_mrecinfo_update_sb(struct silofs_mrecinfo    *mreci,
                              const struct silofs_uaddr *sb_uaddr);

int silofs_mrecinfo_encode(struct silofs_mrecinfo *mreci,
                           struct silofs_mrec1k   *out_mrec1k_enc);

int silofs_mrecinfo_decode(struct silofs_mrecinfo     *mreci,
                           const struct silofs_mrec1k *mrec1k_enc);

bool silofs_mrecinfo_has_ref(const struct silofs_mrecinfo *mreci,
                             const struct silofs_caddr    *caddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encode_mrec(const struct silofs_env  *env,
                       const struct silofs_mrec *mrec,
                       struct silofs_mrec1k     *out_mrec1k_enc);

int silofs_decode_mrec(const struct silofs_env    *env,
                       const struct silofs_mrec1k *mrec1k_enc,
                       struct silofs_mrec         *out_mrec);

int silofs_save_mrec(const struct silofs_env  *env,
                     const struct silofs_mrec *mrec,
                     struct silofs_caddr      *out_caddr);

int silofs_load_mrec(const struct silofs_env   *env,
                     const struct silofs_caddr *caddr,
                     struct silofs_mrec        *out_mrec);

int silofs_unlink_mrec(const struct silofs_env   *env,
                       const struct silofs_caddr *caddr);

int silofs_calc_mrec_caddr(const struct silofs_env  *env,
                           const struct silofs_mrec *mrec,
                           struct silofs_caddr      *out_caddr);

#endif /* SILOFS_MREC_H_ */
