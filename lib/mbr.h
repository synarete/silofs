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
#ifndef SILOFS_MBR_H_
#define SILOFS_MBR_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "bs.h"

struct silofs_env;

/* main boot-record, in-memory representation */
struct silofs_mbr {
	struct silofs_ivkey main_ivkey;
	struct silofs_uuid  uuid;
	struct silofs_uaddr sb_addr;
	struct silofs_caddr ar_addr;
	enum silofs_mbrf    flags;
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
struct silofs_mbrctl {
	struct silofs_mbr     mbr;
	struct silofs_cipher  cipher;
	struct silofs_mdigest mdigest;
	struct silofs_ivkey   ivkey;
	struct silofs_caddr   mref;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbr_init(struct silofs_mbr *mbr);

void silofs_mbr_fini(struct silofs_mbr *mbr);

void silofs_mbr_assign(struct silofs_mbr *mbr, const struct silofs_mbr *other);

void silofs_mbr_gen_uuid(struct silofs_mbr *mbr);

void silofs_mbr_set_ivkey(struct silofs_mbr         *mbr,
                          const struct silofs_ivkey *ivkey);

int silofs_mbr_gen_ivkey(struct silofs_mbr           *mbr,
                         const struct silofs_mdigest *md);

void silofs_mbr_set_sb_addr(struct silofs_mbr         *mbr,
                            const struct silofs_uaddr *sb_uaddr);

void silofs_mbr_set_ar_addr(struct silofs_mbr         *mbr,
                            const struct silofs_caddr *caddr);

void silofs_make_mbr_uaddr(const struct silofs_blobid *blobid,
                           struct silofs_uaddr        *out_uaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mbrctl_init(struct silofs_mbrctl *mbrc);

void silofs_mbrctl_fini(struct silofs_mbrctl *mbrc);

int silofs_mbrctl_regen(struct silofs_mbrctl *mbrc);

int silofs_mbrctl_update_sb(struct silofs_mbrctl      *mbrc,
                            const struct silofs_uaddr *sb_uaddr);

int silofs_mbrctl_encode(const struct silofs_mbrctl *mbrc,
                         struct silofs_mbr1k        *out_mbr1k_enc,
                         struct silofs_caddr        *out_caddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encode_mbr(const struct silofs_env *env,
                      const struct silofs_mbr *mbr,
                      struct silofs_mbr1k     *out_mbr1k_enc);

int silofs_decode_mbr(const struct silofs_env   *env,
                      const struct silofs_mbr1k *mbr1k_enc,
                      struct silofs_mbr         *out_mbr);

int silofs_stat_mbr(const struct silofs_env   *env,
                    const struct silofs_caddr *caddr);

int silofs_save_mbr(const struct silofs_env *env, const struct silofs_mbr *mbr,
                    struct silofs_caddr *out_caddr);

int silofs_load_mbr(const struct silofs_env   *env,
                    const struct silofs_caddr *caddr,
                    struct silofs_mbr         *out_mbr);

int silofs_reload_mbr(struct silofs_env *env, const struct silofs_caddr *caddr,
                      struct silofs_mbr *out_mbr);

int silofs_unlink_mbr(const struct silofs_env   *env,
                      const struct silofs_caddr *caddr);

int silofs_calc_mbr_caddr(const struct silofs_env *env,
                          const struct silofs_mbr *mbr,
                          struct silofs_caddr     *out_caddr);

#endif /* SILOFS_MBR_H_ */
