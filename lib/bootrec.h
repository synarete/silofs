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
#ifndef SILOFS_BOOTREC_H_
#define SILOFS_BOOTREC_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "obs.h"

struct silofs_env;

/* top-level boot-record representation (in-memory) */
struct silofs_bootrec {
	struct silofs_uuid   uuid;
	struct silofs_ivkey  main_ivkey;
	struct silofs_uaddr  sb_uaddr;
	struct silofs_pvsegr pvsegr;
	enum silofs_bootrecf flags;
	int32_t              cipher_algo;
	int32_t              cipher_mode;
};

/* a tuple of content-addressable references to bootrec blocks */
struct silofs_bootrec_caddrs {
	struct silofs_caddr base;
	struct silofs_caddr curr;
	struct silofs_caddr fork;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec1k_init(struct silofs_bootrec1k *bootrec1k);

void silofs_bootrec1k_fini(struct silofs_bootrec1k *bootrec1k);

void silofs_bootrec1k_stamp(struct silofs_bootrec1k     *bootrec1k,
                            const struct silofs_mdigest *md);

int silofs_bootrec1k_verify(const struct silofs_bootrec1k *bootrec1k,
                            const struct silofs_mdigest   *md);

void silofs_bootrec1k_xtoh(const struct silofs_bootrec1k *bootrec1k,
                           struct silofs_bootrec         *bootrec);

void silofs_bootrec1k_htox(struct silofs_bootrec1k     *bootrec1k,
                           const struct silofs_bootrec *bootrec);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *bootrec);

void silofs_bootrec_fini(struct silofs_bootrec *bootrec);

void silofs_bootrec_assign(struct silofs_bootrec       *bootrec,
                           const struct silofs_bootrec *other);

void silofs_bootrec_gen_uuid(struct silofs_bootrec *bootrec);

void silofs_bootrec_set_ivkey(struct silofs_bootrec     *bootrec,
                              const struct silofs_ivkey *ivkey);

int silofs_bootrec_gen_ivkey(struct silofs_bootrec       *bootrec,
                             const struct silofs_mdigest *md);

void silofs_bootrec_pvsegr(const struct silofs_bootrec *bootrec,
                           struct silofs_pvsegr        *out_pvsegr);

void silofs_bootrec_set_pvsegr(struct silofs_bootrec      *bootrec,
                               const struct silofs_pvsegr *pvsegr);

void silofs_bootrec_sb_uaddr(const struct silofs_bootrec *bootrec,
                             struct silofs_uaddr         *out_uaddr);

void silofs_bootrec_set_sb_uaddr(struct silofs_bootrec     *bootrec,
                                 const struct silofs_uaddr *sb_uaddr);

void silofs_bootrec_blobid(const struct silofs_bootrec *bootrec,
                           struct silofs_blobid        *out_vid);

void silofs_make_bootrec_uaddr(const struct silofs_blobid *blobid,
                               struct silofs_uaddr        *out_uaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encode_bootrec(const struct silofs_env     *env,
                          const struct silofs_bootrec *bootrec,
                          struct silofs_bootrec1k     *out_bootrec1k_enc);

int silofs_decode_bootrec(const struct silofs_env       *env,
                          const struct silofs_bootrec1k *bootrec1k_enc,
                          struct silofs_bootrec         *out_bootrec);

int silofs_stat_bootrec(const struct silofs_env   *env,
                        const struct silofs_caddr *caddr);

int silofs_save_bootrec(const struct silofs_env     *env,
                        const struct silofs_bootrec *bootrec,
                        struct silofs_caddr         *out_caddr);

int silofs_load_bootrec(const struct silofs_env   *env,
                        const struct silofs_caddr *caddr,
                        struct silofs_bootrec     *out_bootrec);

int silofs_reload_bootrec(struct silofs_env         *env,
                          const struct silofs_caddr *caddr,
                          struct silofs_bootrec     *out_bootrec);

int silofs_unlink_bootrec(const struct silofs_env   *env,
                          const struct silofs_caddr *caddr);

int silofs_calc_bootrec_caddr(const struct silofs_env     *env,
                              const struct silofs_bootrec *bootrec,
                              struct silofs_caddr         *out_caddr);

#endif /* SILOFS_BOOTREC_H_ */
