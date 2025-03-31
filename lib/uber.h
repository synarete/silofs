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
#ifndef SILOFS_UBER_H_
#define SILOFS_UBER_H_

#include "infra.h"
#include "crypt.h"
#include "addr.h"
#include "pvlogs.h"

struct silofs_env;

/* top-level boot-record representation (in-memory) */
struct silofs_uber {
	struct silofs_uuid   uuid;
	struct silofs_ivkey  main_ivkey;
	struct silofs_ulink  sb_ulink;
	struct silofs_pvsegr pvsegr;
	enum silofs_uberf    flags;
	int32_t              cipher_algo;
	int32_t              cipher_mode;
};

/* a tuple of content-addressable references to uber blocks */
struct silofs_uber_caddrs {
	struct silofs_caddr base;
	struct silofs_caddr curr;
	struct silofs_caddr fork;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uber1k_init(struct silofs_uber1k *uber1k);

void silofs_uber1k_fini(struct silofs_uber1k *uber1k);

void silofs_uber1k_stamp(struct silofs_uber1k        *uber1k,
                         const struct silofs_mdigest *md);

int silofs_uber1k_verify(const struct silofs_uber1k  *uber1k,
                         const struct silofs_mdigest *md);

void silofs_uber1k_xtoh(const struct silofs_uber1k *uber1k,
                        struct silofs_uber         *uber);

void silofs_uber1k_htox(struct silofs_uber1k     *uber1k,
                        const struct silofs_uber *uber);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uber_init(struct silofs_uber *uber);

void silofs_uber_fini(struct silofs_uber *uber);

void silofs_uber_assign(struct silofs_uber       *uber,
                        const struct silofs_uber *other);

void silofs_uber_gen_uuid(struct silofs_uber *uber);

void silofs_uber_set_ivkey(struct silofs_uber        *uber,
                           const struct silofs_ivkey *ivkey);

int silofs_uber_gen_ivkey(struct silofs_uber          *uber,
                          const struct silofs_mdigest *md);

void silofs_uber_pvsegr(const struct silofs_uber *uber,
                        struct silofs_pvsegr     *out_pvsegr);

void silofs_uber_set_pvsegr(struct silofs_uber         *uber,
                            const struct silofs_pvsegr *pvsegr);

void silofs_uber_sb_ulink(const struct silofs_uber *uber,
                          struct silofs_ulink      *out_ulink);

void silofs_uber_set_sb_ulink(struct silofs_uber        *uber,
                              const struct silofs_ulink *sb_ulink);

void silofs_uber_reset_sb_ulink(struct silofs_uber *uber);

void silofs_uber_volumeid(const struct silofs_uber *uber,
                          struct silofs_volumeid   *out_vid);

void silofs_make_uber_uaddr(const struct silofs_volumeid *volumeid,
                            struct silofs_uaddr          *out_uaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_encode_uber(const struct silofs_env  *env,
                       const struct silofs_uber *uber,
                       struct silofs_uber1k     *out_uber1k_enc);

int silofs_decode_uber(const struct silofs_env    *env,
                       const struct silofs_uber1k *uber1k_enc,
                       struct silofs_uber         *out_uber);

int silofs_stat_uber(const struct silofs_env   *env,
                     const struct silofs_caddr *caddr);

int silofs_save_uber(const struct silofs_env  *env,
                     const struct silofs_uber *uber,
                     struct silofs_caddr      *out_caddr);

int silofs_load_uber(const struct silofs_env   *env,
                     const struct silofs_caddr *caddr,
                     struct silofs_uber        *out_uber);

int silofs_reload_uber(struct silofs_env         *env,
                       const struct silofs_caddr *caddr,
                       struct silofs_uber        *out_uber);

int silofs_unlink_uber(const struct silofs_env   *env,
                       const struct silofs_caddr *caddr);

int silofs_calc_uber_caddr(const struct silofs_env  *env,
                           const struct silofs_uber *uber,
                           struct silofs_caddr      *out_caddr);

#endif /* SILOFS_UBER_H_ */
