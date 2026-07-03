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
#ifndef SILOFS_ADDR_H_
#define SILOFS_ADDR_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <silofs/ondisk.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/crypt.h>

#include <silofs/addr/offlen.h>
#include <silofs/addr/htox.h>
#include <silofs/addr/namestr.h>
#include <silofs/addr/creds.h>
#include <silofs/addr/laddr.h>
#include <silofs/addr/uniqid.h>
#include <silofs/addr/blobid.h>
#include <silofs/addr/paddr.h>
#include <silofs/addr/pnptr.h>
#include <silofs/addr/fsref.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* hash */

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other);

void silofs_hash256_assign(struct silofs_hash256       *hash,
                           const struct silofs_hash256 *other);

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256       *other);

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf        *out_name);

int silofs_hash256_to_str(const struct silofs_hash256 *hash, char *str,
                          size_t len);

int silofs_hash256_from_str(struct silofs_hash256 *hash, const char *str,
                            size_t len);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* spdesc */

/* space descriptor as p-addresses range */
struct silofs_spdesc {
	struct silofs_paddr beg;
	struct silofs_paddr end;
};

const struct silofs_spdesc *silofs_spdesc_none(void);

void silofs_spdesc_setup(struct silofs_spdesc      *spdesc,
                         const struct silofs_paddr *beg,
                         const struct silofs_paddr *end);

void silofs_spdesc_setup1(struct silofs_spdesc      *spdesc,
                          const struct silofs_paddr *beg);

void silofs_spdesc_htox(struct silofs_spdesc128b   *spdesc128,
                        const struct silofs_spdesc *spdesc);

void silofs_spdesc_xtoh(const struct silofs_spdesc128b *spdesc128,
                        struct silofs_spdesc           *spdesc);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* genid */

void silofs_generate_civ(struct silofs_prandgen *prng,
                         struct silofs_civ      *out_civ);

void silofs_generate_ckey(struct silofs_prandgen *prng,
                          struct silofs_ckey     *out_ckey);

void silofs_generate_uniqid(struct silofs_prandgen *prng,
                            struct silofs_uniqid   *out_uniqid);

void silofs_generate_layerid(struct silofs_layerid *out_layerid);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#endif /* SILOFS_ADDR_H_ */
