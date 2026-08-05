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
#ifndef SILOFS_PRAND_H_
#define SILOFS_PRAND_H_

#include <stdlib.h>
#include <stdint.h>
#include <silofs/crypt/mdigest.h>

/* prng state input */
struct silofs_prndstate {
	uint8_t s[32];
};

/* pseudo random generator using libgcrypt SHA3 */
struct silofs_prandgen {
	struct silofs_prndstate  state[16];
	uint64_t                 prandom[32];
	uint64_t                 icount;
	uint64_t                 xcount;
	uint64_t                 ntake;
	uint32_t                 cycle;
	uint32_t                 slot;
	struct silofs_mdigest_hd md_hd;
};

int silofs_prandgen_init(struct silofs_prandgen *prng);

void silofs_prandgen_fini(struct silofs_prandgen *prng);

void silofs_prandgen_feed(struct silofs_prandgen *prng, const void *p,
                          size_t n);

void silofs_prandgen_take(struct silofs_prandgen *prng, void *p, size_t n);

#endif /* SILOFS_PRAND_H_ */
