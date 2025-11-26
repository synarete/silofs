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
#ifndef SILOFS_PRANDOM_H_
#define SILOFS_PRANDOM_H_

#include <stdlib.h>
#include <stdint.h>
#include "ivkey.h"
#include "mdigest.h"

struct silofs_prandgen {
	uint64_t              entropy[12];
	uint8_t               prandom[113];
	uint64_t              cycle;
	uint32_t              slot;
	uint32_t              xxprev;
	struct silofs_mdigest mdigest;
};

void silofs_getentropy(void *p, size_t n);

void silofs_prandom(void *p, size_t n);

int silofs_prandgen_init(struct silofs_prandgen *prng);

void silofs_prandgen_fini(struct silofs_prandgen *prng);

void silofs_prandgen_take(struct silofs_prandgen *prng, void *buf, size_t bsz);

void silofs_prandgen_key(struct silofs_prandgen *prng, struct silofs_key *key);

void silofs_prandgen_iv(struct silofs_prandgen *prng, struct silofs_iv *iv);

#endif /* SILOFS_PRANDOM_H_ */
