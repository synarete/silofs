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
#include "ivkey.h"
#include "mdigest.h"

/* pseudo random generator */
struct silofs_prandgen {
	uint32_t entropy[24];
	uint64_t prandom[113];
	uint64_t cycle;
	uint16_t slot;
	uint16_t count;
	uint32_t xseed;
	/* produce pseudo-random via crypto hasher */
	struct silofs_mdigest_hd md_hd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_prandgen_init(struct silofs_prandgen *prng);

void silofs_prandgen_fini(struct silofs_prandgen *prng);

void silofs_prandgen_take(struct silofs_prandgen *prng, void *buf, size_t bsz);

uint64_t silofs_prandgen_take64(struct silofs_prandgen *prng);

#endif /* SILOFS_PRAND_H_ */
