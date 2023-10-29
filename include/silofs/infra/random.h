/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_RANDOM_H_
#define SILOFS_RANDOM_H_

#include <stdlib.h>
#include <stdint.h>

struct silofs_prandgen {
	uint32_t used_slots;
	uint32_t take_cycle;
	uint64_t rands[127];
};


void silofs_getentropy(void *buf, size_t len);


void silofs_prandgen_init(struct silofs_prandgen *prng);

void silofs_prandgen_take(struct silofs_prandgen *prng, void *buf, size_t bsz);

void silofs_prandgen_take_u64(struct silofs_prandgen *prng, uint64_t *out);


void silofs_prandgen_ascii(struct silofs_prandgen *prng, char *str, size_t n);

#endif /* SILOFS_RANDOM_H_ */
