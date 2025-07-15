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
#include "configs.h"
#include <stdlib.h>
#include "htox.h"

uint64_t silofs_u8b_as_u64(const uint8_t p[8])
{
	uint64_t u = 0;

	u |= (uint64_t)(p[0]) << 56;
	u |= (uint64_t)(p[1]) << 48;
	u |= (uint64_t)(p[2]) << 40;
	u |= (uint64_t)(p[3]) << 32;
	u |= (uint64_t)(p[4]) << 24;
	u |= (uint64_t)(p[5]) << 16;
	u |= (uint64_t)(p[6]) << 8;
	u |= (uint64_t)(p[7]);

	return u;
}

void silofs_u8b_from_u64(uint8_t p[8], uint64_t u)
{
	p[0] = (uint8_t)(u >> 56);
	p[1] = (uint8_t)(u >> 48);
	p[2] = (uint8_t)(u >> 40);
	p[3] = (uint8_t)(u >> 32);
	p[4] = (uint8_t)(u >> 24);
	p[5] = (uint8_t)(u >> 16);
	p[6] = (uint8_t)(u >> 8);
	p[7] = (uint8_t)(u);
}
