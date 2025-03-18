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
#ifndef SILOFS_HASH_H_
#define SILOFS_HASH_H_

#include <silofs/ccattr.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t silofs_hash_fnv1a(const void *buf, size_t len, uint64_t seed);

uint32_t silofs_hash_xxh32(const void *buf, size_t len, uint32_t seed);

uint64_t silofs_hash_xxh64(const void *buf, size_t len, uint64_t seed);

silofs_attr_const uint64_t silofs_twang_mix64(uint64_t n);

#endif /* SILOFS_HASH_H_ */
