/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_ASCII_H_
#define SILOFS_ASCII_H_

#include <stdlib.h>
#include <stdint.h>

__attribute__((const))
char silofs_nibble_to_ascii(int n);

__attribute__((const))
int silofs_ascii_to_nibble(char a);


void silofs_uint64_to_ascii(uint64_t u, char *a);

int silofs_ascii_to_uint64(const char *a, uint64_t *out_u);


void silofs_byte_to_ascii(uint8_t b, char *a);

int silofs_ascii_to_byte(const char *a, uint8_t *b);


void silofs_mem_to_ascii(const void *mem, size_t msz,
                         char *asb, size_t asz, size_t *out_cnt);

int silofs_ascii_to_mem(void *mem, size_t msz,
                        const char *asb, size_t asz, size_t *out_cnt);


#endif /* SILOFS_ASCII_H_ */
