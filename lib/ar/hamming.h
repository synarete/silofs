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
#ifndef SILOFS_HAMMING_H_
#define SILOFS_HAMMING_H_

#include <stdlib.h>
#include <stdint.h>

int silofs_hamming12_encode(uint8_t octect, uint16_t *out_codeword12);

int silofs_hamming12_decode(uint16_t codeword12, uint8_t *out_octet);

int silofs_hamming12_encode_buf(const void *inb, size_t inlen, void *outb,
                                size_t outlen);

int silofs_hamming12_decode_buf(const void *inb, size_t inlen, void *outb,
                                size_t outlen);

#endif /* SILOFS_HAMMING_H_ */
