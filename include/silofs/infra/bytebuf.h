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
#ifndef SILOFS_BYTEBUF_H_
#define SILOFS_BYTEBUF_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct silofs_bytebuf {
	uint8_t *ptr;
	size_t   len;
	size_t   cap;
};

void silofs_bytebuf_init(struct silofs_bytebuf *bb, void *p, size_t n);

void silofs_bytebuf_init2(struct silofs_bytebuf *bb, void *p, size_t n);

void silofs_bytebuf_fini(struct silofs_bytebuf *bb);

void silofs_bytebuf_reset(struct silofs_bytebuf *bb);

void *silofs_bytebuf_end(const struct silofs_bytebuf *bb);

bool silofs_bytebuf_has_free(const struct silofs_bytebuf *bb, size_t cnt);

size_t
silofs_bytebuf_append(struct silofs_bytebuf *bb, const void *p, size_t len);

size_t silofs_bytebuf_append2(struct silofs_bytebuf       *bb,
                              const struct silofs_bytebuf *other);

size_t silofs_bytebuf_insert(struct silofs_bytebuf *bb, size_t pos,
                             const void *p, size_t len);

#endif /* SILOFS_BYTEBUF_H_ */
