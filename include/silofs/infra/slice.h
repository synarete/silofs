/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#ifndef SILOFS_SLICE_H_
#define SILOFS_SLICE_H_

#include <stdlib.h>

struct silofs_slice {
	void  *ptr;
	size_t len;
	size_t cap;
};

void silofs_slice_init(struct silofs_slice *sl, void *p, size_t n);

void silofs_slice_fini(struct silofs_slice *sl);

void *silofs_slice_end(const struct silofs_slice *sl);

size_t silofs_slice_append(struct silofs_slice *sl, const void *p, size_t len);

#endif /* SILOFS_SLICE_H_ */
