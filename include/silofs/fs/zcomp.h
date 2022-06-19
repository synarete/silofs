/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_ZCOMP_H_
#define SILOFS_ZCOMP_H_


struct silofs_zcomp {
	void *ctx;
	int   mode;
};

const char *silofs_zstd_version(void);

int silofs_zcomp_init(struct silofs_zcomp *zc, bool de);

void silofs_zcomp_fini(struct silofs_zcomp *zc);

int silofs_zcomp_compress(const struct silofs_zcomp *zc,
                          void *dst, size_t dst_cap, const void *src,
                          size_t src_size, int cl_in, size_t *out_sz);

int silofs_zcomp_decompress(const struct silofs_zcomp *zc,
                            void *dst, size_t dst_cap, const void *src,
                            size_t src_size, size_t *out_sz);

#endif /* SILOFS_ZCOMP_H_ */
