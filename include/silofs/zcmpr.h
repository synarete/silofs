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
#ifndef SILOFS_ZCMPR_H_
#define SILOFS_ZCMPR_H_


struct silofs_zcmpr {
	void *ctx;
	int   mode;
};

const char *silofs_zstd_version(void);

int silofs_zcmpr_init(struct silofs_zcmpr *zc, bool de);

void silofs_zcmpr_fini(struct silofs_zcmpr *zc);

int silofs_zcmpr_compress(const struct silofs_zcmpr *zc,
                          void *dst, size_t dst_cap, const void *src,
                          size_t src_size, int cl_in, size_t *out_sz);

int silofs_zcmpr_decompress(const struct silofs_zcmpr *zc,
                            void *dst, size_t dst_cap, const void *src,
                            size_t src_size, size_t *out_sz);

#endif /* SILOFS_ZCMPR_H_ */
