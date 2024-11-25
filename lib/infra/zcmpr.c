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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include <silofs/infra/zcmpr.h>
#include <zstd.h>

#if (ZSTD_VERSION_NUMBER >= 10502)
#define ZCOMP_ZSTD_DEFAULT_CLEVEL (ZSTD_defaultCLevel())
#else
#define ZCOMP_ZSTD_DEFAULT_CLEVEL (3)
#endif

#define ZCOMP_ZSTD_CCTX (1)
#define ZCOMP_ZSTD_DCTX (2)

const char *silofs_zstd_version(void)
{
	return ZSTD_versionString();
}

static int zcmpr_init_cctx(struct silofs_zcmpr *zc)
{
	ZSTD_CCtx *cctx;

	cctx = ZSTD_createCCtx();
	if (cctx == NULL) {
		return -SILOFS_ENOMEM;
	}
	zc->ctx = cctx;
	zc->mode = ZCOMP_ZSTD_CCTX;
	return 0;
}

static int zcmpr_init_dctx(struct silofs_zcmpr *zc)
{
	ZSTD_DCtx *dctx;

	dctx = ZSTD_createDCtx();
	if (dctx == NULL) {
		return -SILOFS_ENOMEM;
	}
	zc->ctx = dctx;
	zc->mode = ZCOMP_ZSTD_DCTX;
	return 0;
}

int silofs_zcmpr_init(struct silofs_zcmpr *zc, bool de)
{
	return de ? zcmpr_init_dctx(zc) : zcmpr_init_cctx(zc);
}

static void zcmpr_fini_cctx(struct silofs_zcmpr *zc)
{
	ZSTD_CCtx *cctx = zc->ctx;

	ZSTD_freeCCtx(cctx);
	zc->ctx = NULL;
	zc->mode = 0;
}

static void zcmpr_fini_dctx(struct silofs_zcmpr *zc)
{
	ZSTD_DCtx *dctx = zc->ctx;

	ZSTD_freeDCtx(dctx);
}

void silofs_zcmpr_fini(struct silofs_zcmpr *zc)
{
	if (zc->mode == ZCOMP_ZSTD_CCTX) {
		zcmpr_fini_cctx(zc);
	} else if (zc->mode == ZCOMP_ZSTD_DCTX) {
		zcmpr_fini_dctx(zc);
	}
}

static int compress_level_of(int cl_in)
{
	const int cl_min = ZSTD_minCLevel();
	const int cl_max = ZSTD_maxCLevel();

	return ((cl_in >= cl_min) && (cl_in <= cl_max)) ?
		       cl_in :
		       ZCOMP_ZSTD_DEFAULT_CLEVEL;
}

int silofs_zcmpr_compress(const struct silofs_zcmpr *zc, void *dst,
			  size_t dst_cap, const void *src, size_t src_size,
			  int cl_in, size_t *out_sz)
{
	size_t ret;
	int cl;

	if (zc->mode != ZCOMP_ZSTD_CCTX) {
		return -SILOFS_EINVAL;
	}
	cl = compress_level_of(cl_in);
	ret = ZSTD_compressCCtx(zc->ctx, dst, dst_cap, src, src_size, cl);
	if (ZSTD_isError(ret)) {
		return -SILOFS_ECOMPRESS;
	}
	*out_sz = ret;
	return 0;
}

int silofs_zcmpr_decompress(const struct silofs_zcmpr *zc, void *dst,
			    size_t dst_cap, const void *src, size_t src_size,
			    size_t *out_sz)
{
	size_t ret;

	if (zc->mode != ZCOMP_ZSTD_DCTX) {
		return -SILOFS_EINVAL;
	}
	ret = ZSTD_decompressDCtx(zc->ctx, dst, dst_cap, src, src_size);
	if (ZSTD_isError(ret)) {
		return -SILOFS_EDECOMPRESS;
	}
	*out_sz = ret;
	return 0;
}
