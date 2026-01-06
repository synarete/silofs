/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/ondisk.h>
#include <silofs/errors.h>
#include <gcrypt.h>
#include "infra.h"
#include "gcry.h"
#include "mdigest.h"

int silofs_mdigest_init(struct silofs_mdigest_hd *md_hd)
{
	const int16_t algos[] = {
		GCRY_MD_MD5,           //
		GCRY_MD_CRC32,         //
		GCRY_MD_CRC32_RFC1510, //
		GCRY_MD_CRC24_RFC2440, //
		GCRY_MD_SHA256,        //
		GCRY_MD_SHA3_256,      //
		GCRY_MD_SHA3_512,      //
	};
	gcry_error_t err;

	STATICASSERT_EQ(ARRAY_SIZE(md_hd->md_algos), ARRAY_SIZE(algos));

	md_hd->md_nalgos = 0;
	err = gcry_md_open(&md_hd->md_hd, 0, 0 /* GCRY_MD_FLAG_SECURE */);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_md_open");
	}
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(algos); ++i) {
		md_hd->md_algos[md_hd->md_nalgos++] = algos[i];
		err = gcry_md_enable(md_hd->md_hd, algos[i]);
		if (err) {
			return silofs_gcrypt_status(err, "gcry_md_enable");
		}
	}
	return 0;
}

void silofs_mdigest_fini(struct silofs_mdigest_hd *md_hd)
{
	if (md_hd->md_nalgos > 0) {
		gcry_md_close(md_hd->md_hd);
		md_hd->md_nalgos = 0;
	}
}

static void mdigest_calc_buf(const struct silofs_mdigest_hd *md_hd,
                             const void *buf, size_t bsz)
{
	gcry_md_reset(md_hd->md_hd);
	gcry_md_write(md_hd->md_hd, buf, bsz);
	gcry_md_final(md_hd->md_hd);
}

static void mdigest_calc_iov(const struct silofs_mdigest_hd *md_hd,
                             const struct iovec *iovs, size_t cnt)
{
	const struct iovec *iov;

	gcry_md_reset(md_hd->md_hd);
	for (size_t i = 0; i < cnt; ++i) {
		iov = &iovs[i];
		if (iov->iov_base && iov->iov_len) {
			gcry_md_write(md_hd->md_hd, iov->iov_base,
			              iov->iov_len);
		}
	}
	gcry_md_final(md_hd->md_hd);
}

static void mdigest_read_hval(const struct silofs_mdigest_hd *md_hd, int algo,
                              size_t hash_len, void *out_hash_buf)
{
	const void *hval;

	hval = gcry_md_read(md_hd->md_hd, algo);
	memcpy(out_hash_buf, hval, hash_len);
}

static void
mdigest_calc(const struct silofs_mdigest_hd *md_hd, int algo, const void *buf,
             size_t bsz, size_t hash_len, void *out_hash_buf)
{
	mdigest_calc_buf(md_hd, buf, bsz);
	mdigest_read_hval(md_hd, algo, hash_len, out_hash_buf);
}

static void mdigest_vcalc(const struct silofs_mdigest_hd *md_hd, int algo,
                          const struct iovec *iovs, size_t cnt,
                          size_t hash_len, void *out_hash_buf)
{
	mdigest_calc_iov(md_hd, iovs, cnt);
	mdigest_read_hval(md_hd, algo, hash_len, out_hash_buf);
}

static void require_algo_dlen(int algo, size_t hlen)
{
	const size_t dlen = gcry_md_get_algo_dlen(algo);

	if (dlen != hlen) {
		silofs_panic("algo-dlen mismatch: algo=%d dlen=%lu hlen=%lu",
		             algo, dlen, hlen);
	}
}

void silofs_sha256_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
                      size_t bsz, struct silofs_hash256 *out_hash)
{
	const int    algo = GCRY_MD_SHA256;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md_hd, algo, buf, bsz, hlen, out_hash->hash);
}

void silofs_sha256_ofv(const struct silofs_mdigest_hd *md_hd,
                       const struct iovec *iov, size_t cnt,
                       struct silofs_hash256 *out_hash)
{
	const size_t hlen = sizeof(out_hash->hash);
	const int    algo = GCRY_MD_SHA256;

	require_algo_dlen(algo, hlen);
	mdigest_vcalc(md_hd, algo, iov, cnt, hlen, out_hash->hash);
}

void silofs_sha3_256_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
                        size_t bsz, struct silofs_hash256 *out_hash)
{
	const size_t hlen = sizeof(out_hash->hash);
	const int    algo = GCRY_MD_SHA3_256;

	require_algo_dlen(algo, hlen);
	mdigest_calc(md_hd, algo, buf, bsz, hlen, out_hash->hash);
}

void silofs_sha3_256_ofv(const struct silofs_mdigest_hd *md_hd,
                         const struct iovec *iov, size_t cnt,
                         struct silofs_hash256 *out_hash)
{
	const size_t hlen = sizeof(out_hash->hash);
	const int    algo = GCRY_MD_SHA3_256;

	require_algo_dlen(algo, hlen);
	mdigest_vcalc(md_hd, algo, iov, cnt, hlen, out_hash->hash);
}

void silofs_sha3_512_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
                        size_t bsz, struct silofs_hash512 *out_hash)
{
	const size_t hlen = sizeof(out_hash->hash);
	const int    algo = GCRY_MD_SHA3_512;

	require_algo_dlen(algo, hlen);
	mdigest_calc(md_hd, algo, buf, bsz, hlen, out_hash->hash);
}

static uint32_t digest_to_uint32(const uint8_t *digest)
{
	const uint32_t d0 = digest[0];
	const uint32_t d1 = digest[1];
	const uint32_t d2 = digest[2];
	const uint32_t d3 = digest[3];

	return (d0 << 24) | (d1 << 16) | (d2 << 8) << d3;
}

void silofs_crc32_of(const struct silofs_mdigest_hd *md_hd, const void *buf,
                     size_t bsz, uint32_t *out_crc32)
{
	const int    algo = GCRY_MD_CRC32;
	const size_t hlen = sizeof(*out_crc32);
	const void  *ptr  = nullptr;

	require_algo_dlen(algo, hlen);
	gcry_md_reset(md_hd->md_hd);
	gcry_md_write(md_hd->md_hd, buf, bsz);
	gcry_md_final(md_hd->md_hd);
	ptr = gcry_md_read(md_hd->md_hd, algo);

	*out_crc32 = digest_to_uint32(ptr);
}
