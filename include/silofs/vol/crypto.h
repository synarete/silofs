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
#ifndef SILOFS_CRYPTO_H_
#define SILOFS_CRYPTO_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <gcrypt.h>

/* pass-phrase buffers */
struct silofs_password {
	uint8_t pass[SILOFS_PASSWORD_MAX + 1];
	size_t passlen;
};

/* cryptographic interfaces with libgcrypt */
struct silofs_mdigest {
	gcry_md_hd_t md_hd;
};

struct silofs_cipher {
	gcry_cipher_hd_t cipher_hd;
};

/* cryptographic-cipher arguments */
struct silofs_cipher_args {
	struct silofs_kdf_pair  kdf;
	unsigned int cipher_algo;
	unsigned int cipher_mode;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const char *silofs_gcrypt_version(void);

int silofs_init_gcrypt(void);

int silofs_mdigest_init(struct silofs_mdigest *md);

void silofs_mdigest_fini(struct silofs_mdigest *md);

int silofs_cipher_init(struct silofs_cipher *ci);

void silofs_cipher_fini(struct silofs_cipher *ci);


int silofs_derive_ivkey(const struct silofs_cipher_args *cip_args,
                        const struct silofs_password *pp,
                        const struct silofs_mdigest *md,
                        struct silofs_ivkey *ivkey);


void silofs_blake2s128_of(const struct silofs_mdigest *md,
                          const void *buf, size_t bsz,
                          struct silofs_hash128 *out_hash);

void silofs_sha256_of(const struct silofs_mdigest *md,
                      const void *buf, size_t bsz,
                      struct silofs_hash256 *out_hash);

void silofs_sha3_256_of(const struct silofs_mdigest *md,
                        const void *buf, size_t bsz,
                        struct silofs_hash256 *out_hash);

void silofs_sha3_512_of(const struct silofs_mdigest *md,
                        const void *buf, size_t bsz,
                        struct silofs_hash512 *out_hash);

void silofs_crc32_of(const struct silofs_mdigest *md,
                     const void *buf, size_t bsz, uint32_t *out_crc32);

int silofs_encrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey,
                       const void *in_dat, void *out_dat, size_t dat_len);

int silofs_decrypt_buf(const struct silofs_cipher *ci,
                       const struct silofs_ivkey *ivkey,
                       const void *in_dat, void *out_dat, size_t dat_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_password_setup(struct silofs_password *pp, const char *pass);

void silofs_password_reset(struct silofs_password *pp);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_calc_caddr_of(const struct iovec *iov, size_t cnt,
                          enum silofs_ctype ctype,
                          const struct silofs_mdigest *md,
                          struct silofs_caddr *out_caddr);

#endif /* SILOFS_CRYPTO_H_ */
