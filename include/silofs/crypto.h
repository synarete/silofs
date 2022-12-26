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
#ifndef SILOFS_CRYPTO_H_
#define SILOFS_CRYPTO_H_


const char *silofs_gcrypt_version(void);

int silofs_init_gcrypt(void);

int silofs_mdigest_init(struct silofs_mdigest *md);

void silofs_mdigest_fini(struct silofs_mdigest *md);

int silofs_crypto_init(struct silofs_crypto *crypto);

void silofs_crypto_fini(struct silofs_crypto *crypto);

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

void silofs_sha256_ofv(const struct silofs_mdigest *md,
                       const struct iovec *iov, size_t cnt,
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


int silofs_password_setup(struct silofs_password *pp, const void *pass);

void silofs_password_reset(struct silofs_password *pp);


void silofs_ivkey_init(struct silofs_ivkey *ivkey);

void silofs_ivkey_fini(struct silofs_ivkey *ivkey);

void silofs_ivkey_copyto(const struct silofs_ivkey *ivkey,
                         struct silofs_ivkey *other);

void silofs_gcry_randomize(void *buf, size_t len, bool very_strong);


#endif /* SILOFS_CRYPTO_H_ */
