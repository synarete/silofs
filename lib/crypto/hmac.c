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
#include <gcrypt.h>

#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/crypto.h>

static void mac_reset(struct silofs_mac *mac)
{
	memset(mac, 0, sizeof(*mac));
}

bool silofs_mac_isequal(const struct silofs_mac *mac,
                        const struct silofs_mac *other)
{
	return (memcmp(mac->mac, other->mac, sizeof(mac->mac)) == 0);
}

int silofs_hmac_init(struct silofs_hmac_hd *hmac_hd)
{
	gcry_error_t err;
	const int algo = GCRY_MAC_HMAC_SHA3_256;

	err = gcry_mac_open(&hmac_hd->hm_hd, algo, 0, nullptr);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_open");
	}
	hmac_hd->hm_algo = algo;
	return 0;
}

void silofs_hmac_fini(struct silofs_hmac_hd *hmac_hd)
{
	if (hmac_hd->hm_algo != 0) {
		gcry_mac_close(hmac_hd->hm_hd);
		hmac_hd->hm_algo = 0;
	}
}

static int
hmac_set_key(struct silofs_hmac_hd *hmac_hd, const struct silofs_ckey *key)
{
	gcry_error_t err;
	unsigned int keylen;

	keylen = gcry_mac_get_algo_keylen(hmac_hd->hm_algo);
	if (!keylen || (keylen > sizeof(key->key))) {
		silofs_log_warn("bad keylen: algo=%d keylen=%u",
		                hmac_hd->hm_algo, keylen);
		return -SILOFS_EINVAL;
	}
	err = gcry_mac_setkey(hmac_hd->hm_hd, key->key, keylen);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_setkey");
	}
	return 0;
}

static int hmac_prepare(struct silofs_hmac_hd *hmac_hd)
{
	gcry_error_t err;

	err = gcry_mac_reset(hmac_hd->hm_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_reset");
	}
	return 0;
}

static int
hmac_feed(struct silofs_hmac_hd *hmac_hd, const void *dat, size_t dsz)
{
	gcry_error_t err;

	err = gcry_mac_write(hmac_hd->hm_hd, dat, dsz);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_write");
	}
	return 0;
}

static int
hmac_seep(struct silofs_hmac_hd *hmac_hd, struct silofs_mac *out_mac)
{
	gcry_error_t err;
	size_t maclen;

	maclen = gcry_mac_get_algo_maclen(hmac_hd->hm_algo);
	if (maclen != sizeof(out_mac->mac)) {
		silofs_log_warn("bad maclen: algo=%d maclen=%zu",
		                hmac_hd->hm_algo, maclen);
		return -SILOFS_EINVAL;
	}
	mac_reset(out_mac);
	err = gcry_mac_read(hmac_hd->hm_hd, out_mac->mac, &maclen);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_read");
	}
	return 0;
}

int silofs_hmac_calc(struct silofs_hmac_hd *hmac_hd,
                     const struct silofs_ckey *key, const void *dat,
                     size_t dsz, struct silofs_mac *out_mac)
{
	int err;

	err = hmac_prepare(hmac_hd);
	if (err) {
		return err;
	}
	err = hmac_set_key(hmac_hd, key);
	if (err) {
		return err;
	}
	err = hmac_feed(hmac_hd, dat, dsz);
	if (err) {
		return err;
	}
	err = hmac_seep(hmac_hd, out_mac);
	if (err) {
		return err;
	}
	return 0;
}
