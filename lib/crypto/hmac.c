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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include <gcrypt.h>
#include "infra.h"
#include "gcry.h"
#include "hmac.h"

static void mac_reset(struct silofs_mac *mac)
{
	memset(mac, 0, sizeof(*mac));
}

int silofs_hmac_init(struct silofs_hmac_hd *hm_hd)
{
	gcry_error_t err;
	const int    algo = GCRY_MAC_HMAC_SHA3_256;

	err = gcry_mac_open(&hm_hd->hm_hd, algo, 0, NULL);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_open");
	}
	hm_hd->hm_algo = algo;
	return 0;
}

void silofs_hmac_fini(struct silofs_hmac_hd *hm_hd)
{
	if (hm_hd->hm_algo != 0) {
		gcry_mac_close(hm_hd->hm_hd);
		hm_hd->hm_algo = 0;
	}
}

static int
hmac_set_key(struct silofs_hmac_hd *hm_hd, const struct silofs_ckey *key)
{
	gcry_error_t err;
	unsigned int keylen;

	keylen = gcry_mac_get_algo_keylen(hm_hd->hm_algo);
	if (!keylen || (keylen > sizeof(key->key))) {
		silofs_log_warn("bad keylen: algo=%d keylen=%u",
		                hm_hd->hm_algo, keylen);
		return -SILOFS_EINVAL;
	}
	err = gcry_mac_setkey(hm_hd->hm_hd, key->key, keylen);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_setkey");
	}
	return 0;
}

static int hmac_prepare(struct silofs_hmac_hd *hm_hd)
{
	gcry_error_t err;

	err = gcry_mac_reset(hm_hd->hm_hd);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_reset");
	}
	return 0;
}

static int hmac_feed(struct silofs_hmac_hd *hm_hd, const void *dat, size_t dsz)
{
	gcry_error_t err;

	err = gcry_mac_write(hm_hd->hm_hd, dat, dsz);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_write");
	}
	return 0;
}

static int hmac_seep(struct silofs_hmac_hd *hm_hd, struct silofs_mac *out_mac)
{
	gcry_error_t err;
	unsigned int maclen;
	size_t       len = 0;

	maclen = gcry_mac_get_algo_maclen(hm_hd->hm_algo);
	if (maclen != sizeof(out_mac->mac)) {
		silofs_log_warn("bad maclen: algo=%d maclen=%u",
		                hm_hd->hm_algo, maclen);
		return -SILOFS_EINVAL;
	}
	mac_reset(out_mac);
	err = gcry_mac_read(hm_hd->hm_hd, out_mac->mac, &len);
	if (err) {
		return silofs_gcrypt_status(err, "gcry_mac_read");
	}
	if (len != maclen) {
		silofs_log_warn("bad mac-read len: algo=%d len=%zu",
		                hm_hd->hm_algo, len);
		return -SILOFS_EINVAL;
	}
	return 0;
}

int silofs_hmac_calc(struct silofs_hmac_hd    *hm_hd,
                     const struct silofs_ckey *key, const void *dat,
                     size_t dsz, struct silofs_mac *out_mac)
{
	int err;

	err = hmac_prepare(hm_hd);
	if (err) {
		return err;
	}
	err = hmac_set_key(hm_hd, key);
	if (err) {
		return err;
	}
	err = hmac_feed(hm_hd, dat, dsz);
	if (err) {
		return err;
	}
	err = hmac_seep(hm_hd, out_mac);
	if (err) {
		return err;
	}
	return 0;
}
