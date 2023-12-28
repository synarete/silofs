/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/infra.h>
#include <silofs/addr.h>


static uint32_t hdr_magic(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_magic);
}

static void hdr_set_magic(struct silofs_header *hdr, uint32_t magic)
{
	hdr->h_magic = silofs_cpu_to_le32(magic);
}

static size_t hdr_size(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_size);
}

static size_t hdr_payload_size(const struct silofs_header *hdr)
{
	return hdr_size(hdr) - sizeof(*hdr);
}

static void hdr_set_size(struct silofs_header *hdr, size_t size)
{
	hdr->h_size = silofs_cpu_to_le32((uint32_t)size);
}

static uint8_t hdr_type(const struct silofs_header *hdr)
{
	return hdr->h_type;
}

static void hdr_set_type(struct silofs_header *hdr, uint8_t ltype)
{
	hdr->h_type = (uint8_t)ltype;
}

static uint32_t hdr_csum(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct silofs_header *hdr, uint32_t csum)
{
	hdr->h_csum = silofs_cpu_to_le32(csum);
	hdr->h_flags |= SILOFS_HDRF_CSUM;
}

static bool hdr_has_csum(const struct silofs_header *hdr)
{
	return (hdr->h_flags & SILOFS_HDRF_CSUM) > 0;
}

static const void *hdr_payload(const struct silofs_header *hdr)
{
	return hdr + 1;
}

void silofs_hdr_setup(struct silofs_header *hdr, uint8_t type, size_t size)
{
	hdr_set_magic(hdr, SILOFS_META_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_type(hdr, type);
	hdr->h_csum = 0;
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

static int hdr_verify_base(const struct silofs_header *hdr,
                           uint8_t expected_type, size_t expected_size)
{
	const size_t hsz = hdr_size(hdr);

	if (hdr_magic(hdr) != SILOFS_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_type(hdr) != expected_type) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hsz != expected_size) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static uint32_t hdr_calc_chekcsum(const struct silofs_header *hdr)
{
	const void *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	return silofs_hash_xxh32(payload, pl_size, SILOFS_META_MAGIC);
}

void silofs_hdr_seal(struct silofs_header *hdr)
{
	const uint32_t csum = hdr_calc_chekcsum(hdr);

	hdr_set_csum(hdr, csum);
}

static int hdr_verify_checksum(const struct silofs_header *hdr)
{
	uint32_t csum;

	if (!hdr_has_csum(hdr)) {
		return 0;
	}
	csum = hdr_calc_chekcsum(hdr);
	if (csum != hdr_csum(hdr)) {
		return -SILOFS_EFSBADCRC;
	}
	return 0;
}

int silofs_hdr_verify(const struct silofs_header *hdr,
                      uint8_t expected_type, size_t expected_size)
{
	int err;

	err = hdr_verify_base(hdr, expected_type, expected_size);
	if (err) {
		return err;
	}
	err = hdr_verify_checksum(hdr);
	if (err) {
		return err;
	}
	return 0;
}
