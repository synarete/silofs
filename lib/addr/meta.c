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
#include "configs.h"
#include <uuid/uuid.h>
#include <errno.h>
#include "infra.h"
#include "str.h"
#include "htox.h"
#include "mtype.h"
#include "meta.h"

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other)
{
	return (memcmp(hash->hash, other->hash, sizeof(hash->hash)) == 0);
}

void silofs_hash256_copyto(const struct silofs_hash256 *hash,
                           struct silofs_hash256 *other)
{
	memcpy(other->hash, hash->hash, sizeof(other->hash));
}

void silofs_hash256_to_u64s(const struct silofs_hash256 *hash, uint64_t u[4])
{
	const uint8_t *p = hash->hash;

	SILOFS_STATICASSERT_EQ(sizeof(hash->hash), 4 * sizeof(uint64_t));

	u[0] = silofs_u8b_as_u64(p);
	u[1] = silofs_u8b_as_u64(p + 8);
	u[2] = silofs_u8b_as_u64(p + 16);
	u[3] = silofs_u8b_as_u64(p + 24);
}

void silofs_hash256_from_u64s(struct silofs_hash256 *hash, const uint64_t u[4])
{
	uint8_t *p = hash->hash;

	SILOFS_STATICASSERT_EQ(sizeof(hash->hash), 4 * sizeof(uint64_t));

	silofs_u8b_from_u64(p, u[0]);
	silofs_u8b_from_u64(p + 8, u[1]);
	silofs_u8b_from_u64(p + 16, u[2]);
	silofs_u8b_from_u64(p + 24, u[3]);
}

size_t silofs_hash256_to_name(const struct silofs_hash256 *hash,
                              struct silofs_strbuf *out_name)
{
	size_t cnt = 0;

	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(hash->hash, sizeof(hash->hash), out_name->str,
	                    sizeof(out_name->str) - 1, &cnt);
	return cnt;
}

int silofs_hash256_by_name(struct silofs_hash256 *hash,
                           const struct silofs_strbuf *name)
{
	struct silofs_strview sv;
	size_t cnt = 0;
	int err;

	silofs_strbuf_as_sv(name, &sv);
	err = silofs_ascii_to_mem(hash->hash, sizeof(hash->hash), sv.str,
	                          sv.len, &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(hash->hash)) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static void hdr_set_size(struct silofs_header *hdr, size_t size)
{
	silofs_assert_gt(size, sizeof(*hdr));
	silofs_assert_le(size, SILOFS_LBK_SIZE);

	hdr->h_size = silofs_cpu_to_le32((uint32_t)size);
}

static size_t hdr_payload_size(const struct silofs_header *hdr)
{
	const size_t size = hdr_size(hdr);

	silofs_assert_gt(size, sizeof(*hdr));
	silofs_assert_le(size, SILOFS_LBK_SIZE);

	return size - sizeof(*hdr);
}

static uint16_t hdr_type(const struct silofs_header *hdr)
{
	return silofs_le16_to_cpu(hdr->h_type);
}

static void hdr_set_type(struct silofs_header *hdr, uint16_t type)
{
	silofs_assert_le(hdr->h_size, SILOFS_LBK_SIZE);

	hdr->h_type = silofs_cpu_to_le16(type);
}

static enum silofs_hdrf hdr_flags(const struct silofs_header *hdr)
{
	const int flags = (int)silofs_le16_to_cpu(hdr->h_flags);

	return (enum silofs_hdrf)flags;
}

static void hdr_set_flags(struct silofs_header *hdr, enum silofs_hdrf flags)
{
	silofs_assert_le(hdr->h_size, SILOFS_LBK_SIZE);

	hdr->h_flags = silofs_cpu_to_le16((uint16_t)flags);
}

static void hdr_add_flags(struct silofs_header *hdr, enum silofs_hdrf flags)
{
	hdr_set_flags(hdr, flags | hdr_flags(hdr));
}

static bool
hdr_has_flags(const struct silofs_header *hdr, enum silofs_hdrf flags)
{
	return (hdr_flags(hdr) & flags) > 0;
}

static uint32_t hdr_csum(const struct silofs_header *hdr)
{
	return silofs_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct silofs_header *hdr, uint32_t csum)
{
	hdr->h_csum = silofs_cpu_to_le32(csum);
	hdr_add_flags(hdr, SILOFS_HDRF_CSUM);
}

static bool hdr_has_csum(const struct silofs_header *hdr)
{
	return hdr_has_flags(hdr, SILOFS_HDRF_CSUM);
}

static const void *hdr_payload(const struct silofs_header *hdr)
{
	return hdr + 1;
}

void silofs_hdr_setup(struct silofs_header *hdr, uint16_t type, size_t size)
{
	silofs_hdr_setup2(hdr, type, size, SILOFS_HDRF_NONE);
}

void silofs_hdr_setup2(struct silofs_header *hdr, uint16_t type, size_t size,
                       enum silofs_hdrf flags)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr_set_magic(hdr, SILOFS_META_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_type(hdr, type);
	hdr_set_flags(hdr, flags);
	hdr->h_csum = 0;
	hdr->h_flags = 0;
}

static int hdr_verify_base(const struct silofs_header *hdr, uint16_t type,
                           size_t size, enum silofs_hdrf flags)
{
	if (hdr_magic(hdr) != SILOFS_META_MAGIC) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_type(hdr) != type) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (hdr_size(hdr) != size) {
		return -SILOFS_EFSCORRUPTED;
	}
	if (!hdr_has_flags(hdr, flags)) {
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static uint32_t hdr_calc_chekcsum(const struct silofs_header *hdr)
{
	const void *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	return silofs_xxh32(payload, pl_size, SILOFS_META_MAGIC);
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

int silofs_hdr_verify(const struct silofs_header *hdr, uint16_t type,
                      size_t size, enum silofs_hdrf flags)
{
	int err;

	err = hdr_verify_base(hdr, type, size, flags);
	if (err) {
		return err;
	}
	err = hdr_verify_checksum(hdr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_hdr_verify2(const struct silofs_header *hdr,
                       enum silofs_mtype mtype)
{
	return silofs_hdr_verify(hdr, (uint16_t)mtype,
	                         silofs_mtype_size(mtype), SILOFS_HDRF_CSUM);
}
