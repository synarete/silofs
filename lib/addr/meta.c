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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <uuid/uuid.h>


uint32_t silofs_squash_to_u32(const void *ptr, size_t len)
{
	const uint8_t *ba = ptr;
	const size_t len_head = (len / 4) * 4;
	const size_t len_tail = len - len_head;
	uint32_t ret = 0;
	uint32_t lei = 0;
	size_t pos = 0;

	while (pos < len_head) {
		lei = ((uint32_t)(ba[pos]) << 24) |
		      ((uint32_t)(ba[pos + 1]) << 16) |
		      ((uint32_t)(ba[pos + 2]) << 8) |
		      ((uint32_t)(ba[pos + 3]));
		ret ^= silofs_le32_to_cpu(lei);
		pos += 4;
	}

	switch (len_tail) {
	case 3:
		lei = ((uint32_t)(ba[pos]) << 16) |
		      ((uint32_t)(ba[pos + 1]) << 8) |
		      ((uint32_t)(ba[pos + 2]));
		break;
	case 2:
		lei = ((uint32_t)(ba[pos]) << 8) |
		      ((uint32_t)(ba[pos + 1]));
		break;
	case 1:
		lei = ((uint32_t)(ba[pos]));
		break;
	default:
		lei = 0;
		break;
	}
	ret ^= silofs_le32_to_cpu(lei);

	return ret;
}

uint64_t silofs_u8b_as_u64(const uint8_t p[8])
{
	uint64_t u = 0;

	u |= (uint64_t)(p[0]) << 56;
	u |= (uint64_t)(p[1]) << 48;
	u |= (uint64_t)(p[2]) << 40;
	u |= (uint64_t)(p[3]) << 32;
	u |= (uint64_t)(p[4]) << 24;
	u |= (uint64_t)(p[5]) << 16;
	u |= (uint64_t)(p[6]) << 8;
	u |= (uint64_t)(p[7]);

	return u;
}

static void silofs_u8b_from_u64(uint8_t p[8], uint64_t u)
{
	p[0] = (uint8_t)(u >> 56);
	p[1] = (uint8_t)(u >> 48);
	p[2] = (uint8_t)(u >> 40);
	p[3] = (uint8_t)(u >> 32);
	p[4] = (uint8_t)(u >> 24);
	p[5] = (uint8_t)(u >> 16);
	p[6] = (uint8_t)(u >> 8);
	p[7] = (uint8_t)(u);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uuid_generate(struct silofs_uuid *uu)
{
	STATICASSERT_EQ(sizeof(uu->uu), sizeof(uuid_t));

	uuid_generate_random(uu->uu);
}

void silofs_uuid_assign(struct silofs_uuid *uu,
                        const struct silofs_uuid *other)
{
	uuid_copy(uu->uu, other->uu);
}

long silofs_uuid_compare(const struct silofs_uuid *uu1,
                         const struct silofs_uuid *uu2)
{
	return uuid_compare(uu1->uu, uu2->uu);
}

void silofs_uuid_unparse(const struct silofs_uuid *uu,
                         struct silofs_strbuf *sbuf)
{
	silofs_strbuf_reset(sbuf);
	uuid_unparse_lower(uu->uu, sbuf->str);
}

int silofs_uuid_parse(struct silofs_uuid *uu,
                      const struct silofs_strbuf *sbuf)
{
	const size_t len = strlen(sbuf->str);
	int ret = -EINVAL;

	if (len == 36) {
		ret = uuid_parse_range(sbuf->str, sbuf->str + len, uu->uu);
	}
	return ret;
}

int silofs_uuid_parse2(struct silofs_uuid *uu,
                       const struct silofs_substr *ss)
{
	struct silofs_strbuf sbuf;

	silofs_strbuf_reset(&sbuf);
	silofs_substr_copyto(ss, sbuf.str, sizeof(sbuf.str) - 1);
	return silofs_uuid_parse(uu, &sbuf);
}

void silofs_uuid_as_u64s(const struct silofs_uuid *uu, uint64_t u[2])
{
	const uint8_t *p = uu->uu;

	STATICASSERT_EQ(sizeof(uu->uu), 16);

	u[0] = silofs_u8b_as_u64(p);
	u[1] = silofs_u8b_as_u64(p + 8);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static enum silofs_hdrf hdr_flags(const struct silofs_header *hdr)
{
	const int flags = (int)silofs_le16_to_cpu(hdr->h_flags);

	return (enum silofs_hdrf)flags;
}

static void hdr_set_flags(struct silofs_header *hdr, enum silofs_hdrf flags)
{
	hdr->h_flags = silofs_cpu_to_le16((uint16_t)flags);
}

static void hdr_add_flags(struct silofs_header *hdr, enum silofs_hdrf flags)
{
	hdr_set_flags(hdr, flags | hdr_flags(hdr));
}

static bool hdr_has_flags(const struct silofs_header *hdr,
                          enum silofs_hdrf flags)
{
	return (hdr_flags(hdr) & flags) > 0;
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

void silofs_hdr_setup(struct silofs_header *hdr,
                      uint8_t type, size_t size, enum silofs_hdrf flags)
{
	hdr_set_magic(hdr, SILOFS_META_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_type(hdr, type);
	hdr_set_flags(hdr, flags);
	hdr->h_csum = 0;
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

static int hdr_verify_base(const struct silofs_header *hdr,
                           uint8_t type, size_t size, enum silofs_hdrf flags)
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
                      uint8_t type, size_t size, enum silofs_hdrf flags)
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_hash256 s_hash_nil;

bool silofs_hash256_isnil(const struct silofs_hash256 *hash)
{
	return silofs_hash256_isequal(hash, &s_hash_nil);
}

bool silofs_hash256_isequal(const struct silofs_hash256 *hash,
                            const struct silofs_hash256 *other)
{
	return (memcmp(hash->hash, other->hash, sizeof(hash->hash)) == 0);
}

void silofs_hash256_assign(struct silofs_hash256 *hash,
                           const struct silofs_hash256 *other)
{
	memcpy(hash->hash, other->hash, sizeof(hash->hash));
}

void silofs_hash256_to_u64s(const struct silofs_hash256 *hash, uint64_t u[4])
{
	const uint8_t *p = hash->hash;

	STATICASSERT_EQ(sizeof(hash->hash), 4 * sizeof(uint64_t));

	u[0] = silofs_u8b_as_u64(p);
	u[1] = silofs_u8b_as_u64(p + 8);
	u[2] = silofs_u8b_as_u64(p + 16);
	u[3] = silofs_u8b_as_u64(p + 24);
}

void silofs_hash256_from_u64s(struct silofs_hash256 *hash, const uint64_t u[4])
{
	uint8_t *p = hash->hash;

	STATICASSERT_EQ(sizeof(hash->hash), 4 * sizeof(uint64_t));

	silofs_u8b_from_u64(p, u[0]);
	silofs_u8b_from_u64(p + 8, u[1]);
	silofs_u8b_from_u64(p + 16, u[2]);
	silofs_u8b_from_u64(p + 24, u[3]);
}

void silofs_hash256_to_name(const struct silofs_hash256 *hash,
                            struct silofs_strbuf *out_name)
{
	size_t cnt = 0;

	silofs_strbuf_reset(out_name);
	silofs_mem_to_ascii(hash->hash, sizeof(hash->hash),
	                    out_name->str, sizeof(out_name->str) - 1, &cnt);
}

int silofs_hash256_by_name(struct silofs_hash256 *hash,
                           const struct silofs_strbuf *name)
{
	size_t cnt = 0;
	int err;

	err = silofs_ascii_to_mem(hash->hash, sizeof(hash->hash),
	                          name->str, strlen(name->str), &cnt);
	if (err) {
		return err;
	}
	if (cnt != sizeof(hash->hash)) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}
