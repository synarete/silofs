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

#include <limits.h>

#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>

static int check_name_len(const struct silofs_strview *sv)
{
	const size_t namelen_max = silofs_min(SILOFS_NAME_MAX, NAME_MAX);

	if (sv->len == 0) {
		return -SILOFS_EILLSTR;
	}
	if (sv->len > namelen_max) {
		return -SILOFS_ENAMETOOLONG;
	}
	return 0;
}

static int check_name_dat(const struct silofs_strview *sv)
{
	if (sv->str == nullptr) {
		return -SILOFS_EILLSTR;
	}
	if (memchr(sv->str, '/', sv->len)) {
		return -SILOFS_EILLSTR;
	}
	if (sv->str[sv->len] != '\0') {
		return -SILOFS_EILLSTR;
	}
	return 0;
}

static int check_name(const struct silofs_strview *sv)
{
	int err;

	err = check_name_len(sv);
	return_if_err(err);

	err = check_name_dat(sv);
	return_if_err(err);

	return 0;
}

int silofs_namestr_init_by(struct silofs_namestr *nstr,
                           const struct silofs_strview *sv)
{
	int err;

	err = check_name(sv);
	return_if_err(err);

	silofs_strview_init_by(&nstr->sv, sv);
	nstr->hash = 0;
	return 0;
}

int silofs_namestr_init(struct silofs_namestr *nstr, const char *s)
{
	struct silofs_strview sv;

	silofs_strview_init(&sv, s);
	return silofs_namestr_init_by(nstr, &sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t hash256_to_u64(const struct silofs_hash256 *hash)
{
	const uint8_t *h = hash->hash;

	STATICASSERT_EQ(ARRAY_SIZE(hash->hash), 4 * sizeof(uint64_t));

	return silofs_u8b_as_u64(h) ^ silofs_u8b_as_u64(h + 8) ^
	       silofs_u8b_as_u64(h + 16) ^ silofs_u8b_as_u64(h + 24);
}

static uint64_t
namehash_by_sha3_256(const struct silofs_strview *sv,
                     const struct silofs_mdigest_hd *md, uint64_t seed)
{
	struct silofs_hash256 sha256;

	silofs_sha3_256_of(md, sv->str, sv->len, &sha256);
	return seed ^ hash256_to_u64(&sha256);
}

static uint64_t
namehash_by_xxh3(const struct silofs_strview *sv, uint64_t seed)
{
	return silofs_xxh3_seed(sv->str, sv->len, seed);
}

static int
namehash_of(const struct silofs_strview *sv,
            const struct silofs_mdigest_hd *md, enum silofs_namehfn nhfn,
            uint64_t seed, uint64_t *out_hash)
{
	switch (nhfn) {
	case SILOFS_NAMEHASH_SHA3_256:
		*out_hash = namehash_by_sha3_256(sv, md, seed);
		break;
	case SILOFS_NAMEHASH_XXH3:
		*out_hash = namehash_by_xxh3(sv, seed);
		break;
	default:
		return -SILOFS_EINVAL;
	}
	return 0;
}

int silofs_namestr_calc_hash(struct silofs_namestr *nstr,
                             const struct silofs_mdigest_hd *md,
                             enum silofs_namehfn nhfn, uint64_t seed)
{
	struct silofs_strbuf sbuf;
	struct silofs_strview asv;
	size_t alen;

	STATICASSERT_EQ(sizeof(sbuf.str) % 8, 0);
	STATICASSERT_EQ(sizeof(sbuf.str), SILOFS_NAME_MAX + 1);

	alen = 8 * silofs_div_round_up(nstr->sv.len, 8);
	silofs_strbuf_bzero(&sbuf, alen);
	silofs_strbuf_setup(&sbuf, &nstr->sv);
	silofs_strview_initn(&asv, sbuf.str, alen);
	return namehash_of(&asv, md, nhfn, seed, &nstr->hash);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int check_ascii_fs_name(const struct silofs_strview *sv)
{
	const char *allowed = "abcdefghijklmnopqrstuvwxyz"
			      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			      "0123456789_-.+=@";
	size_t n;

	if (!silofs_strview_isprint(sv)) {
		return -SILOFS_EILLSTR;
	}
	if (!silofs_strview_isascii(sv)) {
		return -SILOFS_EILLSTR;
	}
	n = silofs_strview_count_if(sv, silofs_chr_isspace);
	if (n > 0) {
		return -SILOFS_EILLSTR;
	}
	n = silofs_strview_count_if(sv, silofs_chr_iscntrl);
	if (n > 0) {
		return -SILOFS_EILLSTR;
	}
	n = silofs_strview_find_first_not_of(sv, allowed);
	if (n < sv->len) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}

int silofs_check_fsname(const struct silofs_namestr *nstr)
{
	const struct silofs_strview *sv = &nstr->sv;
	int err;

	if (!sv->len || (sv->str == nullptr)) {
		return -SILOFS_EILLSTR;
	}
	if (sv->str[0] == '.') {
		return -SILOFS_EILLSTR;
	}
	if (sv->len > SILOFS_FSNAME_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	err = check_ascii_fs_name(sv);
	if (err) {
		return err;
	}
	return 0;
}
