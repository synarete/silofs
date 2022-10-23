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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fsdef.h>
#include <silofs/ioctls.h>
#include <silofs/types.h>
#include <silofs/address.h>
#include <silofs/crypto.h>
#include <silofs/boot.h>
#include <silofs/namei.h>
#include <silofs/fs-private.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <endian.h>

static int check_ascii_fs_name(const struct silofs_namestr *nstr)
{
	const char *allowed =
	        "abcdefghijklmnopqrstuvwxyz"
	        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	        "0123456789_-+.";
	struct silofs_substr ss;
	size_t n;

	silofs_substr_init_rd(&ss, nstr->s.str, nstr->s.len);
	if (!silofs_substr_isprint(&ss)) {
		return -EINVAL;
	}
	n = silofs_substr_count_if(&ss, silofs_chr_isspace);
	if (n > 0) {
		return -EINVAL;
	}
	n = silofs_substr_count_if(&ss, silofs_chr_iscntrl);
	if (n > 0) {
		return -EINVAL;
	}
	n = silofs_substr_find_first_not_of(&ss, allowed);
	if (n < ss.len) {
		return -EINVAL;
	}
	return 0;
}

static int check_name_len(const struct silofs_namestr *nstr)
{
	if (nstr->s.len == 0) {
		return -EINVAL;
	}
	if (nstr->s.len > SILOFS_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	return 0;
}

static int check_name_dat(const struct silofs_namestr *nstr)
{
	if (nstr->s.str == NULL) {
		return -EINVAL;
	}
	if (memchr(nstr->s.str, '/', nstr->s.len)) {
		return -EINVAL;
	}
	if (nstr->s.str[nstr->s.len] != '\0') {
		return -EINVAL;
	}
	return 0;
}

int silofs_check_name(const struct silofs_namestr *nstr)
{
	int err;

	err = check_name_len(nstr);
	if (err) {
		return err;
	}
	err = check_name_dat(nstr);
	if (err) {
		return err;
	}
	return 0;
}

static int check_fsname(const struct silofs_namestr *nstr)
{
	int err;

	err = silofs_check_name(nstr);
	if (err) {
		return err;
	}
	if (nstr->s.str[0] == '.') {
		return -EINVAL;
	}
	if (nstr->s.len > (SILOFS_NAME_MAX / 2)) {
		return -ENAMETOOLONG;
	}
	err = check_ascii_fs_name(nstr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_make_namestr(struct silofs_namestr *nstr, const char *s)
{
	silofs_namestr_init(nstr, s);
	return silofs_check_name(nstr);
}

int silofs_make_fsnamestr(struct silofs_namestr *nstr, const char *s)
{
	silofs_namestr_init(nstr, s);
	return check_fsname(nstr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_cipher_args s_default_cip_args = {
	.kdf = {
		.kdf_iv = {
			.kd_iterations = 4096,
			.kd_algo = SILOFS_KDF_PBKDF2,
			.kd_subalgo = SILOFS_MD_SHA256,
			.kd_salt_md = SILOFS_MD_SHA3_256,
		},
		.kdf_key = {
			.kd_iterations = 256,
			.kd_algo = SILOFS_KDF_SCRYPT,
			.kd_subalgo = 8,
			.kd_salt_md = SILOFS_MD_SHA3_512,
		}
	},
	.cipher_algo = SILOFS_CIPHER_AES256,
	.cipher_mode = SILOFS_CIPHER_MODE_GCM,
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cip_args_isequal(const struct silofs_cipher_args *cip_args1,
                             const struct silofs_cipher_args *cip_args2)
{
	return (memcmp(cip_args1, cip_args2, sizeof(*cip_args1)) == 0);
}

static void cip_args_assign(struct silofs_cipher_args *cip_args,
                            const struct silofs_cipher_args *other)
{
	memcpy(cip_args, other, sizeof(*cip_args));
}

void silofs_default_cip_args(struct silofs_cipher_args *cip_args)
{
	cip_args_assign(cip_args, &s_default_cip_args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void kdf_to_cpu(const struct silofs_kdf_desc *kd_le,
                       struct silofs_kdf_desc *kd)
{
	kd->kd_iterations = silofs_le32_to_cpu(kd_le->kd_iterations);
	kd->kd_algo = silofs_le32_to_cpu(kd_le->kd_algo);
	kd->kd_subalgo = silofs_le16_to_cpu(kd_le->kd_subalgo);
	kd->kd_salt_md = silofs_le16_to_cpu(kd_le->kd_salt_md);
}

static void cpu_to_kdf(const struct silofs_kdf_desc *kd,
                       struct silofs_kdf_desc *kd_le)
{
	kd_le->kd_iterations = silofs_cpu_to_le32(kd->kd_iterations);
	kd_le->kd_algo = silofs_cpu_to_le32(kd->kd_algo);
	kd_le->kd_subalgo = silofs_cpu_to_le16(kd->kd_subalgo);
	kd_le->kd_salt_md = silofs_cpu_to_le16(kd->kd_salt_md);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t bsec1k_magic(const struct silofs_bootsec1k *bsc)
{
	return silofs_le64_to_cpu(bsc->bs_magic);
}

static void bsec1k_set_magic(struct silofs_bootsec1k *bsc, uint64_t magic)
{
	bsc->bs_magic = silofs_cpu_to_le64(magic);
}

static uint64_t bsec1k_version(const struct silofs_bootsec1k *bsc)
{
	return silofs_le64_to_cpu(bsc->bs_version);
}

static void bsec1k_set_version(struct silofs_bootsec1k *bsc, uint64_t version)
{
	bsc->bs_version = silofs_cpu_to_le64(version);
}

static enum silofs_bootf bsec1k_flags(const struct silofs_bootsec1k *bsc)
{
	const uint64_t f = silofs_le64_to_cpu(bsc->bs_flags);

	return (enum silofs_bootf)f;
}

static void bsec1k_set_flags(struct silofs_bootsec1k *bsc, enum silofs_bootf f)
{
	bsc->bs_flags = silofs_cpu_to_le64((uint64_t)f);
}

static void bsec1k_uuid(const struct silofs_bootsec1k *bsc,
                        struct silofs_uuid *uu)
{
	silofs_uuid_assign(uu, &bsc->bs_uuid);
}

static void bsec1k_set_uuid(struct silofs_bootsec1k *bsc,
                            const struct silofs_uuid *uu)
{
	silofs_uuid_assign(&bsc->bs_uuid, uu);
}

static void bsec1k_key_hash(const struct silofs_bootsec1k *bsc,
                            struct silofs_hash256 *out_hash)
{
	silofs_hash256_assign(out_hash, &bsc->bs_key_hash);
}

static void bsec1k_set_key_hash(struct silofs_bootsec1k *bsc,
                                const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&bsc->bs_key_hash, hash);
}

static void bsec1k_kdf(const struct silofs_bootsec1k *bsc,
                       struct silofs_kdf_pair *kdf)
{
	kdf_to_cpu(&bsc->bs_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&bsc->bs_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void bsec1k_set_kdf(struct silofs_bootsec1k *bsc,
                           const struct silofs_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &bsc->bs_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &bsc->bs_kdf_pair.kdf_key);
}

static uint32_t bsec1k_chiper_algo(const struct silofs_bootsec1k *bsc)
{
	return silofs_le32_to_cpu(bsc->bs_chiper_algo);
}

static uint32_t bsec1k_chiper_mode(const struct silofs_bootsec1k *bsc)
{
	return silofs_le32_to_cpu(bsc->bs_chiper_mode);
}

static void bsec1k_set_cipher(struct silofs_bootsec1k *bsc,
                              uint32_t cipher_algo, uint32_t cipher_mode)
{
	bsc->bs_chiper_algo = silofs_cpu_to_le32(cipher_algo);
	bsc->bs_chiper_mode = silofs_cpu_to_le32(cipher_mode);
}

static void bsec1k_fill_rands(struct silofs_bootsec1k *bsc)
{
	silofs_getentropy(bsc->bs_rands, sizeof(bsc->bs_rands));
}

void silofs_bsec1k_init(struct silofs_bootsec1k *bsc)
{
	const struct silofs_cipher_args *cip_args = &s_default_cip_args;

	silofs_memzero(bsc, sizeof(*bsc));
	bsec1k_set_magic(bsc, SILOFS_BOOT_RECORD_MAGIC);
	bsec1k_set_version(bsc, SILOFS_FMT_VERSION);
	bsec1k_set_flags(bsc, SILOFS_BOOTF_NONE);
	bsec1k_set_kdf(bsc, &cip_args->kdf);
	bsec1k_set_cipher(bsc, cip_args->cipher_algo, cip_args->cipher_mode);
	bsec1k_fill_rands(bsc);
}

void silofs_bsec1k_fini(struct silofs_bootsec1k *bsc)
{
	silofs_memffff(bsc, sizeof(*bsc));
}

static void bsec1k_sb_uaddr(const struct silofs_bootsec1k *bsc,
                            struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&bsc->bs_sb_uaddr, out_uaddr);
}

static void bsec1k_set_sb_uaddr(struct silofs_bootsec1k *bsc,
                                const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&bsc->bs_sb_uaddr, uaddr);
}

static void bsec1k_sb_cold(const struct silofs_bootsec1k *bsc,
                           struct silofs_blobid *out_blobid)
{
	silofs_blobid40b_parse(&bsc->bs_sb_cold, out_blobid);
}

static void bsec1k_set_sb_cold(struct silofs_bootsec1k *bsc,
                               const struct silofs_blobid *blobid)
{
	silofs_blobid40b_set(&bsc->bs_sb_cold, blobid);
}

static int bsec1k_check_base(const struct silofs_bootsec1k *bsc)
{
	uint64_t magic;
	uint64_t version;

	magic = bsec1k_magic(bsc);
	if (magic != SILOFS_BOOT_RECORD_MAGIC) {
		log_dbg("bad bootsec magic: 0x%lx", magic);
		return -EFSCORRUPTED;
	}
	version = bsec1k_version(bsc);
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad bootsec version: %lu", version);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int bsec1k_check_sb_uaddr(const struct silofs_bootsec1k *bsc)
{
	struct silofs_uaddr uaddr;

	bsec1k_sb_uaddr(bsc, &uaddr);
	if ((uaddr.stype != SILOFS_STYPE_SUPER) ||
	    (uaddr.height != SILOFS_HEIGHT_SUPER)) {
		log_dbg("bad bootsec sb-uaddr: stype=%d height=%d",
		        (int)uaddr.stype, (int)uaddr.height);
		return -EFSCORRUPTED;
	}
	return 0;
}

static void bsec1k_cipher_args(const struct silofs_bootsec1k *bsc,
                               struct silofs_cipher_args *cip_args)
{
	bsec1k_kdf(bsc, &cip_args->kdf);
	cip_args->cipher_algo = bsec1k_chiper_algo(bsc);
	cip_args->cipher_mode = bsec1k_chiper_mode(bsc);
}

static int bsec1k_check(const struct silofs_bootsec1k *bsc)
{
	struct silofs_cipher_args cip_args = {
		.cipher_algo = 0,
		.cipher_mode = 0,
	};
	int err;

	err = bsec1k_check_base(bsc);
	if (err) {
		return err;
	}
	err = bsec1k_check_sb_uaddr(bsc);
	if (err) {
		return err;
	}
	/* currently, requires default values */
	bsec1k_cipher_args(bsc, &cip_args);
	if (!cip_args_isequal(&cip_args, &s_default_cip_args)) {
		return -EINVAL;
	}
	return 0;
}

static void bsec1k_hash(const struct silofs_bootsec1k *bsc,
                        struct silofs_hash256 *hash)
{
	silofs_hash256_assign(hash, &bsc->bs_hash);
}

static void bsec1k_set_hash(struct silofs_bootsec1k *bsc,
                            const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&bsc->bs_hash, hash);
}

static void bsec1k_calc_hash(const struct silofs_bootsec1k *bsc,
                             const struct silofs_mdigest *md,
                             struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_bootsec1k, bs_hash);

	silofs_sha3_256_of(md, bsc, len, out_hash);
}

void silofs_bsec1k_stamp(struct silofs_bootsec1k *bsc,
                         const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	bsec1k_calc_hash(bsc, md, &hash);
	bsec1k_set_hash(bsc, &hash);
}

static int bsec1k_check_hash(const struct silofs_bootsec1k *bsc,
                             const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	bsec1k_hash(bsc, &hash[0]);
	bsec1k_calc_hash(bsc, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -EFSCORRUPTED;
}

int silofs_bsec1k_verify(const struct silofs_bootsec1k *bsc,
                         const struct silofs_mdigest *md)
{
	int err;

	err = bsec1k_check(bsc);
	if (err) {
		return err;
	}
	err = bsec1k_check_hash(bsc, md);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_bsec1k_parse(const struct silofs_bootsec1k *bsc,
                         struct silofs_bootsec *bsec)
{
	bsec1k_sb_uaddr(bsc, &bsec->sb_uaddr);
	bsec1k_sb_cold(bsc, &bsec->sb_cold);
	bsec1k_uuid(bsc, &bsec->uuid);
	bsec1k_cipher_args(bsc, &bsec->cip_args);
	bsec->flags = bsec1k_flags(bsc);
	if (bsec->flags & SILOFS_BOOTF_KEY_SHA256) {
		bsec1k_key_hash(bsc, &bsec->key_hash);
	}
}

void silofs_bsec1k_set(struct silofs_bootsec1k *bsc,
                       const struct silofs_bootsec *bsec)
{
	silofs_bsec1k_init(bsc);
	bsec1k_set_sb_uaddr(bsc, &bsec->sb_uaddr);
	bsec1k_set_sb_cold(bsc, &bsec->sb_cold);
	bsec1k_set_uuid(bsc, &bsec->uuid);
	bsec1k_set_flags(bsc, bsec->flags);
	if (bsec->flags & SILOFS_BOOTF_KEY_SHA256) {
		bsec1k_set_key_hash(bsc, &bsec->key_hash);
	}
}

void silofs_bsec1k_setn(struct silofs_bootsec1k *bsc,
                        const struct silofs_bootsec *bsec, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		silofs_bsec1k_set(&bsc[i], &bsec[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootsec_init(struct silofs_bootsec *bsec)
{
	silofs_memzero(bsec, sizeof(*bsec));
	silofs_uaddr_reset(&bsec->sb_uaddr);
	silofs_blobid_reset(&bsec->sb_cold);
	silofs_default_cip_args(&bsec->cip_args);
	silofs_uuid_generate(&bsec->uuid);
	bsec->flags = SILOFS_BOOTF_NONE;
}

void silofs_bootsec_fini(struct silofs_bootsec *bsec)
{
	silofs_memffff(bsec, sizeof(*bsec));
}

void silofs_bootsec_uuid(const struct silofs_bootsec *bsec,
                         struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &bsec->uuid);
}

void silofs_bootsec_set_uuid(struct silofs_bootsec *bsec,
                             const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&bsec->uuid, uuid);
}

void silofs_bootsec_sb_uaddr(const struct silofs_bootsec *bsec,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_assign(out_uaddr, &bsec->sb_uaddr);
}

void silofs_bootsec_set_sb_uaddr(struct silofs_bootsec *bsec,
                                 const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr_assign(&bsec->sb_uaddr, sb_uaddr);
}

void silofs_bootsec_sb_cold(const struct silofs_bootsec *bsec,
                            struct silofs_blobid *out_blobid)
{
	silofs_blobid_assign(out_blobid, &bsec->sb_cold);
}

void silofs_bootsec_set_sb_cold(struct silofs_bootsec *bsec,
                                const struct silofs_blobid *blobid)
{
	silofs_blobid_assign(&bsec->sb_cold, blobid);
}

void silofs_bootsec_set_keyhash(struct silofs_bootsec *bsec,
                                const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&bsec->key_hash, hash);
	bsec->flags |= SILOFS_BOOTF_KEY_SHA256;
}

void silofs_bootsec_clear_keyhash(struct silofs_bootsec *bsec)
{
	silofs_memzero(&bsec->key_hash, sizeof(bsec->key_hash));
	bsec->flags &= (enum silofs_bootf)(~SILOFS_BOOTF_KEY_SHA256);
}

static bool bootsec_has_keyhash(const struct silofs_bootsec *bsec,
                                const struct silofs_hash256 *hash)
{
	return silofs_hash256_isequal(&bsec->key_hash, hash);
}

int silofs_bootsec_check_keyhash(const struct silofs_bootsec *bsec,
                                 const struct silofs_hash256 *hash)
{
	return bootsec_has_keyhash(bsec, hash) ? 0 : -EKEYEXPIRED;
}

void silofs_bootsec_cipher_args(const struct silofs_bootsec *bsec,
                                struct silofs_cipher_args *out_cip_args)
{
	if (!bsec || !bsec->cip_args.cipher_algo) {
		silofs_default_cip_args(out_cip_args);
	} else {
		cip_args_assign(out_cip_args, &bsec->cip_args);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bpath,
                          const char *repodir, const char *name)
{
	size_t len;
	int ret;

	len = silofs_str_length(repodir);
	if (len && (len < SILOFS_REPOPATH_MAX)) {
		bpath->repodir.str = repodir;
		bpath->repodir.len = len;
		ret = silofs_make_namestr(&bpath->name, name);
	} else {
		silofs_memzero(bpath, sizeof(*bpath));
		ret = -EINVAL;
	}
	return ret;
}

void silofs_bootpath_assign(struct silofs_bootpath *bpath,
                            const struct silofs_bootpath *other)
{
	bpath->repodir.str = other->repodir.str;
	bpath->repodir.len = other->repodir.len;

	bpath->name.s.str = other->name.s.str;
	bpath->name.s.len = other->name.s.len;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_calc_key_hash(const struct silofs_key *key,
                          const struct silofs_mdigest *md,
                          struct silofs_hash256 *out_hash)
{
	silofs_sha256_of(md, key->key, sizeof(key->key), out_hash);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int errno_or_errnum(int errnum)
{
	return (errno > 0) ? -errno : -abs(errnum);
}

static int check_endianess32(uint32_t val, const char *str)
{
	const uint32_t val_le = htole32(val);
	char buf[16] = "";

	for (size_t i = 0; i < 4; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess64(uint64_t val, const char *str)
{
	const uint64_t val_le = htole64(val);
	char buf[16] = "";

	for (size_t i = 0; i < 8; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess(void)
{
	int err;

	err = check_endianess64(SILOFS_REPO_META_MAGIC, "#SILOFS#");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_BOOT_RECORD_MAGIC, "@SILOFS@");
	if (err) {
		return err;
	}
	err = check_endianess64(SILOFS_SUPER_MAGIC, "@silofs@");
	if (err) {
		return err;
	}
	err = check_endianess32(SILOFS_FSID_MAGIC, "SILO");
	if (err) {
		return err;
	}
	err = check_endianess32(SILOFS_STYPE_MAGIC, "silo");
	if (err) {
		return err;
	}
	return 0;
}

static int check_sysconf(void)
{
	long val;
	long page_shift = 0;
	const long page_size_min = SILOFS_PAGE_SIZE_MIN;
	const long page_shift_min = SILOFS_PAGE_SHIFT_MIN;
	const long page_shift_max = SILOFS_PAGE_SHIFT_MAX;
	const long cl_size_min = SILOFS_CACHELINE_SIZE;

	errno = 0;
	val = silofs_sc_phys_pages();
	if (val <= 0) {
		return errno_or_errnum(ENOMEM);
	}
	val = silofs_sc_avphys_pages();
	if (val <= 0) {
		return errno_or_errnum(ENOMEM);
	}
	val = silofs_sc_l1_dcache_linesize();
	if ((val != cl_size_min) || (val % cl_size_min)) {
		return errno_or_errnum(EOPNOTSUPP);
	}
	val = silofs_sc_page_size();
	if ((val < page_size_min) || (val % page_size_min)) {
		return errno_or_errnum(EOPNOTSUPP);
	}
	for (long shift = page_shift_min; shift <= page_shift_max; ++shift) {
		if (val == (1L << shift)) {
			page_shift = val;
			break;
		}
	}
	if (page_shift == 0) {
		return -EOPNOTSUPP;
	}
	return 0;
}

static int check_system_page_size(void)
{
	long page_size;
	const size_t page_shift[] = { 12, 13, 14, 16 };

	page_size = silofs_sc_page_size();
	if (page_size > SILOFS_BK_SIZE) {
		return -EOPNOTSUPP;
	}
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(page_shift); ++i) {
		if (page_size == (1L << page_shift[i])) {
			return 0;
		}
	}
	return -EOPNOTSUPP;
}

static int check_proc_rlimits(void)
{
	int err;
	struct rlimit rlim;

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_MEGA) {
		return -ENOMEM;
	}
	err = silofs_sys_getrlimit(RLIMIT_NOFILE, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < 64) {
		return -EMFILE;
	}
	return 0;
}

static int g_boot_lib_once;

int silofs_lib_setup(void)
{
	int err;

	silofs_lib_verify_defs();

	if (g_boot_lib_once) {
		return 0;
	}
	err = check_endianess();
	if (err) {
		return err;
	}
	err = check_sysconf();
	if (err) {
		return err;
	}
	err = check_system_page_size();
	if (err) {
		return err;
	}
	err = check_proc_rlimits();
	if (err) {
		return err;
	}
	err = silofs_init_gcrypt();
	if (err) {
		return err;
	}
	silofs_burnstack();

	g_boot_lib_once = 1;

	return 0;
}


