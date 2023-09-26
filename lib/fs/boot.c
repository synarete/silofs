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
#include <silofs/fsdef.h>
#include <silofs/ioctls.h>
#include <silofs/errors.h>
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


#define SILOFS_NOFILES_MIN      (512)


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
		return -SILOFS_EINVAL;
	}
	n = silofs_substr_count_if(&ss, silofs_chr_isspace);
	if (n > 0) {
		return -SILOFS_EINVAL;
	}
	n = silofs_substr_count_if(&ss, silofs_chr_iscntrl);
	if (n > 0) {
		return -SILOFS_EINVAL;
	}
	n = silofs_substr_find_first_not_of(&ss, allowed);
	if (n < ss.len) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int check_name_len(const struct silofs_namestr *nstr)
{
	if (nstr->s.len == 0) {
		return -SILOFS_EINVAL;
	}
	if (nstr->s.len > SILOFS_NAME_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	return 0;
}

static int check_name_dat(const struct silofs_namestr *nstr)
{
	if (nstr->s.str == NULL) {
		return -SILOFS_EINVAL;
	}
	if (memchr(nstr->s.str, '/', nstr->s.len)) {
		return -SILOFS_EINVAL;
	}
	if (nstr->s.str[nstr->s.len] != '\0') {
		return -SILOFS_EINVAL;
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
		return -SILOFS_EINVAL;
	}
	if (nstr->s.len > (SILOFS_NAME_MAX / 2)) {
		return -SILOFS_ENAMETOOLONG;
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
		.kdf_key = {
			.kd_iterations = 4096,
			.kd_algo = SILOFS_KDF_PBKDF2,
			.kd_subalgo = SILOFS_MD_SHA256,
			.kd_salt_md = SILOFS_MD_SHA3_512,
		},
		.kdf_iv = {
			.kd_iterations = 1024,
			.kd_algo = SILOFS_KDF_SCRYPT,
			.kd_subalgo = 8,
			.kd_salt_md = SILOFS_MD_SHA3_256,
		},
	},
	.cipher_algo = SILOFS_CIPHER_AES256,
	.cipher_mode = SILOFS_CIPHER_MODE_XTS,
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

static uint64_t bootrec1k_magic(const struct silofs_bootrec1k *bsc)
{
	return silofs_le64_to_cpu(bsc->br_magic);
}

static void bootrec1k_set_magic(struct silofs_bootrec1k *bsc, uint64_t magic)
{
	bsc->br_magic = silofs_cpu_to_le64(magic);
}

static uint64_t bootrec1k_version(const struct silofs_bootrec1k *bsc)
{
	return silofs_le64_to_cpu(bsc->br_version);
}

static void bootrec1k_set_version(struct silofs_bootrec1k *bsc,
                                  uint64_t version)
{
	bsc->br_version = silofs_cpu_to_le64(version);
}

static enum silofs_bootf bootrec1k_flags(const struct silofs_bootrec1k *bsc)
{
	const uint64_t f = silofs_le64_to_cpu(bsc->br_flags);

	return (enum silofs_bootf)f;
}

static void bootrec1k_set_flags(struct silofs_bootrec1k *bsc,
                                enum silofs_bootf f)
{
	bsc->br_flags = silofs_cpu_to_le64((uint64_t)f);
}

static void bootrec1k_uuid(const struct silofs_bootrec1k *bsc,
                           struct silofs_uuid *uu)
{
	silofs_uuid_assign(uu, &bsc->br_uuid);
}

static void bootrec1k_set_uuid(struct silofs_bootrec1k *bsc,
                               const struct silofs_uuid *uu)
{
	silofs_uuid_assign(&bsc->br_uuid, uu);
}

static void bootrec1k_key_hash(const struct silofs_bootrec1k *bsc,
                               struct silofs_hash256 *out_hash)
{
	silofs_hash256_assign(out_hash, &bsc->br_key_hash);
}

static void bootrec1k_set_key_hash(struct silofs_bootrec1k *bsc,
                                   const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&bsc->br_key_hash, hash);
}

static void bootrec1k_kdf(const struct silofs_bootrec1k *bsc,
                          struct silofs_kdf_pair *kdf)
{
	kdf_to_cpu(&bsc->br_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&bsc->br_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void bootrec1k_set_kdf(struct silofs_bootrec1k *bsc,
                              const struct silofs_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &bsc->br_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &bsc->br_kdf_pair.kdf_key);
}

static uint32_t bootrec1k_chiper_algo(const struct silofs_bootrec1k *bsc)
{
	return silofs_le32_to_cpu(bsc->br_chiper_algo);
}

static uint32_t bootrec1k_chiper_mode(const struct silofs_bootrec1k *bsc)
{
	return silofs_le32_to_cpu(bsc->br_chiper_mode);
}

static void bootrec1k_set_cipher(struct silofs_bootrec1k *bsc,
                                 uint32_t cipher_algo, uint32_t cipher_mode)
{
	bsc->br_chiper_algo = silofs_cpu_to_le32(cipher_algo);
	bsc->br_chiper_mode = silofs_cpu_to_le32(cipher_mode);
}

static void bootrec1k_fill_rands(struct silofs_bootrec1k *bsc)
{
	silofs_getentropy(bsc->br_rands, sizeof(bsc->br_rands));
}

void silofs_bootrec1k_init(struct silofs_bootrec1k *brec1k)
{
	const struct silofs_cipher_args *cip_args = &s_default_cip_args;

	silofs_memzero(brec1k, sizeof(*brec1k));
	bootrec1k_fill_rands(brec1k);
	bootrec1k_set_magic(brec1k, SILOFS_BOOT_RECORD_MAGIC);
	bootrec1k_set_version(brec1k, SILOFS_FMT_VERSION);
	bootrec1k_set_flags(brec1k, SILOFS_BOOTF_NONE);
	bootrec1k_set_kdf(brec1k, &cip_args->kdf);
	bootrec1k_set_cipher(brec1k, cip_args->cipher_algo,
	                     cip_args->cipher_mode);
}

void silofs_bootrec1k_fini(struct silofs_bootrec1k *brec1k)
{
	silofs_memffff(brec1k, sizeof(*brec1k));
}

static void bootrec1k_sb_uaddr(const struct silofs_bootrec1k *brec1k,
                               struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&brec1k->br_sb_uaddr, out_uaddr);
}

static void bootrec1k_set_sb_uaddr(struct silofs_bootrec1k *brec1k,
                                   const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&brec1k->br_sb_uaddr, uaddr);
}

static void bootrec1k_sb_riv(const struct silofs_bootrec1k *brec1k,
                             struct silofs_iv *out_riv)
{
	silofs_iv_assign(out_riv, &brec1k->br_sb_riv);
}

static void bootrec1k_set_sb_riv(struct silofs_bootrec1k *brec1k,
                                 const struct silofs_iv *riv)
{
	silofs_iv_assign(&brec1k->br_sb_riv, riv);
}


static int bootrec1k_check_base(const struct silofs_bootrec1k *brec1k)
{
	uint64_t magic;
	uint64_t version;

	magic = bootrec1k_magic(brec1k);
	if (magic != SILOFS_BOOT_RECORD_MAGIC) {
		log_dbg("bad bootrec magic: 0x%lx", magic);
		return -SILOFS_EFSCORRUPTED;
	}
	version = bootrec1k_version(brec1k);
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad bootrec version: %lu", version);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static int bootrec1k_check_sb_uaddr(const struct silofs_bootrec1k *brec1k)
{
	struct silofs_uaddr uaddr;

	bootrec1k_sb_uaddr(brec1k, &uaddr);
	if ((uaddr.stype != SILOFS_STYPE_SUPER) ||
	    (uaddr.paddr.blobid.height != SILOFS_HEIGHT_SUPER)) {
		log_dbg("bad bootrec sb-uaddr: stype=%d height=%d",
		        (int)uaddr.stype, (int)uaddr.paddr.blobid.height);
		return -SILOFS_EFSCORRUPTED;
	}
	return 0;
}

static void bootrec1k_cipher_args(const struct silofs_bootrec1k *brec1k,
                                  struct silofs_cipher_args *cip_args)
{
	bootrec1k_kdf(brec1k, &cip_args->kdf);
	cip_args->cipher_algo = bootrec1k_chiper_algo(brec1k);
	cip_args->cipher_mode = bootrec1k_chiper_mode(brec1k);
}

static int bootrec1k_check(const struct silofs_bootrec1k *brec1k)
{
	struct silofs_cipher_args cip_args = {
		.cipher_algo = 0,
		.cipher_mode = 0,
	};
	int err;

	err = bootrec1k_check_base(brec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_check_sb_uaddr(brec1k);
	if (err) {
		return err;
	}
	/* currently, requires default values */
	bootrec1k_cipher_args(brec1k, &cip_args);
	if (!cip_args_isequal(&cip_args, &s_default_cip_args)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static void bootrec1k_hash(const struct silofs_bootrec1k *brec1k,
                           struct silofs_hash256 *hash)
{
	silofs_hash256_assign(hash, &brec1k->br_hash);
}

static void bootrec1k_set_hash(struct silofs_bootrec1k *brec1k,
                               const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&brec1k->br_hash, hash);
}

static void bootrec1k_calc_hash(const struct silofs_bootrec1k *brec1k,
                                const struct silofs_mdigest *md,
                                struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_bootrec1k, br_hash);

	silofs_sha3_256_of(md, brec1k, len, out_hash);
}

void silofs_bootrec1k_stamp(struct silofs_bootrec1k *brec1k,
                            const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	bootrec1k_calc_hash(brec1k, md, &hash);
	bootrec1k_set_hash(brec1k, &hash);
}

static int bootrec1k_check_hash(const struct silofs_bootrec1k *brec1k,
                                const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	bootrec1k_hash(brec1k, &hash[0]);
	bootrec1k_calc_hash(brec1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ?
	       0 : -SILOFS_EFSCORRUPTED;
}

int silofs_bootrec1k_verify(const struct silofs_bootrec1k *brec1k,
                            const struct silofs_mdigest *md)
{
	int err;

	err = bootrec1k_check(brec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_check_hash(brec1k, md);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_bootrec1k_parse(const struct silofs_bootrec1k *brec1k,
                            struct silofs_bootrec *brec)
{
	bootrec1k_sb_uaddr(brec1k, &brec->sb_ulink.uaddr);
	bootrec1k_sb_riv(brec1k, &brec->sb_ulink.riv);
	bootrec1k_uuid(brec1k, &brec->uuid);
	bootrec1k_cipher_args(brec1k, &brec->cip_args);
	brec->flags = bootrec1k_flags(brec1k);
	if (brec->flags & SILOFS_BOOTF_KEY_SHA256) {
		bootrec1k_key_hash(brec1k, &brec->key_hash);
	}
}

void silofs_bootrec1k_set(struct silofs_bootrec1k *brec1k,
                          const struct silofs_bootrec *brec)
{
	silofs_bootrec1k_init(brec1k);
	bootrec1k_set_sb_uaddr(brec1k, &brec->sb_ulink.uaddr);
	bootrec1k_set_sb_riv(brec1k, &brec->sb_ulink.riv);
	bootrec1k_set_uuid(brec1k, &brec->uuid);
	bootrec1k_set_flags(brec1k, brec->flags);
	if (brec->flags & SILOFS_BOOTF_KEY_SHA256) {
		bootrec1k_set_key_hash(brec1k, &brec->key_hash);
	}
}

void silofs_bootrec1k_setn(struct silofs_bootrec1k *brec1k,
                           const struct silofs_bootrec *brec, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		silofs_bootrec1k_set(&brec1k[i], &brec[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *brec)
{
	silofs_memzero(brec, sizeof(*brec));
	silofs_ulink_reset(&brec->sb_ulink);
	silofs_default_cip_args(&brec->cip_args);
	silofs_uuid_generate(&brec->uuid);
	brec->flags = SILOFS_BOOTF_NONE;
}

void silofs_bootrec_fini(struct silofs_bootrec *brec)
{
	silofs_memffff(brec, sizeof(*brec));
}

void silofs_bootrec_uuid(const struct silofs_bootrec *brec,
                         struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &brec->uuid);
}

void silofs_bootrec_set_uuid(struct silofs_bootrec *brec,
                             const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&brec->uuid, uuid);
}

void silofs_bootrec_sb_ulink(const struct silofs_bootrec *brec,
                             struct silofs_ulink *out_ulink)
{
	silofs_ulink_assign(out_ulink, &brec->sb_ulink);
}

void silofs_bootrec_set_sb_ulink(struct silofs_bootrec *brec,
                                 const struct silofs_ulink *sb_ulink)
{
	silofs_ulink_assign(&brec->sb_ulink, sb_ulink);
}

void silofs_bootrec_set_keyhash(struct silofs_bootrec *brec,
                                const struct silofs_hash256 *hash)
{
	silofs_hash256_assign(&brec->key_hash, hash);
	brec->flags |= SILOFS_BOOTF_KEY_SHA256;
}

void silofs_bootrec_clear_keyhash(struct silofs_bootrec *brec)
{
	silofs_memzero(&brec->key_hash, sizeof(brec->key_hash));
	brec->flags &= (enum silofs_bootf)(~SILOFS_BOOTF_KEY_SHA256);
}

static bool bootrec_has_keyhash(const struct silofs_bootrec *brec,
                                const struct silofs_hash256 *hash)
{
	return silofs_hash256_isequal(&brec->key_hash, hash);
}

int silofs_bootrec_check_keyhash(const struct silofs_bootrec *brec,
                                 const struct silofs_hash256 *hash)
{
	return bootrec_has_keyhash(brec, hash) ? 0 : -EKEYEXPIRED;
}

void silofs_bootrec_cipher_args(const struct silofs_bootrec *brec,
                                struct silofs_cipher_args *out_cip_args)
{
	if (!brec || !brec->cip_args.cipher_algo) {
		silofs_default_cip_args(out_cip_args);
	} else {
		cip_args_assign(out_cip_args, &brec->cip_args);
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
		ret = -SILOFS_EINVAL;
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
	char buf[16] = "";
	const uint32_t val_le = htole32(val);

	for (size_t i = 0; i < 4; ++i) {
		buf[i] = (char)(val_le >> (i * 8));
	}
	return !strcmp(buf, str) ? 0 : -EBADE;
}

static int check_endianess64(uint64_t val, const char *str)
{
	char buf[16] = "";
	const uint64_t val_le = htole64(val);

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
	err = check_endianess64(SILOFS_JOURNAL_MAGIC, "%silofs%");
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
	const long cl_size_min = SILOFS_CACHELINE_SIZE_MIN;
	const long cl_size_max = SILOFS_CACHELINE_SIZE_MAX;

	errno = 0;
	val = silofs_sc_phys_pages();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEM);
	}
	val = silofs_sc_avphys_pages();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEM);
	}
	val = silofs_sc_l1_dcache_linesize();
	if ((val < cl_size_min) || (val > cl_size_max)) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	val = silofs_sc_page_size();
	if ((val < page_size_min) || (val % page_size_min)) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	for (long shift = page_shift_min; shift <= page_shift_max; ++shift) {
		if (val == (1L << shift)) {
			page_shift = val;
			break;
		}
	}
	if (page_shift == 0) {
		return errno_or_errnum(SILOFS_EOPNOTSUPP);
	}
	val = silofs_sc_nproc_onln();
	if (val <= 0) {
		return errno_or_errnum(SILOFS_ENOMEDIUM);
	}
	return 0;
}

static int check_system_page_size(void)
{
	long page_size;
	const size_t page_shift[] = { 12, 13, 14, 16 };

	page_size = silofs_sc_page_size();
	if (page_size > SILOFS_LBK_SIZE) {
		return -SILOFS_EOPNOTSUPP;
	}
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(page_shift); ++i) {
		if (page_size == (1L << page_shift[i])) {
			return 0;
		}
	}
	return -SILOFS_EOPNOTSUPP;
}

static int check_proc_rlimits(void)
{
	struct rlimit rlim;
	int err;

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_MEGA) {
		return -SILOFS_ENOMEM;
	}
	err = silofs_sys_getrlimit(RLIMIT_NOFILE, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < SILOFS_NOFILES_MIN) {
		return -SILOFS_ENFILE;
	}
	return 0;
}

static bool g_init_libsilofs_done;

static int init_libsilofs(void)
{
	int err;

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
	return 0;
}

int silofs_init_lib(void)
{
	int ret = 0;

	silofs_validate_fsdefs();
	if (g_init_libsilofs_done) {
		goto out;
	}
	ret = init_libsilofs();
	if (ret) {
		goto out;
	}
	g_init_libsilofs_done = true;
out:
	silofs_burnstack();
	return ret;
}


