/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/fs/defs.h>
#include <silofs/fs/ioctls.h>
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/boot.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <endian.h>

static const struct silofs_cipher_args silofs_default_cip_args = {
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

static bool cip_args_isequal(const struct silofs_cipher_args *cip_args1,
                             const struct silofs_cipher_args *cip_args2)
{
	return (memcmp(cip_args1, cip_args2, sizeof(*cip_args1)) == 0);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t mbr_magic(const struct silofs_main_bootrec *mbr)
{
	return silofs_le64_to_cpu(mbr->mbr_magic);
}

static void mbr_set_magic(struct silofs_main_bootrec *mbr, uint64_t magic)
{
	mbr->mbr_magic = silofs_cpu_to_le64(magic);
}

static uint64_t mbr_version(const struct silofs_main_bootrec *mbr)
{
	return silofs_le64_to_cpu(mbr->mbr_version);
}

static void mbr_set_version(struct silofs_main_bootrec *mbr, uint64_t version)
{
	mbr->mbr_version = silofs_cpu_to_le64(version);
}

static void mbr_set_uuid(struct silofs_main_bootrec *mbr)
{
	silofs_uuid_generate(&mbr->mbr_uuid);
}

static void
mbr_kdf(const struct silofs_main_bootrec *mbr, struct silofs_kdf_pair *kdf)
{
	kdf_to_cpu(&mbr->mbr_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&mbr->mbr_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void mbr_set_kdf(struct silofs_main_bootrec *mbr,
                        const struct silofs_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &mbr->mbr_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &mbr->mbr_kdf_pair.kdf_key);
}

static uint32_t mbr_chiper_algo(const struct silofs_main_bootrec *mbr)
{
	return silofs_le32_to_cpu(mbr->mbr_chiper_algo);
}

static uint32_t mbr_chiper_mode(const struct silofs_main_bootrec *mbr)
{
	return silofs_le32_to_cpu(mbr->mbr_chiper_mode);
}

static void mbr_set_cipher(struct silofs_main_bootrec *mbr,
                           uint32_t cipher_algo, uint32_t cipher_mode)
{
	mbr->mbr_chiper_algo = silofs_cpu_to_le32(cipher_algo);
	mbr->mbr_chiper_mode = silofs_cpu_to_le32(cipher_mode);
}

void silofs_mbr_init(struct silofs_main_bootrec *mbr)
{
	const struct silofs_cipher_args *cip_args = &silofs_default_cip_args;

	memset(mbr, 0, sizeof(*mbr));
	mbr_set_magic(mbr, SILOFS_MBR_MAGIC);
	mbr_set_version(mbr, SILOFS_FMT_VERSION);
	mbr_set_uuid(mbr);
	mbr_set_kdf(mbr, &cip_args->kdf);
	mbr_set_cipher(mbr, cip_args->cipher_algo, cip_args->cipher_mode);
}

void silofs_mbr_fini(struct silofs_main_bootrec *mbr)
{
	memset(mbr, 0xFF, sizeof(*mbr));
	mbr_set_magic(mbr, 0);
}

void silofs_mbr_copyto(const struct silofs_main_bootrec *mbr,
                       struct silofs_main_bootrec *other)
{
	memmove(other, mbr, sizeof(*other));
}

void silofs_mbr_sb_ref(const struct silofs_main_bootrec *mbr,
                       struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr56b_parse(&mbr->mbr_sb_ref.uor_uadr, out_uaddr);
}

void silofs_mbr_set_sb_ref(struct silofs_main_bootrec *mbr,
                           const struct silofs_uaddr *uaddr)
{
	silofs_uaddr56b_set(&mbr->mbr_sb_ref.uor_uadr, uaddr);
}

static int mbr_check_base(const struct silofs_main_bootrec *mbr)
{
	if (mbr_magic(mbr) != SILOFS_MBR_MAGIC) {
		return -EINVAL;
	}
	if (mbr_version(mbr) != SILOFS_FMT_VERSION) {
		return -EUCLEAN;
	}
	return 0;
}

static void mbr_cipher_args(const struct silofs_main_bootrec *mbr,
                            struct silofs_cipher_args *cip_args)
{
	silofs_assert_not_null(mbr);

	mbr_kdf(mbr, &cip_args->kdf);
	cip_args->cipher_algo = mbr_chiper_algo(mbr);
	cip_args->cipher_mode = mbr_chiper_mode(mbr);
}

int silofs_mbr_check(const struct silofs_main_bootrec *mbr)
{
	int err;
	struct silofs_cipher_args cip_args = {
		.cipher_algo = 0,
		.cipher_mode = 0,
	};

	err = mbr_check_base(mbr);
	if (err) {
		return err;
	}
	/* currently, requires default values */
	mbr_cipher_args(mbr, &cip_args);
	if (!cip_args_isequal(&cip_args, &silofs_default_cip_args)) {
		return -EINVAL;
	}
	return 0;
}

int silofs_mbr_cipher_args(const struct silofs_main_bootrec *mbr,
                           struct silofs_cipher_args *cip_args)
{
	int err;
	silofs_assert_not_null(mbr);

	err = mbr_check_base(mbr);
	if (err) {
		return err;
	}
	mbr_cipher_args(mbr, cip_args);
	return 0;
}

struct silofs_main_bootrec *silofs_mbr_new(struct silofs_alloc_if *alif)
{
	struct silofs_main_bootrec *mbr;

	mbr = silofs_allocate(alif, sizeof(*mbr));
	if (mbr != NULL) {
		silofs_mbr_init(mbr);
	}
	return mbr;
}

void silofs_mbr_del(struct silofs_main_bootrec *mbr,
                    struct silofs_alloc_if *alif)
{
	silofs_mbr_fini(mbr);
	silofs_deallocate(alif, mbr, sizeof(*mbr));
}

void silofs_calc_pass_hash(const struct silofs_passphrase *pp,
                           const struct silofs_mdigest *md,
                           struct silofs_hash512 *out_hash)
{
	if (pp->passlen) {
		silofs_sha3_512_of(md, pp->pass, pp->passlen, out_hash);
	} else {
		silofs_memzero(out_hash, sizeof(*out_hash));
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

	err = check_endianess64(SILOFS_MBR_MAGIC, "@SILOFS@");
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
	const long page_size_min = SILOFS_PAGE_SIZE;
	const long page_shift_min = SILOFS_PAGE_SHIFT;
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

int silofs_boot_lib(void)
{
	int err;

	silofs_guarantee_consistency();

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t align_down(size_t sz, size_t align)
{
	return (sz / align) * align;
}

static int getmemlimit(size_t *out_lim)
{
	int err;
	struct rlimit rlim = {
		.rlim_cur = 0
	};

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	if (!err) {
		*out_lim = rlim.rlim_cur;
	}
	return err;
}

int silofs_boot_memsize(size_t mem_want, size_t *out_mem_size)
{
	int err;
	size_t mem_floor;
	size_t mem_ceil;
	size_t mem_rlim;
	size_t mem_glim;
	size_t page_size;
	size_t phys_pages;
	size_t mem_total;
	size_t mem_uget;

	page_size = (size_t)silofs_sc_page_size();
	phys_pages = (size_t)silofs_sc_phys_pages();
	mem_total = (page_size * phys_pages);
	mem_floor = SILOFS_UGIGA / 8;
	if (mem_total < mem_floor) {
		return -ENOMEM;
	}
	err = getmemlimit(&mem_rlim);
	if (err) {
		return err;
	}
	if (mem_rlim < mem_floor) {
		return -ENOMEM;
	}
	mem_glim = 64 * SILOFS_UGIGA;
	mem_ceil = silofs_min3(mem_glim, mem_rlim, mem_total / 4);

	if (mem_want == 0) {
		mem_want = 2 * SILOFS_GIGA;
	}
	mem_uget = silofs_clamp(mem_want, mem_floor, mem_ceil);

	*out_mem_size = align_down(mem_uget, SILOFS_UMEGA);
	return 0;
}

