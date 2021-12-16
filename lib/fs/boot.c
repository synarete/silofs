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
#include <silofs/fs/defs.h>
#include <silofs/fs/ioctls.h>
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/private.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <endian.h>


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

static uint64_t bsec4k_magic(const struct silofs_bootsec4k *bsc)
{
	return silofs_le64_to_cpu(bsc->bs_magic);
}

static void bsec4k_set_magic(struct silofs_bootsec4k *bsc, uint64_t magic)
{
	bsc->bs_magic = silofs_cpu_to_le64(magic);
}

static uint64_t bsec4k_version(const struct silofs_bootsec4k *bsc)
{
	return silofs_le64_to_cpu(bsc->bs_version);
}

static void bsec4k_set_version(struct silofs_bootsec4k *bsc, uint64_t version)
{
	bsc->bs_version = silofs_cpu_to_le64(version);
}

static void bsec4k_uuid(const struct silofs_bootsec4k *bsc,
                        struct silofs_uuid *uu)
{
	silofs_uuid_assign(uu, &bsc->bs_uuid);
}

static void bsec4k_set_uuid(struct silofs_bootsec4k *bsc,
                            const struct silofs_uuid *uu)
{
	silofs_uuid_assign(&bsc->bs_uuid, uu);
}

static time_t bsec4k_btime(const struct silofs_bootsec4k *bsc)
{
	return (time_t)silofs_le64_to_cpu(bsc->bs_btime);
}

static void bsec4k_set_btime(struct silofs_bootsec4k *bsc, time_t tm)
{
	bsc->bs_btime = silofs_cpu_to_le64((uint64_t)tm);
}

static enum silofs_bootf bsec4k_flags(const struct silofs_bootsec4k *bsc)
{
	const uint64_t f = silofs_le64_to_cpu(bsc->bs_flags);

	return (enum silofs_bootf)f;
}

static void bsec4k_set_flags(struct silofs_bootsec4k *bsc,
                             enum silofs_bootf flags)
{
	const uint64_t f = (uint64_t)flags;

	bsc->bs_flags = silofs_cpu_to_le64(f);
}

static void bsec4k_name(const struct silofs_bootsec4k *bsc,
                        struct silofs_namebuf *nb)
{
	silofs_namebuf_assign2(nb, &bsc->bs_name);
}

static void bsec4k_set_name(struct silofs_bootsec4k *bsc,
                            const struct silofs_namebuf *nb)
{
	silofs_namebuf_copyto(nb, &bsc->bs_name);
}

static void bsec4k_kdf(const struct silofs_bootsec4k *bsc,
                       struct silofs_kdf_pair *kdf)
{
	kdf_to_cpu(&bsc->bs_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&bsc->bs_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void bsec4k_set_kdf(struct silofs_bootsec4k *bsc,
                           const struct silofs_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &bsc->bs_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &bsc->bs_kdf_pair.kdf_key);
}

static uint32_t bsec4k_chiper_algo(const struct silofs_bootsec4k *bsc)
{
	return silofs_le32_to_cpu(bsc->bs_chiper_algo);
}

static uint32_t bsec4k_chiper_mode(const struct silofs_bootsec4k *bsc)
{
	return silofs_le32_to_cpu(bsc->bs_chiper_mode);
}

static void bsec4k_set_cipher(struct silofs_bootsec4k *bsc,
                              uint32_t cipher_algo, uint32_t cipher_mode)
{
	bsc->bs_chiper_algo = silofs_cpu_to_le32(cipher_algo);
	bsc->bs_chiper_mode = silofs_cpu_to_le32(cipher_mode);
}

void silofs_bsec4k_init(struct silofs_bootsec4k *bsc)
{
	const struct silofs_cipher_args *cip_args = &s_default_cip_args;

	silofs_memzero(bsc, sizeof(*bsc));
	bsec4k_set_magic(bsc, SILOFS_BOOT_RECORD_MAGIC);
	bsec4k_set_version(bsc, SILOFS_FMT_VERSION);
	bsec4k_set_kdf(bsc, &cip_args->kdf);
	bsec4k_set_cipher(bsc, cip_args->cipher_algo, cip_args->cipher_mode);
}

void silofs_bsec4k_fini(struct silofs_bootsec4k *bsc)
{
	silofs_memffff(bsc, sizeof(*bsc));
}

static void bsec4k_sb_ref(const struct silofs_bootsec4k *bsc,
                          struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr64b_parse(&bsc->bs_sb_ref, out_uaddr);
}

static void bsec4k_set_sb_ref(struct silofs_bootsec4k *bsc,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uaddr64b_set(&bsc->bs_sb_ref, uaddr);
}

static int bsec4k_check_base(const struct silofs_bootsec4k *bsc)
{
	if (bsec4k_magic(bsc) != SILOFS_BOOT_RECORD_MAGIC) {
		return -EINVAL;
	}
	if (bsec4k_version(bsc) != SILOFS_FMT_VERSION) {
		return -EUCLEAN;
	}
	return 0;
}

static void bsec4k_cipher_args(const struct silofs_bootsec4k *bsc,
                               struct silofs_cipher_args *cip_args)
{
	silofs_assert_not_null(bsc);

	bsec4k_kdf(bsc, &cip_args->kdf);
	cip_args->cipher_algo = bsec4k_chiper_algo(bsc);
	cip_args->cipher_mode = bsec4k_chiper_mode(bsc);
}

static int bsec4k_check(const struct silofs_bootsec4k *bsc)
{
	int err;
	struct silofs_cipher_args cip_args = {
		.cipher_algo = 0,
		.cipher_mode = 0,
	};

	err = bsec4k_check_base(bsc);
	if (err) {
		return err;
	}
	/* currently, requires default values */
	bsec4k_cipher_args(bsc, &cip_args);
	if (!cip_args_isequal(&cip_args, &s_default_cip_args)) {
		return -EINVAL;
	}
	return 0;
}

static void bsec4k_hash(const struct silofs_bootsec4k *bsc,
                        struct silofs_hash512 *hash)
{
	silofs_hash512_assign(hash, &bsc->bs_hash);
}

static void bsec4k_set_hash(struct silofs_bootsec4k *bsc,
                            const struct silofs_hash512 *hash)
{
	silofs_hash512_assign(&bsc->bs_hash, hash);
}

static void bsec4k_calc_hash(const struct silofs_bootsec4k *bsc,
                             const struct silofs_mdigest *md,
                             struct silofs_hash512 *out_hash)
{
	const size_t len = offsetof(struct silofs_bootsec4k, bs_hash);

	silofs_sha3_512_of(md, bsc, len, out_hash);
}

void silofs_bsec4k_stamp(struct silofs_bootsec4k *bsc,
                         const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash;

	bsec4k_calc_hash(bsc, md, &hash);
	bsec4k_set_hash(bsc, &hash);
}

static int bsec4k_check_hash(const struct silofs_bootsec4k *bsc,
                             const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash[2];

	bsec4k_hash(bsc, &hash[0]);
	bsec4k_calc_hash(bsc, md, &hash[1]);

	return silofs_hash512_isequal(&hash[0], &hash[1]) ? 0 : -EUCLEAN;
}

int silofs_bsec4k_verify(const struct silofs_bootsec4k *bsc,
                         const struct silofs_mdigest *md)
{
	int err;

	err = bsec4k_check(bsc);
	if (err) {
		return err;
	}
	err = bsec4k_check_hash(bsc, md);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_bsec4k_parse(const struct silofs_bootsec4k *bsc,
                         struct silofs_bootsec *bsec)
{
	bsec4k_sb_ref(bsc, &bsec->sb_uaddr);
	bsec4k_uuid(bsc, &bsec->uuid);
	bsec4k_name(bsc, &bsec->name);
	bsec4k_cipher_args(bsc, &bsec->cip_args);
	bsec->btime = bsec4k_btime(bsc);
	bsec->bootf = bsec4k_flags(bsc);
}

void silofs_bsec4k_set(struct silofs_bootsec4k *bsc,
                       const struct silofs_bootsec *bsec)
{
	silofs_bsec4k_init(bsc);
	bsec4k_set_sb_ref(bsc, &bsec->sb_uaddr);
	bsec4k_set_uuid(bsc, &bsec->uuid);
	bsec4k_set_name(bsc, &bsec->name);
	bsec4k_set_btime(bsc, bsec->btime);
	bsec4k_set_flags(bsc, bsec->bootf);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootsec_init(struct silofs_bootsec *bsec)
{
	silofs_memzero(bsec, sizeof(*bsec));
	silofs_default_cip_args(&bsec->cip_args);
	silofs_uuid_generate(&bsec->uuid);
	bsec->btime = silofs_time_now();
	bsec->bootf = SILOFS_BOOTF_ACTIVE;
}

void silofs_bootsec_fini(struct silofs_bootsec *bsec)
{
	silofs_memffff(bsec, sizeof(*bsec));
	bsec->bootf = SILOFS_BOOTF_NONE;
}

void silofs_bootsec_name(const struct silofs_bootsec *bsec,
                         struct silofs_namestr *out_name)
{
	silofs_namebuf_str(&bsec->name, out_name);
}

void silofs_bootsec_set_name(struct silofs_bootsec *bsec,
                             const struct silofs_namestr *name)
{
	silofs_namebuf_assign_str(&bsec->name, name);
}

bool silofs_bootsec_has_name(const struct silofs_bootsec *bsec,
                             const struct silofs_namestr *name)
{
	return silofs_namebuf_isequal(&bsec->name, name);
}

void silofs_bootsec_set_sb_uaddr(struct silofs_bootsec *bsec,
                                 const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr_assign(&bsec->sb_uaddr, sb_uaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

	silofs_boot_cons();

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

int silofs_boot_mem(size_t mem_want, size_t *out_mem_size)
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

