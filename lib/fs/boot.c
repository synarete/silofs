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

static void mbr_uuid(const struct silofs_main_bootrec *mbr,
                     struct silofs_uuid *uu)
{
	silofs_uuid_assign(uu, &mbr->mbr_uuid);
}

static void mbr_set_uuid(struct silofs_main_bootrec *mbr,
                         const struct silofs_uuid *uu)
{
	silofs_uuid_assign(&mbr->mbr_uuid, uu);
}

static size_t mbr_index(const struct silofs_main_bootrec *mbr)
{
	return silofs_le64_to_cpu(mbr->mbr_index);
}

static void mbr_set_index(struct silofs_main_bootrec *mbr, size_t idx)
{
	mbr->mbr_index = silofs_cpu_to_le64(idx);
}

static time_t mbr_btime(const struct silofs_main_bootrec *mbr)
{
	return (time_t)silofs_le64_to_cpu(mbr->mbr_btime);
}

static void mbr_set_btime(struct silofs_main_bootrec *mbr, time_t tm)
{
	mbr->mbr_btime = silofs_cpu_to_le64((uint64_t)tm);
}

static void mbr_name(const struct silofs_main_bootrec *mbr,
                     struct silofs_namebuf *nb)
{
	silofs_namebuf_assign2(nb, &mbr->mbr_name);
}

static void mbr_set_name(struct silofs_main_bootrec *mbr,
                         const struct silofs_namebuf *nb)
{
	silofs_namebuf_copyto(nb, &mbr->mbr_name);
}

static void mbr_kdf(const struct silofs_main_bootrec *mbr,
                    struct silofs_kdf_pair *kdf)
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

static void mbr_init_defaults(struct silofs_main_bootrec *mbr)
{
	const struct silofs_cipher_args *cip_args = &s_default_cip_args;

	memset(mbr, 0, sizeof(*mbr));
	mbr_set_magic(mbr, SILOFS_BOOT_RECORD_MAGIC);
	mbr_set_version(mbr, SILOFS_FMT_VERSION);
	mbr_set_kdf(mbr, &cip_args->kdf);
	mbr_set_cipher(mbr, cip_args->cipher_algo, cip_args->cipher_mode);
}

static void mbr_sb_ref(const struct silofs_main_bootrec *mbr,
                       struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr56b_parse(&mbr->mbr_sb_ref.uor_uadr, out_uaddr);
}

static void mbr_set_sb_ref(struct silofs_main_bootrec *mbr,
                           const struct silofs_uaddr *uaddr)
{
	silofs_uaddr56b_set(&mbr->mbr_sb_ref.uor_uadr, uaddr);
}

static int mbr_check_base(const struct silofs_main_bootrec *mbr)
{
	if (mbr_magic(mbr) != SILOFS_BOOT_RECORD_MAGIC) {
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

static int mbr_check(const struct silofs_main_bootrec *mbr)
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
	if (!cip_args_isequal(&cip_args, &s_default_cip_args)) {
		return -EINVAL;
	}
	return 0;
}

static void mbr_hash(const struct silofs_main_bootrec *mbr,
                     struct silofs_hash512 *hash)
{
	silofs_hash512_assign(hash, &mbr->mbr_hash);
}

static void mbr_set_hash(struct silofs_main_bootrec *mbr,
                         const struct silofs_hash512 *hash)
{
	silofs_hash512_assign(&mbr->mbr_hash, hash);
}

static void mbr_calc_hash(const struct silofs_main_bootrec *mbr,
                          const struct silofs_mdigest *md,
                          struct silofs_hash512 *out_hash)
{
	const size_t len = offsetof(struct silofs_main_bootrec, mbr_hash);

	silofs_sha3_512_of(md, mbr, len, out_hash);
}

static void mbr_stamp_hash(struct silofs_main_bootrec *mbr,
                           const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash;

	mbr_calc_hash(mbr, md, &hash);
	mbr_set_hash(mbr, &hash);
}

static int mbr_check_hash(const struct silofs_main_bootrec *mbr,
                          const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash[2];

	mbr_hash(mbr, &hash[0]);
	mbr_calc_hash(mbr, md, &hash[1]);

	return silofs_hash512_isequal(&hash[0], &hash[1]) ? 0 : -EUCLEAN;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_mbootrec_info *
mbri_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_mbootrec_info *mbri = NULL;

	mbri = container_of2(lh, struct silofs_mbootrec_info, mbr_lh);
	return unconst(mbri);
}

static void mbri_init(struct silofs_mbootrec_info *mbri)
{
	silofs_memzero(mbri, sizeof(*mbri));
	silofs_list_head_init(&mbri->mbr_lh);
	silofs_uaddr_reset(&mbri->mbr_sb_uaddr);
	silofs_uuid_generate(&mbri->mbr_uuid);
	mbri->mbr_btime = silofs_time_now();
	mbri->mbr_index = 0;
}

static void mbri_fini(struct silofs_mbootrec_info *mbri)
{
	silofs_list_head_fini(&mbri->mbr_lh);
	silofs_uaddr_reset(&mbri->mbr_sb_uaddr);
}

static struct silofs_mbootrec_info *mbri_new(struct silofs_alloc_if *alif)
{
	struct silofs_mbootrec_info *mbri;

	mbri = silofs_allocate(alif, sizeof(*mbri));
	if (mbri != NULL) {
		mbri_init(mbri);
	}
	return mbri;
}

static void mbri_del(struct silofs_mbootrec_info *mbri,
                     struct silofs_alloc_if *alif)
{
	mbri_fini(mbri);
	silofs_deallocate(alif, mbri, sizeof(*mbri));
}

static void mbri_import(struct silofs_mbootrec_info *mbri,
                        const struct silofs_main_bootrec *mbr)
{
	mbr_sb_ref(mbr, &mbri->mbr_sb_uaddr);
	mbr_uuid(mbr, &mbri->mbr_uuid);
	mbr_name(mbr, &mbri->mbr_name);
	mbr_cipher_args(mbr, &mbri->mbr_cip_args);
	mbri->mbr_btime = mbr_btime(mbr);
	mbri->mbr_index = (long)mbr_index(mbr);
}

static void mbri_export(const struct silofs_mbootrec_info *mbri,
                        struct silofs_main_bootrec *mbr)
{
	mbr_init_defaults(mbr);
	mbr_set_sb_ref(mbr, &mbri->mbr_sb_uaddr);
	mbr_set_uuid(mbr, &mbri->mbr_uuid);
	mbr_set_name(mbr, &mbri->mbr_name);
	mbr_set_btime(mbr, mbri->mbr_btime);
	mbr_set_index(mbr, (uint64_t)mbri->mbr_index);
}

static void mbri_update(struct silofs_mbootrec_info *mbri,
                        const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr_assign(&mbri->mbr_sb_uaddr, sb_uaddr);
}

static void mbri_assign(struct silofs_mbootrec_info *mbri, loff_t idx,
                        const struct silofs_namestr *name,
                        const struct silofs_uaddr *sb_uaddr)

{
	silofs_namebuf_assign_str(&mbri->mbr_name, name);
	mbri_update(mbri, sb_uaddr);
	cip_args_assign(&mbri->mbr_cip_args, &s_default_cip_args);
	mbri->mbr_btime = silofs_time_now();
	mbri->mbr_index = idx;
}

static bool mbri_has_name(const struct silofs_mbootrec_info *mbri,
                          const struct silofs_namestr *name)
{
	return silofs_namebuf_isequal(&mbri->mbr_name, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mbi_new_mbri(const struct silofs_mboot_info *mbi,
                        struct silofs_mbootrec_info **out_mbri)
{
	*out_mbri = mbri_new(mbi->mbt_alif);
	return (*out_mbri != NULL) ? 0 : -ENOMEM;
}

static void mbi_del_mbri(struct silofs_mboot_info *mbi,
                         struct silofs_mbootrec_info *mbri)
{
	mbri_del(mbri, mbi->mbt_alif);
}

int silofs_mbi_init(struct silofs_mboot_info *mbi,
                    struct silofs_alloc_if *alif, struct silofs_mdigest *md)
{
	listq_init(&mbi->mbt_lsq);
	mbi->mbt_alif = alif;
	mbi->mbt_md = md;
	mbi->mbt_next_index = 1;
	return 0;
}

int silofs_mbi_init_by(struct silofs_mboot_info *mbi,
                       const struct silofs_fs_apex *apex)
{
	return silofs_mbi_init(mbi, apex->ap_alif, &apex->ap_crypto->md);
}

static void mbi_insert(struct silofs_mboot_info *mbi,
                       struct silofs_mbootrec_info *mbri)
{
	listq_push_back(&mbi->mbt_lsq, &mbri->mbr_lh);
	mbi->mbt_next_index =
	        silofs_max64(mbi->mbt_next_index, mbri->mbr_index + 1);
}

static void mbi_free_all(struct silofs_mboot_info *mbi)
{
	struct silofs_list_head *lh;
	struct silofs_mbootrec_info *bri;
	struct silofs_listq *lsq = &mbi->mbt_lsq;

	lh = listq_pop_front(lsq);
	while (lh != NULL) {
		bri = mbri_from_lh(lh);
		mbi_del_mbri(mbi, bri);
		lh = listq_pop_front(lsq);
	}
}

void silofs_mbi_fini(struct silofs_mboot_info *mbi)
{
	mbi_free_all(mbi);
	listq_fini(&mbi->mbt_lsq);
	mbi->mbt_md = NULL;
	mbi->mbt_alif = NULL;
}

static int mbi_check_buf(const struct silofs_mboot_info *mbi,
                         const void *buf, size_t bsz)
{
	const size_t mbr_size = SILOFS_BOOTREC_SIZE;
	const size_t nmbr = mbi->mbt_lsq.sz;

	if ((bsz < mbr_size) || (bsz % mbr_size)) {
		return -EINVAL;
	}
	if ((nmbr * mbr_size) > bsz) {
		return -EINVAL;
	}
	if (buf == NULL) {
		return -EINVAL;
	}
	return 0;
}

static int mbi_decode_recs(struct silofs_mboot_info *mbi,
                           const struct silofs_main_bootrec *mbrs, size_t cnt)
{
	const struct silofs_main_bootrec *mbr = NULL;
	struct silofs_mbootrec_info *bri = NULL;
	int err;

	for (size_t i = 0; i < cnt; ++i) {
		mbr = &mbrs[i];
		err = mbr_check(mbr);
		if (err) {
			return err;
		}
		err = mbr_check_hash(mbr, mbi->mbt_md);
		if (err) {
			return err;
		}
		err = mbi_new_mbri(mbi, &bri);
		if (err) {
			return err;
		}
		mbri_import(bri, mbr);
		mbi_insert(mbi, bri);
	}
	return 0;
}

int silofs_mbi_decode(struct silofs_mboot_info *mbi,
                      const void *buf, size_t bsz)
{
	int err;

	err = mbi_check_buf(mbi, buf, bsz);
	if (err) {
		return err;
	}
	err = mbi_decode_recs(mbi, buf, bsz / SILOFS_BOOTREC_SIZE);
	if (err) {
		return err;
	}
	return 0;
}

static void mbi_stamp_mbr(const struct silofs_mboot_info *mbi,
                          struct silofs_main_bootrec *mbr)
{
	mbr_stamp_hash(mbr, mbi->mbt_md);
}

static struct silofs_mbootrec_info *
mbi_first(const struct silofs_mboot_info *mbi)
{
	const struct silofs_listq *lsq = &mbi->mbt_lsq;
	const struct silofs_list_head *lh = lsq->ls.next;

	return (lh != &lsq->ls) ? mbri_from_lh(lh) : NULL;
}

static struct silofs_mbootrec_info *
mbi_nextof(const struct silofs_mboot_info *mbi,
           const struct silofs_mbootrec_info *mbri)
{
	const struct silofs_listq *lsq = &mbi->mbt_lsq;
	const struct silofs_list_head *lh = mbri->mbr_lh.next;

	return (lh != &lsq->ls) ? mbri_from_lh(lh) : NULL;
}

static const struct silofs_mbootrec_info *
mbi_iterate(const struct silofs_mboot_info *mbi, loff_t indx)
{
	const struct silofs_mbootrec_info *iter;
	const struct silofs_mbootrec_info *mbri = NULL;

	iter = mbi_first(mbi);
	while (iter != NULL) {
		if (indx <= iter->mbr_index) {
			if (!mbri || (mbri->mbr_index > iter->mbr_index)) {
				mbri = iter;
			}
		}
		iter = mbi_nextof(mbi, iter);
	}
	return mbri;
}

static int mbi_encode_recs(const struct silofs_mboot_info *mbi,
                           struct silofs_main_bootrec *mbrs, size_t *out_cnt)
{
	struct silofs_main_bootrec *mbr;
	const struct silofs_mbootrec_info *mbri;
	size_t cnt = 0;

	mbri = mbi_iterate(mbi, 0);
	while (mbri != NULL) {
		mbr = &mbrs[cnt++];
		mbri_export(mbri, mbr);
		mbi_stamp_mbr(mbi, mbr);

		mbri = mbi_iterate(mbi, mbri->mbr_index + 1);
	}
	silofs_assert_eq(cnt, mbi->mbt_lsq.sz);

	*out_cnt = cnt;
	return 0;
}

static size_t mbi_enc_size_of(const struct silofs_mboot_info *mbi, size_t cnt)
{
	silofs_unused(mbi);

	return cnt * SILOFS_BOOTREC_SIZE;
}

int silofs_mbi_encode(const struct silofs_mboot_info *mbi,
                      void *buf, size_t bsz, size_t *out_esz)
{
	size_t cnt = 0;
	int err;

	err = mbi_check_buf(mbi, buf, bsz);
	if (err) {
		return err;
	}
	err = mbi_encode_recs(mbi, buf, &cnt);
	if (err) {
		return err;
	}
	*out_esz = mbi_enc_size_of(mbi, cnt);
	return 0;
}

int silofs_mbi_encsize(const struct silofs_mboot_info *mbi, size_t *out_esz)
{
	const size_t nrecs = listq_size(&mbi->mbt_lsq);

	*out_esz = mbi_enc_size_of(mbi, nrecs);
	return (nrecs > 0) ? 0 : -EINVAL;
}

static int mbi_insert_new(struct silofs_mboot_info *mbi,
                          const struct silofs_namestr *name,
                          const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_mbootrec_info *mbri = NULL;
	int err;

	err = mbi_new_mbri(mbi, &mbri);
	if (err) {
		return err;
	}
	mbri_assign(mbri, mbi->mbt_next_index++, name, sb_uaddr);
	mbi_insert(mbi, mbri);
	return 0;
}

static struct silofs_mbootrec_info *
mbi_find(const struct silofs_mboot_info *mbi,
         const struct silofs_namestr *name)
{
	struct silofs_mbootrec_info *mbri;

	mbri = mbi_first(mbi);
	while (mbri != NULL) {
		if (mbri_has_name(mbri, name)) {
			return mbri;
		}
		mbri = mbi_nextof(mbi, mbri);
	}
	return NULL;
}

int silofs_mbi_lookup(const struct silofs_mboot_info *mbi,
                      const struct silofs_namestr *name,
                      struct silofs_mbootrec_info **out_mbri)
{
	*out_mbri = mbi_find(mbi, name);
	return (*out_mbri == NULL) ? -ENOENT : 0;
}


int silofs_mbi_insert(struct silofs_mboot_info *mbi,
                      const struct silofs_namestr *name,
                      const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_mbootrec_info *mbri;

	mbri = mbi_find(mbi, name);
	if (mbri == NULL) {
		return mbi_insert_new(mbi, name, sb_uaddr);
	}
	mbri_update(mbri, sb_uaddr);
	return 0;
}

int silofs_mbi_nextof(const struct silofs_mboot_info *mbi, loff_t idx,
                      struct silofs_mbootrec_info **out_mbri)
{
	const struct silofs_mbootrec_info *mbri = NULL;

	mbri = mbi_iterate(mbi, idx);
	if (mbri == NULL) {
		return -ENOENT;
	}
	*out_mbri = unconst(mbri);
	return 0;
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

