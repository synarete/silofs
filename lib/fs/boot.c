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
#include <silofs/fs.h>
#include <silofs/fs-private.h>


static int check_ascii_fs_name(const struct silofs_namestr *nstr)
{
	const char *allowed =
	        "abcdefghijklmnopqrstuvwxyz"
	        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	        "0123456789_-+.";
	const struct silofs_substr *ss = &nstr->s;
	size_t n;

	if (!silofs_substr_isprint(ss)) {
		return -SILOFS_EILLSTR;
	}
	n = silofs_substr_count_if(ss, silofs_chr_isspace);
	if (n > 0) {
		return -SILOFS_EILLSTR;
	}
	n = silofs_substr_count_if(ss, silofs_chr_iscntrl);
	if (n > 0) {
		return -SILOFS_EILLSTR;
	}
	n = silofs_substr_find_first_not_of(ss, allowed);
	if (n < ss->len) {
		return -SILOFS_EILLSTR;
	}
	return 0;
}

static int check_name_len(const struct silofs_namestr *nstr)
{
	if (nstr->s.len == 0) {
		return -SILOFS_EILLSTR;
	}
	if (nstr->s.len > SILOFS_NAME_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	return 0;
}

static int check_name_dat(const struct silofs_namestr *nstr)
{
	if (nstr->s.str == NULL) {
		return -SILOFS_EILLSTR;
	}
	if (memchr(nstr->s.str, '/', nstr->s.len)) {
		return -SILOFS_EILLSTR;
	}
	if (nstr->s.str[nstr->s.len] != '\0') {
		return -SILOFS_EILLSTR;
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

int silofs_make_namestr(struct silofs_namestr *nstr, const char *s)
{
	silofs_substr_init(&nstr->s, s);
	nstr->hash = 0;
	return silofs_check_name(nstr);
}

static int check_fsname(const struct silofs_namestr *nstr)
{
	int err;

	if (nstr->s.str[0] == '.') {
		return -SILOFS_EILLSTR;
	}
	if (nstr->s.len > SILOFS_FSNAME_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	err = check_ascii_fs_name(nstr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_make_fsnamestr(struct silofs_namestr *nstr, const char *s)
{
	int err;

	err = silofs_make_namestr(nstr, s);
	if (err) {
		return err;
	}
	err = check_fsname(nstr);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct silofs_cipher_args s_default_cip_args = {
	.kdf = {
		.kdf_key = {
			.kd_iterations = 8192,
			.kd_algo = SILOFS_KDF_PBKDF2,
			.kd_subalgo = SILOFS_MD_SHA256,
			.kd_salt_md = SILOFS_MD_SHA3_512,
		},
		.kdf_iv = {
			.kd_iterations = 2048,
			.kd_algo = SILOFS_KDF_SCRYPT,
			.kd_subalgo = 8,
			.kd_salt_md = SILOFS_MD_SHA3_256,
		},
	},
	.cipher_algo = SILOFS_CIPHER_AES256,
	.cipher_mode = SILOFS_CIPHER_MODE_XTS,
};

static const struct silofs_cipher_args s_bootrec_cip_args = {
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

static uint64_t bootrec1k_magic(const struct silofs_bootrec1k *brec1k)
{
	return silofs_le64_to_cpu(brec1k->br_magic);
}

static void
bootrec1k_set_magic(struct silofs_bootrec1k *brec1k, uint64_t magic)
{
	brec1k->br_magic = silofs_cpu_to_le64(magic);
}

static uint64_t bootrec1k_version(const struct silofs_bootrec1k *brec1k)
{
	return silofs_le64_to_cpu(brec1k->br_version);
}

static void
bootrec1k_set_version(struct silofs_bootrec1k *brec1k, uint64_t version)
{
	brec1k->br_version = silofs_cpu_to_le64(version);
}

static enum silofs_bootf bootrec1k_flags(const struct silofs_bootrec1k *brec1k)
{
	const uint64_t f = silofs_le64_to_cpu(brec1k->br_flags);

	return (enum silofs_bootf)f;
}

static void
bootrec1k_set_flags(struct silofs_bootrec1k *brec1k, enum silofs_bootf f)
{
	brec1k->br_flags = silofs_cpu_to_le64((uint64_t)f);
}

static void bootrec1k_kdf(const struct silofs_bootrec1k *brec1k,
                          struct silofs_kdf_pair *kdf)
{
	kdf_to_cpu(&brec1k->br_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&brec1k->br_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void bootrec1k_set_kdf(struct silofs_bootrec1k *brec1k,
                              const struct silofs_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &brec1k->br_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &brec1k->br_kdf_pair.kdf_key);
}

static uint32_t bootrec1k_chiper_algo(const struct silofs_bootrec1k *brec1k)
{
	return silofs_le32_to_cpu(brec1k->br_chiper_algo);
}

static uint32_t bootrec1k_chiper_mode(const struct silofs_bootrec1k *brec1k)
{
	return silofs_le32_to_cpu(brec1k->br_chiper_mode);
}

static void bootrec1k_set_cipher(struct silofs_bootrec1k *brec1k,
                                 uint32_t cipher_algo, uint32_t cipher_mode)
{
	brec1k->br_chiper_algo = silofs_cpu_to_le32(cipher_algo);
	brec1k->br_chiper_mode = silofs_cpu_to_le32(cipher_mode);
}

void silofs_bootrec1k_init(struct silofs_bootrec1k *brec1k)
{
	const struct silofs_cipher_args *cip_args = &s_default_cip_args;

	silofs_memzero(brec1k, sizeof(*brec1k));
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
                               struct silofs_uaddr *out_sb_uaddr)
{
	silofs_uaddr64b_xtoh(&brec1k->br_sb_uaddr, out_sb_uaddr);
}

static void bootrec1k_set_sb_uaddr(struct silofs_bootrec1k *brec1k,
                                   const struct silofs_uaddr *sb_uaddr)
{
	silofs_uaddr64b_htox(&brec1k->br_sb_uaddr, sb_uaddr);
}

static void bootrec1k_sb_riv(const struct silofs_bootrec1k *brec1k,
                             struct silofs_iv *out_sb_riv)
{
	silofs_iv_assign(out_sb_riv, &brec1k->br_sb_riv);
}

static void bootrec1k_set_sb_riv(struct silofs_bootrec1k *brec1k,
                                 const struct silofs_iv *sb_riv)
{
	silofs_iv_assign(&brec1k->br_sb_riv, sb_riv);
}


static int bootrec1k_check_base(const struct silofs_bootrec1k *brec1k)
{
	const uint64_t magic = bootrec1k_magic(brec1k);
	const uint64_t version = bootrec1k_version(brec1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_BOOT_RECORD_MAGIC) &&
	    (version != SILOFS_FMT_VERSION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_BOOT_RECORD_MAGIC) {
		log_dbg("bad bootrec magic: 0x%lx", magic);
		return -SILOFS_EBADBOOT;
	}
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad bootrec version: %lu", version);
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static int bootrec1k_check_uaddr_sb(const struct silofs_bootrec1k *brec1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;

	bootrec1k_sb_uaddr(brec1k, &uaddr);
	height = uaddr_height(&uaddr);
	if ((uaddr.laddr.ltype != SILOFS_LTYPE_SUPER) ||
	    (height != SILOFS_HEIGHT_SUPER) || (uaddr.voff != 0)) {
		log_dbg("bad bootrec uaddr-sb: voff=%ld ltype=%d height=%d",
		        uaddr.voff, (int)uaddr.laddr.ltype, (int)height);
		return -SILOFS_EBADBOOT;
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
	err = bootrec1k_check_uaddr_sb(brec1k);
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

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int bootrec1k_verify(const struct silofs_bootrec1k *brec1k,
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

int silofs_bootrec1k_verify(const struct silofs_bootrec1k *brec1k,
                            const struct silofs_mdigest *md)
{
	return bootrec1k_verify(brec1k, md);
}

void silofs_bootrec1k_xtoh(const struct silofs_bootrec1k *brec1k,
                           struct silofs_bootrec *brec)
{
	STATICASSERT_EQ(sizeof(brec->rands), sizeof(brec1k->br_rands));

	bootrec1k_sb_uaddr(brec1k, &brec->sb_ulink.uaddr);
	bootrec1k_sb_riv(brec1k, &brec->sb_ulink.riv);
	bootrec1k_cipher_args(brec1k, &brec->cip_args);
	brec->flags = bootrec1k_flags(brec1k);
	memcpy(brec->rands, brec1k->br_rands, sizeof(brec->rands));
}

void silofs_bootrec1k_htox(struct silofs_bootrec1k *brec1k,
                           const struct silofs_bootrec *brec)
{
	STATICASSERT_EQ(sizeof(brec1k->br_rands), sizeof(brec->rands));

	silofs_bootrec1k_init(brec1k);
	bootrec1k_set_sb_uaddr(brec1k, &brec->sb_ulink.uaddr);
	bootrec1k_set_sb_riv(brec1k, &brec->sb_ulink.riv);
	bootrec1k_set_flags(brec1k, brec->flags);
	memcpy(brec1k->br_rands, brec->rands, sizeof(brec1k->br_rands));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *brec)
{
	silofs_memzero(brec, sizeof(*brec));
	silofs_ulink_reset(&brec->sb_ulink);
	silofs_default_cip_args(&brec->cip_args);
	brec->flags = SILOFS_BOOTF_NONE;
}

void silofs_bootrec_fini(struct silofs_bootrec *brec)
{
	silofs_memffff(brec, sizeof(*brec));
}

static void bootrec_fill_rands(struct silofs_bootrec *brec)
{
	silofs_getentropy(brec->rands, sizeof(brec->rands));
}

void silofs_bootrec_setup(struct silofs_bootrec *brec)
{
	silofs_bootrec_init(brec);
	bootrec_fill_rands(brec);
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

void silofs_bootrec_cipher_args(const struct silofs_bootrec *brec,
                                struct silofs_cipher_args *out_cip_args)
{
	if (!brec || !brec->cip_args.cipher_algo) {
		silofs_default_cip_args(out_cip_args);
	} else {
		cip_args_assign(out_cip_args, &brec->cip_args);
	}
}

void silofs_bootrec_lvid(const struct silofs_bootrec *brec,
                         struct silofs_lvid *out_lvid)
{
	const struct silofs_uaddr *sb_uaddr = &brec->sb_ulink.uaddr;

	silofs_lvid_assign(out_lvid, &sb_uaddr->laddr.lsegid.lvid);
}

static void
bootrec_uaddr_by_lvid(const struct silofs_lvid *lvid,
                      struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsegid lsegid;
	const enum silofs_ltype ltype = SILOFS_LTYPE_BOOTREC;
	const enum silofs_height height = SILOFS_HEIGHT_BOOT;

	silofs_lsegid_setup(&lsegid, lvid, 0, ltype, height);
	silofs_uaddr_setup(out_uaddr, &lsegid, 0, ltype, 0);
}

void silofs_bootrec_self_uaddr(const struct silofs_bootrec *brec,
                               struct silofs_uaddr *out_uaddr)
{
	struct silofs_lvid lvid;

	silofs_bootrec_lvid(brec, &lvid);
	bootrec_uaddr_by_lvid(&lvid, out_uaddr);
}

void silofs_make_bootrec_uaddr(const struct silofs_lvid *lvid,
                               struct silofs_uaddr *out_uaddr)
{
	bootrec_uaddr_by_lvid(lvid, out_uaddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_ivkey_for_bootrec(struct silofs_ivkey *ivkey,
                             const struct silofs_password *passwd,
                             const struct silofs_mdigest *mdigest)
{
	const struct silofs_cipher_args *cip_args = &s_bootrec_cip_args;

	return silofs_derive_ivkey(cip_args, passwd, mdigest, ivkey);
}

static int encrypt_brec1k(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_bootrec1k *brec1k_in,
                          struct silofs_bootrec1k *brec1k_out)
{
	return silofs_encrypt_buf(ci, ivkey, brec1k_in,
	                          brec1k_out, sizeof(*brec1k_out));
}

static int decrypt_brec1k(const struct silofs_cipher *ci,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_bootrec1k *brec1k_in,
                          struct silofs_bootrec1k *brec1k_out)
{
	return silofs_decrypt_buf(ci, ivkey, brec1k_in,
	                          brec1k_out, sizeof(*brec1k_out));
}

static int bootrec_encode(const struct silofs_bootrec *brec,
                          const struct silofs_mdigest *mdigest,
                          const struct silofs_cipher *cipher,
                          const struct silofs_ivkey *ivkey,
                          struct silofs_bootrec1k *out_brec1k)
{
	struct silofs_bootrec1k brec1k;

	silofs_bootrec1k_htox(&brec1k, brec);
	silofs_bootrec1k_stamp(&brec1k, mdigest);
	return encrypt_brec1k(cipher, ivkey, &brec1k, out_brec1k);
}

static int bootrec_decode(struct silofs_bootrec *brec,
                          const struct silofs_mdigest *mdigest,
                          const struct silofs_cipher *cipher,
                          const struct silofs_ivkey *ivkey,
                          const struct silofs_bootrec1k *brec1k_enc)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 1 };
	int err;

	err = decrypt_brec1k(cipher, ivkey, brec1k_enc, &brec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_verify(&brec1k, mdigest);
	if (err) {
		return err;
	}
	silofs_bootrec1k_xtoh(&brec1k, brec);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_bootpath_setup(struct silofs_bootpath *bpath,
                          const char *repodir, const char *name)
{
	size_t len;

	silofs_memzero(bpath, sizeof(*bpath));
	len = silofs_str_length(repodir);
	if (!len || (len >= SILOFS_REPOPATH_MAX)) {
		return -SILOFS_EINVAL;
	}
	silofs_substr_init(&bpath->repodir, repodir);
	if (name == NULL) {
		return 0; /* boot with repo-dir only */
	}
	return silofs_make_namestr(&bpath->name, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_calc_key_hash(const struct silofs_key *key,
                          const struct silofs_mdigest *md,
                          struct silofs_hash256 *out_hash)
{
	silofs_sha256_of(md, key->key, sizeof(key->key), out_hash);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_encode_bootrec(const struct silofs_fsenv *fsenv,
                          const struct silofs_bootrec *brec,
                          struct silofs_bootrec1k *out_brec1k)
{
	const struct silofs_mdigest *mdigest = &fsenv->fse_mdigest;
	const struct silofs_cipher *cipher = &fsenv->fse_enc_cipher;
	const struct silofs_ivkey *ivkey = fsenv->fse.boot_ivkey;

	return bootrec_encode(brec, mdigest, cipher, ivkey, out_brec1k);
}

int silofs_decode_bootrec(const struct silofs_fsenv *fsenv,
                          const struct silofs_bootrec1k *brec1k_enc,
                          struct silofs_bootrec *out_brec)
{
	const struct silofs_mdigest *mdigest = &fsenv->fse_mdigest;
	const struct silofs_cipher *cipher = &fsenv->fse_dec_cipher;
	const struct silofs_ivkey *ivkey = fsenv->fse.boot_ivkey;

	return bootrec_decode(out_brec, mdigest, cipher, ivkey, brec1k_enc);
}

static void calc_bootrec1k_caddr(const struct silofs_fsenv *fsenv,
                                 const struct silofs_bootrec1k *brec1k,
                                 struct silofs_caddr *out_caddr)
{
	const struct iovec iov = {
		.iov_base = unconst(brec1k),
		.iov_len = sizeof(*brec1k)
	};

	silofs_calc_caddr_of(&iov, 1, &fsenv->fse_mdigest, out_caddr);
}

static int verify_bootrec1k_caddr(const struct silofs_fsenv *fsenv,
                                  const struct silofs_bootrec1k *brec1k,
                                  const struct silofs_caddr *caddr)
{
	struct silofs_caddr caddr2;

	calc_bootrec1k_caddr(fsenv, brec1k, &caddr2);
	return caddr_isequal(caddr, &caddr2) ? 0 : -SILOFS_EBADBOOT;
}

int silofs_save_bootrec(const struct silofs_fsenv *fsenv,
                        const struct silofs_bootrec *brec,
                        struct silofs_caddr *out_caddr)
{
	struct silofs_bootrec1k brec1k_enc = {
		.br_magic = 1,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &brec1k_enc,
		.rov_len = sizeof(brec1k_enc)
	};
	int err;

	err = silofs_encode_bootrec(fsenv, brec, &brec1k_enc);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	calc_bootrec1k_caddr(fsenv, &brec1k_enc, out_caddr);
	err = silofs_repo_save_cobj(fsenv->fse.repo, out_caddr, &rovec);
	if (err) {
		log_err("failed to save bootrec: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_load_bootrec(const struct silofs_fsenv *fsenv,
                        const struct silofs_caddr *caddr,
                        struct silofs_bootrec *out_brec)
{
	struct silofs_bootrec1k brec1k_enc = {
		.br_magic = 0
	};
	struct silofs_rwvec rwvec = {
		.rwv_base = &brec1k_enc,
		.rwv_len = sizeof(brec1k_enc)
	};
	int err;

	err = silofs_repo_load_cobj(fsenv->fse.repo, caddr, &rwvec);
	if (err) {
		log_dbg("failed to load bootrec: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOBOOT : err;
	}
	err = verify_bootrec1k_caddr(fsenv, &brec1k_enc, caddr);
	if (err) {
		log_dbg("failed to verify bootrec: err=%d", err);
		return err;
	}
	err = silofs_decode_bootrec(fsenv, &brec1k_enc, out_brec);
	if (err) {
		log_dbg("failed to decode bootrec: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_stat_bootrec(const struct silofs_fsenv *fsenv,
                        const struct silofs_caddr *caddr)
{
	size_t sz = 0;
	int err;

	err = silofs_repo_stat_cobj(fsenv->fse.repo, caddr, &sz);
	if (err) {
		log_err("failed to stat bootrec: err=%d", err);
		return err;
	}
	if (sz != SILOFS_BOOTREC_SIZE) {
		log_warn("bad bootrec: size=%zu", sz);
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

int silofs_unlink_bootrec(const struct silofs_fsenv *fsenv,
                          const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_repo_unlink_cobj(fsenv->fse.repo, caddr);
	if (err) {
		log_err("failed to unlink bootrec: err=%d", err);
		return err;
	}
	return 0;
}
