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
	const struct silofs_strview *sv = &nstr->sv;
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

static int check_name_len(const struct silofs_namestr *nstr)
{
	if (nstr->sv.len == 0) {
		return -SILOFS_EILLSTR;
	}
	if (nstr->sv.len > SILOFS_NAME_MAX) {
		return -SILOFS_ENAMETOOLONG;
	}
	return 0;
}

static int check_name_dat(const struct silofs_namestr *nstr)
{
	if (nstr->sv.str == NULL) {
		return -SILOFS_EILLSTR;
	}
	if (memchr(nstr->sv.str, '/', nstr->sv.len)) {
		return -SILOFS_EILLSTR;
	}
	if (nstr->sv.str[nstr->sv.len] != '\0') {
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
	silofs_strview_init(&nstr->sv, s);
	nstr->hash = 0;
	return silofs_check_name(nstr);
}

static int check_fsname(const struct silofs_namestr *nstr)
{
	int err;

	if (nstr->sv.str[0] == '.') {
		return -SILOFS_EILLSTR;
	}
	if (nstr->sv.len > SILOFS_FSNAME_MAX) {
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

static int32_t bootrec1k_chiper_algo(const struct silofs_bootrec1k *brec1k)
{
	return (int32_t)silofs_le32_to_cpu(brec1k->br_chiper_algo);
}

static int32_t bootrec1k_chiper_mode(const struct silofs_bootrec1k *brec1k)
{
	return (int32_t)silofs_le32_to_cpu(brec1k->br_chiper_mode);
}

static void bootrec1k_set_cipher(struct silofs_bootrec1k *brec1k,
                                 int32_t cipher_algo, int32_t cipher_mode)
{
	brec1k->br_chiper_algo = silofs_cpu_to_le32((uint32_t)cipher_algo);
	brec1k->br_chiper_mode = silofs_cpu_to_le32((uint32_t)cipher_mode);
}

void silofs_bootrec1k_init(struct silofs_bootrec1k *brec1k)
{
	silofs_memzero(brec1k, sizeof(*brec1k));
	bootrec1k_set_magic(brec1k, SILOFS_BOOT_RECORD_MAGIC);
	bootrec1k_set_version(brec1k, SILOFS_FMT_VERSION);
	bootrec1k_set_flags(brec1k, SILOFS_BOOTF_NONE);
	bootrec1k_set_cipher(brec1k, SILOFS_CIPHER_ALGO_DEFAULT,
	                     SILOFS_CIPHER_MODE_DEFAULT);
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

static void bootrec1k_main_ivkey(const struct silofs_bootrec1k *brec1k,
                                 struct silofs_ivkey *out_ivkey)
{
	silofs_ivkey_setup(out_ivkey, &brec1k->br_main_key,
	                   &brec1k->br_main_iv);
}

static void bootrec1k_set_main_ivkey(struct silofs_bootrec1k *brec1k,
                                     const struct silofs_ivkey *ivkey)
{
	silofs_key_assign(&brec1k->br_main_key, &ivkey->key);
	silofs_iv_assign(&brec1k->br_main_iv, &ivkey->iv);
}

static void bootrec1k_meta_prange(const struct silofs_bootrec1k *brec1k,
                                  struct silofs_prange *out_prange)
{
	silofs_prange48b_xtoh(&brec1k->br_meta_prange, out_prange);
}

static void bootrec1k_set_meta_prange(struct silofs_bootrec1k *brec1k,
                                      const struct silofs_prange *prange)
{
	silofs_prange48b_htox(&brec1k->br_meta_prange, prange);
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
	enum silofs_ltype ltype;

	bootrec1k_sb_uaddr(brec1k, &uaddr);
	height = uaddr_height(&uaddr);
	ltype = uaddr_ltype(&uaddr);
	if ((ltype != SILOFS_LTYPE_SUPER) ||
	    (height != SILOFS_HEIGHT_SUPER) || (uaddr.voff != 0)) {
		log_dbg("bad bootrec uaddr-sb: voff=%ld ltype=%d height=%d",
		        uaddr.voff, (int)ltype, (int)height);
		return -SILOFS_EBADBOOT;
	}
	return 0;
}

static void bootrec1k_uuid(const struct silofs_bootrec1k *brec1k,
                           struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &brec1k->br_uuid);
}

static void bootrec1k_set_uuid(struct silofs_bootrec1k *brec1k,
                               const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&brec1k->br_uuid, uuid);
}

static int bootrec1k_check(const struct silofs_bootrec1k *brec1k)
{
	int algo;
	int mode;
	int err;

	err = bootrec1k_check_base(brec1k);
	if (err) {
		return err;
	}
	err = bootrec1k_check_uaddr_sb(brec1k);
	if (err) {
		return err;
	}
	algo = bootrec1k_chiper_algo(brec1k);
	mode = bootrec1k_chiper_mode(brec1k);
	err = silofs_check_cipher_args(algo, mode);
	if (err) {
		return err;
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
	bootrec1k_sb_uaddr(brec1k, &brec->sb_ulink.uaddr);
	bootrec1k_sb_riv(brec1k, &brec->sb_ulink.riv);
	brec->flags = bootrec1k_flags(brec1k);
	bootrec1k_uuid(brec1k, &brec->uuid);
	bootrec1k_main_ivkey(brec1k, &brec->main_ivkey);
	bootrec1k_meta_prange(brec1k, &brec->meta_prange);
	brec->cipher_algo = (int32_t)bootrec1k_chiper_algo(brec1k);
	brec->cipher_mode = (int32_t)bootrec1k_chiper_mode(brec1k);
}

void silofs_bootrec1k_htox(struct silofs_bootrec1k *brec1k,
                           const struct silofs_bootrec *brec)
{
	silofs_bootrec1k_init(brec1k);
	bootrec1k_set_sb_uaddr(brec1k, &brec->sb_ulink.uaddr);
	bootrec1k_set_sb_riv(brec1k, &brec->sb_ulink.riv);
	bootrec1k_set_flags(brec1k, brec->flags);
	bootrec1k_set_uuid(brec1k, &brec->uuid);
	bootrec1k_set_main_ivkey(brec1k, &brec->main_ivkey);
	bootrec1k_set_meta_prange(brec1k, &brec->meta_prange);
	bootrec1k_set_cipher(brec1k, brec->cipher_algo, brec->cipher_mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootrec_init(struct silofs_bootrec *brec)
{
	silofs_memzero(brec, sizeof(*brec));
	silofs_ulink_reset(&brec->sb_ulink);
	brec->flags = SILOFS_BOOTF_NONE;
	brec->cipher_algo = SILOFS_CIPHER_AES256;
	brec->cipher_mode = SILOFS_CIPHER_MODE_XTS;
}

void silofs_bootrec_fini(struct silofs_bootrec *brec)
{
	silofs_memffff(brec, sizeof(*brec));
}

void silofs_bootrec_setup(struct silofs_bootrec *brec)
{
	silofs_bootrec_init(brec);
	silofs_bootrec_gen_uuid(brec);
}

void silofs_bootrec_assign(struct silofs_bootrec *brec,
                           const struct silofs_bootrec *other)
{
	silofs_uuid_assign(&brec->uuid, &other->uuid);
	silofs_ivkey_assign(&brec->main_ivkey, &other->main_ivkey);
	silofs_prange_assign(&brec->meta_prange, &other->meta_prange);
	silofs_ulink_assign(&brec->sb_ulink, &other->sb_ulink);
	brec->flags = other->flags;
	brec->cipher_algo = other->cipher_algo;
	brec->cipher_mode = other->cipher_mode;
}

void silofs_bootrec_gen_uuid(struct silofs_bootrec *brec)
{
	silofs_uuid_generate(&brec->uuid);
}

void silofs_bootrec_set_ivkey(struct silofs_bootrec *brec,
                              const struct silofs_ivkey *ivkey)
{
	silofs_ivkey_assign(&brec->main_ivkey, ivkey);
}

void silofs_bootrec_gen_ivkey(struct silofs_bootrec *brec)
{
	struct silofs_ivkey ivkey;

	silofs_ivkey_mkrand(&ivkey);
	silofs_bootrec_set_ivkey(brec, &ivkey);
}

void silofs_bootrec_meta_prange(const struct silofs_bootrec *brec,
                                struct silofs_prange *out_prange)
{
	silofs_prange_assign(out_prange, &brec->meta_prange);
}

void silofs_bootrec_set_meta_prange(struct silofs_bootrec *brec,
                                    const struct silofs_prange *prange)
{
	silofs_prange_assign(&brec->meta_prange, prange);
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

void silofs_bootrec_lvid(const struct silofs_bootrec *brec,
                         struct silofs_lvid *out_lvid)
{
	const struct silofs_uaddr *sb_uaddr = &brec->sb_ulink.uaddr;

	silofs_lvid_assign(out_lvid, &sb_uaddr->laddr.lsid.lvid);
}

static void
bootrec_uaddr_by_lvid(const struct silofs_lvid *lvid,
                      struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid;
	const enum silofs_ltype ltype = SILOFS_LTYPE_BOOTREC;
	const enum silofs_height height = SILOFS_HEIGHT_BOOT;

	silofs_lsid_setup(&lsid, lvid, 0, ltype, height, ltype);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
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
	silofs_strview_init(&bpath->repodir, repodir);
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
	const struct silofs_cipher *cipher = &fsenv->fse_boot.cipher;
	const struct silofs_ivkey *ivkey = &fsenv->fse_boot.ivkey;

	return bootrec_encode(brec, mdigest, cipher, ivkey, out_brec1k);
}

int silofs_decode_bootrec(const struct silofs_fsenv *fsenv,
                          const struct silofs_bootrec1k *brec1k_enc,
                          struct silofs_bootrec *out_brec)
{
	const struct silofs_mdigest *mdigest = &fsenv->fse_mdigest;
	const struct silofs_cipher *cipher = &fsenv->fse_boot.cipher;
	const struct silofs_ivkey *ivkey = &fsenv->fse_boot.ivkey;

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

	silofs_calc_caddr_of(&iov, 1, SILOFS_CTYPE_BOOTREC,
	                     &fsenv->fse_mdigest, out_caddr);
}

static int verify_bootrec1k_caddr(const struct silofs_fsenv *fsenv,
                                  const struct silofs_bootrec1k *brec1k,
                                  const struct silofs_caddr *caddr)
{
	struct silofs_caddr caddr2;

	calc_bootrec1k_caddr(fsenv, brec1k, &caddr2);
	return caddr_isequal(caddr, &caddr2) ? 0 : -SILOFS_EBADBOOT;
}

int silofs_calc_bootrec_caddr(const struct silofs_fsenv *fsenv,
                              const struct silofs_bootrec *brec,
                              struct silofs_caddr *out_caddr)
{
	struct silofs_bootrec1k brec1k_enc = {
		.br_magic = 1,
	};
	int err;

	err = silofs_encode_bootrec(fsenv, brec, &brec1k_enc);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	calc_bootrec1k_caddr(fsenv, &brec1k_enc, out_caddr);
	return 0;
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
	struct silofs_caddr caddr;
	int err;

	err = silofs_encode_bootrec(fsenv, brec, &brec1k_enc);
	if (err) {
		log_err("failed to encode bootrec: err=%d", err);
		return err;
	}
	calc_bootrec1k_caddr(fsenv, &brec1k_enc, &caddr);
	err = silofs_repo_save_cobj(fsenv->fse.repo, &caddr, &rovec);
	if (err) {
		log_err("failed to save bootrec: err=%d", err);
		return err;
	}
	err = silofs_repo_create_ref(fsenv->fse.repo, &caddr);
	if (err) {
		log_err("failed to create ref: err=%d", err);
		return err;
	}
	silofs_caddr_assign(out_caddr, &caddr);
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

	err = silofs_repo_lookup_ref(fsenv->fse.repo, caddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOREF : err;
	}
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

	err = silofs_repo_lookup_ref(fsenv->fse.repo, caddr);
	if (err) {
		log_err("failed to lookup ref: err=%d", err);
		return err;
	}
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
	err = silofs_repo_remove_ref(fsenv->fse.repo, caddr);
	if (err) {
		log_err("failed to unlink ref: err=%d", err);
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_bootref_init(struct silofs_fs_bref *bref)
{
	silofs_caddr_reset(&bref->caddr);
	bref->repodir = NULL;
	bref->name = NULL;
	bref->passwd = NULL;
}

void silofs_bootref_fini(struct silofs_fs_bref *bref)
{
	silofs_caddr_reset(&bref->caddr);
	bref->repodir = NULL;
	bref->name = NULL;
	bref->passwd = NULL;
}

void silofs_bootref_assign(struct silofs_fs_bref *bref,
                           const struct silofs_fs_bref *other)
{
	silofs_caddr_assign(&bref->caddr, &other->caddr);
	bref->repodir = other->repodir;
	bref->name = other->name;
	bref->passwd = other->passwd;
}

void silofs_bootref_update(struct silofs_fs_bref *bref,
                           const struct silofs_caddr *caddr,
                           const char *name)
{
	silofs_caddr_assign(&bref->caddr, caddr);
	bref->name = name;
}

int silofs_bootref_import(struct silofs_fs_bref *bref,
                          const struct silofs_strview *sv)
{
	return silofs_caddr_by_name2(&bref->caddr, sv);
}

void silofs_bootref_export(const struct silofs_fs_bref *bref,
                           struct silofs_strbuf *sbuf)
{
	silofs_caddr_to_name(&bref->caddr, sbuf);
}
