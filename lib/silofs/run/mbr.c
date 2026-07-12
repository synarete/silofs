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
#include <silofs/version.h>
#include <silofs/ondisk.h>
#include <silofs/infra.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>
#include <silofs/run.h>

static void swv64b_htox(struct silofs_sw_version64b *swv64,
                        const struct silofs_sw_version *swv)
{
	STATICASSERT_EQ_SIZEOF(swv64->sw_revision, swv->revision);

	memset(swv64, 0, sizeof(*swv64));
	swv64->sw_major    = silofs_cpu_to_le32(swv->major);
	swv64->sw_minor    = silofs_cpu_to_le32(swv->minor);
	swv64->sw_sublevel = silofs_cpu_to_le32(swv->sublevel);
	memcpy(swv64->sw_revision, swv->revision, sizeof(swv64->sw_revision));
}

static void swv64b_xtoh(const struct silofs_sw_version64b *swv64,
                        struct silofs_sw_version *swv)
{
	STATICASSERT_EQ_SIZEOF(swv->revision, swv64->sw_revision);

	memset(swv, 0, sizeof(*swv));
	swv->major    = silofs_le32_to_cpu(swv64->sw_major);
	swv->minor    = silofs_le32_to_cpu(swv64->sw_minor);
	swv->sublevel = silofs_le32_to_cpu(swv64->sw_sublevel);

	memcpy(swv->revision, swv64->sw_revision, sizeof(swv->revision));
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
calc_cas_paddr(const struct silofs_mdigest_hd *md_hd, enum silofs_ptype ptype,
               enum silofs_ltype ltype, const struct iovec *iov,
               size_t iov_cnt, struct silofs_paddr *out_paddr)
{
	struct silofs_hash256 hash;
	struct silofs_blobid blobid;
	struct silofs_layerid layerid;
	struct silofs_uniqid uniqid;
	const struct silofs_stype stype = {
		.ptype = ptype,
		.ltype = ltype,
	};

	silofs_sha3_256_ofv(md_hd, iov, iov_cnt, &hash);

	silofs_layerid_reset(&layerid);
	silofs_uniqid_setup_by(&uniqid, &hash);
	silofs_blobid_init(&blobid, &stype, &layerid, &uniqid);

	silofs_paddr_init(out_paddr, &blobid, 0);
}

static void
calc_mbr_cas_paddr(const struct silofs_mdigest_hd *md_hd,
                   const struct iovec *iov, struct silofs_paddr *out_paddr)
{
	calc_cas_paddr(md_hd, SILOFS_PTYPE_MBR, SILOFS_LTYPE_NONE, //
	               iov, 1, out_paddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static bool pnptr_isuber(const struct silofs_pnptr *pnptr)
{
	return pnptr->paddr.blobid.stype.ptype == SILOFS_PTYPE_UBER;
}

static void mbr_meta_assign(struct silofs_mbr_meta *meta,
                            const struct silofs_mbr_meta *other)
{
	silofs_nmeta_assign(&meta->nmeta, &other->nmeta);
	silofs_ckey_assign(&meta->hmac_key, &other->hmac_key);
}

static void mbr_meta_reset(struct silofs_mbr_meta *meta)
{
	silofs_nmeta_reset(&meta->nmeta);
	silofs_ckey_reset(&meta->hmac_key);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t mbr1k_magic(const struct silofs_mbr1k *mbr1k)
{
	return silofs_le64_to_cpu(mbr1k->mbr_magic);
}

static void mbr1k_set_magic(struct silofs_mbr1k *mbr1k, uint64_t magic)
{
	mbr1k->mbr_magic = silofs_cpu_to_le64(magic);
}

static uint64_t mbr1k_version(const struct silofs_mbr1k *mbr1k)
{
	return silofs_le64_to_cpu(mbr1k->mbr_version);
}

static void mbr1k_set_version(struct silofs_mbr1k *mbr1k, uint64_t version)
{
	mbr1k->mbr_version = silofs_cpu_to_le64(version);
}

static void mbr1k_set_flags(struct silofs_mbr1k *mbr1k, uint32_t flags)
{
	mbr1k->mbr_flags = silofs_cpu_to_le32(flags);
}

static void mbr1k_set_mode(struct silofs_mbr1k *mbr1k, uint32_t mode)
{
	mbr1k->mbr_mode = silofs_cpu_to_le32(mode);
}

static void
mbr1k_set_uuid(struct silofs_mbr1k *mbr1k, const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&mbr1k->mbr_uuid, uuid);
}

static void mbr1k_gen_uuid(struct silofs_mbr1k *mbr1k)
{
	struct silofs_uuid uuid;

	silofs_uuid_generate(&uuid);
	mbr1k_set_uuid(mbr1k, &uuid);
}

static void mbr1k_sw_version(const struct silofs_mbr1k *mbr1k,
                             struct silofs_sw_version *out_swv)
{
	swv64b_xtoh(&mbr1k->mbr_sw_version, out_swv);
}

static void mbr1k_set_sw_version(struct silofs_mbr1k *mbr1k,
                                 const struct silofs_sw_version *swv)
{
	swv64b_htox(&mbr1k->mbr_sw_version, swv);
}

static void
mbr1k_root(const struct silofs_mbr1k *mbr1k, struct silofs_pnptr *out_pnptr)
{
	silofs_pnptr256b_xtoh(&mbr1k->mbr_root_uber, out_pnptr);
}

static void
mbr1k_set_root(struct silofs_mbr1k *mbr1k, const struct silofs_pnptr *pnptr)
{
	silofs_pnptr256b_htox(&mbr1k->mbr_root_uber, pnptr);
}

static void mbr1k_reset_root(struct silofs_mbr1k *mbr1k)
{
	mbr1k_set_root(mbr1k, silofs_pnptr_none());
}

static int mbr1k_check_base(const struct silofs_mbr1k *mbr1k)
{
	const uint64_t magic   = mbr1k_magic(mbr1k);
	const uint64_t version = mbr1k_version(mbr1k);
	int err = 0, errcnt = 0;

	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad mbr magic: 0x%lx", magic);
		err = -SILOFS_EBADMBR;
		errcnt++;
	}
	if (version != SILOFS_FMT_VERSION) {
		log_dbg("bad mbr version: %lu", version);
		err = -SILOFS_EBADMBR;
		errcnt++;
	}
	/*
	 * When both magic and version are no valid, we assume it is most likely
	 * due to bad password provided by user.
	 */
	return (errcnt == 2) ? -SILOFS_EKEYEXPIRED : err;
}

static int mbr1k_check_root(const struct silofs_mbr1k *mbr1k)
{
	struct silofs_pnptr pnptr;

	mbr1k_root(mbr1k, &pnptr);
	return silofs_ciargs_check(&pnptr.nmeta.ciargs);
}

static int mbr1k_check(const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = mbr1k_check_base(mbr1k);
	return_if_err(err);

	err = mbr1k_check_root(mbr1k);
	return_if_err(err);

	return 0;
}

static void
mbr1k_hash(const struct silofs_mbr1k *mbr1k, struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(&mbr1k->mbr_hash, hash);
}

static void
mbr1k_set_hash(struct silofs_mbr1k *mbr1k, const struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(hash, &mbr1k->mbr_hash);
}

static void mbr1k_calc_hash(const struct silofs_mbr1k *mbr1k,
                            const struct silofs_mdigest_hd *md,
                            struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_mbr1k, mbr_hash);

	silofs_sha3_256_of(md, mbr1k, len, out_hash);
}

static void
mbr1k_stamp(struct silofs_mbr1k *mbr1k, const struct silofs_mdigest_hd *md)
{
	struct silofs_hash256 hash;

	mbr1k_calc_hash(mbr1k, md, &hash);
	mbr1k_set_hash(mbr1k, &hash);
}

static int mbr1k_check_hash(const struct silofs_mbr1k *mbr1k,
                            const struct silofs_mdigest_hd *md)
{
	struct silofs_hash256 hash[2];

	mbr1k_hash(mbr1k, &hash[0]);
	mbr1k_calc_hash(mbr1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int mbr1k_verify(const struct silofs_mbr1k *mbr1k,
                        const struct silofs_mdigest_hd *md)
{
	int err;

	err = mbr1k_check(mbr1k);
	return_if_err(err);

	err = mbr1k_check_hash(mbr1k, md);
	return_if_err(err);

	return 0;
}

static void mbr1k_init(struct silofs_mbr1k *mbr1k)
{
	silofs_memzero(mbr1k, sizeof(*mbr1k));
	mbr1k_set_magic(mbr1k, SILOFS_MBR_MAGIC);
	mbr1k_set_version(mbr1k, SILOFS_FMT_VERSION);
	mbr1k_reset_root(mbr1k);
	mbr1k_set_mode(mbr1k, 0);
	mbr1k_set_flags(mbr1k, 0);
	mbr1k_gen_uuid(mbr1k);
}

static void mbr1k_fini(struct silofs_mbr1k *mbr1k)
{
	silofs_memffff(mbr1k, sizeof(*mbr1k));
}

static size_t mbr1k_enclen(void)
{
	return offsetof(struct silofs_mbr1k, mbr_hmac);
}

static int mbr1k_encrypt(const struct silofs_mbr1k *mbr1k,
                         const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         struct silofs_mbr1k *out_mbr1k)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = mbr1k,
		.data_out = out_mbr1k,
		.data_len = mbr1k_enclen(),
	};

	return silofs_encrypt(&ed_ctx);
}

static int mbr1k_decrypt(const struct silofs_mbr1k *mbr1k,
                         const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey *civkey,
                         struct silofs_mbr1k *out_mbr1k)
{
	const struct silofs_encdec_ctx ed_ctx = {
		.ci_hd    = ci_hd,
		.civ      = &civkey->iv,
		.ckey     = &civkey->key,
		.caad     = nullptr,
		.ctag_in  = nullptr,
		.ctag_out = nullptr,
		.data_in  = mbr1k,
		.data_out = out_mbr1k,
		.data_len = mbr1k_enclen(),
	};

	return silofs_decrypt(&ed_ctx);
}

static int
mbr1k_calc_hmac(const struct silofs_mbr1k *mbr1k,
                struct silofs_hmac_hd *hmac_hd, const struct silofs_ckey *key,
                struct silofs_mac *out_hmac)
{
	return silofs_hmac_calc(hmac_hd, key, mbr1k, mbr1k_enclen(), out_hmac);
}

static int
mbr1k_assign_hmac(struct silofs_mbr1k *mbr1k, struct silofs_hmac_hd *hmac_hd,
                  const struct silofs_ckey *key)
{
	return mbr1k_calc_hmac(mbr1k, hmac_hd, key, &mbr1k->mbr_hmac);
}

static int
mbr1k_check_hmac(const struct silofs_mbr1k *mbr1k,
                 struct silofs_hmac_hd *hmac_hd, const struct silofs_ckey *key)
{
	struct silofs_mac hmac;
	int err;

	err = mbr1k_calc_hmac(mbr1k, hmac_hd, key, &hmac);
	if (err) {
		return err;
	}
	if (!silofs_mac_isequal(&hmac, &mbr1k->mbr_hmac)) {
		return -SILOFS_EBADMBR;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* auxiliary controller for MBR operations */
struct silofs_mbraux {
	struct silofs_mdigest_hd md_hd;
	struct silofs_hmac_hd hmac_hd;
	struct silofs_cipher_hd ci_hd;
	const struct silofs_mbr_meta *meta;
};

static void mbraux_fini(struct silofs_mbraux *aux)
{
	silofs_cipher_fini(&aux->ci_hd);
	silofs_hmac_fini(&aux->hmac_hd);
	silofs_mdigest_fini(&aux->md_hd);
	aux->meta = nullptr;
}

static int
mbraux_init(struct silofs_mbraux *aux, const struct silofs_mbr_meta *meta)
{
	int err;

	silofs_memzero(aux, sizeof(*aux));
	err = silofs_mdigest_init(&aux->md_hd);
	goto_out_if_err(err);

	err = silofs_hmac_init(&aux->hmac_hd);
	goto_out_if_err(err);

	err = silofs_cipher_init(&aux->ci_hd);
	goto_out_if_err(err);

	aux->meta = meta;
	return 0;
out:
	mbraux_fini(aux);
	return err;
}

static int
mbraux_encode_mbr1k(struct silofs_mbraux *aux, struct silofs_mbr1k *mbr1k,
                    struct silofs_mbr1k *out_mbr1k)
{
	int err;

	mbr1k_stamp(mbr1k, &aux->md_hd);
	err = mbr1k_encrypt(mbr1k, &aux->ci_hd, &aux->meta->nmeta.civkey,
	                    out_mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_assign_hmac(out_mbr1k, &aux->hmac_hd,
	                        &aux->meta->hmac_key);
	if (err) {
		return err;
	}
	return 0;
}

static void
mbraux_calc_mbref(struct silofs_mbraux *aux, const struct silofs_mbr1k *mbr1k,
                  struct silofs_mbref *out_mbref)
{
	struct silofs_paddr paddr;
	const struct iovec iov = {
		.iov_base = silofs_unconst(mbr1k),
		.iov_len  = sizeof(*mbr1k),
	};

	calc_mbr_cas_paddr(&aux->md_hd, &iov, &paddr);
	silofs_mbref_derive(out_mbref, &aux->md_hd, &paddr);
}

static int mbraux_verify_mbref(struct silofs_mbraux *aux,
                               const struct silofs_mbref *mbref,
                               const struct silofs_mbr1k *mbr1k)
{
	struct silofs_mbref mbref2;

	mbraux_calc_mbref(aux, mbr1k, &mbref2);
	return silofs_mbref_isequal(mbref, &mbref2) ? 0 : -SILOFS_EBADMBR;
}

static int mbraux_decode_mbr1k(struct silofs_mbraux *aux,
                               const struct silofs_mbr1k *mbr1k,
                               struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = mbr1k_check_hmac(mbr1k, &aux->hmac_hd, &aux->meta->hmac_key);
	if (err) {
		return err;
	}
	err = mbr1k_decrypt(mbr1k, &aux->ci_hd, &aux->meta->nmeta.civkey,
	                    out_mbr1k);
	if (err) {
		return err;
	}
	err = mbr1k_verify(out_mbr1k, &aux->md_hd);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*
 * TODO-0061: Use ARGON2 KDF
 *
 * ARGON2 is considered stronger (GPU-resistant) then PBKDF2 (see [1]) but
 * requires extra wrapping over libgcrypt APIs. Use it.
 *
 * [1] https://fedoraproject.org/wiki/Changes/ \
 *       RemoveFipsModeSetup#Context_information_on_FIPS
 */
static const struct silofs_kdf_descs s_mbr_kdf_descs = {
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
};

static const struct silofs_kdf_desc s_mbr_hmac_kdf_desc = {
	.kd_iterations = 16384,
	.kd_algo       = SILOFS_KDF_SCRYPT,
	.kd_subalgo    = 8,
	.kd_salt_md    = SILOFS_MD_SHA3_256,
};

static int derive_mbr_civkey(const struct silofs_mdigest_hd *md_hd,
                             const struct silofs_password *pw,
                             struct silofs_civkey *out_civkey)
{
	return silofs_derive_civkey(md_hd, pw, &s_mbr_kdf_descs, out_civkey);
}

static int derive_mbr_hmac_ckey(const struct silofs_mdigest_hd *md_hd,
                                const struct silofs_password *pw,
                                struct silofs_ckey *out_key)
{
	return silofs_derive_hmac_key(md_hd, pw, &s_mbr_hmac_kdf_desc,
	                              out_key);
}

static int derive_mbr_meta(const struct silofs_password *passwd,
                           struct silofs_mbr_meta *out_mbr_meta)
{
	struct silofs_civkey civkey;
	struct silofs_mdigest_hd md_hd;
	int err;

	silofs_memzero(out_mbr_meta, sizeof(*out_mbr_meta));
	if ((passwd == nullptr) || (passwd->passlen == 0)) {
		return 0; /* OK -- password-less mode */
	}
	err = silofs_mdigest_init(&md_hd);
	if (err) {
		return err;
	}
	err = derive_mbr_hmac_ckey(&md_hd, passwd, &out_mbr_meta->hmac_key);
	if (err) {
		goto out;
	}
	err = derive_mbr_civkey(&md_hd, passwd, &civkey);
	if (err) {
		goto out;
	}
	silofs_nmeta_setup(&out_mbr_meta->nmeta, &civkey);
out:
	silofs_mdigest_fini(&md_hd);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
mbi_set_ref(struct silofs_mbr_info *mbi, const struct silofs_mbref *mbref)
{
	silofs_mbref_assign(&mbi->mb_ref, mbref);
}

static void mbi_reset_ref(struct silofs_mbr_info *mbi)
{
	silofs_mbref_reset(&mbi->mb_ref);
}

void silofs_mbi_init(struct silofs_mbr_info *mbi)
{
	const struct silofs_mbr_meta meta_none = {};

	mbr_meta_assign(&mbi->mb_meta, &meta_none);
	mbr1k_init(&mbi->mb_mbr1k);
	mbr1k_set_sw_version(&mbi->mb_mbr1k, &silofs_sw_vers);
	mbi_reset_ref(mbi);
}

void silofs_mbi_fini(struct silofs_mbr_info *mbi)
{
	mbi_reset_ref(mbi);
	mbr_meta_reset(&mbi->mb_meta);
	mbr1k_fini(&mbi->mb_mbr1k);
}

static void
mbi_set_meta(struct silofs_mbr_info *mbi, const struct silofs_mbr_meta *meta)
{
	mbr_meta_assign(&mbi->mb_meta, meta);
}

static void mbi_get_mbr1k(const struct silofs_mbr_info *mbi,
                          struct silofs_mbr1k *out_mbr1k)
{
	memcpy(out_mbr1k, &mbi->mb_mbr1k, sizeof(*out_mbr1k));
}

static int
mbi_export(const struct silofs_mbr_info *mbi, struct silofs_mbref *out_mbref,
           struct silofs_mbr1k *out_mbr1k_enc)
{
	struct silofs_mbr1k mbr1k;
	struct silofs_mbraux aux;
	int err;

	mbi_get_mbr1k(mbi, &mbr1k);
	err = mbraux_init(&aux, &mbi->mb_meta);
	return_if_err(err);

	err = mbraux_encode_mbr1k(&aux, &mbr1k, out_mbr1k_enc);
	goto_out_if_err(err);

	mbraux_calc_mbref(&aux, out_mbr1k_enc, out_mbref);
out:
	mbraux_fini(&aux);
	return err;
}

static void
mbi_assign_mbr1k(struct silofs_mbr_info *mbi, const struct silofs_mbr1k *mbr1k)
{
	memcpy(&mbi->mb_mbr1k, mbr1k, sizeof(mbi->mb_mbr1k));
}

static int
mbi_import(struct silofs_mbr_info *mbi, const struct silofs_mbref *mbref,
           const struct silofs_mbr1k *mbr1k_enc)
{
	struct silofs_mbr1k mbr1k;
	struct silofs_mbraux aux;
	int err;

	err = mbraux_init(&aux, &mbi->mb_meta);
	return_if_err(err);

	err = mbraux_verify_mbref(&aux, mbref, mbr1k_enc);
	goto_out_if_err(err);

	err = mbraux_decode_mbr1k(&aux, mbr1k_enc, &mbr1k);
	goto_out_if_err(err);

	mbi_assign_mbr1k(mbi, &mbr1k);
out:
	mbraux_fini(&aux);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int
stat_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref)
{
	struct stat st;
	int err;

	err = silofs_dstor_stat_mbr(dstor, mbref, &st);
	if (err) {
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	if (st.st_size != SILOFS_MBR_SIZE) {
		log_warn("bad mbr: size=%zd", st.st_size);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int
load_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref,
            struct silofs_mbr1k *out_mbr1k)
{
	size_t msz;
	int err;

	msz = sizeof(*out_mbr1k);
	err = silofs_dstor_load_mbr(dstor, mbref, out_mbr1k, msz);
	if (err) {
		log_dbg("failed to load mbr: msz=%zu err=%d", msz, err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int
save_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref,
            const struct silofs_mbr1k *mbr1k)
{
	size_t msz;
	int err;

	msz = sizeof(*mbr1k);
	err = silofs_dstor_save_mbr(dstor, mbref, mbr1k, msz);
	if (err) {
		log_dbg("failed to save mbr: msz=%zu err=%d", msz, err);
		return err;
	}
	return 0;
}

static int
unref_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_dstor_unref_mbr(dstor, mbref);
	if (err) {
		log_err("failed to unref mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_commit_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                      struct silofs_mbref *out_mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = mbi_export(mbi, out_mbref, &mbr1k);
	return_if_err(err);

	err = save_mbr_at(dstor, out_mbref, &mbr1k);
	return_if_err(err);

	mbi_set_ref(mbi, out_mbref);
	return 0;
}

int silofs_sense_mbr(struct silofs_dstor *dstor,
                     const struct silofs_mbref *mbref)
{
	return stat_mbr_at(dstor, mbref);
}

int silofs_reload_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                      const struct silofs_mbref *mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = stat_mbr_at(dstor, mbref);
	return_if_err(err);

	err = load_mbr_at(dstor, mbref, &mbr1k);
	return_if_err(err);

	err = mbi_import(mbi, mbref, &mbr1k);
	return_if_err(err);

	mbi_set_ref(mbi, mbref);
	return 0;
}

int silofs_unref_mbr(struct silofs_mbr_info *mbi, struct silofs_dstor *dstor,
                     const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_reload_mbr(mbi, dstor, mbref);
	return_if_err(err);

	err = unref_mbr_at(dstor, mbref);
	return_if_err(err);

	mbi_reset_ref(mbi);
	return 0;
}

int silofs_update_mbr(struct silofs_mbr_info *mbi,
                      const struct silofs_password *passwd)
{
	struct silofs_mbr_meta mbr_meta = {};
	int err;

	err = derive_mbr_meta(passwd, &mbr_meta);
	return_if_err(err);

	mbi_set_meta(mbi, &mbr_meta);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_get_fsroot(const struct silofs_mbr_info *mbi,
                      struct silofs_pnptr *out_pnptr,
                      struct silofs_sw_version *out_swv)
{
	mbr1k_root(&mbi->mb_mbr1k, out_pnptr);
	mbr1k_sw_version(&mbi->mb_mbr1k, out_swv);
	return pnptr_isuber(out_pnptr) ? 0 : -SILOFS_ENOENT;
}

void silofs_set_fsroot(struct silofs_mbr_info *mbi,
                       const struct silofs_pnptr *pnptr,
                       const struct silofs_sw_version *swv)
{
	mbr1k_set_root(&mbi->mb_mbr1k, pnptr);
	mbr1k_set_sw_version(&mbi->mb_mbr1k, swv);
}
