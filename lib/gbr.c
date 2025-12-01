/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include <silofs/ondisk.h>
#include "infra.h"
#include "crypt.h"
#include "bstore.h"
#include "gbr.h"
#include "vfs.h"
#include "env.h"

static uint64_t gbr1k_magic(const struct silofs_gbr1k *gbr1k)
{
	return silofs_le64_to_cpu(gbr1k->gbr_magic);
}

static void gbr1k_set_magic(struct silofs_gbr1k *gbr1k, uint64_t magic)
{
	gbr1k->gbr_magic = silofs_cpu_to_le64(magic);
}

static uint64_t gbr1k_version(const struct silofs_gbr1k *gbr1k)
{
	return silofs_le64_to_cpu(gbr1k->gbr_version);
}

static void gbr1k_set_version(struct silofs_gbr1k *gbr1k, uint64_t version)
{
	gbr1k->gbr_version = silofs_cpu_to_le64(version);
}

static uint32_t gbr1k_flags(const struct silofs_gbr1k *gbr1k)
{
	return silofs_le32_to_cpu(gbr1k->gbr_flags);
}

static void gbr1k_set_flags(struct silofs_gbr1k *gbr1k, uint32_t flags)
{
	gbr1k->gbr_flags = silofs_cpu_to_le32(flags);
}

static enum silofs_gbr_kind gbr1k_kind(const struct silofs_gbr1k *gbr1k)
{
	const uint32_t gbr_kind = silofs_le32_to_cpu(gbr1k->gbr_kind);

	return (enum silofs_gbr_kind)gbr_kind;
}

static void
gbr1k_set_kind(struct silofs_gbr1k *gbr1k, enum silofs_gbr_kind gbr_kind)
{
	gbr1k->gbr_kind = silofs_cpu_to_le32((uint32_t)gbr_kind);
}

static void
gbr1k_root(const struct silofs_gbr1k *gbr1k, struct silofs_pmeta *out_pmeta)
{
	silofs_pmeta192b_xtoh(&gbr1k->gbr_root, out_pmeta);
}

static void
gbr1k_set_root(struct silofs_gbr1k *gbr1k, const struct silofs_pmeta *pmeta)
{
	silofs_pmeta192b_htox(&gbr1k->gbr_root, pmeta);
}

static void gbr1k_reset_root(struct silofs_gbr1k *gbr1k)
{
	gbr1k_set_root(gbr1k, silofs_pmeta_none());
}

static void gbr1k_sb_addr(const struct silofs_gbr1k *gbr1k,
                          struct silofs_uaddr *out_sb_addr)
{
	silofs_uaddr128b_xtoh(&gbr1k->gbr_sb_addr, out_sb_addr);
}

static void gbr1k_set_sb_addr(struct silofs_gbr1k *gbr1k,
                              const struct silofs_uaddr *sb_addr)
{
	silofs_uaddr128b_htox(&gbr1k->gbr_sb_addr, sb_addr);
}

static void gbr1k_setup(struct silofs_gbr1k *gbr1k)
{
	silofs_memzero(gbr1k, sizeof(*gbr1k));
	gbr1k_set_magic(gbr1k, SILOFS_MBR_MAGIC);
	gbr1k_set_version(gbr1k, SILOFS_FMT_REVISION);
	gbr1k_reset_root(gbr1k);
}

static int gbr1k_check_base(const struct silofs_gbr1k *gbr1k)
{
	const uint64_t magic = gbr1k_magic(gbr1k);
	const uint64_t version = gbr1k_version(gbr1k);

	/* When both magic and version are no valid, we are likely to assume it
	 * is due to bad password provided by user. */
	if ((magic != SILOFS_MBR_MAGIC) && (version != SILOFS_FMT_REVISION)) {
		return -SILOFS_EKEYEXPIRED;
	}
	if (magic != SILOFS_MBR_MAGIC) {
		log_dbg("bad gbr magic: 0x%lx", magic);
		return -SILOFS_EBADMBR;
	}
	if (version != SILOFS_FMT_REVISION) {
		log_dbg("bad gbr version: %lu", version);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int gbr1k_check_uaddr_sb(const struct silofs_gbr1k *gbr1k)
{
	struct silofs_uaddr uaddr;
	enum silofs_height height;
	enum silofs_mtype mtype;

	gbr1k_sb_addr(gbr1k, &uaddr);
	if (silofs_uaddr_isnull(&uaddr)) {
		return 0;
	}
	height = silofs_uaddr_height(&uaddr);
	mtype = silofs_uaddr_mtype(&uaddr);
	if ((mtype != SILOFS_MTYPE_SUPER) || (height != SILOFS_HEIGHT_SUPER) ||
	    (uaddr.voff != 0)) {
		log_dbg("bad gbr uaddr-sb: voff=%ld mtype=%d height=%d",
		        uaddr.voff, (int)mtype, (int)height);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static void
gbr1k_uuid(const struct silofs_gbr1k *gbr1k, struct silofs_uuid *out_uuid)
{
	silofs_uuid_assign(out_uuid, &gbr1k->gbr_uuid);
}

static void
gbr1k_set_uuid(struct silofs_gbr1k *gbr1k, const struct silofs_uuid *uuid)
{
	silofs_uuid_assign(&gbr1k->gbr_uuid, uuid);
}

static int gbr1k_check(const struct silofs_gbr1k *gbr1k)
{
	struct silofs_pmeta pmeta;
	int err;

	err = gbr1k_check_base(gbr1k);
	if (err) {
		return err;
	}
	err = gbr1k_check_uaddr_sb(gbr1k);
	if (err) {
		return err;
	}
	gbr1k_root(gbr1k, &pmeta);
	err = silofs_ciargs_check(&pmeta.cmeta.ciargs);
	if (err) {
		return err;
	}
	return 0;
}

static void
gbr1k_hash(const struct silofs_gbr1k *gbr1k, struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(&gbr1k->gbr_hash, hash);
}

static void
gbr1k_set_hash(struct silofs_gbr1k *gbr1k, const struct silofs_hash256 *hash)
{
	silofs_hash256_copyto(hash, &gbr1k->gbr_hash);
}

static void gbr1k_calc_hash(const struct silofs_gbr1k *gbr1k,
                            const struct silofs_mdigest *md,
                            struct silofs_hash256 *out_hash)
{
	const size_t len = offsetof(struct silofs_gbr1k, gbr_hash);

	silofs_sha3_256_of(md, gbr1k, len, out_hash);
}

static void
gbr1k_stamp(struct silofs_gbr1k *gbr1k, const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash;

	gbr1k_calc_hash(gbr1k, md, &hash);
	gbr1k_set_hash(gbr1k, &hash);
}

static int gbr1k_check_hash(const struct silofs_gbr1k *gbr1k,
                            const struct silofs_mdigest *md)
{
	struct silofs_hash256 hash[2];

	gbr1k_hash(gbr1k, &hash[0]);
	gbr1k_calc_hash(gbr1k, md, &hash[1]);

	return silofs_hash256_isequal(&hash[0], &hash[1]) ? 0 : -SILOFS_ECSUM;
}

static int
gbr1k_verify(const struct silofs_gbr1k *gbr1k, const struct silofs_mdigest *md)
{
	int err;

	err = gbr1k_check(gbr1k);
	if (err) {
		return err;
	}
	err = gbr1k_check_hash(gbr1k, md);
	if (err) {
		return err;
	}
	return 0;
}

static void
gbr1k_xtoh(const struct silofs_gbr1k *gbr1k, struct silofs_gbr *gbr)
{
	gbr1k_uuid(gbr1k, &gbr->uuid);
	gbr1k_sb_addr(gbr1k, &gbr->sb_addr);
	gbr1k_root(gbr1k, &gbr->root);
	gbr->kind = gbr1k_kind(gbr1k);
	gbr->flags = gbr1k_flags(gbr1k);
}

static void
gbr1k_htox(struct silofs_gbr1k *gbr1k, const struct silofs_gbr *gbr)
{
	gbr1k_setup(gbr1k);
	gbr1k_set_sb_addr(gbr1k, &gbr->sb_addr);
	gbr1k_set_root(gbr1k, &gbr->root);
	gbr1k_set_kind(gbr1k, gbr->kind);
	gbr1k_set_flags(gbr1k, gbr->flags);
	gbr1k_set_uuid(gbr1k, &gbr->uuid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void gbr_gen_uuid(struct silofs_gbr *gbr)
{
	silofs_uuid_generate(&gbr->uuid);
}

static bool
gbr_has_sb_addr(const struct silofs_gbr *gbr, const struct silofs_uaddr *uaddr)
{
	return silofs_uaddr_isequal(&gbr->sb_addr, uaddr);
}

static void
gbr_set_sb_addr(struct silofs_gbr *gbr, const struct silofs_uaddr *uaddr)
{
	silofs_uaddr_assign(&gbr->sb_addr, uaddr);
}

int silofs_gbr_root(const struct silofs_gbr *gbr,
                    struct silofs_pmeta *out_pmeta)
{
	silofs_pmeta_assign(out_pmeta, &gbr->root);
	return silofs_pmeta_isnull(out_pmeta) ? -SILOFS_ENOENT : 0;
}

void silofs_gbr_set_root(struct silofs_gbr *gbr,
                         const struct silofs_pmeta *pmeta)
{
	silofs_pmeta_assign(&gbr->root, pmeta);
}

void silofs_gbr_set_rootc(struct silofs_gbr *gbr,
                          const struct silofs_cmeta *cmeta)
{
	silofs_cmeta_assign(&gbr->root.cmeta, cmeta);
}

void silofs_gbr_set_rootc_by(struct silofs_gbr *gbr,
                             const struct silofs_gbr *other)
{
	silofs_gbr_set_rootc(gbr, &other->root.cmeta);
}

void silofs_gbr_init(struct silofs_gbr *gbr, enum silofs_gbr_kind kind)
{
	silofs_memzero(gbr, sizeof(*gbr));
	silofs_pmeta_reset(&gbr->root);
	silofs_uaddr_reset(&gbr->sb_addr);
	gbr_gen_uuid(gbr);
	gbr->kind = kind;
	gbr->flags = 0;
}

void silofs_gbr_fini(struct silofs_gbr *gbr)
{
	silofs_uaddr_reset(&gbr->sb_addr);
	silofs_pmeta_reset(&gbr->root);
	gbr->kind = SILOFS_GBR_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int encrypt_gbr1k(const struct silofs_cipher *ci,
                         const struct silofs_civkey *civkey,
                         const struct silofs_gbr1k *gbr1k_in,
                         struct silofs_gbr1k *gbr1k_out)
{
	return silofs_encrypt_buf(ci, civkey, gbr1k_in, gbr1k_out,
	                          sizeof(*gbr1k_out));
}

static int decrypt_gbr1k(const struct silofs_cipher *ci,
                         const struct silofs_civkey *civkey,
                         const struct silofs_gbr1k *gbr1k_in,
                         struct silofs_gbr1k *gbr1k_out)
{
	return silofs_decrypt_buf(ci, civkey, gbr1k_in, gbr1k_out,
	                          sizeof(*gbr1k_out));
}

static int
gbr_encode(const struct silofs_gbr *gbr, const struct silofs_mdigest *mdigest,
           const struct silofs_cipher *cipher,
           const struct silofs_civkey *civkey, struct silofs_gbr1k *out_gbr1k)
{
	struct silofs_gbr1k gbr1k;

	gbr1k_htox(&gbr1k, gbr);
	gbr1k_stamp(&gbr1k, mdigest);
	return encrypt_gbr1k(cipher, civkey, &gbr1k, out_gbr1k);
}

static int gbr_decode(struct silofs_gbr *gbr, //
                      const struct silofs_mdigest *mdigest,
                      const struct silofs_cipher *cipher,
                      const struct silofs_civkey *civkey,
                      const struct silofs_gbr1k *enc_gbr1k)
{
	struct silofs_gbr1k gbr1k = { .gbr_magic = 1 };
	int err;

	err = decrypt_gbr1k(cipher, civkey, enc_gbr1k, &gbr1k);
	if (err) {
		return err;
	}
	err = gbr1k_verify(&gbr1k, mdigest);
	if (err) {
		return err;
	}
	gbr1k_xtoh(&gbr1k, gbr);
	return 0;
}

void silofs_gbr_update_sb(struct silofs_gbr *gbr,
                          const struct silofs_uaddr *sb_uaddr)
{
	if (!gbr_has_sb_addr(gbr, sb_uaddr)) {
		gbr_set_sb_addr(gbr, sb_uaddr);
		gbr_gen_uuid(gbr);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* auxiliary controller for GBR operations */
struct silofs_gbraux {
	struct silofs_mdigest mdigest;
	struct silofs_cipher cipher;
	struct silofs_cmeta cmeta;
};

static int
gbraux_init(struct silofs_gbraux *aux, const struct silofs_cmeta *cmeta)
{
	int err;

	err = silofs_mdigest_init(&aux->mdigest);
	if (err) {
		return err;
	}
	err = silofs_cipher_init(&aux->cipher);
	if (err) {
		silofs_mdigest_fini(&aux->mdigest);
		return err;
	}
	silofs_cmeta_assign(&aux->cmeta, cmeta);
	return 0;
}

static void gbraux_fini(struct silofs_gbraux *aux)
{
	silofs_cmeta_reset(&aux->cmeta);
	silofs_cipher_fini(&aux->cipher);
	silofs_mdigest_fini(&aux->mdigest);
}

static int
gbraux_encode_gbr(struct silofs_gbraux *aux, const struct silofs_gbr *gbr,
                  struct silofs_gbr1k *out_gbr1k)
{
	return gbr_encode(gbr, &aux->mdigest, &aux->cipher, &aux->cmeta.civkey,
	                  out_gbr1k);
}

static void gbraux_calc_paddr_of(struct silofs_gbraux *aux,
                                 const struct silofs_gbr1k *gbr1k,
                                 struct silofs_paddr *out_paddr)
{
	const struct iovec iov = {
		.iov_base = silofs_unconst(gbr1k),
		.iov_len = sizeof(*gbr1k),
	};

	silofs_calc_cas_paddr(&aux->mdigest, SILOFS_MTYPE_GBR, &iov, 1,
	                      out_paddr);
}

int silofs_gbr_encode_by(const struct silofs_gbr *gbr,
                         const struct silofs_cmeta *cmeta,
                         struct silofs_paddr *out_paddr,
                         struct silofs_gbr1k *out_gbr1k)
{
	struct silofs_gbraux aux;
	int err;

	err = gbraux_init(&aux, cmeta);
	if (err) {
		return err;
	}
	err = gbraux_encode_gbr(&aux, gbr, out_gbr1k);
	if (err) {
		goto out;
	}
	gbraux_calc_paddr_of(&aux, out_gbr1k, out_paddr);
out:
	gbraux_fini(&aux);
	return err;
}

static int gbraux_verify_paddr(struct silofs_gbraux *aux,
                               const struct silofs_paddr *paddr,
                               const struct silofs_gbr1k *gbr1k)
{
	struct silofs_paddr calc_paddr;

	gbraux_calc_paddr_of(aux, gbr1k, &calc_paddr);
	return silofs_paddr_isequal(paddr, &calc_paddr) ? 0 : -SILOFS_EBADMBR;
}

static int gbraux_decode_gbr(struct silofs_gbraux *aux, struct silofs_gbr *gbr,
                             const struct silofs_gbr1k *gbr1k)
{
	return gbr_decode(gbr, &aux->mdigest, &aux->cipher, &aux->cmeta.civkey,
	                  gbr1k);
}

int silofs_gbr_decode_by(struct silofs_gbr *gbr,
                         const struct silofs_cmeta *cmeta,
                         const struct silofs_paddr *paddr,
                         const struct silofs_gbr1k *gbr1k)
{
	struct silofs_gbraux aux;
	int err;

	err = gbraux_init(&aux, cmeta);
	if (err) {
		return err;
	}
	err = gbraux_verify_paddr(&aux, paddr, gbr1k);
	if (err) {
		goto out;
	}
	err = gbraux_decode_gbr(&aux, gbr, gbr1k);
out:
	gbraux_fini(&aux);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_derive_gbr_cmeta(const struct silofs_password *passwd,
                            struct silofs_cmeta *out_cmeta)
{
	struct silofs_civkey civkey;
	struct silofs_mdigest mdigest;
	int err;

	silofs_cmeta_reset(out_cmeta);
	if ((passwd == nullptr) || (passwd->passlen == 0)) {
		return 0;
	}
	err = silofs_mdigest_init(&mdigest);
	if (err) {
		return err;
	}
	err = silofs_derive_default_civkey(&mdigest, passwd, &civkey);
	if (err) {
		goto out;
	}
	silofs_cmeta_setup(out_cmeta, &civkey);
out:
	silofs_mdigest_fini(&mdigest);
	return err;
}
