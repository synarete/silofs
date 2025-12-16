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
#include <silofs/configs.h>
#include <stdint.h>
#include "infra.h"
#include "addr.h"
#include "bstore.h"
#include "fs.h"
#include "index.h"

static void
ard_init(struct silofs_ar_desc *ard, const struct silofs_paddr *paddr,
         const struct silofs_laddr *laddr, size_t len)
{
	silofs_paddr_assign(&ard->paddr, paddr);
	silofs_laddr_assign(&ard->laddr, laddr);
	ard->len = len;
}

static void ard_reset(struct silofs_ar_desc *ard)
{
	silofs_paddr_reset(&ard->paddr);
	silofs_laddr_reset(&ard->laddr);
	ard->len = SIZE_MAX;
}

static void ard256b_htox(struct silofs_ar_desc256b   *ard256,
                         const struct silofs_ar_desc *ard)
{
	silofs_memzero(ard256, sizeof(*ard256));
	silofs_paddr64b_htox(&ard256->ard_paddr, &ard->paddr);
	silofs_laddr96b_htox(&ard256->ard_laddr, &ard->laddr);
	ard256->ard_len = silofs_cpu_to_le64(ard->len);
}

static void ard256b_xtoh(const struct silofs_ar_desc256b *ard256,
                         struct silofs_ar_desc           *ard)
{
	silofs_paddr64b_xtoh(&ard256->ard_paddr, &ard->paddr);
	silofs_laddr96b_xtoh(&ard256->ard_laddr, &ard->laddr);
	ard->len = silofs_le64_to_cpu(ard256->ard_len);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void arn_setup_hdr(struct silofs_arix_node *arn)
{
	silofs_hdr_setup(&arn->arn_hdr, SILOFS_MTYPE_ARIX);
}

static void arn_seal_hdr(struct silofs_arix_node *arn)
{
	silofs_hdr_seal(&arn->arn_hdr);
}

static int arn_verify_hdr(const struct silofs_arix_node *arn)
{
	return silofs_hdr_verify(&arn->arn_hdr, SILOFS_MTYPE_ARIX);
}

static void
arn_set_btime(struct silofs_arix_node *arn, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &arn->arn_btime);
}

static void arn_reset_btime(struct silofs_arix_node *arn)
{
	const struct timespec ts = { 0, 0 };

	arn_set_btime(arn, &ts);
}

static void arn_set_flags(struct silofs_arix_node *arn, uint32_t flags)
{
	arn->arn_flags = silofs_cpu_to_le32(flags);
}

static size_t arn_ndescs(const struct silofs_arix_node *arn)
{
	return silofs_le32_to_cpu(arn->arn_ndescs);
}

static void arn_set_ndescs(struct silofs_arix_node *arn, size_t n)
{
	silofs_assert_le(n, ARRAY_SIZE(arn->arn_descs));

	arn->arn_ndescs = silofs_cpu_to_le32((uint32_t)n);
}

static void arn_inc_ndescs(struct silofs_arix_node *arn)
{
	arn_set_ndescs(arn, 1 + arn_ndescs(arn));
}

static bool arn_has_room(const struct silofs_arix_node *arn)
{
	return (arn_ndescs(arn) < ARRAY_SIZE(arn->arn_descs));
}

static void
arn_next(const struct silofs_arix_node *arn, struct silofs_pmeta *out_pmeta)
{
	silofs_pmeta192b_xtoh(&arn->arn_next, out_pmeta);
}

static void
arn_set_next(struct silofs_arix_node *arn, const struct silofs_pmeta *pmeta)
{
	silofs_pmeta192b_htox(&arn->arn_next, pmeta);
}

static void arn_reset_next(struct silofs_arix_node *arn)
{
	arn_set_next(arn, silofs_pmeta_none());
}

static void arn_desc(const struct silofs_arix_node *arn, size_t slot,
                     struct silofs_ar_desc *out_ard)
{
	silofs_assert_lt(slot, ARRAY_SIZE(arn->arn_descs));

	ard256b_xtoh(&arn->arn_descs[slot], out_ard);
}

static void arn_set_desc(struct silofs_arix_node *arn, size_t slot,
                         const struct silofs_ar_desc *ard)
{
	silofs_assert_lt(slot, ARRAY_SIZE(arn->arn_descs));

	ard256b_htox(&arn->arn_descs[slot], ard);
}

static void
arn_append_desc(struct silofs_arix_node *arn, const struct silofs_ar_desc *ard)
{
	arn_set_desc(arn, arn_ndescs(arn), ard);
	arn_inc_ndescs(arn);
}

static void arn_reset_descs(struct silofs_arix_node *arn)
{
	struct silofs_ar_desc ard_none;

	ard_reset(&ard_none);
	for (size_t slot = 0; slot < ARRAY_SIZE(arn->arn_descs); ++slot) {
		arn_set_desc(arn, slot, &ard_none);
	}
}

static void arn_init(struct silofs_arix_node *arn)
{
	arn_setup_hdr(arn);
	arn_reset_btime(arn);
	arn_set_flags(arn, 0);
	arn_set_ndescs(arn, 0);
	arn_reset_next(arn);
	arn_reset_descs(arn);
}

static void arn_fini(struct silofs_arix_node *arn)
{
	arn_reset_btime(arn);
	arn_reset_next(arn);
	arn_reset_descs(arn);
}

static struct silofs_arix_node *arn_malloc(struct silofs_alloc *alloc)
{
	struct silofs_arix_node *arn;

	arn = silofs_memalloc(alloc, sizeof(*arn), SILOFS_ALLOCF_BZERO);
	return arn;
}

static void arn_free(struct silofs_arix_node *arn, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, arn, sizeof(*arn), SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_arix_node *arn_new(struct silofs_alloc *alloc)
{
	struct silofs_arix_node *arn;

	arn = arn_malloc(alloc);
	if (arn != nullptr) {
		arn_init(arn);
	}
	return arn;
}

static void arn_del(struct silofs_arix_node *arn, struct silofs_alloc *alloc)
{
	if (arn != nullptr) {
		arn_fini(arn);
		arn_free(arn, alloc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_arnode_info *ari_malloc(struct silofs_alloc *alloc)
{
	struct silofs_arnode_info *ari = nullptr;

	ari = silofs_memalloc(alloc, sizeof(*ari), 0);
	return ari;
}

static void
ari_free(struct silofs_arnode_info *ari, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ari, sizeof(*ari), 0);
}

static void
ari_init(struct silofs_arnode_info *ari, const struct silofs_pmeta *pmeta)
{
	silofs_pmeta_assign(&ari->arn_pmeta, pmeta);
	ari->arn = nullptr;
}

static void ari_fini(struct silofs_arnode_info *ari)
{
	silofs_pmeta_reset(&ari->arn_pmeta);
	ari->arn = nullptr;
}

struct silofs_arnode_info *
silofs_ari_new(struct silofs_alloc *alloc, const struct silofs_pmeta *pmeta)
{
	struct silofs_arix_node   *arn = nullptr;
	struct silofs_arnode_info *ari = nullptr;

	arn = arn_new(alloc);
	if (arn == nullptr) {
		return nullptr;
	}
	ari = ari_malloc(alloc);
	if (ari == nullptr) {
		arn_del(arn, alloc);
		return nullptr;
	}
	ari_init(ari, pmeta);
	ari->arn = arn;
	return ari;
}

void silofs_ari_del(struct silofs_arnode_info *ari, struct silofs_alloc *alloc)
{
	arn_del(ari->arn, alloc);
	ari_fini(ari);
	ari_free(ari, alloc);
}

size_t silofs_ari_ndescs(const struct silofs_arnode_info *ari)
{
	return arn_ndescs(ari->arn);
}

bool silofs_ari_isfull(const struct silofs_arnode_info *ari)
{
	return !arn_has_room(ari->arn);
}

void silofs_ari_set_btime(struct silofs_arnode_info *ari,
                          const struct timespec     *ts)
{
	arn_set_btime(ari->arn, ts);
}

void silofs_ari_get_paddr(const struct silofs_arnode_info *ari,
                          struct silofs_paddr             *out_paddr)
{
	silofs_paddr_assign(out_paddr, &ari->arn_pmeta.paddr);
}

void silofs_ari_set_paddr(struct silofs_arnode_info *ari,
                          const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&ari->arn_pmeta.paddr, paddr);
}

static void
ari_set_next(struct silofs_arnode_info *ari, const struct silofs_pmeta *pmeta)
{
	if (pmeta != nullptr) {
		arn_set_next(ari->arn, pmeta);
	} else {
		arn_reset_next(ari->arn);
	}
}

void silofs_ari_set_next(struct silofs_arnode_info *ari,
                         const struct silofs_pmeta *pmeta)
{
	ari_set_next(ari, pmeta);
}

void silofs_ari_get_next(const struct silofs_arnode_info *ari,
                         struct silofs_pmeta             *out_pmeta)
{
	arn_next(ari->arn, out_pmeta);
}

int silofs_ari_append_desc(struct silofs_arnode_info   *ari,
                           const struct silofs_ar_desc *ard)
{
	if (!arn_has_room(ari->arn)) {
		return -SILOFS_ENOSPC;
	}
	arn_append_desc(ari->arn, ard);
	return 0;
}

int silofs_ari_fetch_desc(const struct silofs_arnode_info *ari, size_t slot,
                          struct silofs_ar_desc *out_ard)
{
	const size_t ndescs = arn_ndescs(ari->arn);

	if (slot >= ndescs) {
		return -SILOFS_ENOENT;
	}
	arn_desc(ari->arn, slot, out_ard);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ari_pre_encrypt(const struct silofs_arnode_info *ari,
                            struct silofs_arix_node         *arn)
{
	memcpy(arn, ari->arn, sizeof(*arn));
	arn_seal_hdr(arn);
}

static int encrypt_arix_node(const struct silofs_ar_cargs *ar_cargs,
                             struct silofs_arix_node      *arn)
{
	return silofs_encrypt_buf(ar_cargs->cipher, &ar_cargs->nmeta.civkey,
	                          arn, arn, sizeof(*arn));
}

int silofs_export_arix_node(const struct silofs_arnode_info *ari,
                            const struct silofs_ar_cargs    *ar_cargs,
                            struct silofs_arix_node         *arn_enc)
{
	ari_pre_encrypt(ari, arn_enc);
	return encrypt_arix_node(ar_cargs, arn_enc);
}

int silofs_save_arix_node(struct silofs_vbs             *vbs,
                          const struct silofs_paddr     *paddr,
                          const struct silofs_arix_node *arn_enc)
{
	const struct silofs_rovec rov = {
		.rov_base = arn_enc,
		.rov_len  = sizeof(*arn_enc),
	};
	int err;

	err = silofs_vbs_require_blob(vbs, &paddr->blobid);
	if (err) {
		log_err("failed to spawn archive-index: err=%d", err);
		return err;
	}
	err = silofs_vbs_write_blob(vbs, paddr, &rov);
	if (err) {
		log_err("failed to save archive-index: err=%d", err);
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_load_arix_node(struct silofs_vbs         *vbs,
                          const struct silofs_paddr *paddr,
                          struct silofs_arix_node   *arn_enc)
{
	struct silofs_rwvec rwv = {
		.rwv_base = arn_enc,
		.rwv_len  = sizeof(*arn_enc),
	};

	return silofs_vbs_read_blob(vbs, paddr, &rwv);
}

static int decrypt_arix_node(const struct silofs_ar_cargs *ar_cargs,
                             struct silofs_arix_node      *arn)
{
	return silofs_decrypt_buf(ar_cargs->cipher, &ar_cargs->nmeta.civkey,
	                          arn, arn, sizeof(*arn));
}

static int ari_post_decrypt(struct silofs_arnode_info     *ari,
                            const struct silofs_arix_node *arn)
{
	int err;

	/* TODO: verify all */
	err = arn_verify_hdr(arn);
	if (err) {
		return err;
	}
	memcpy(ari->arn, arn, sizeof(*arn));
	return 0;
}

int silofs_import_arix_node(struct silofs_arnode_info    *ari,
                            const struct silofs_ar_cargs *ar_cargs,
                            struct silofs_arix_node      *arn_enc)
{
	int err;

	err = decrypt_arix_node(ar_cargs, arn_enc);
	if (err) {
		return err;
	}
	err = ari_post_decrypt(ari, arn_enc);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_calc_ar_desc(const struct silofs_mdigest *mdigest,
                         const struct silofs_laddr   *laddr,
                         const struct silofs_rovec   *rovec,
                         struct silofs_ar_desc       *out_ard)
{
	struct silofs_paddr paddr = {
		.pos = -1,
	};
	const struct iovec iov = {
		.iov_base = unconst(rovec->rov_base),
		.iov_len  = rovec->rov_len,
	};
	enum silofs_mtype mtype;

	mtype = silofs_blobid_get_mtype(&laddr->lsid.blobid);
	silofs_calc_cas_paddr(mdigest, mtype, &iov, 1, &paddr);

	ard_init(out_ard, &paddr, laddr, iov.iov_len);
}

void silofs_calc_arix_paddr(const struct silofs_arix_node *arn_enc,
                            const struct silofs_mdigest   *mdigest,
                            struct silofs_paddr           *out_paddr)
{
	const struct iovec iov = {
		.iov_base = unconst(arn_enc),
		.iov_len  = sizeof(*arn_enc),
	};

	silofs_calc_cas_paddr(mdigest, SILOFS_MTYPE_ARIX, &iov, 1, out_paddr);
}

int silofs_verify_arix_paddr(const struct silofs_arix_node *arn_enc,
                             const struct silofs_mdigest   *mdigest,
                             const struct silofs_paddr     *paddr)
{
	struct silofs_paddr paddr2;

	silofs_calc_arix_paddr(arn_enc, mdigest, &paddr2);
	return silofs_paddr_isequal(paddr, &paddr2) ? 0 : -SILOFS_EBADARIX;
}
