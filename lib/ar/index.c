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

static void ard256b_htox(struct silofs_ar_desc256b *ard256,
                         const struct silofs_ar_desc *ard)
{
	silofs_memzero(ard256, sizeof(*ard256));
	silofs_paddr64b_htox(&ard256->ard_paddr, &ard->paddr);
	silofs_laddr96b_htox(&ard256->ard_laddr, &ard->laddr);
	ard256->ard_len = silofs_cpu_to_le64(ard->len);
}

static void ard256b_xtoh(const struct silofs_ar_desc256b *ard256,
                         struct silofs_ar_desc *ard)
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
arn_next(const struct silofs_arix_node *arn, struct silofs_paddr *out_paddr)
{
	silofs_paddr64b_xtoh(&arn->arn_next, out_paddr);
}

static void
arn_set_next(struct silofs_arix_node *arn, const struct silofs_paddr *paddr)
{
	silofs_paddr64b_htox(&arn->arn_next, paddr);
}

static void arn_reset_next(struct silofs_arix_node *arn)
{
	arn_set_next(arn, silofs_paddr_none());
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
	struct silofs_arnode_info *abi = nullptr;

	abi = silofs_memalloc(alloc, sizeof(*abi), 0);
	return abi;
}

static void
abi_free(struct silofs_arnode_info *abi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, abi, sizeof(*abi), 0);
}

static void
ari_init(struct silofs_arnode_info *abi, const struct silofs_arn_base *base)
{
	memcpy(&abi->arn_base, base, sizeof(abi->arn_base));
	silofs_paddr_reset(&abi->arn_paddr);
	abi->arn = nullptr;
	abi->arn_enc = nullptr;
}

static void abi_fini(struct silofs_arnode_info *abi)
{
	silofs_paddr_reset(&abi->arn_paddr);
	abi->arn = nullptr;
	abi->arn_enc = nullptr;
}

struct silofs_arnode_info *
silofs_ari_new(struct silofs_alloc *alloc, const struct silofs_arn_base *base)
{
	struct silofs_arix_node *arn = nullptr;
	struct silofs_arix_node *arn_enc = nullptr;
	struct silofs_arnode_info *ari = nullptr;

	arn = arn_new(alloc);
	if (arn == nullptr) {
		goto out_err;
	}
	arn_enc = arn_new(alloc);
	if (arn_enc == nullptr) {
		goto out_err;
	}
	ari = ari_malloc(alloc);
	if (ari == nullptr) {
		goto out_err;
	}
	ari_init(ari, base);
	ari->arn = arn;
	ari->arn_enc = arn_enc;
	return ari;
out_err:
	arn_del(arn, alloc);
	arn_del(arn_enc, alloc);
	return nullptr;
}

void silofs_ari_del(struct silofs_arnode_info *ari, struct silofs_alloc *alloc)
{
	arn_del(ari->arn, alloc);
	arn_del(ari->arn_enc, alloc);
	abi_fini(ari);
	abi_free(ari, alloc);
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
                          const struct timespec *ts)
{
	arn_set_btime(ari->arn, ts);
}

void silofs_ari_get_paddr(const struct silofs_arnode_info *ari,
                          struct silofs_paddr *out_paddr)
{
	silofs_paddr_assign(out_paddr, &ari->arn_paddr);
}

void silofs_ari_set_paddr(struct silofs_arnode_info *ari,
                          const struct silofs_paddr *paddr)
{
	silofs_paddr_assign(&ari->arn_paddr, paddr);
}

static void
ari_set_next(struct silofs_arnode_info *ari, const struct silofs_paddr *paddr)
{
	if (paddr != nullptr) {
		arn_set_next(ari->arn, paddr);
	} else {
		arn_reset_next(ari->arn);
	}
}

void silofs_ari_set_next(struct silofs_arnode_info *ari,
                         const struct silofs_arnode_info *abi_next)
{
	if (abi_next != nullptr) {
		ari_set_next(ari, &abi_next->arn_paddr);
	} else {
		ari_set_next(ari, nullptr);
	}
}

void silofs_ari_get_next(const struct silofs_arnode_info *ari,
                         struct silofs_paddr *out_paddr)
{
	arn_next(ari->arn, out_paddr);
}

void silofs_ari_calc_desc(const struct silofs_arnode_info *ari,
                          const struct silofs_laddr *laddr,
                          const struct silofs_rovec *rovec,
                          struct silofs_ar_desc *out_ard)
{
	const struct silofs_mdigest *md = ari->arn_base.mdigest;
	struct silofs_paddr paddr = {
		.pos = -1,
	};
	const struct iovec iov = {
		.iov_base = unconst(rovec->rov_base),
		.iov_len = rovec->rov_len,
	};
	enum silofs_mtype mtype;

	mtype = silofs_blobid_get_mtype(&laddr->lsid.blobid);
	silofs_calc_cas_paddr(md, mtype, &iov, 1, &paddr);

	ard_init(out_ard, &paddr, laddr, iov.iov_len);
}

int silofs_ari_append_desc(struct silofs_arnode_info *ari,
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

static void ari_calc_paddr(const struct silofs_arnode_info *ari,
                           const struct silofs_mdigest *mdigest,
                           struct silofs_paddr *out_paddr)
{
	const struct iovec iov = {
		.iov_base = ari->arn_enc,
		.iov_len = sizeof(*ari->arn_enc),
	};

	silofs_calc_cas_paddr(mdigest, SILOFS_MTYPE_ARIX, &iov, 1, out_paddr);
}

static void ari_update_paddr(struct silofs_arnode_info *ari,
                             const struct silofs_mdigest *mdigest)
{
	struct silofs_paddr paddr;

	ari_calc_paddr(ari, mdigest, &paddr);
	silofs_ari_set_paddr(ari, &paddr);
}

static bool ari_has_paddr(const struct silofs_arnode_info *ari,
                          const struct silofs_paddr *paddr)
{
	return silofs_paddr_isequal(&ari->arn_paddr, paddr);
}

static int ari_verify_paddr(const struct silofs_arnode_info *ari,
                            const struct silofs_mdigest *mdigest)
{
	struct silofs_paddr paddr;

	ari_calc_paddr(ari, mdigest, &paddr);
	return ari_has_paddr(ari, &paddr) ? 0 : -SILOFS_EBADARIX;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ari_pre_encrypt(struct silofs_arnode_info *ari)
{
	arn_seal_hdr(ari->arn);
}

static int ari_encrypt(struct silofs_arnode_info *ari,
                       const struct silofs_ar_cargs *ar_cargs)
{
	struct silofs_arix_node *arn_enc = ari->arn_enc;

	return silofs_encrypt_buf(ar_cargs->cipher, &ar_cargs->nmeta.civkey,
	                          ari->arn, arn_enc, sizeof(*arn_enc));
}

int silofs_export_arix_node(struct silofs_arnode_info *ari,
                            const struct silofs_ar_cargs *ar_cargs)
{
	int err;

	ari_pre_encrypt(ari);
	err = ari_encrypt(ari, ar_cargs);
	if (err) {
		return err;
	}
	ari_update_paddr(ari, ar_cargs->mdigest);
	return 0;
}

int silofs_save_arix_node(struct silofs_arnode_info *ari,
                          struct silofs_filos *filos)
{
	const struct silofs_arix_node *arn_enc = ari->arn_enc;
	const struct silofs_rovec rov = {
		.rov_base = arn_enc,
		.rov_len = sizeof(*arn_enc),
	};
	int err;

	err = silofs_filos_spawn_blob(filos, &ari->arn_paddr.blobid);
	if (err) {
		log_err("failed to spawn archive-index: err=%d", err);
		return err;
	}
	err = silofs_filos_write_blob(filos, &ari->arn_paddr, &rov);
	if (err) {
		log_err("failed to save archive-index: err=%d", err);
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_load_arix_node(const struct silofs_arnode_info *ari,
                          struct silofs_filos *filos)
{
	struct silofs_arix_node *arn_enc = ari->arn_enc;
	struct silofs_rwvec rwv = {
		.rwv_base = arn_enc,
		.rwv_len = sizeof(*arn_enc),
	};

	return silofs_filos_read_blob(filos, &ari->arn_paddr, &rwv);
}

static int ari_decrypt(struct silofs_arnode_info *ari,
                       const struct silofs_ar_cargs *ar_cargs)
{
	const struct silofs_arix_node *arn_enc = ari->arn_enc;

	return silofs_decrypt_buf(ar_cargs->cipher, &ar_cargs->nmeta.civkey,
	                          arn_enc, ari->arn, sizeof(*ari->arn));
}

static int ari_post_decrypt(struct silofs_arnode_info *ari)
{
	/* TODO: verify all */
	return arn_verify_hdr(ari->arn);
}

int silofs_import_arix_node(struct silofs_arnode_info *ari,
                            const struct silofs_ar_cargs *ar_cargs)
{
	int err;

	err = ari_verify_paddr(ari, ar_cargs->mdigest);
	if (err) {
		return err;
	}
	err = ari_decrypt(ari, ar_cargs);
	if (err) {
		return err;
	}
	err = ari_post_decrypt(ari);
	if (err) {
		return err;
	}
	return 0;
}
