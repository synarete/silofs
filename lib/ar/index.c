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
#include "fs.h"
#include "bs.h"
#include "index.h"

static void
ard_init2(struct silofs_ar_desc *ard, const struct silofs_baddr *baddr,
          const struct silofs_laddr *laddr, size_t len)
{
	silofs_baddr_assign(&ard->baddr, baddr);
	silofs_laddr_assign(&ard->laddr, laddr);
	ard->len = len;
}

void silofs_ard_init(struct silofs_ar_desc *ard,
                     const struct silofs_laddr *laddr, size_t len)
{
	ard_init2(ard, silofs_baddr_none(), laddr, len);
}

void silofs_ard_reset(struct silofs_ar_desc *ard)
{
	silofs_baddr_reset(&ard->baddr);
	silofs_laddr_reset(&ard->laddr);
	ard->len = SIZE_MAX;
}

void silofs_ard_fini(struct silofs_ar_desc *ard)
{
	silofs_ard_reset(ard);
	ard->len = 0;
}

static enum silofs_mtype ard_mtype(const struct silofs_ar_desc *ard)
{
	return ard->laddr.lsid.mtype;
}

void silofs_ard_update_baddr(struct silofs_ar_desc *ard,
                             const struct silofs_mdigest *md,
                             const struct silofs_rovec *rov)
{
	const struct iovec iov = {
		.iov_base = unconst(rov->rov_base),
		.iov_len = rov->rov_len,
	};

	silofs_calc_baddr_of(md, ard_mtype(ard), &iov, 1, &ard->baddr);
}

void silofs_ard256b_htox(struct silofs_ar_desc256b *ard256,
                         const struct silofs_ar_desc *ard)
{
	silofs_memzero(ard256, sizeof(*ard256));
	silofs_baddr64b_htox(&ard256->ad_baddr, &ard->baddr);
	silofs_laddr64b_htox(&ard256->ad_laddr, &ard->laddr);
	ard256->ad_len = silofs_cpu_to_le64(ard->len);
}

void silofs_ard256b_xtoh(const struct silofs_ar_desc256b *ard256,
                         struct silofs_ar_desc *ard)
{
	silofs_baddr64b_xtoh(&ard256->ad_baddr, &ard->baddr);
	silofs_laddr64b_xtoh(&ard256->ad_laddr, &ard->laddr);
	ard->len = silofs_le64_to_cpu(ard256->ad_len);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ab_setup_hdr(struct silofs_arix_block *ab)
{
	silofs_hdr_setup(&ab->ab_hdr, SILOFS_MTYPE_ARIX, sizeof(*ab));
}

static void ab_seal_hdr(struct silofs_arix_block *ab)
{
	silofs_hdr_seal(&ab->ab_hdr);
}

static int ab_verify_hdr(const struct silofs_arix_block *ab)
{
	return silofs_hdr_verify2(&ab->ab_hdr, SILOFS_MTYPE_ARIX);
}

static void
ab_set_btime(struct silofs_arix_block *ab, const struct timespec *ts)
{
	silofs_cpu_to_ts(ts, &ab->ab_btime);
}

static void ab_reset_btime(struct silofs_arix_block *ab)
{
	const struct timespec ts = { 0, 0 };

	ab_set_btime(ab, &ts);
}

static void ab_set_flags(struct silofs_arix_block *ab, uint32_t flags)
{
	ab->ab_flags = silofs_cpu_to_le32(flags);
}

static size_t ab_ndescs(const struct silofs_arix_block *ab)
{
	return silofs_le32_to_cpu(ab->ab_ndescs);
}

static void ab_set_ndescs(struct silofs_arix_block *ab, size_t n)
{
	silofs_assert_le(n, ARRAY_SIZE(ab->ab_descs));

	ab->ab_ndescs = silofs_cpu_to_le32((uint32_t)n);
}

static void ab_inc_ndescs(struct silofs_arix_block *ab)
{
	ab_set_ndescs(ab, 1 + ab_ndescs(ab));
}

static bool ab_has_room(const struct silofs_arix_block *ab)
{
	return (ab_ndescs(ab) < ARRAY_SIZE(ab->ab_descs));
}

static void
ab_next(const struct silofs_arix_block *ab, struct silofs_baddr *out_baddr)
{
	silofs_baddr64b_xtoh(&ab->ab_next, out_baddr);
}

static void
ab_set_next(struct silofs_arix_block *ab, const struct silofs_baddr *baddr)
{
	silofs_baddr64b_htox(&ab->ab_next, baddr);
}

static void ab_reset_next(struct silofs_arix_block *ab)
{
	ab_set_next(ab, silofs_baddr_none());
}

static void ab_desc(const struct silofs_arix_block *ab, size_t slot,
                    struct silofs_ar_desc *out_ard)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ab->ab_descs));

	silofs_ard256b_xtoh(&ab->ab_descs[slot], out_ard);
}

static void ab_set_desc(struct silofs_arix_block *ab, size_t slot,
                        const struct silofs_ar_desc *ard)
{
	silofs_assert_lt(slot, ARRAY_SIZE(ab->ab_descs));

	silofs_ard256b_htox(&ab->ab_descs[slot], ard);
}

static void
ab_append_desc(struct silofs_arix_block *ab, const struct silofs_ar_desc *ard)
{
	ab_set_desc(ab, ab_ndescs(ab), ard);
	ab_inc_ndescs(ab);
}

static void ab_reset_descs(struct silofs_arix_block *ab)
{
	struct silofs_ar_desc ard_none;

	silofs_ard_reset(&ard_none);
	for (size_t slot = 0; slot < ARRAY_SIZE(ab->ab_descs); ++slot) {
		ab_set_desc(ab, slot, &ard_none);
	}
}

static void ab_init(struct silofs_arix_block *ab)
{
	ab_setup_hdr(ab);
	ab_reset_btime(ab);
	ab_set_flags(ab, 0);
	ab_set_ndescs(ab, 0);
	ab_reset_next(ab);
	ab_reset_descs(ab);
}

static void ab_fini(struct silofs_arix_block *ab)
{
	ab_reset_btime(ab);
	ab_reset_next(ab);
	ab_reset_descs(ab);
}

static struct silofs_arix_block *ab_malloc(struct silofs_alloc *alloc)
{
	struct silofs_arix_block *ab;

	ab = silofs_memalloc(alloc, sizeof(*ab), SILOFS_ALLOCF_BZERO);
	return ab;
}

static void ab_free(struct silofs_arix_block *ab, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, ab, sizeof(*ab), SILOFS_ALLOCF_TRYPUNCH);
}

static struct silofs_arix_block *ab_new(struct silofs_alloc *alloc)
{
	struct silofs_arix_block *ab;

	ab = ab_malloc(alloc);
	if (ab != nullptr) {
		ab_init(ab);
	}
	return ab;
}

static void ab_del(struct silofs_arix_block *ab, struct silofs_alloc *alloc)
{
	if (ab != nullptr) {
		ab_fini(ab);
		ab_free(ab, alloc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ab_info *abi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ab_info *abi = nullptr;

	abi = silofs_memalloc(alloc, sizeof(*abi), 0);
	return abi;
}

static void abi_free(struct silofs_ab_info *abi, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, abi, sizeof(*abi), 0);
}

static void
abi_init(struct silofs_ab_info *abi, const struct silofs_ab_meta *meta)
{
	memcpy(&abi->ab_meta, meta, sizeof(abi->ab_meta));
	silofs_baddr_reset(&abi->ab_baddr);
	abi->ab = nullptr;
	abi->ab_enc = nullptr;
}

static void abi_fini(struct silofs_ab_info *abi)
{
	silofs_baddr_reset(&abi->ab_baddr);
	abi->ab = nullptr;
	abi->ab_enc = nullptr;
}

struct silofs_ab_info *
silofs_abi_new(struct silofs_alloc *alloc, const struct silofs_ab_meta *meta)
{
	struct silofs_arix_block *ab = nullptr;
	struct silofs_arix_block *ab_enc = nullptr;
	struct silofs_ab_info *abi = nullptr;

	ab = ab_new(alloc);
	if (ab == nullptr) {
		goto out_err;
	}
	ab_enc = ab_new(alloc);
	if (ab_enc == nullptr) {
		goto out_err;
	}
	abi = abi_malloc(alloc);
	if (abi == nullptr) {
		goto out_err;
	}
	abi_init(abi, meta);
	abi->ab = ab;
	abi->ab_enc = ab_enc;
	return abi;
out_err:
	ab_del(ab, alloc);
	ab_del(ab_enc, alloc);
	return nullptr;
}

void silofs_abi_del(struct silofs_ab_info *abi, struct silofs_alloc *alloc)
{
	ab_del(abi->ab, alloc);
	ab_del(abi->ab_enc, alloc);
	abi_fini(abi);
	abi_free(abi, alloc);
}

size_t silofs_abi_ndescs(const struct silofs_ab_info *abi)
{
	return ab_ndescs(abi->ab);
}

bool silofs_abi_isfull(const struct silofs_ab_info *abi)
{
	return !ab_has_room(abi->ab);
}

void silofs_abi_set_btime(struct silofs_ab_info *abi,
                          const struct timespec *ts)
{
	ab_set_btime(abi->ab, ts);
}

void silofs_abi_get_baddr(const struct silofs_ab_info *abi,
                          struct silofs_baddr *out_baddr)
{
	silofs_baddr_assign(out_baddr, &abi->ab_baddr);
}

void silofs_abi_set_baddr(struct silofs_ab_info *abi,
                          const struct silofs_baddr *baddr)
{
	silofs_assert(!silofs_baddr_isnull(baddr));
	silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_ARIX);

	silofs_baddr_assign(&abi->ab_baddr, baddr);
}

static void
abi_set_next(struct silofs_ab_info *abi, const struct silofs_baddr *baddr)
{
	if (baddr != nullptr) {
		silofs_assert(!silofs_baddr_isnull(baddr));
		silofs_assert_eq(baddr->mtype, SILOFS_MTYPE_ARIX);

		ab_set_next(abi->ab, baddr);
	} else {
		ab_reset_next(abi->ab);
	}
}

void silofs_abi_chain(struct silofs_ab_info *abi,
                      const struct silofs_ab_info *abi_next)
{
	if (abi_next != nullptr) {
		abi_set_next(abi, &abi_next->ab_baddr);
	} else {
		abi_set_next(abi, nullptr);
	}
}

void silofs_abi_next_chain(const struct silofs_ab_info *abi,
                           struct silofs_baddr *out_baddr)
{
	ab_next(abi->ab, out_baddr);
}

void silofs_abi_calc_desc(const struct silofs_ab_info *abi,
                          const struct silofs_laddr *laddr,
                          const struct silofs_rovec *rovec,
                          struct silofs_ar_desc *out_ard)
{
	const struct silofs_mdigest *md = abi->ab_meta.mdigest;
	struct silofs_baddr baddr = {
		.pos = -1,
	};
	const struct iovec iov = {
		.iov_base = unconst(rovec->rov_base),
		.iov_len = rovec->rov_len,
	};
	silofs_calc_baddr_of(md, laddr->lsid.mtype, &iov, 1, &baddr);

	ard_init2(out_ard, &baddr, laddr, iov.iov_len);
}

int silofs_abi_append_desc(struct silofs_ab_info *abi,
                           const struct silofs_ar_desc *ard)
{
	if (!ab_has_room(abi->ab)) {
		return -SILOFS_ENOSPC;
	}
	ab_append_desc(abi->ab, ard);
	return 0;
}

int silofs_abi_fetch_desc(const struct silofs_ab_info *abi, size_t slot,
                          struct silofs_ar_desc *out_ard)
{
	const size_t ndescs = ab_ndescs(abi->ab);

	if (slot >= ndescs) {
		return -SILOFS_ENOENT;
	}
	ab_desc(abi->ab, slot, out_ard);
	return 0;
}

static void abi_calc_baddr(const struct silofs_ab_info *abi,
                           struct silofs_baddr *out_baddr)
{
	const struct silofs_mdigest *md = abi->ab_meta.mdigest;
	const struct iovec iov = {
		.iov_base = abi->ab_enc,
		.iov_len = sizeof(*abi->ab_enc),
	};

	silofs_calc_baddr_of(md, SILOFS_MTYPE_ARIX, &iov, 1, out_baddr);
}

static void abi_update_baddr(struct silofs_ab_info *abi)
{
	struct silofs_baddr baddr;

	abi_calc_baddr(abi, &baddr);
	silofs_abi_set_baddr(abi, &baddr);
}

static bool abi_has_baddr(const struct silofs_ab_info *abi,
                          const struct silofs_baddr *baddr)
{
	return silofs_baddr_isequal(&abi->ab_baddr, baddr);
}

static int abi_verify_baddr(const struct silofs_ab_info *abi)
{
	struct silofs_baddr baddr;

	abi_calc_baddr(abi, &baddr);
	return abi_has_baddr(abi, &baddr) ? 0 : -SILOFS_EBADARIX;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void abi_pre_encrypt(struct silofs_ab_info *abi)
{
	ab_seal_hdr(abi->ab);
}

static int
abi_encrypt(struct silofs_ab_info *abi, const struct silofs_ivkey *ivkey)
{
	const struct silofs_arix_block *ab = abi->ab;
	struct silofs_arix_block *ab_enc = abi->ab_enc;
	const struct silofs_cipher *ci = abi->ab_meta.enc_cipher;

	return silofs_encrypt_buf(ci, ivkey, ab, ab_enc, sizeof(*ab_enc));
}

static int
abi_seal(struct silofs_ab_info *abi, const struct silofs_ivkey *ivkey)
{
	int err;

	abi_pre_encrypt(abi);
	err = abi_encrypt(abi, ivkey);
	if (err) {
		return err;
	}
	abi_update_baddr(abi);
	return 0;
}

static int abi_save(const struct silofs_ab_info *abi)
{
	const struct silofs_arix_block *ab_enc = abi->ab_enc;
	const struct silofs_rovec rov = {
		.rov_base = ab_enc,
		.rov_len = sizeof(*ab_enc),
	};

	return silofs_repo_save_cobj(abi->ab_meta.repo, &abi->ab_baddr, &rov);
}

int silofs_store_arix_block(struct silofs_ab_info *abi,
                            const struct silofs_ivkey *ivkey)
{
	int err;

	err = abi_seal(abi, ivkey);
	if (err) {
		return err;
	}
	err = abi_save(abi);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int abi_load(const struct silofs_ab_info *abi)
{
	struct silofs_arix_block *ab_enc = abi->ab_enc;
	struct silofs_rwvec rwv = {
		.rwv_base = ab_enc,
		.rwv_len = sizeof(*ab_enc),
	};

	return silofs_repo_load_cobj(abi->ab_meta.repo, &abi->ab_baddr, &rwv);
}

static int
abi_decrypt(struct silofs_ab_info *abi, const struct silofs_ivkey *ivkey)
{
	struct silofs_arix_block *ab = abi->ab;
	const struct silofs_arix_block *ab_enc = abi->ab_enc;
	const struct silofs_cipher *ci = abi->ab_meta.dec_cipher;

	return silofs_decrypt_buf(ci, ivkey, ab_enc, ab, sizeof(*ab));
}

static int abi_post_decrypt(struct silofs_ab_info *abi)
{
	/* TODO: verify all */
	return ab_verify_hdr(abi->ab);
}

static int
abi_unseal(struct silofs_ab_info *abi, const struct silofs_ivkey *ivkey)
{
	int err;

	err = abi_verify_baddr(abi);
	if (err) {
		return err;
	}
	err = abi_decrypt(abi, ivkey);
	if (err) {
		return err;
	}
	err = abi_post_decrypt(abi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_fetch_arix_block(struct silofs_ab_info *abi,
                            const struct silofs_ivkey *ivkey)
{
	int err;

	err = abi_load(abi);
	if (err) {
		return err;
	}
	err = abi_unseal(abi, ivkey);
	if (err) {
		return err;
	}
	return 0;
}
