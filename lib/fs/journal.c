/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#include <silofs/fs.h>
#include <silofs/fs-private.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t jrec_magic(const struct silofs_journal_rec *jrec)
{
	return silofs_le64_to_cpu(jrec->jr_magic);
}

static void jrec_set_magic(struct silofs_journal_rec *jrec, uint64_t magic)
{
	jrec->jr_magic = silofs_cpu_to_le64(magic);
}

static uint64_t jrec_uniq_id(const struct silofs_journal_rec *jrec)
{
	return silofs_le64_to_cpu(jrec->jr_uniq_id);
}

static void jrec_set_uniq_id(struct silofs_journal_rec *jrec, uint64_t uniq_id)
{
	jrec->jr_uniq_id = silofs_cpu_to_le64(uniq_id);
}

static size_t jrec_length(const struct silofs_journal_rec *jrec)
{
	return silofs_le32_to_cpu(jrec->jr_length);
}

static void jrec_set_length(struct silofs_journal_rec *jrec, size_t len)
{
	jrec->jr_length = silofs_cpu_to_le32((uint32_t)len);
}

static size_t jrec_tx_count(const struct silofs_journal_rec *jrec)
{
	return silofs_le32_to_cpu(jrec->jr_tx_count);
}

static void jrec_set_tx_count(struct silofs_journal_rec *jrec, size_t tx_count)
{
	jrec->jr_tx_count = silofs_cpu_to_le32((uint32_t)tx_count);
}

static size_t jrec_tx_index(const struct silofs_journal_rec *jrec)
{
	return silofs_le32_to_cpu(jrec->jr_tx_index);
}

static void jrec_set_tx_index(struct silofs_journal_rec *jrec, size_t tx_index)
{
	jrec->jr_tx_index = silofs_cpu_to_le32((uint32_t)tx_index);
}

static void jrec_src_tsegid(const struct silofs_journal_rec *jrec,
                            struct silofs_tsegid *out_tsegid)
{
	silofs_tsegid32b_xtoh(&jrec->jr_src_tsegid, out_tsegid);
}

static void jrec_set_src_tsegid(struct silofs_journal_rec *jrec,
                                const struct silofs_tsegid *tsegid)
{
	silofs_tsegid32b_htox(&jrec->jr_src_tsegid, tsegid);
}

static void jrec_dst_tsegid(const struct silofs_journal_rec *jrec,
                            struct silofs_tsegid *out_tsegid)
{
	silofs_tsegid32b_xtoh(&jrec->jr_dst_tsegid, out_tsegid);
}

static void jrec_set_dst_tsegid(struct silofs_journal_rec *jrec,
                                const struct silofs_tsegid *tsegid)
{
	silofs_tsegid32b_htox(&jrec->jr_dst_tsegid, tsegid);
}

static loff_t jrec_src_off(const struct silofs_journal_rec *jrec)
{
	return silofs_off_to_cpu(jrec->jr_src_off);
}

static void jrec_set_src_off(struct silofs_journal_rec *jrec, loff_t off)
{
	jrec->jr_src_off = silofs_cpu_to_off(off);
}

static loff_t jrec_dst_off(const struct silofs_journal_rec *jrec)
{
	return silofs_off_to_cpu(jrec->jr_dst_off);
}

static void jrec_set_dst_off(struct silofs_journal_rec *jrec, loff_t off)
{
	jrec->jr_dst_off = silofs_cpu_to_off(off);
}

static uint64_t jrec_csum(const struct silofs_journal_rec *jrec)
{
	return silofs_le64_to_cpu(jrec->jr_csum);
}

static void jrec_set_csum(struct silofs_journal_rec *jrec, uint64_t csum)
{
	jrec->jr_csum = silofs_cpu_to_le64(csum);
}

static void jrec_setup(struct silofs_journal_rec *jrec)
{
	const struct silofs_tsegid *tsegid_none = silofs_tsegid_none();

	memset(jrec, 0, sizeof(*jrec));
	jrec_set_magic(jrec, SILOFS_JOURNAL_MAGIC);
	jrec_set_uniq_id(jrec, 0);
	jrec_set_length(jrec, 0);
	jrec_set_tx_count(jrec, 0);
	jrec_set_tx_index(jrec, 0);
	jrec_set_src_tsegid(jrec, tsegid_none);
	jrec_set_src_off(jrec, SILOFS_OFF_NULL);
	jrec_set_dst_tsegid(jrec, tsegid_none);
	jrec_set_dst_off(jrec, SILOFS_OFF_NULL);
	jrec_set_csum(jrec, 0);
}

void silofs_jrec_by_sqe(struct silofs_journal_rec *jrec,
                        const struct silofs_submitq_ent *sqe)
{
	jrec_setup(jrec);
	jrec_set_uniq_id(jrec, sqe->uniq_id);
	jrec_set_length(jrec, sqe->len);
	jrec_set_tx_count(jrec, sqe->tx_count);
	jrec_set_tx_index(jrec, sqe->tx_index);
	jrec_set_dst_off(jrec, sqe->off);
	jrec_set_dst_tsegid(jrec, &sqe->tsegid);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t calc_checksum_of(const struct silofs_journal_rec *jrec)
{
	const size_t len = offsetof(struct silofs_journal_rec, jr_csum);

	return silofs_hash_xxh64(jrec, len, SILOFS_JOURNAL_MAGIC);
}

void silofs_seal_jrec(struct silofs_journal_rec *jrec)
{
	uint64_t csum;

	csum = calc_checksum_of(jrec);
	jrec_set_csum(jrec, csum);
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_jrec_csum(const struct silofs_journal_rec *jrec)
{
	const uint64_t csum_cur = jrec_csum(jrec);
	const uint64_t csum_exp = calc_checksum_of(jrec);
	int ret = 0;

	if (csum_cur != csum_exp) {
		log_err("corrupted journal-rec: " \
		        "csum_cur=%lx csum_exp=%lx", csum_cur, csum_exp);
		ret = -SILOFS_EFSBADCRC;
	}
	return ret;
}

static int verify_jrec_magic(const struct silofs_journal_rec *jrec)
{
	const uint64_t magic_cur = jrec_magic(jrec);
	const uint64_t magic_exp = SILOFS_JOURNAL_MAGIC;
	int ret = 0;

	if (magic_cur != magic_exp) {
		log_err("corrupted journal-rec: " \
		        "magic_cur=%lx magic_exp=%lx", magic_cur, magic_exp);
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static int verify_jrec_uniq_id(const struct silofs_journal_rec *jrec)
{
	const uint64_t uniq_id = jrec_uniq_id(jrec);
	int ret = 0;

	if (uniq_id == 0) {
		log_err("illegal journal-rec: uniq_id=%lu", uniq_id);
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static int verify_jrec_length(const struct silofs_journal_rec *jrec)
{
	const size_t len = jrec_length(jrec);
	const size_t len_max = 32 * SILOFS_UMEGA;
	int ret = 0;

	if (len || (len >= len_max)) {
		log_err("illegal journal-rec: len=%lu", len);
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static int verify_jrec_tx(const struct silofs_journal_rec *jrec)
{
	const size_t tx_count = jrec_tx_count(jrec);
	const size_t tx_index = jrec_tx_index(jrec);
	int ret = 0;

	if (!tx_count || !tx_index || (tx_index > tx_count)) {
		log_err("illegal journal-rec: tx_index=%lu tx_count=%lu",
		        tx_index, tx_count);
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static bool
tsegid_has_off_within(const struct silofs_tsegid *tsegid, loff_t off)
{
	const size_t bsz = tsegid->size;

	return !off_isnull(off) && (off < (loff_t)bsz);
}

static int verify_jrec_src(const struct silofs_journal_rec *jrec)
{
	struct silofs_tsegid src_tsegid;
	const loff_t src_off = jrec_src_off(jrec);
	int ret = 0;

	jrec_src_tsegid(jrec, &src_tsegid);
	if (tsegid_isnull(&src_tsegid) ||
	    !tsegid_has_off_within(&src_tsegid, src_off)) {
		log_err("illegal journal-rec: src_off=%ld", src_off);
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

static int verify_jrec_dst(const struct silofs_journal_rec *jrec)
{
	struct silofs_tsegid dst_tsegid;
	const loff_t dst_off = jrec_dst_off(jrec);
	int ret = 0;

	jrec_dst_tsegid(jrec, &dst_tsegid);
	if (tsegid_isnull(&dst_tsegid) ||
	    !tsegid_has_off_within(&dst_tsegid, dst_off)) {
		log_err("illegal journal-rec: dst_off=%ld", dst_off);
		ret = -SILOFS_EFSCORRUPTED;
	}
	return ret;
}

int silofs_verify_jrec(const struct silofs_journal_rec *jrec)
{
	int err;

	err = verify_jrec_csum(jrec);
	if (err) {
		return err;
	}
	err = verify_jrec_magic(jrec);
	if (err) {
		return err;
	}
	err = verify_jrec_uniq_id(jrec);
	if (err) {
		return err;
	}
	err = verify_jrec_length(jrec);
	if (err) {
		return err;
	}
	err = verify_jrec_tx(jrec);
	if (err) {
		return err;
	}
	err = verify_jrec_src(jrec);
	if (err) {
		return err;
	}
	err = verify_jrec_dst(jrec);
	if (err) {
		return err;
	}
	return 0;
}

