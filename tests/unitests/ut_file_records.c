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
#include "unitests.h"


struct ut_record {
	void    *data;
	size_t   size;
	uint8_t  seed[16];
	uint64_t hash;
	uint64_t index;
};

static size_t record_base_size(const struct ut_record *rec)
{
	return sizeof(rec->seed) + sizeof(rec->hash) + sizeof(rec->index);
}

static size_t record_size(const struct ut_record *rec, size_t size)
{
	return record_base_size(rec) + size;
}

static struct ut_record *record_new(struct ut_env *ute, size_t size)
{
	size_t rec_size;
	struct ut_record *rec = NULL;

	rec_size = record_size(rec, size);
	rec = (struct ut_record *)ut_zerobuf(ute, sizeof(*rec));
	rec->data = ut_randbuf(ute, rec_size);
	rec->size = size;

	return rec;
}

static void record_encode(const struct ut_record *rec)
{
	uint8_t *ptr = (uint8_t *)rec->data;

	ptr += rec->size;
	memcpy(ptr, rec->seed, sizeof(rec->seed));
	ptr += sizeof(rec->seed);
	memcpy(ptr, &rec->hash, sizeof(rec->hash));
	ptr += sizeof(rec->hash);
	memcpy(ptr, &rec->index, sizeof(rec->index));
}

static void record_decode(struct ut_record *rec)
{
	const uint8_t *ptr = (const uint8_t *)rec->data;

	ptr += rec->size;
	memcpy(rec->seed, ptr, sizeof(rec->seed));
	ptr += sizeof(rec->seed);
	memcpy(&rec->hash, ptr, sizeof(rec->hash));
	ptr += sizeof(rec->hash);
	memcpy(&rec->index, ptr, sizeof(rec->index));
}

static uint64_t ut_fnv1a(const void *buf, size_t len, uint64_t seed)
{
	return silofs_hash_fnv1a(buf, len, seed);
}

static uint64_t record_calchash(const struct ut_record *rec)
{
	return ut_fnv1a(rec->data, rec->size, 0);
}

static void record_sethash(struct ut_record *rec)
{
	rec->hash = record_calchash(rec);
}

static int record_checkhash(const struct ut_record *rec)
{
	const uint64_t hash = record_calchash(rec);

	return (rec->hash == hash) ? 0 : -1;
}

static void record_stamp(struct ut_record *rec, size_t index)
{
	rec->index = index;
	record_sethash(rec);
}

static void record_stamp_encode(struct ut_record *rec, size_t index)
{
	record_stamp(rec, index);
	record_encode(rec);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_write_record(struct ut_env *ute, ino_t ino,
                            const struct ut_record *rec, loff_t off)
{
	const size_t bsz = record_size(rec, rec->size);

	ut_write_read(ute, ino, rec->data, bsz, off);
}

static void ut_read_record(struct ut_env *ute, ino_t ino,
                           const struct ut_record *rec, loff_t off)
{
	const size_t bsz = record_size(rec, rec->size);

	ut_read_ok(ute, ino, rec->data, bsz, off);
}

static void ut_read_record_verify(struct ut_env *ute, ino_t ino,
                                  struct ut_record *rec, loff_t off)
{
	int err;

	ut_read_record(ute, ino, rec, off);
	record_decode(rec);
	err = record_checkhash(rec);
	ut_expect_ok(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t offset_of(const struct ut_record *rec, size_t index,
                        loff_t base_off)
{
	const size_t rec_size = record_size(rec, rec->size);

	return base_off + (loff_t)(index * rec_size);
}

static void ut_file_records_seq_(struct ut_env *ute,
                                 loff_t base, size_t size, size_t cnt)
{
	ino_t ino;
	loff_t off;
	struct ut_record *rec = NULL;
	const char *name = UT_NAME;
	const ino_t root_ino = UT_ROOT_INO;

	ut_create_file(ute, root_ino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		rec = record_new(ute, size);
		record_stamp_encode(rec, i);

		off = offset_of(rec, i, base);
		ut_write_record(ute, ino, rec, off);
	}
	for (size_t j = 0; j < cnt; ++j) {
		rec = record_new(ute, size);
		record_stamp_encode(rec, j);

		off = offset_of(rec, j, base);
		ut_read_record_verify(ute, ino, rec, off);
	}
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_records_seq(struct ut_env *ute)
{
	loff_t base;
	const loff_t base_offs[] = { 0, 111, 11111, 1111111, 111111111 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(base_offs); ++i) {
		base = base_offs[i];
		ut_file_records_seq_(ute, base, 111, 11);
		ut_file_records_seq_(ute, base, 1111, 111);
		ut_file_records_seq_(ute, base, 11111, 1111);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t resolve_offset(const struct ut_record *rec, long pos,
                             loff_t base)
{
	const size_t factor = 11;
	const size_t recsize = record_size(rec, rec->size);

	return base + pos * (loff_t)(factor * recsize);
}

static void ut_file_records_rand_(struct ut_env *ute,
                                  loff_t base, size_t size, size_t cnt)
{
	ino_t ino;
	loff_t off;
	const size_t niter = 2;
	const ino_t root_ino = UT_ROOT_INO;
	struct ut_record *rec;
	const char *name = UT_NAME;
	const long *pos = ut_randseq(ute, cnt, 0);

	ut_create_file(ute, root_ino, name, &ino);
	for (size_t n = 0; n < niter; ++n) {
		for (size_t i = 0; i < cnt; ++i) {
			rec = record_new(ute, size);
			record_stamp_encode(rec, i);

			off = resolve_offset(rec, pos[i], base);
			ut_write_record(ute, ino, rec, off);
		}
		for (size_t j = cnt; j > 0; --j) {
			rec = record_new(ute, size);
			record_stamp_encode(rec, j - 1);

			off = resolve_offset(rec, pos[j - 1], base);
			ut_read_record_verify(ute, ino, rec, off);
		}
	}
	ut_remove_file(ute, root_ino, name, ino);
}


static void ut_file_records_rand_aligned(struct ut_env *ute)
{
	const loff_t base[] = { 0, UT_BK_SIZE, UT_UMEGA, UT_UGIGA, UT_UTERA };

	for (size_t i = 0; i < UT_ARRAY_SIZE(base); ++i) {
		ut_file_records_rand_(ute, base[i], UT_BK_SIZE, 512);
		ut_file_records_rand_(ute, base[i], 8 * UT_BK_SIZE, 64);
		ut_file_records_rand_(ute, base[i], UT_UMEGA, 8);
	}
}

static void ut_file_records_rand_unaligned1(struct ut_env *ute)
{
	const loff_t base[] = { 1, 111, 11111, 1111111, 111111111 };

	for (size_t i = 0; i < UT_ARRAY_SIZE(base); ++i) {
		ut_file_records_rand_(ute, base[i], 111, 1111);
		ut_file_records_rand_(ute, base[i], 1111, 111);
		ut_file_records_rand_(ute, base[i], 11111, 11);
	}
}

static void ut_file_records_rand_unaligned2(struct ut_env *ute)
{
	const loff_t base[] = {
		UT_BK_SIZE - 2, UT_UMEGA - 2, UT_UGIGA - 2, UT_UTERA - 2
	};
	const size_t size_rec = record_base_size(NULL);
	const size_t size_max = UT_IOSIZE_MAX - size_rec;

	for (size_t i = 0; i < UT_ARRAY_SIZE(base); ++i) {
		ut_file_records_rand_(ute, base[i], UT_BK_SIZE + 4, 64);
		ut_file_records_rand_(ute, base[i], UT_UMEGA, 8);
		ut_file_records_rand_(ute, base[i], size_max, 4);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_records_seq),
	UT_DEFTEST(ut_file_records_rand_aligned),
	UT_DEFTEST(ut_file_records_rand_unaligned1),
	UT_DEFTEST(ut_file_records_rand_unaligned2),
};

const struct ut_testdefs ut_tdefs_file_records = UT_MKTESTS(ut_local_tests);
