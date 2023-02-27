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


static void ut_file_simple1_(struct ut_env *ute, loff_t off)
{
	ino_t ino = 0;
	ino_t rootd_ino = SILOFS_INO_ROOT;
	struct statvfs stv[2];
	const char *name = UT_NAME;
	uint8_t z = 0;

	ut_statfs_ok(ute, rootd_ino, &stv[0]);
	ut_create_file(ute, rootd_ino, name, &ino);
	ut_write_read(ute, ino, &z, 1, off);
	ut_remove_file(ute, rootd_ino, name, ino);
	ut_statfs_ok(ute, rootd_ino, &stv[1]);
	ut_expect_statvfs(&stv[0], &stv[1]);
}

static void ut_file_simple2_(struct ut_env *ute, loff_t off)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	const size_t bsz = UT_MEGA / 4;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_release_flush_ok(ute, ino);
	ut_unlink_file(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_simple3_(struct ut_env *ute, loff_t off)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	const size_t bsz = UT_MEGA;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_fsync_ok(ute, ino, true);
	ut_release_file(ute, ino);
	ut_drop_caches_fully(ute);
	ut_open_rdonly(ute, ino);
	ut_read_verify(ute, ino, buf, bsz, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_simple_(struct ut_env *ute, loff_t off)
{
	ut_file_simple1_(ute, off);
	ut_file_simple2_(ute, off);
	ut_file_simple3_(ute, off);
}

static void ut_file_simple(struct ut_env *ute)
{
	ut_file_simple_(ute, 0);
	ut_file_simple_(ute, 1);
	ut_file_simple_(ute, UT_4K);
	ut_file_simple_(ute, UT_4K - 1);
	ut_file_simple_(ute, 3 * UT_4K);
	ut_file_simple_(ute, 3 * UT_4K - 3);
	ut_file_simple_(ute, UT_8K);
	ut_file_simple_(ute, UT_8K - 1);
	ut_file_simple_(ute, 2 * UT_8K - 1);
	ut_file_simple_(ute, UT_BK_SIZE);
	ut_file_simple_(ute, UT_BK_SIZE - 1);
	ut_file_simple_(ute, UT_BK_SIZE + 1);
	ut_file_simple_(ute, UT_MEGA);
	ut_file_simple_(ute, UT_MEGA - 1);
	ut_file_simple_(ute, UT_MEGA + 1);
	ut_file_simple_(ute, UT_MEGA);
	ut_file_simple_(ute, 11 * UT_MEGA - 11);
	ut_file_simple_(ute, 11 * UT_MEGA + 11);
	ut_file_simple_(ute, UT_GIGA);
	ut_file_simple_(ute, UT_GIGA - 3);
	ut_file_simple_(ute, 11 * UT_GIGA - 11);
	ut_file_simple_(ute, UT_TERA);
	ut_file_simple_(ute, UT_TERA - 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_minio_(struct ut_env *ute, loff_t off)
{
	ino_t ino = 0;
	ino_t dino = 0;
	uint8_t bytes[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, bytes, 8, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_minio_aligned(struct ut_env *ute)
{
	ut_file_minio_(ute, 0);
	ut_file_minio_(ute, UT_4K);
	ut_file_minio_(ute, UT_8K);
	ut_file_minio_(ute, UT_BK_SIZE);
	ut_file_minio_(ute, UT_MEGA);
	ut_file_minio_(ute, UT_GIGA);
	ut_file_minio_(ute, UT_TERA);
}

static void ut_file_minio_unaligned(struct ut_env *ute)
{
	ut_file_minio_(ute, UT_4K - 1);
	ut_file_minio_(ute, UT_8K - 1);
	ut_file_minio_(ute, UT_BK_SIZE - 1);
	ut_file_minio_(ute, UT_MEGA - 2);
	ut_file_minio_(ute, UT_GIGA - 3);
	ut_file_minio_(ute, UT_TERA - 4);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_data_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_data(struct ut_env *ute)
{
	ut_file_data_(ute, 0, UT_4K);
	ut_file_data_(ute, 0, UT_8K);
	ut_file_data_(ute, 0, 2 * UT_8K);
	ut_file_data_(ute, 3, 3 * UT_8K + 3);
	ut_file_data_(ute, 0, UT_BK_SIZE);
	ut_file_data_(ute, 0, UT_UMEGA);
	ut_file_data_(ute, UT_MEGA, UT_BK_SIZE);
	ut_file_data_(ute, UT_MEGA, UT_UMEGA);

	ut_file_data_(ute, UT_MEGA - 3, 3 * UT_BK_SIZE + 7);
	ut_file_data_(ute, (11 * UT_MEGA) - 11, UT_UMEGA + UT_BK_SIZE + 1);
	ut_file_data_(ute, 111 * UT_GIGA, UT_UMEGA);
	ut_file_data_(ute, (111 * UT_GIGA) - 11, UT_UMEGA + 111);
}

static void ut_file_iosize_max(struct ut_env *ute)
{
	ut_file_data_(ute, 0, UT_IOSIZE_MAX);
	ut_file_data_(ute, 1, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_MEGA, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_MEGA - 1, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_GIGA, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_GIGA - 1, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_TERA, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_TERA - 1, UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_FILESIZE_MAX - UT_IOSIZE_MAX - 1,
	              UT_IOSIZE_MAX);
	ut_file_data_(ute, UT_FILESIZE_MAX - UT_IOSIZE_MAX, UT_IOSIZE_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_unlinked_(struct ut_env *ute, loff_t off, size_t bsz)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	void *buf = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_unlink_file(ute, dino, name);
	ut_write_read(ute, ino, buf, bsz, off);
	ut_release_file(ute, ino);
	ut_lookup_noent(ute, dino, name);
	ut_getattr_noent(ute, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_unlinked(struct ut_env *ute)
{
	ut_file_unlinked_(ute, 0, UT_MEGA / 8);
	ut_file_unlinked_(ute, 1, UT_MEGA / 8);
	ut_file_unlinked_(ute, UT_MEGA, 8 * UT_KILO);
	ut_file_unlinked_(ute, UT_MEGA - 1, UT_KILO);
	ut_file_unlinked_(ute, UT_GIGA, UT_MEGA);
	ut_file_unlinked_(ute, UT_GIGA - 1, UT_MEGA + 2);
	ut_file_unlinked_(ute, UT_TERA, UT_MEGA);
	ut_file_unlinked_(ute, UT_TERA - 1, UT_MEGA + 2);
	ut_file_unlinked_(ute, UT_FILESIZE_MAX - UT_MEGA - 1, UT_KILO);
	ut_file_unlinked_(ute, UT_FILESIZE_MAX - UT_MEGA, UT_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_multi_(struct ut_env *ute, size_t bsz,
                           loff_t off1, loff_t off2, loff_t off3, loff_t off4)
{
	ino_t ino = 0;
	ino_t dino = 0;
	const char *name = UT_NAME;
	void *buf1 = ut_randbuf(ute, bsz);
	void *buf2 = ut_randbuf(ute, bsz);
	void *buf3 = ut_randbuf(ute, bsz);
	void *buf4 = ut_randbuf(ute, bsz);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_write_read(ute, ino, buf1, bsz, off1);
	ut_write_read(ute, ino, buf2, bsz, off2);
	ut_write_read(ute, ino, buf3, bsz, off3);
	ut_write_read(ute, ino, buf4, bsz, off4);
	ut_fsync_ok(ute, ino, false);

	ut_read_verify(ute, ino, buf1, bsz, off1);
	ut_read_verify(ute, ino, buf2, bsz, off2);
	ut_read_verify(ute, ino, buf3, bsz, off3);
	ut_read_verify(ute, ino, buf4, bsz, off4);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_multi(struct ut_env *ute)
{
	ut_file_multi_(ute, UT_BK_SIZE, 0, UT_BK_SIZE, UT_MEGA, UT_GIGA);
	ut_file_multi_(ute, UT_BK_SIZE,
	               UT_BK_SIZE, UT_MEGA, UT_GIGA, UT_TERA);
	ut_file_multi_(ute, UT_BK_SIZE,
	               UT_MEGA, UT_BK_SIZE, UT_TERA, UT_GIGA);
}

static void ut_file_tricky(struct ut_env *ute)
{
	const size_t bsz = UT_BK_SIZE;
	const loff_t nch = (loff_t)UT_FILEMAP_NCHILDS;
	const loff_t off1 = (loff_t)(UT_BK_SIZE * UT_FILEMAP_NCHILDS);
	const loff_t off2 = off1 * nch;
	const loff_t off3 = (loff_t)UT_FILESIZE_MAX / 2;
	const loff_t off4 = (loff_t)UT_FILESIZE_MAX - (loff_t)bsz;

	ut_file_multi_(ute, bsz, off1, 2 * off1, 4 * off1, 8 * off1);
	ut_file_multi_(ute, bsz, off1, off2, off3, off4);
	ut_file_multi_(ute, bsz, off1 - 1, off2 - 2, off3 - 3, off4 - 4);
	ut_file_multi_(ute, bsz, off4 - 1, off1 - 2, off3 - 3, off2 - 4);
	ut_file_multi_(ute, bsz, off4 - 1, off2 - 2, off1 - 3, off3 - 4);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_overwrite_simple_(struct ut_env *ute,
                                      loff_t off, size_t bsz)
{
	ino_t ino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *name = UT_NAME;
	void *buf1 = ut_randbuf(ute, bsz);
	void *buf2 = ut_randbuf(ute, bsz);

	ut_create_file(ute, root_ino, name, &ino);
	ut_write_read(ute, ino, buf1, bsz, off);
	ut_write_read(ute, ino, buf2, bsz, off);
	ut_read_verify(ute, ino, buf2, bsz, off);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_overwrite_simple(struct ut_env *ute)
{
	ut_file_overwrite_simple_(ute, 0, UT_BK_SIZE);
	ut_file_overwrite_simple_(ute, 0, UT_UMEGA);
	ut_file_overwrite_simple_(ute, 1, UT_BK_SIZE);
	ut_file_overwrite_simple_(ute, 2, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_BK_SIZE, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_BK_SIZE + 1, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_BK_SIZE - 1, UT_UMEGA + 3);
	ut_file_overwrite_simple_(ute, UT_MEGA, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_MEGA + 1, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_MEGA - 1, UT_UMEGA + 3);
	ut_file_overwrite_simple_(ute, UT_GIGA, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_GIGA - 1, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_GIGA + 1, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_TERA, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_TERA - 1, UT_UMEGA);
	ut_file_overwrite_simple_(ute, UT_TERA + 1, UT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_overwrite_complex_(struct ut_env *ute,
                                       loff_t off1, loff_t off2, size_t bsz)
{
	ino_t ino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *name = UT_NAME;
	const loff_t diff = off2 - off1;
	const loff_t offx = off2 + (loff_t)bsz;
	const size_t bszx = bsz - (size_t)(offx - off2);
	const size_t step = (size_t)(offx - off2);
	uint8_t *buf1 = ut_randbuf(ute, bsz);
	uint8_t *buf2 = ut_randbuf(ute, bsz);

	ut_expect_lt(off1, off2);
	ut_expect_le(off2 - off1, (loff_t)bsz);
	ut_expect_le(step, bsz);

	ut_create_file(ute, root_ino, name, &ino);
	ut_write_read(ute, ino, buf1, bsz, off1);
	ut_write_read(ute, ino, buf2, bsz, off2);
	ut_fsync_ok(ute, ino, true);
	ut_read_verify(ute, ino, buf2, bsz, off2);
	ut_read_verify(ute, ino, buf1, (size_t)diff, off1);
	ut_write_read(ute, ino, buf2, bsz, off2);
	ut_write_read(ute, ino, buf1, bsz, off1);
	ut_read_verify(ute, ino, buf1, bsz, off1);
	ut_read_verify(ute, ino, buf2 + step, bszx, offx);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_overwrite_complex(struct ut_env *ute)
{
	ut_file_overwrite_complex_(ute, 0, 1, UT_BK_SIZE);
	ut_file_overwrite_complex_(ute, 1, 2, UT_UMEGA);
	ut_file_overwrite_complex_(ute, UT_MEGA,
	                           UT_MEGA + UT_BK_SIZE, UT_UMEGA);
	ut_file_overwrite_complex_(ute, UT_MEGA - 7, UT_MEGA - 5,
	                           (11 * UT_BK_SIZE) + 11);
	ut_file_overwrite_complex_(ute, UT_GIGA,
	                           UT_GIGA + UT_BK_SIZE, UT_UMEGA);
	ut_file_overwrite_complex_(ute, UT_GIGA - 11111,
	                           UT_GIGA - 111, UT_BK_SIZE + 11111);
	ut_file_overwrite_complex_(ute, UT_TERA,
	                           UT_TERA + UT_BK_SIZE, UT_UMEGA);
	ut_file_overwrite_complex_(ute, UT_TERA - 111111,
	                           UT_TERA - 111, UT_UMEGA + 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_sequence_(struct ut_env *ute, loff_t base, size_t len)
{
	loff_t off = -1;
	ino_t ino = 0;
	uint64_t num = 0;
	const ino_t root_ino = UT_ROOT_INO;
	const char *name = UT_NAME;
	const size_t nsz = sizeof(num);
	const size_t cnt = len / nsz;

	ut_create_file(ute, root_ino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = base + (loff_t)(i * nsz);
		num = (uint64_t)off;
		ut_write_read(ute, ino, &num, nsz, off);
	}
	for (size_t j = 0; j < cnt; ++j) {
		off = base + (loff_t)(j * nsz);
		num = (uint64_t)off;
		ut_read_verify(ute, ino, &num, nsz, off);
		num = ~num;
		ut_write_read(ute, ino, &num, nsz, off);
	}
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_sequence(struct ut_env *ute)
{
	ut_file_sequence_(ute, 0, UT_BK_SIZE);
	ut_file_sequence_(ute, 1, UT_BK_SIZE);
	ut_file_sequence_(ute, 7, UT_BK_SIZE + 7);
	ut_file_sequence_(ute, UT_BK_SIZE - 11, UT_BK_SIZE + 111);
	ut_file_sequence_(ute, UT_MEGA - 111, UT_UMEGA + 1111);
	ut_file_sequence_(ute, UT_GIGA, UT_BK_SIZE);
	ut_file_sequence_(ute, UT_GIGA - 1, 2 * UT_BK_SIZE);
	ut_file_sequence_(ute, UT_TERA, 2 * UT_BK_SIZE);
	ut_file_sequence_(ute, UT_TERA - 1, UT_BK_SIZE + 111);
	ut_file_sequence_(ute, UT_TERA - 11, UT_BK_SIZE + 1111);
	ut_file_sequence_(ute, UT_TERA - 11, UT_UMEGA + 1111);
	ut_file_sequence_(ute, UT_TERA + 111,
	                  (11 * UT_BK_SIZE) + 11);
	ut_file_sequence_(ute, UT_FILESIZE_MAX / 2 - 1, UT_UMEGA + 1);
}

static void ut_file_sequence_long(struct ut_env *ute)
{
	ut_file_sequence_(ute, UT_MEGA - 7, 111111);
	ut_file_sequence_(ute, UT_GIGA - 77, 111111);
	ut_file_sequence_(ute, UT_TERA - 777, 111111);
}

static void ut_file_sequence_at_end(struct ut_env *ute)
{
	const loff_t fsize_max = UT_FILESIZE_MAX;

	ut_file_sequence_(ute, fsize_max - UT_BK_SIZE, UT_BK_SIZE);
	ut_file_sequence_(ute, fsize_max - (3 * UT_BK_SIZE) - 1,
	                  2 * UT_BK_SIZE);
	ut_file_sequence_(ute, fsize_max - (5 * UT_MEGA) - 5, 4 * UT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct ut_urecord {
	uint64_t idx;
	uint8_t pat[UT_BK_SIZE];
};

static void setup_urecord(struct ut_urecord *urec, uint64_t num)
{
	uint8_t *ptr = urec->pat;
	uint8_t *end = urec->pat + sizeof(urec->pat);
	const size_t nsz = sizeof(num);

	memset(urec, 0, sizeof(*urec));
	urec->idx = num;

	while ((ptr + nsz) <= end) {
		memcpy(ptr, &num, nsz);
		num++;
		ptr += nsz;
	}
}

static struct ut_urecord *new_urecord(struct ut_env *ute, uint64_t num)
{
	struct ut_urecord *urec = ut_malloc(ute, sizeof(*urec));

	setup_urecord(urec, num);
	return urec;
}

static void ut_file_unaligned_(struct ut_env *ute,
                               loff_t base, size_t len)
{
	loff_t off = -1;
	ino_t ino = 0;
	const ino_t root_ino = UT_ROOT_INO;
	struct ut_urecord *urec = NULL;
	const char *name = UT_NAME;
	const size_t nsz = sizeof(*urec) - 1;
	const size_t cnt = len / nsz;

	ut_create_file(ute, root_ino, name, &ino);
	for (size_t i = 0; i < cnt; ++i) {
		off = base + (loff_t)(i * nsz);
		urec = new_urecord(ute, (uint64_t)off);
		ut_write_read(ute, ino, urec, nsz, off);
	}
	for (size_t j = 0; j < cnt; ++j) {
		off = base + (loff_t)(j * nsz);
		urec = new_urecord(ute, (uint64_t)off);
		ut_read_verify(ute, ino, urec, nsz, off);
		urec = new_urecord(ute, ~j);
		ut_write_read(ute, ino, urec, nsz, off);
	}
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_unaligned(struct ut_env *ute)
{
	ut_file_unaligned_(ute, 0, 8 * UT_BK_SIZE);
	ut_file_unaligned_(ute, 1, 8 * UT_BK_SIZE);
	ut_file_unaligned_(ute, 0, UT_UMEGA);
	ut_file_unaligned_(ute, UT_GIGA, 8 * UT_BK_SIZE);
	ut_file_unaligned_(ute, UT_GIGA - 1, 8 * UT_BK_SIZE);
	ut_file_unaligned_(ute, UT_TERA, 8 * UT_BK_SIZE);
	ut_file_unaligned_(ute, UT_TERA - 11, (8 * UT_BK_SIZE));
	ut_file_unaligned_(ute, UT_TERA - 11, UT_UMEGA);
	ut_file_unaligned_(ute, UT_FILESIZE_MAX / 2, UT_UMEGA);
}

static void ut_file_unaligned_at_end(struct ut_env *ute)
{
	const loff_t fsize_max = UT_FILESIZE_MAX;

	ut_file_unaligned_(ute, fsize_max - 11111, 11111);
	ut_file_unaligned_(ute, fsize_max - UT_MEGA - 1, UT_MEGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_firstlast_(struct ut_env *ute, loff_t beg, size_t len)
{
	loff_t off = -1;
	ino_t ino = 0;
	uint64_t num = 0;
	const char *name = UT_NAME;
	const size_t nsz = sizeof(num);
	const loff_t end = beg + (loff_t)len;
	const ino_t root_ino = UT_ROOT_INO;

	ut_create_file(ute, root_ino, name, &ino);
	off = beg;
	num = (uint64_t)off;
	ut_write_read(ute, ino, &num, nsz, off);
	off = end - (loff_t)nsz;
	num = (uint64_t)off;
	ut_write_read(ute, ino, &num, nsz, off);
	off = beg;
	num = (uint64_t)off;
	ut_read_verify(ute, ino, &num, nsz, off);
	off = end - (loff_t)nsz;
	num = (uint64_t)off;
	ut_read_verify(ute, ino, &num, nsz, off);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_firstlast(struct ut_env *ute)
{
	ut_file_firstlast_(ute, 0, UT_4K);
	ut_file_firstlast_(ute, 1, UT_4K);
	ut_file_firstlast_(ute, 0, UT_8K);
	ut_file_firstlast_(ute, 1, UT_8K);
	ut_file_firstlast_(ute, 0, UT_BK_SIZE);
	ut_file_firstlast_(ute, 1, UT_BK_SIZE);
	ut_file_firstlast_(ute, 8, UT_BK_SIZE + 8);
	ut_file_firstlast_(ute, 11, UT_BK_SIZE + 11);
	ut_file_firstlast_(ute, UT_BK_SIZE - 11, UT_BK_SIZE + 111);
	ut_file_firstlast_(ute, 0, UT_UMEGA);
	ut_file_firstlast_(ute, 1, UT_UMEGA);
	ut_file_firstlast_(ute, UT_MEGA - 1, UT_UMEGA + 11);
	ut_file_firstlast_(ute, UT_MEGA + 1, 2 * UT_UMEGA);
	ut_file_firstlast_(ute, UT_GIGA, UT_BK_SIZE);
	ut_file_firstlast_(ute, UT_GIGA - 1, 2 * UT_BK_SIZE);
	ut_file_firstlast_(ute, UT_TERA, 2 * UT_BK_SIZE);
	ut_file_firstlast_(ute, UT_TERA - 11, UT_BK_SIZE + 11);
	ut_file_firstlast_(ute, UT_TERA - 111, UT_BK_SIZE + 1111);
	ut_file_firstlast_(ute, UT_FILESIZE_MAX / 2, UT_UMEGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_zigzag_(struct ut_env *ute, loff_t beg, size_t len)
{
	loff_t off = -1;
	ino_t ino = 0;
	uint64_t num = 0;
	const char *name = UT_NAME;
	const size_t nsz = sizeof(num);
	const size_t cnt = len / nsz;
	const loff_t end = beg + (loff_t)len;
	const ino_t root_ino = UT_ROOT_INO;

	ut_create_file(ute, root_ino, name, &ino);
	for (size_t i = 0; i < cnt / 2; ++i) {
		off = beg + (loff_t)(i * nsz);
		num = (uint64_t)off + 1;
		ut_write_read(ute, ino, &num, nsz, off);

		off = end - (loff_t)((i + 1) * nsz);
		num = (uint64_t)off + 1;
		ut_write_read(ute, ino, &num, nsz, off);
	}
	for (size_t i = 0; i < cnt / 2; ++i) {
		off = beg + (loff_t)(i * nsz);
		num = (uint64_t)off + 1;
		ut_read_verify(ute, ino, &num, nsz, off);

		off = end - (loff_t)((i + 1) * nsz);
		num = (uint64_t)off + 1;
		ut_read_verify(ute, ino, &num, nsz, off);
	}
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_zigzag(struct ut_env *ute)
{
	ut_file_zigzag_(ute, 0, UT_BK_SIZE);
	ut_file_zigzag_(ute, 1, UT_BK_SIZE);
	ut_file_zigzag_(ute, 8, UT_BK_SIZE + 8);
	ut_file_zigzag_(ute, 11, UT_BK_SIZE + 11);
	ut_file_zigzag_(ute, UT_BK_SIZE - 11, UT_BK_SIZE + 111);
	ut_file_zigzag_(ute, 0, UT_UMEGA);
	ut_file_zigzag_(ute, 1, UT_UMEGA);
	ut_file_zigzag_(ute, UT_MEGA - 1, UT_UMEGA + 11);
	ut_file_zigzag_(ute, UT_MEGA + 1, 2 * UT_UMEGA);
	ut_file_zigzag_(ute, UT_GIGA, UT_BK_SIZE);
	ut_file_zigzag_(ute, UT_GIGA - 1, 2 * UT_BK_SIZE);
	ut_file_zigzag_(ute, UT_TERA, 2 * UT_BK_SIZE);
	ut_file_zigzag_(ute, UT_TERA - 11, UT_BK_SIZE + 11);
	ut_file_zigzag_(ute, UT_TERA - 111, UT_BK_SIZE + 1111);
	ut_file_zigzag_(ute, UT_FILESIZE_MAX / 2, UT_UMEGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_with_hole_(struct ut_env *ute,
                               loff_t off1, loff_t off2, size_t len)
{
	ino_t ino = 0;
	const char *name = UT_NAME;
	const ino_t root_ino = UT_ROOT_INO;
	const loff_t hole_off1 = off1 + (loff_t)len;
	const size_t hole_len = (size_t)(off2 - hole_off1);
	const size_t nzeros = (hole_len < UT_UMEGA) ? hole_len : UT_UMEGA;
	const loff_t hole_off2 = off2 - (loff_t)nzeros;
	void *buf1 = ut_randbuf(ute, len);
	void *buf2 = ut_randbuf(ute, len);
	void *zeros = ut_zerobuf(ute, nzeros);

	ut_expect_gt(off2, off1);
	ut_expect_gt((off2 - off1), (loff_t)len);
	ut_expect_gt(off2, hole_off1);

	ut_create_file(ute, root_ino, name, &ino);
	ut_write_read(ute, ino, buf1, len, off1);
	ut_write_read(ute, ino, buf2, len, off2);
	ut_read_verify(ute, ino, zeros, nzeros, hole_off1);
	ut_read_verify(ute, ino, zeros, nzeros, hole_off2);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_with_hole(struct ut_env *ute)
{
	ut_file_with_hole_(ute, 0, UT_MEGA, UT_BK_SIZE);
	ut_file_with_hole_(ute, 0, 2 * UT_BK_SIZE, UT_BK_SIZE);
	ut_file_with_hole_(ute, 1, 3 * UT_BK_SIZE, UT_BK_SIZE);
	ut_file_with_hole_(ute, 1, UT_MEGA - 1, UT_BK_SIZE);
	ut_file_with_hole_(ute, 2, 2 * UT_MEGA - 2, UT_UMEGA);
	ut_file_with_hole_(ute, UT_MEGA + 1,
	                   UT_MEGA + UT_BK_SIZE + 2, UT_BK_SIZE);
	ut_file_with_hole_(ute, 0, UT_GIGA, UT_UMEGA);
	ut_file_with_hole_(ute, 1, UT_GIGA - 1, UT_UMEGA);
	ut_file_with_hole_(ute, 2, 2 * UT_GIGA - 2, UT_IOSIZE_MAX);
	ut_file_with_hole_(ute, UT_GIGA + 1,
	                   UT_GIGA + UT_IOSIZE_MAX + 2, UT_IOSIZE_MAX);
	ut_file_with_hole_(ute, 0, UT_TERA, UT_UMEGA);
	ut_file_with_hole_(ute, 1, UT_TERA - 1, UT_UMEGA);
	ut_file_with_hole_(ute, 2, 2 * UT_TERA - 2, UT_UMEGA);
	ut_file_with_hole_(ute, UT_TERA + 1,
	                   UT_TERA + UT_MEGA + 2, UT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_backward_(struct ut_env *ute, loff_t base_off, size_t cnt)
{
	ino_t ino = 0;
	loff_t pos = -1;
	uint64_t val = 0;
	const size_t vsz = sizeof(val);
	const ino_t root_ino = UT_ROOT_INO;
	const char *name = UT_NAME;

	ut_create_file(ute, root_ino, name, &ino);
	for (size_t i = cnt; i > 0; --i) {
		pos = base_off + (loff_t)(i * cnt);
		val = i;
		ut_write_read(ute, ino, &val, vsz, pos);
		ut_read_verify(ute, ino, &val, vsz, pos);
	}
	for (size_t i = cnt; i > 0; --i) {
		pos = base_off + (loff_t)(i * cnt);
		val = i;
		ut_read_verify(ute, ino, &val, vsz, pos);
	}
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_backward(struct ut_env *ute)
{
	ut_file_backward_(ute, 0, 1111);
	ut_file_backward_(ute, 1, 1111);
	ut_file_backward_(ute, 1111, 1111);
	ut_file_backward_(ute, 11111, 1111);
	ut_file_backward_(ute, 111111, 1111);
	ut_file_backward_(ute, 1111111, 1111);
	ut_file_backward_(ute, 11111111, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_read_behind_(struct ut_env *ute, loff_t off)
{
	ino_t ino = 0;
	loff_t pos = -1;
	ssize_t idx = -1;
	uint8_t *buf = NULL;
	uint8_t da = 0xDA;
	const ssize_t bsz = SILOFS_MEGA;
	const ino_t root_ino = UT_ROOT_INO;
	const char *name = UT_NAME;

	pos = (off < bsz) ? 0 : (off - bsz + 1);
	idx = ((off >= 0) && (off < bsz)) ? off : (bsz - 1);
	buf = ut_randbuf(ute, (size_t)bsz);
	buf[idx] = (uint8_t)(~da);

	ut_create_file(ute, root_ino, name, &ino);
	ut_trunacate_file(ute, ino, off + bsz);
	ut_write_read(ute, ino, &da, 1, off);
	ut_read_ok(ute, ino, buf, (size_t)bsz, pos);
	ut_expect_eq(buf[idx], da);
	ut_remove_file(ute, root_ino, name, ino);
}

static void ut_file_read_behind(struct ut_env *ute)
{
	ut_file_read_behind_(ute, 1111);
	ut_file_read_behind_(ute, UT_8K - 1);
	ut_file_read_behind_(ute, UT_8K);
	ut_file_read_behind_(ute, UT_BK_SIZE);
	ut_file_read_behind_(ute, UT_BK_SIZE + 1);
	ut_file_read_behind_(ute, UT_MEGA);
	ut_file_read_behind_(ute, UT_MEGA + 1);
	ut_file_read_behind_(ute, UT_GIGA);
	ut_file_read_behind_(ute, UT_GIGA - 1);
	ut_file_read_behind_(ute, UT_TERA);
	ut_file_read_behind_(ute, UT_TERA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST1(ut_file_simple),
	UT_DEFTEST(ut_file_minio_aligned),
	UT_DEFTEST(ut_file_minio_unaligned),
	UT_DEFTEST(ut_file_data),
	UT_DEFTEST(ut_file_iosize_max),
	UT_DEFTEST(ut_file_unlinked),
	UT_DEFTEST(ut_file_multi),
	UT_DEFTEST(ut_file_tricky),
	UT_DEFTEST(ut_file_overwrite_simple),
	UT_DEFTEST(ut_file_overwrite_complex),
	UT_DEFTEST(ut_file_sequence),
	UT_DEFTEST(ut_file_sequence_long),
	UT_DEFTEST(ut_file_sequence_at_end),
	UT_DEFTEST(ut_file_unaligned),
	UT_DEFTEST(ut_file_unaligned_at_end),
	UT_DEFTEST(ut_file_firstlast),
	UT_DEFTEST(ut_file_zigzag),
	UT_DEFTEST(ut_file_with_hole),
	UT_DEFTEST(ut_file_backward),
	UT_DEFTEST(ut_file_read_behind),
};

const struct ut_testdefs ut_tdefs_file_basic = UT_MKTESTS(ut_local_tests);
