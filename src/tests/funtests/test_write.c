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
#include "funtests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful single write(3p) to regular file.
 */
static void test_write_only_(struct ft_env *fte, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	void *buf = ft_new_buf_rands(fte, len);
	size_t nwr = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_WRONLY, 0600, &fd);
	ft_write(fd, buf, len, &nwr);
	ft_expect_eq(len, nwr);

	ft_close(fd);
	ft_unlink(path);
}

static void test_write_only(struct ft_env *fte)
{
	const size_t len[] = {
		1,
		11,
		FT_1K,
		FT_1K + 1,
		FT_4K,
		FT_4K + 11,
		FT_64K,
		FT_64K + 111,
		FT_1M - 1111,
		FT_1M,
		FT_1M + 11111,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(len); ++i) {
		test_write_only_(fte, len[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write(3p) to unlinked file
 */
static void test_write_unlinked_(struct ft_env *fte, loff_t off, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	const void *wbuf = ft_new_buf_rands(fte, len);
	void *rbuf = ft_new_buf_rands(fte, len);
	int wfd = -1;
	int rfd = -1;

	ft_open(path, O_CREAT | O_WRONLY, 0600, &wfd);
	ft_open(path, O_RDONLY, 0600, &rfd);
	ft_unlink(path);
	ft_pwriten(wfd, wbuf, len, off);
	ft_preadn(rfd, rbuf, len, off);
	ft_expect_eqm(rbuf, wbuf, len);
	ft_ftruncate(wfd, off);
	ft_pwriten(wfd, wbuf, len, off);
	ft_preadn(rfd, rbuf, len, off);
	ft_expect_eqm(rbuf, wbuf, len);
	ft_close(rfd);
	ft_close(wfd);
}

static void test_write_unlinked(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_4K),
		FT_MKRANGE(0, FT_8K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_1K, FT_1K),
		FT_MKRANGE(FT_1K, FT_4K),
		FT_MKRANGE(FT_1K, FT_8K),
		FT_MKRANGE(FT_1K, FT_64K),
		FT_MKRANGE(FT_4K, FT_1K),
		FT_MKRANGE(FT_4K, FT_4K),
		FT_MKRANGE(FT_4K, FT_8K),
		FT_MKRANGE(FT_4K, FT_64K),
		FT_MKRANGE(FT_64K, FT_4K),
		FT_MKRANGE(FT_64K, FT_64K),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
		/* unaligned */
		FT_MKRANGE(1, FT_1K + 1),
		FT_MKRANGE(11, FT_4K - 11),
		FT_MKRANGE(111, FT_8K + 111),
		FT_MKRANGE(1111, FT_64K - 1),
		FT_MKRANGE(FT_1K - 1, FT_1K + 11),
		FT_MKRANGE(FT_1K + 1, FT_4K - 11),
		FT_MKRANGE(FT_2K + 1, FT_64K - 11),
		FT_MKRANGE(FT_4K - 1, FT_1K + 11),
		FT_MKRANGE(FT_4K + 11, FT_8K - 111),
		FT_MKRANGE(FT_4K + 111, FT_64K - 1),
		FT_MKRANGE(FT_64K - 1, FT_4K + 11),
		FT_MKRANGE(FT_64K + 1, FT_1M - 111),
		FT_MKRANGE(FT_1M - 1, FT_64K + 1111),
		FT_MKRANGE(FT_1G - 11, FT_1M - 11111),
		FT_MKRANGE(FT_1T - 111, FT_1M - 111111),
	};

	ft_exec_with_ranges(fte, test_write_unlinked_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects pwrite(3p) to return -ESPIPE if an attempt was made to write to a
 * file-descriptor which is associated with a pipe or FIFO.
 */
static void test_write_espipe(struct ft_env *fte)
{
	const char *path = ft_new_path_unique(fte);
	uint8_t dat[] = { 1, 2, 3, 4, 5 };
	int fd = -1;

	ft_mkfifo(path, 0777);
	ft_open(path, O_RDWR, 0, &fd);
	ft_pwrite_err(fd, dat, sizeof(dat), FT_1G, -ESPIPE);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-seek-read of single buffer
 */
static void test_write_lseek_read_(struct ft_env *fte, size_t len)
{
	const char *path = ft_new_path_unique(fte);
	void *buf1 = ft_new_buf_rands(fte, len);
	void *buf2 = ft_new_buf_rands(fte, len);
	loff_t pos = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_write(fd, buf1, len, &nwr);
	ft_expect_eq(nwr, len);
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	ft_read(fd, buf2, len, &nrd);
	ft_expect_eq(nrd, len);
	ft_expect_eqm(buf1, buf2, len);
	ft_close(fd);
	ft_unlink(path);
}

static void test_write_lseek_read(struct ft_env *fte)
{
	const size_t len[] = {
		1,
		11,
		FT_1K,
		FT_1K + 1,
		FT_4K,
		FT_4K + 1,
		FT_64K,
		FT_64K + 1,
		FT_1M / 2,
		FT_1M,
		FT_1M + 1,
	};

	for (size_t i = 0; i < FT_ARRAY_SIZE(len); ++i) {
		test_write_lseek_read_(fte, len[i]);
		ft_relax_mem(fte);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects upon successful completion of write(3p) to update the last data
 * modification and last file status change time-stamps of the file, only if
 * nbytes-written is greater than 0.
 */
static void test_write_mctimes_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st[2];
	const char *path = ft_new_path_unique(fte);
	const void *buf = ft_new_buf_rands(fte, len);
	size_t nwr = 0;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st[0]);
	ft_suspend1(fte);
	ft_pwriten(fd, buf, len, off);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_suspend1(fte);
	ft_pwriten(fd, buf, len, off);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_suspend1(fte);
	ft_pwrite(fd, buf, 0, off, &nwr);
	ft_expect_eq(nwr, 0);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_eq(&st[0], &st[1]);
	ft_expect_mtime_eq(&st[0], &st[1]);
	ft_close(fd);
	ft_unlink(path);
}

static void test_write_mctimes(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		/* aligned */
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_8K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(FT_4K, FT_64K),
		FT_MKRANGE(FT_64K, FT_1M),
		FT_MKRANGE(FT_1M, FT_64K),
		FT_MKRANGE(FT_1G, FT_1M),
		FT_MKRANGE(FT_1T, FT_1M),
		/* unaligned */
		FT_MKRANGE(1, FT_1K + 1),
		FT_MKRANGE(11, FT_4K - 11),
		FT_MKRANGE(FT_64K + 1, FT_1M - 111),
		FT_MKRANGE(FT_1M - 1, FT_64K + 1111),
		FT_MKRANGE(FT_1G - 11, FT_1M - 11111),
		FT_MKRANGE(FT_1T - 111, FT_1M - 111111),
	};

	ft_exec_with_ranges(fte, test_write_mctimes_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful pwrite(3p) to clear SUID bit, pread(3p) to not change
 */
static void test_write_read_suid_(struct ft_env *fte,
                                  loff_t off, size_t bsz)
{
	struct stat st = { .st_size = -1 };
	const char *path = ft_new_path_unique(fte);
	void *buf = ft_new_buf_rands(fte, bsz);
	const mode_t mode = 0610;
	const mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, mode, &fd);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_fchmod(fd, st.st_mode | S_ISUID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_pwriten(fd, buf, bsz, off + (loff_t)bsz);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, 0);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_fchmod(fd, st.st_mode | S_ISUID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_preadn(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_close(fd);
	ft_unlink(path);
}

static void test_write_read_suid(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(1, FT_1K),
		FT_MKRANGE(11, 11 * FT_1K  + 1),
		FT_MKRANGE(FT_1G - 1, FT_64K),
		FT_MKRANGE(FT_1T, FT_1M),
		FT_MKRANGE(FT_1T - 1, FT_1M + 3),
	};

	ft_exec_with_ranges(fte, test_write_read_suid_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful pwrite(3p) to clear SGID bit, pread(3p) to not change
 */
static void test_write_read_sgid_(struct ft_env *fte, loff_t off, size_t len)
{
	struct stat st = { .st_size = 0 };
	const char *path = ft_new_path_unique(fte);
	void *buf = ft_new_buf_rands(fte, len);
	const mode_t mode = 0710;
	const mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
	int fd = -1;

	ft_open(path, O_CREAT | O_RDWR, mode, &fd);
	ft_fstat(fd, &st);
	ft_fchmod(fd, st.st_mode | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_pwriten(fd, buf, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_fchmod(fd, st.st_mode | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_preadn(fd, buf, len, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	ft_pwriten(fd, buf, len, 2 * off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & (S_ISUID | S_ISGID), 0);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_close(fd);
	ft_unlink(path);
}

static void test_write_read_sgid(struct ft_env *fte)
{
	const struct ft_range ranges[] = {
		FT_MKRANGE(0, FT_1K),
		FT_MKRANGE(0, FT_64K),
		FT_MKRANGE(0, FT_1M),
		FT_MKRANGE(1, FT_1M),
		FT_MKRANGE(FT_1M, FT_1M),
		FT_MKRANGE(FT_1G - 1, FT_1M),
		FT_MKRANGE(FT_1T - 1, FT_1M + 3),
	};

	ft_exec_with_ranges(fte, test_write_read_sgid_, ranges);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_write_only),
	FT_DEFTEST(test_write_unlinked),
	FT_DEFTEST(test_write_espipe),
	FT_DEFTEST(test_write_mctimes),
	FT_DEFTEST(test_write_lseek_read),
	FT_DEFTEST(test_write_read_suid),
	FT_DEFTEST(test_write_read_sgid),
};

const struct ft_tests ft_test_write = FT_DEFTESTS(ft_local_tests);


