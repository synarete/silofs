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
#include "fftests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write(3p) of single block to regular file
 */
static void test_write_basic(struct ft_env *fte)
{
	int fd;
	void *buf1;
	size_t nwr = 0;
	size_t bsz = FT_BK_SIZE;
	const char *path = ft_new_path_unique(fte);

	buf1 = ft_new_buf_rands(fte, bsz);
	ft_open(path, O_CREAT | O_WRONLY, 0600, &fd);
	ft_write(fd, buf1, bsz, &nwr);
	ft_expect_eq(bsz, nwr);

	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write(3p) to unlinked file
 */
static void test_write_unlinked_(struct ft_env *fte, loff_t off, size_t bsz)
{
	int wfd = -1;
	int rfd = -1;
	void *rbuf = ft_new_buf_rands(fte, bsz);
	const void *data = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_WRONLY, 0600, &wfd);
	ft_open(path, O_RDONLY, 0600, &rfd);
	ft_unlink(path);
	ft_pwriten(wfd, data, bsz, off);
	ft_preadn(rfd, rbuf, bsz, off);
	ft_expect_eqm(rbuf, data, bsz);
	ft_ftruncate(wfd, off);
	ft_pwriten(wfd, data, bsz, off);
	ft_preadn(rfd, rbuf, bsz, off);
	ft_expect_eqm(rbuf, data, bsz);
	ft_close(rfd);
	ft_close(wfd);
}

static void test_write_unlinked(struct ft_env *fte)
{
	test_write_unlinked_(fte, 0, FT_1K);
	test_write_unlinked_(fte, 0, FT_4K);
	test_write_unlinked_(fte, 0, FT_BK_SIZE);
	test_write_unlinked_(fte, FT_BK_SIZE, FT_MEGA);
	test_write_unlinked_(fte, FT_MEGA, FT_BK_SIZE);
	test_write_unlinked_(fte, FT_GIGA, FT_MEGA);
	test_write_unlinked_(fte, FT_TERA, FT_MEGA);

	test_write_unlinked_(fte, 1, FT_1K + 1);
	test_write_unlinked_(fte, 11, FT_4K + 11);
	test_write_unlinked_(fte, 111, FT_BK_SIZE - 11);
	test_write_unlinked_(fte, FT_BK_SIZE - 111, FT_MEGA + 1111);
	test_write_unlinked_(fte, FT_MEGA - 1111, FT_BK_SIZE + 111);
	test_write_unlinked_(fte, FT_GIGA - 11111, FT_MEGA + 11);
	test_write_unlinked_(fte, FT_TERA  - 1, FT_MEGA + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects pwrite(3p) to return -ESPIPE if an attempt was made to write to a
 * file-descriptor which is associated with a pipe or FIFO.
 */
static void test_write_espipe(struct ft_env *fte)
{
	int fd = -1;
	size_t bsz = FT_BK_SIZE;
	const loff_t off = FT_GIGA;
	const void *data = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_mkfifo(path, 0777);
	ft_open(path, O_RDWR, 0, &fd);
	ft_pwrite_err(fd, data, bsz, off, -ESPIPE);
	ft_close(fd);
	ft_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of single large-chunk to regular file
 */
static void test_write_read_chunk_(struct ft_env *fte, size_t bsz)
{
	int fd = -1;
	loff_t pos = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	void *buf1 = ft_new_buf_rands(fte, bsz);
	void *buf2 = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_write(fd, buf1, bsz, &nwr);
	ft_expect_eq(nwr, bsz);
	ft_llseek(fd, 0, SEEK_SET, &pos);
	ft_expect_eq(pos, 0);
	ft_read(fd, buf2, bsz, &nrd);
	ft_expect_eq(nrd, bsz);
	ft_expect_eqm(buf1, buf2, bsz);
	ft_close(fd);
	ft_unlink(path);
}

static void test_write_read_chunk(struct ft_env *fte)
{
	test_write_read_chunk_(fte, FT_UMEGA / 2);
	test_write_read_chunk_(fte, FT_UMEGA * 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects upon successful completion of write(3p) to update the last data
 * modification and last file status change time-stamps of the file, only if
 * nbytes-written is greater than 0.
 */
static void test_write_mctimes_(struct ft_env *fte, loff_t off, size_t bsz)
{
	int fd;
	size_t nwr = 0;
	struct stat st[2];
	const void *buf = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, 0600, &fd);
	ft_fstat(fd, &st[0]);
	ft_suspends(fte, 1);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_suspends(fte, 1);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st[1]);
	ft_expect_ctime_gt(&st[0], &st[1]);
	ft_expect_mtime_gt(&st[0], &st[1]);
	ft_fstat(fd, &st[0]);
	ft_suspends(fte, 1);
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
	test_write_mctimes_(fte, 0, FT_KILO);
	test_write_mctimes_(fte, FT_GIGA - 1, FT_UMEGA + 2);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful pwrite(3p) to clear SUID bit, pread(3p) to not change
 */
static void test_write_read_suid_(struct ft_env *fte,
                                  loff_t off, size_t bsz)
{
	int fd;
	void *buf;
	struct stat st;
	mode_t mode = 0610;
	mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
	const char *path = ft_new_path_unique(fte);

	buf = ft_new_buf_rands(fte, bsz);
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
	test_write_read_suid_(fte, 0, FT_BK_SIZE);
	test_write_read_suid_(fte, 0, FT_MEGA);
	test_write_read_suid_(fte, FT_GIGA - 1, FT_BK_SIZE);
	test_write_read_suid_(fte, FT_TERA, FT_MEGA);
	test_write_read_suid_(fte, FT_TERA - 1, FT_MEGA + 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful pwrite(3p) to clear SGID bit, pread(3p) to not change
 */
static void test_write_read_sgid_(struct ft_env *fte, loff_t off, size_t bsz)
{
	int fd = -1;
	mode_t mode = 0710;
	mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
	struct stat st = { .st_size = 0 };
	void *buf = ft_new_buf_rands(fte, bsz);
	const char *path = ft_new_path_unique(fte);

	ft_open(path, O_CREAT | O_RDWR, mode, &fd);
	ft_fstat(fd, &st);
	ft_fchmod(fd, st.st_mode | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_pwriten(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, 0);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_fchmod(fd, st.st_mode | S_ISGID);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_preadn(fd, buf, bsz, off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	ft_pwriten(fd, buf, bsz, 2 * off);
	ft_fstat(fd, &st);
	ft_expect_eq(st.st_mode & (S_ISUID | S_ISGID), 0);
	ft_expect_eq(st.st_mode & mask, mode);
	ft_close(fd);
	ft_unlink(path);
}

static void test_write_read_sgid(struct ft_env *fte)
{
	test_write_read_sgid_(fte, 0, FT_BK_SIZE);
	test_write_read_sgid_(fte, FT_MEGA - 1, FT_BK_SIZE + 3);
	test_write_read_sgid_(fte, FT_GIGA, FT_MEGA);
	test_write_read_sgid_(fte, FT_TERA - 3, FT_MEGA / 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_write_basic),
	FT_DEFTEST(test_write_unlinked),
	FT_DEFTEST(test_write_espipe),
	FT_DEFTEST(test_write_mctimes),
	FT_DEFTEST(test_write_read_chunk),
	FT_DEFTEST(test_write_read_suid),
	FT_DEFTEST(test_write_read_sgid),
};

const struct ft_tests ft_test_write = FT_DEFTESTS(ft_local_tests);


