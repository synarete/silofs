/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include "vfstests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write(3p) of single block to regular file
 */
static void test_write_basic(struct vt_env *vte)
{
	int fd;
	void *buf1;
	size_t nwr = 0;
	size_t bsz = VT_BK_SIZE;
	const char *path = vt_new_path_unique(vte);

	buf1 = vt_new_buf_rands(vte, bsz);
	vt_open(path, O_CREAT | O_WRONLY, 0600, &fd);
	vt_write(fd, buf1, bsz, &nwr);
	vt_expect_eq(bsz, nwr);

	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write(3p) to unlinked file
 */
static void test_write_unlinked_(struct vt_env *vte, loff_t off, size_t bsz)
{
	int wfd = -1;
	int rfd = -1;
	void *rbuf = vt_new_buf_rands(vte, bsz);
	const void *data = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_WRONLY, 0600, &wfd);
	vt_open(path, O_RDONLY, 0600, &rfd);
	vt_unlink(path);
	vt_pwriten(wfd, data, bsz, off);
	vt_preadn(rfd, rbuf, bsz, off);
	vt_expect_eqm(rbuf, data, bsz);
	vt_ftruncate(wfd, off);
	vt_pwriten(wfd, data, bsz, off);
	vt_preadn(rfd, rbuf, bsz, off);
	vt_expect_eqm(rbuf, data, bsz);
	vt_close(rfd);
	vt_close(wfd);
}

static void test_write_unlinked(struct vt_env *vte)
{
	test_write_unlinked_(vte, 0, VT_1K);
	test_write_unlinked_(vte, 0, VT_4K);
	test_write_unlinked_(vte, 0, VT_BK_SIZE);
	test_write_unlinked_(vte, VT_BK_SIZE, VT_MEGA);
	test_write_unlinked_(vte, VT_MEGA, VT_BK_SIZE);
	test_write_unlinked_(vte, VT_GIGA, VT_MEGA);
	test_write_unlinked_(vte, VT_TERA, VT_MEGA);

	test_write_unlinked_(vte, 1, VT_1K + 1);
	test_write_unlinked_(vte, 11, VT_4K + 11);
	test_write_unlinked_(vte, 111, VT_BK_SIZE - 11);
	test_write_unlinked_(vte, VT_BK_SIZE - 111, VT_MEGA + 1111);
	test_write_unlinked_(vte, VT_MEGA - 1111, VT_BK_SIZE + 111);
	test_write_unlinked_(vte, VT_GIGA - 11111, VT_MEGA + 11);
	test_write_unlinked_(vte, VT_TERA  - 1, VT_MEGA + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects pwrite(3p) to return -ESPIPE if an attempt was made to write to a
 * file-descriptor which is associated with a pipe or FIFO.
 */
static void test_write_espipe(struct vt_env *vte)
{
	int fd = -1;
	size_t bsz = VT_BK_SIZE;
	const loff_t off = VT_GIGA;
	const void *data = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_mkfifo(path, 0777);
	vt_open(path, O_RDWR, 0, &fd);
	vt_pwrite_err(fd, data, bsz, off, -ESPIPE);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful write-read of single large-chunk to regular file
 */
static void test_write_read_chunk_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	loff_t pos = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	void *buf1 = vt_new_buf_rands(vte, bsz);
	void *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_write(fd, buf1, bsz, &nwr);
	vt_expect_eq(nwr, bsz);
	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	vt_read(fd, buf2, bsz, &nrd);
	vt_expect_eq(nrd, bsz);
	vt_expect_eqm(buf1, buf2, bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_write_read_chunk(struct vt_env *vte)
{
	test_write_read_chunk_(vte, VT_UMEGA / 2);
	test_write_read_chunk_(vte, VT_UMEGA * 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects upon successful completion of write(3p) to update the last data
 * modification and last file status change time-stamps of the file, only if
 * nbytes-written is greater than 0.
 */
static void test_write_mctimes_(struct vt_env *vte, loff_t off, size_t bsz)
{
	int fd;
	size_t nwr = 0;
	struct stat st[2];
	const void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st[0]);
	vt_suspends(vte, 1);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_expect_mtime_gt(&st[0], &st[1]);
	vt_fstat(fd, &st[0]);
	vt_suspends(vte, 1);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_gt(&st[0], &st[1]);
	vt_expect_mtime_gt(&st[0], &st[1]);
	vt_fstat(fd, &st[0]);
	vt_suspends(vte, 1);
	vt_pwrite(fd, buf, 0, off, &nwr);
	vt_expect_eq(nwr, 0);
	vt_fstat(fd, &st[1]);
	vt_expect_ctime_eq(&st[0], &st[1]);
	vt_expect_mtime_eq(&st[0], &st[1]);
	vt_close(fd);
	vt_unlink(path);
}

static void test_write_mctimes(struct vt_env *vte)
{
	test_write_mctimes_(vte, 0, VT_KILO);
	test_write_mctimes_(vte, VT_GIGA - 1, VT_UMEGA + 2);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful pwrite(3p) to clear SUID bit, pread(3p) to not change
 */
static void test_write_read_suid_(struct vt_env *vte,
                                  loff_t off, size_t bsz)
{
	int fd;
	void *buf;
	struct stat st;
	mode_t mode = 0610;
	mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
	const char *path = vt_new_path_unique(vte);

	buf = vt_new_buf_rands(vte, bsz);
	vt_open(path, O_CREAT | O_RDWR, mode, &fd);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_fchmod(fd, st.st_mode | S_ISUID);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_pwriten(fd, buf, bsz, off + (loff_t)bsz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISUID, 0);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_fchmod(fd, st.st_mode | S_ISUID);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	vt_preadn(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISUID, S_ISUID);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_close(fd);
	vt_unlink(path);
}

static void test_write_read_suid(struct vt_env *vte)
{
	test_write_read_suid_(vte, 0, VT_BK_SIZE);
	test_write_read_suid_(vte, 0, VT_MEGA);
	test_write_read_suid_(vte, VT_GIGA - 1, VT_BK_SIZE);
	test_write_read_suid_(vte, VT_TERA, VT_MEGA);
	test_write_read_suid_(vte, VT_TERA - 1, VT_MEGA + 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects successful pwrite(3p) to clear SGID bit, pread(3p) to not change
 */
static void test_write_read_sgid_(struct vt_env *vte, loff_t off, size_t bsz)
{
	int fd = -1;
	mode_t mode = 0710;
	mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
	struct stat st = { .st_size = 0 };
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, mode, &fd);
	vt_fstat(fd, &st);
	vt_fchmod(fd, st.st_mode | S_ISGID);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_pwriten(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISGID, 0);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_fchmod(fd, st.st_mode | S_ISGID);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_preadn(fd, buf, bsz, off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & S_ISGID, S_ISGID);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_fchmod(fd, st.st_mode | S_ISUID | S_ISGID);
	vt_pwriten(fd, buf, bsz, 2 * off);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_mode & (S_ISUID | S_ISGID), 0);
	vt_expect_eq(st.st_mode & mask, mode);
	vt_close(fd);
	vt_unlink(path);
}

static void test_write_read_sgid(struct vt_env *vte)
{
	test_write_read_sgid_(vte, 0, VT_BK_SIZE);
	test_write_read_sgid_(vte, VT_MEGA - 1, VT_BK_SIZE + 3);
	test_write_read_sgid_(vte, VT_GIGA, VT_MEGA);
	test_write_read_sgid_(vte, VT_TERA - 3, VT_MEGA / 3);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_write_basic),
	VT_DEFTEST(test_write_unlinked),
	VT_DEFTEST(test_write_espipe),
	VT_DEFTEST(test_write_mctimes),
	VT_DEFTEST(test_write_read_chunk),
	VT_DEFTEST(test_write_read_suid),
	VT_DEFTEST(test_write_read_sgid),
};

const struct vt_tests vt_test_write = VT_DEFTESTS(vt_local_tests);


