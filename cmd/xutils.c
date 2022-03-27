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
#include <silofs/cmd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>


static void cmd_openat(int dfd, const char *name, int flags, int *out_fd)
{
	int err;

	err = silofs_sys_openat(dfd, name, flags, 0, out_fd);
	if (err) {
		silofs_die(err, "failed to open: %s flags=%o", name, flags);
	}
}

static void cmd_opendir(const char *pathname, int *out_dfd)
{
	int err;

	err = silofs_sys_opendir(pathname, out_dfd);
	if (err) {
		silofs_die(err, "failed to open directory: %s", pathname);
	}
}

static void cmd_read(int fd, void *buf, size_t cnt, size_t *nrd)
{
	int err;

	err = silofs_sys_read(fd, buf, cnt, nrd);
	if (err) {
		silofs_die(err, "read error");
	}
}

static void cmd_readfile(int fd, char *buf, size_t bsz, size_t *out_nrd)
{
	size_t cnt;
	size_t nrd = 0;
	size_t len = 0;
	const size_t pgsz = (size_t)silofs_sc_page_size();

	while (len < bsz) {
		cnt = silofs_min(pgsz, bsz - len);
		cmd_read(fd, buf + len, cnt, &nrd);
		if (!nrd) {
			break;
		}
		len += nrd;
		nrd = 0;
	}
	*out_nrd = len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sys_flock(int fd, int operation)
{
	return silofs_sys_flock(fd, operation);
}

static void cmd_lockf(int fd, const char *repodir, const char *name)
{
	int err;

	err = sys_flock(fd, LOCK_EX | LOCK_NB);
	if (err == -EWOULDBLOCK) {
		silofs_die(0, "already locked by another process: %s/%s",
		           repodir, name);
	} else if (err) {
		silofs_die(err, "can not lock: %s/%s", repodir, name);
	}
}

static int cmd_trylockf(int fd, const char *repodir, const char *name)
{
	int err;

	err = sys_flock(fd, LOCK_EX | LOCK_NB);
	if (err && (err != -EWOULDBLOCK)) {
		silofs_die(err, "can not lock: %s/%s", repodir, name);
	}
	return err;
}

static void cmd_unlockf(int fd)
{
	int err;

	err = sys_flock(fd, LOCK_UN);
	if (err) {
		silofs_die(err, "failed to unlock");
	}
}

static void cmd_fchmodat(int dfd, const char *name, mode_t mode)
{
	int err;

	err = silofs_sys_fchmodat(dfd, name, mode, 0);
	if (err) {
		silofs_die(err, "failed to chmod: %s mode=%o", name, mode);
	}
}

static void cmd_closefd(int *pfd)
{
	int err;

	err = silofs_sys_closefd(pfd);
	if (err) {
		silofs_die(err, "close error: fd=%d", *pfd);
	}
}

static void cmd_openlockf(int dfd, const char *name, int *out_fd)
{
	cmd_fchmodat(dfd, name, 0600);
	cmd_openat(dfd, name, O_RDWR, out_fd);
	cmd_fchmodat(dfd, name, 0400);
}

void silofs_cmd_lockf(const char *repodir, const char *name, int *out_fd)
{
	int dfd = -1;
	int fd = -1;

	cmd_opendir(repodir, &dfd);
	cmd_openlockf(dfd, name, &fd);
	cmd_closefd(&dfd);
	cmd_lockf(fd, repodir, name);
	*out_fd = fd;
}

bool silofs_cmd_trylockf(const char *repodir, const char *name, int *out_fd)
{
	int dfd = -1;
	int fd = -1;
	int err;

	cmd_opendir(repodir, &dfd);
	cmd_openlockf(dfd, name, &fd);
	cmd_closefd(&dfd);
	err = cmd_trylockf(fd, repodir, name);
	if (err) {
		cmd_closefd(&fd);
		*out_fd = -1;
		return false;
	}
	*out_fd = fd;
	return true;
}

void silofs_cmd_unlockf(int *pfd)
{
	if (pfd && (*pfd > 0)) {
		cmd_unlockf(*pfd);
		cmd_closefd(pfd);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *cmd_read_proc_mountinfo(void)
{
	const size_t bsz = 1UL << 20;
	char *buf = silofs_cmd_zalloc(bsz);
	size_t size = 0;
	int dfd = -1;
	int fd = -1;

	cmd_opendir("/proc/self", &dfd);
	cmd_openat(dfd, "mountinfo", O_RDONLY, &fd);
	cmd_closefd(&dfd);
	cmd_readfile(fd, buf, bsz, &size);
	cmd_closefd(&fd);
	return buf;
}

static bool substr_isempty(const struct silofs_substr *ss)
{
	return silofs_substr_isempty(ss);
}

static void cmd_parse_field(const struct silofs_substr *line, size_t idx,
                            struct silofs_substr *out_field)
{
	struct silofs_substr_pair pair;
	struct silofs_substr *word = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_init(out_field, "");
	silofs_substr_split(line, " \t\v", &pair);
	while (!substr_isempty(word) || !substr_isempty(tail)) {
		if (idx == 0) {
			silofs_substr_strip_ws(word, out_field);
			break;
		}
		silofs_substr_split(tail, " \t\v", &pair);
		idx--;
	}
}

static void cmd_parse_mountinfo_line(const struct silofs_substr *line,
                                     struct silofs_substr *out_mntdir,
                                     struct silofs_substr *out_mntargs)
{
	struct silofs_substr_pair pair;
	struct silofs_substr *head = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_split_str(line, " - ", &pair);
	cmd_parse_field(head, 4, out_mntdir);
	cmd_parse_field(tail, 2, out_mntargs);
}

static bool cmd_isfusesilofs_mountinfo_line(const struct silofs_substr *line)
{
	return (silofs_substr_find(line, "fuse.silofs") < line->len);
}

static size_t round_up(size_t sz)
{
	const size_t align = sizeof(void *);

	return ((sz + align - 1) / align) * align;
}

static void *memory_at(void *mem, size_t pos)
{
	return (uint8_t *)mem + pos;
}

static struct silofs_proc_mntinfo *
cmd_new_mntinfo(const struct silofs_substr *mntdir,
                const struct silofs_substr *mntargs)
{
	struct silofs_proc_mntinfo *mi;
	void *mem;
	char *str;
	size_t sz1;
	size_t sz2;
	size_t hsz;
	size_t msz;

	hsz = round_up(sizeof(*mi));
	sz1 = round_up(mntdir->len + 1);
	sz2 = round_up(mntargs->len + 1);
	msz = hsz + sz1 + sz2;
	mem = silofs_cmd_zalloc(msz);

	mi = mem;
	mi->msz = msz;
	mi->next = NULL;

	str = memory_at(mem, hsz);
	silofs_substr_copyto(mntdir, str, sz1);
	mi->mntdir = str;

	str = memory_at(mem, hsz + sz1);
	silofs_substr_copyto(mntargs, str, sz2);
	mi->mntargs = str;

	return mi;
};

static struct silofs_proc_mntinfo *
cmd_new_mntinfo_of(const struct silofs_substr *line)
{
	struct silofs_substr mntdir;
	struct silofs_substr mntargs;

	cmd_parse_mountinfo_line(line, &mntdir, &mntargs);
	return cmd_new_mntinfo(&mntdir, &mntargs);
}

static void cmd_append_mntinfo(struct silofs_proc_mntinfo **pmi,
                               struct silofs_proc_mntinfo *mi)
{
	if (*pmi != NULL) {
		(*pmi)->next = mi;
	}
	*pmi = mi;
}

static void cmd_parse_mountinfo(struct silofs_proc_mntinfo **pmi_list,
                                const char *mount_info)
{
	struct silofs_substr info;
	struct silofs_substr_pair pair;
	struct silofs_substr *line = &pair.first;
	struct silofs_substr *tail = &pair.second;
	struct silofs_proc_mntinfo *mi = NULL;

	silofs_substr_init(&info, mount_info);
	silofs_substr_split_chr(&info, '\n', &pair);
	while (!silofs_substr_isempty(line) || !silofs_substr_isempty(tail)) {
		if (cmd_isfusesilofs_mountinfo_line(line)) {
			mi = cmd_new_mntinfo_of(line);
			cmd_append_mntinfo(pmi_list, mi);
		}
		silofs_substr_split_chr(tail, '\n', &pair);
	}
}

struct silofs_proc_mntinfo *silofs_cmd_parse_mountinfo(void)
{
	struct silofs_proc_mntinfo *mi_list = NULL;
	char *mount_info;

	mount_info = cmd_read_proc_mountinfo();
	cmd_parse_mountinfo(&mi_list, mount_info);
	silofs_cmd_pfrees(&mount_info);

	return mi_list;
}

void silofs_cmd_free_mountinfo(struct silofs_proc_mntinfo *mi_list)
{
	struct silofs_proc_mntinfo *mi_next;


	while (mi_list != NULL) {
		mi_next = mi_list->next;
		silofs_cmd_zfree(mi_list, mi_list->msz);
		mi_list = mi_next;
	}
}

