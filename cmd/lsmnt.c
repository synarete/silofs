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
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>


static struct silofs_subcmd_lsmnt *lsmnt_args;

static char *lsmnt_mountinfo;

static const char *lsmnt_usage[] = {
	"lsmnt [options]",
	"",
	"options:",
	"  -l, --long                   Long listing format",
	NULL
};

static void lsmnt_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "long", no_argument, NULL, 'l' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("lh", opts);
		if (opt_chr == 'l') {
			lsmnt_args->long_listing = true;
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(lsmnt_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void lsmnt_finalize(void)
{
	silofs_cmd_pfrees(&lsmnt_mountinfo);
	silofs_cmd_pfrees(&lsmnt_args->mntpoint_real);
}

static void lsmnt_start(void)
{
	lsmnt_args = &silofs_globals.cmd.lsmnt;
	atexit(lsmnt_finalize);
}

static void lsmnt_prepare(void)
{
	struct stat st;
	const char *path;

	path = lsmnt_args->mntpoint;
	if (path != NULL) {
		silofs_cmd_stat_ok(path, &st);
		if (!S_ISDIR(st.st_mode)) {
			silofs_die(-ENOTDIR, "bad mount-point: %s", path);
		}
		if (st.st_ino != SILOFS_INO_ROOT) {
			silofs_die(0, "not a silofs mount-point: %s", path);
		}
		lsmnt_args->mntpoint_real = silofs_cmd_realpath(path);
	}
}

static void lsmnt_read_mountinfo(void)
{
	int err;
	int fd = -1;
	size_t nrd = 0;
	size_t len = 0;
	const size_t len_max = 1UL << 20;
	const char *proc_path = "/proc/self/mountinfo";
	const size_t pgsz = (size_t)silofs_sc_page_size();

	err = silofs_sys_open(proc_path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "failed to open: %s", proc_path);
	}
	lsmnt_mountinfo = silofs_cmd_zalloc(len_max);
	while (len < len_max) {
		err = silofs_sys_read(fd, lsmnt_mountinfo, pgsz, &nrd);
		if (err) {
			silofs_die(err, "read error: %s", proc_path);
		}
		if (nrd == 0) {
			break;
		}
		len += nrd;
	}
	err = silofs_sys_closefd(&fd);
	if (err) {
		silofs_die(err, "close error: %s", proc_path);
	}
	if (len >= len_max) {
		silofs_die(0, "unsupported mountinfo: %s", proc_path);
	}
}

static void lsmnt_print_mntdir(const struct silofs_substr *mntdir)
{
	printf("%.*s\n", (int)mntdir->len, mntdir->str);
}

static void lsmnt_print_mntdir_long(const struct silofs_substr *mntdir)
{
	int err;
	int dfd = -1;
	int o_flags;
	mode_t mode;
	struct stat st;
	char perm[11] = "";
	char path[SILOFS_MNTPATH_MAX + 1] = "";

	silofs_substr_copyto(mntdir, path, sizeof(path) - 1);

	memset(perm, '?', sizeof(perm) - 1);
	o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	err = silofs_sys_openat(AT_FDCWD, path, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}
	err = silofs_sys_fstat(dfd, &st);
	if (err) {
		goto out;
	}
	mode = st.st_mode;
	perm[0] = S_ISDIR(mode) ? 'd' : (S_ISLNK(mode) ? 'l' : '-');
	perm[1] = (mode & S_IRUSR) ? 'r' : '-';
	perm[2] = (mode & S_IWUSR) ? 'w' : '-';
	perm[3] = (mode & S_IXUSR) ? 'x' : '-';
	perm[4] = (mode & S_IRGRP) ? 'r' : '-';
	perm[5] = (mode & S_IWGRP) ? 'w' : '-';
	perm[6] = (mode & S_IXGRP) ? 'x' : '-';
	perm[7] = (mode & S_IROTH) ? 'r' : '-';
	perm[8] = (mode & S_IWOTH) ? 'w' : '-';
	perm[9] = (mode & S_IXOTH) ? 'x' : '-';
out:
	silofs_sys_closefd(&dfd);
	printf("%s %.*s ", perm, (int)mntdir->len, mntdir->str);
}

static void lsmnt_print_mntargs(const struct silofs_substr *args)
{
	printf("%.*s \n", (int)args->len, args->str);
}

static void lsmnt_parse_field(const struct silofs_substr *line,
                              size_t idx, struct silofs_substr *field)
{
	struct silofs_substr_pair pair;
	struct silofs_substr *word = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_init(field, "");
	silofs_substr_split(line, " \t\v", &pair);
	while (!silofs_substr_isempty(word) || !silofs_substr_isempty(tail)) {
		if (idx == 0) {
			silofs_substr_strip_ws(word, field);
			break;
		}
		silofs_substr_split(tail, " \t\v", &pair);
		idx--;
	}
}

static void lsmnt_parse_mountinfo_line(const struct silofs_substr *line)
{
	struct silofs_substr mntdir;
	struct silofs_substr mntargs;
	struct silofs_substr_pair pair;
	struct silofs_substr *head = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_split_str(line, " - ", &pair);
	lsmnt_parse_field(head, 4, &mntdir);
	lsmnt_parse_field(tail, 2, &mntargs);

	if (lsmnt_args->long_listing) {
		lsmnt_print_mntdir_long(&mntdir);
		lsmnt_print_mntargs(&mntargs);
	} else {
		lsmnt_print_mntdir(&mntdir);
	}
}

static bool lsmnt_isfusesilofs(const struct silofs_substr *line)
{
	return (silofs_substr_find(line, "fuse.silofs") < line->len);
}

static void lsmnt_parse_mountinfo(void)
{
	struct silofs_substr info;
	struct silofs_substr_pair pair;
	struct silofs_substr *line = &pair.first;
	struct silofs_substr *tail = &pair.second;

	silofs_substr_init(&info, lsmnt_mountinfo);
	silofs_substr_split_chr(&info, '\n', &pair);
	while (!silofs_substr_isempty(line) || !silofs_substr_isempty(tail)) {
		if (lsmnt_isfusesilofs(line)) {
			lsmnt_parse_mountinfo_line(line);
		}
		silofs_substr_split_chr(tail, '\n', &pair);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_lsmnt(void)
{
	/* Do all cleanups upon exits */
	lsmnt_start();

	/* Parse command's arguments */
	lsmnt_getopt();

	/* Verify user's arguments */
	lsmnt_prepare();

	/* Read mount info into global variable, all at once */
	lsmnt_read_mountinfo();

	/* Parse line-by-line */
	lsmnt_parse_mountinfo();

	/* Post execution cleanups */
	lsmnt_finalize();
}

