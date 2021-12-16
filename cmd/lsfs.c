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
#include <dirent.h>

static struct silofs_subcmd_lsfs *lsfs_args;

static const char *lsfs_usage[] = {
	"lsfs [options] <pathname>",
	"",
	"options:",
	"  -l, --full                   Long format",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	NULL
};

static void lsfs_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "full", no_argument, NULL, 'l' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_cmd_getopt("lV:h", opts);
		if (opt_chr == 'l') {
			lsfs_args->full = true;
		} else if (opt_chr == 'V') {
			silofs_set_verbose_mode(optarg);
		} else if (opt_chr == 'h') {
			silofs_show_help_and_exit(lsfs_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_cmd_getarg_or_cwd("pathname", &lsfs_args->pathname);
	silofs_cmd_endargs();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void lsfs_finalize(void)
{
	silofs_destroy_fse_inst();
	silofs_cmd_pfrees(&lsfs_args->pathname_real);
	silofs_cmd_pfrees(&lsfs_args->repodir_real);
	silofs_cmd_pfrees(&lsfs_args->pathname);
}

static void lsfs_start(void)
{
	lsfs_args = &silofs_globals.cmd.lsfs;
	atexit(lsfs_finalize);
}

static void lsfs_prepare(void)
{
	struct stat st;

	silofs_cmd_stat_reg_or_dir(lsfs_args->pathname, &st);
	lsfs_args->pathname_real = silofs_cmd_realpath(lsfs_args->pathname);
}

static void lsfs_do_ioctl_query(struct silofs_ioc_query *query)
{
	const char *path = lsfs_args->pathname_real;
	int fd = -1;
	int err;

	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "failed to open: %s", path);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_FS_IOC_QUERY, query);
	silofs_sys_close(fd);
	if (err) {
		silofs_die(err, "ioctl error: %s", path);
	}
}

static void lsfs_resolve_repodir(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_REPO };

	lsfs_do_ioctl_query(&query);
	lsfs_args->repodir_real = silofs_cmd_realpath(query.u.repo.r_path);
	silofs_die_if_not_dir(lsfs_args->repodir_real, false);
}

static void lsfs_create_fs_env(void)
{
	const struct silofs_fs_args fs_args = {
		.repodir = lsfs_args->repodir_real,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.lock_repo = false,
	};

	silofs_create_fse_inst(&fs_args);
}

static void lsfs_open_repo(void)
{
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	err = silofs_fse_open_repo(fse);
	if (err) {
		silofs_die(err, "failed to open repo: %s",
		           lsfs_args->repodir_real);
	}
}

static void lsfs_show_boorec(const struct silofs_bootsec *bsec)
{
	struct tm tm;
	char tms[128] = "";
	time_t btime = bsec->btime;

	if (lsfs_args->full) {
		localtime_r(&btime, &tm);
		strftime(tms, sizeof(tms) - 1, "%b %e %Y %H:%M", &tm);
	}
	printf("%-16s %s\n", bsec->name.name, tms);
}

static void lsfs_show_entry(const char *name)
{
	struct silofs_bootsec bsec;
	struct silofs_namestr nstr;
	struct silofs_fs_env *fse = silofs_fse_inst();
	int err;

	silofs_namestr_init(&nstr, name);
	err = silofs_check_fs_name(&nstr);
	if (err) {
		return;
	}
	err = silofs_fse_load_boot(fse, &nstr, &bsec);
	if (err) {
		return;
	}
	lsfs_show_boorec(&bsec);
}

static void lsfs_execute(void)
{
	char buf[512];
	struct dirent64 de;
	const char *path = lsfs_args->repodir_real;
	loff_t off = 0;
	size_t nde = 1;
	int dfd = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		silofs_die(err, "open-dir error: %s", path);
	}
	while (off >= 0) {
		err = silofs_sys_llseek(dfd, off, SEEK_SET, &off);
		if (err) {
			break;
		}
		err = silofs_sys_getdents(dfd, buf, sizeof(buf), &de, 1, &nde);
		if (err || !nde) {
			break;
		}
		lsfs_show_entry(de.d_name);
		off = de.d_off;
	}
	if (err) {
		silofs_die(err, "readdir failure: %s", path);
	}
	err = silofs_sys_close(dfd);
	if (err) {
		silofs_die(err, "close-dir error: %s", path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_lsfs(void)
{
	/* Do all cleanups upon exits */
	lsfs_start();

	/* Parse command's arguments */
	lsfs_getopt();

	/* Verify user's arguments */
	lsfs_prepare();

	/* Resolve repo-dir from fs */
	lsfs_resolve_repodir();

	/* Prepare environment */
	lsfs_create_fs_env();

	/* Open repository */
	lsfs_open_repo();

	/* Do actual listing */
	lsfs_execute();

	/* Post execution cleanups */
	lsfs_finalize();
}


