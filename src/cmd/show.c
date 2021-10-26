/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <sys/mount.h>

static const char *show_usage[] = {
	"show <pathname>",
	NULL
};

static void show_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = silofs_getopt_subcmd("h", opts);
		if (opt_chr == 'h') {
			silofs_show_help_and_exit(show_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	silofs_globals.cmd.show.pathname =
	        silofs_consume_cmdarg("pathname", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void show_finalize(void)
{
	/* no-op */
}

static void show_setup_check_params(void)
{
	struct stat st;

	silofs_stat_reg_or_dir(silofs_globals.cmd.show.pathname, &st);
}

static void show_do_ioctl_query(struct silofs_ioc_query *query)
{
	int err;
	int fd = -1;
	const char *path = silofs_globals.cmd.show.pathname;

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

static void show_version(void)
{
	struct silofs_ioc_query query = {
		.qtype = SILOFS_QUERY_VERSION
	};

	show_do_ioctl_query(&query);
	printf("version:        %s\n", query.u.version.string);
}

static void show_volume(void)
{
	struct silofs_ioc_query query = {
		.qtype = SILOFS_QUERY_VOLUME
	};

	show_do_ioctl_query(&query);
	printf("volume:         %s\n", query.u.volume.path);
}

struct silofs_msflag_name {
	long ms_flag;
	const char *name;
};

static void make_mntflags_str(long flags, char *buf, size_t bsz)
{
	size_t len;
	const char *end = buf + bsz;
	const struct silofs_msflag_name *ms_name = NULL;
	const struct silofs_msflag_name ms_names[] = {
		{ MS_RDONLY, "rdonly" },
		{ MS_NODEV, "nodev" },
		{ MS_NOSUID, "nosuid" },
		{ MS_NOEXEC, "noexec" },
	};

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(ms_names); ++i) {
		ms_name = &ms_names[i];
		len = strlen(ms_name->name);
		if (((buf + len + 2) < end) && (flags & ms_name->ms_flag)) {
			memcpy(buf, ms_names[i].name, len);
			buf[len] = ' ';
			buf += len + 1;
			buf[0] = '\0';
		}
	}
}

static void show_fsinfo(void)
{
	long ms_flags;
	char ms_flags_str[64] = "";
	struct silofs_ioc_query query = {
		.qtype = SILOFS_QUERY_FSINFO
	};

	show_do_ioctl_query(&query);
	ms_flags = (long)query.u.fsinfo.msflags;
	make_mntflags_str(ms_flags, ms_flags_str, sizeof(ms_flags_str) - 1);

	printf("uptime-seconds: %ld\n", query.u.fsinfo.uptime);
	printf("mount-flags:    %s\n", ms_flags_str);
}

static void show_execute(void)
{
	show_version();
	show_volume();
	show_fsinfo();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_show(void)
{
	/* Do all cleanups upon exits */
	atexit(show_finalize);

	/* Parse command's arguments */
	show_getopt();

	/* Verify user's arguments */
	show_setup_check_params();

	/* Do actual query + show */
	show_execute();

	/* Post execution cleanups */
	show_finalize();
}


