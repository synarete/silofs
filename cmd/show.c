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
#include <sys/mount.h>

static struct silofs_subcmd_show *show_args;

static const char *show_usage[] = {
	"show <subcmd> <pathname>",
	"",
	"sub commands:",
	"  version      Show mounted file-system's version",
	"  repo         Show back-end repo path",
	"  statfsx      Show extended file-system info",
	"  statx        Show extended file stats",
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
		opt_chr = silofs_cmd_getopt("h", opts);
		if (opt_chr == 'h') {
			silofs_show_help_and_exit(show_usage);
		} else if (opt_chr > 0) {
			silofs_die_unsupported_opt();
		}
	}
	show_args->subcmd = silofs_cmd_getarg("subcmd", false);
	show_args->pathname = silofs_cmd_getarg("pathname", true);
}


static const char *show_subcommands[] = {
	[SILOFS_QUERY_VERSION]  = "version",
	[SILOFS_QUERY_REPO]     = "repo",
	[SILOFS_QUERY_STATFSX]  = "statfsx",
	[SILOFS_QUERY_STATX]    = "statx",
};

static enum silofs_query_type show_subcmd_qtype(void)
{
	const int nelems = (int)SILOFS_ARRAY_SIZE(show_subcommands);
	const char *subcmd = show_args->subcmd;

	for (int qtype = 0; qtype < nelems; ++qtype) {
		if ((show_subcommands[qtype] != NULL) &&
		    !strcmp(show_subcommands[qtype], subcmd)) {
			return (enum silofs_query_type)qtype;
		}
	}
	return SILOFS_QUERY_NONE;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void show_finalize(void)
{
	silofs_pfree_string(&show_args->pathname_real);
}

static void show_start(void)
{
	show_args = &silofs_globals.cmd.show;
	atexit(show_finalize);
}

static void show_setup_check_params(void)
{
	struct stat st;

	show_args->pathname_real =
	        silofs_cmd_realpath(show_args->pathname);
	silofs_cmd_stat_reg_or_dir(show_args->pathname_real, &st);
	if (show_subcmd_qtype() == SILOFS_QUERY_NONE) {
		silofs_die(0, "unknown sub-command %s", show_args->subcmd);
	}
}

static void show_do_ioctl_query(struct silofs_ioc_query *query)
{
	const char *path = show_args->pathname_real;
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

static void show_version(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_VERSION };

	show_do_ioctl_query(&query);
	printf("%s\n", query.u.version.v_str);
}

static void show_repo(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_REPO };

	show_do_ioctl_query(&query);
	printf("%s\n", query.u.repo.r_path);
}

static void show_fsname(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_FSNAME };

	show_do_ioctl_query(&query);
	printf("%s\n", query.u.fsname.f_name);
}

struct silofs_msflag_name {
	unsigned long ms_flag;
	const char *name;
};

static void msflags_str(unsigned long msflags, char *buf, size_t bsz)
{
	bool first = true;
	size_t len;
	const char *end = buf + bsz;
	const struct silofs_msflag_name *ms_name = NULL;
	const struct silofs_msflag_name ms_names[] = {
		{ MS_RDONLY,    "rdonly" },
		{ MS_NODEV,     "nodev" },
		{ MS_NOSUID,    "nosuid" },
		{ MS_NOEXEC,    "noexec" },
		{ MS_MANDLOCK,  "mandlock" },
		{ MS_NOATIME,   "noatime" },
	};

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(ms_names); ++i) {
		ms_name = &ms_names[i];
		len = strlen(ms_name->name);
		if (!(msflags & ms_name->ms_flag)) {
			continue;
		}
		if ((buf + len + 2) < end) {
			memcpy(buf, ms_names[i].name, len);
			buf += len;
			if (!first) {
				buf[len] = ',';
				buf += 1;
			}
			buf[0] = '\0';
			first = false;
		}
	}
}

static void show_statfsx(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_STATFSX };
	const struct silofs_query_statfsx *qstfsx = &query.u.statfsx;
	char mntfstr[128] = "";

	show_do_ioctl_query(&query);
	msflags_str(qstfsx->f_msflags, mntfstr, sizeof(mntfstr) - 1);

	printf("mountf:     %s \n", mntfstr);
	printf("uptime:     %ld seconds \n", qstfsx->f_uptime);
	printf("bsize:      %lu bytes \n", qstfsx->f_bsize);
	printf("bused:      %lu bytes \n", qstfsx->f_bused);
	printf("ilimit:     %lu inodes \n", qstfsx->f_ilimit);
	printf("icurr:      %lu inodes \n", qstfsx->f_icurr);
	printf("umeta:      %lu bytes \n", qstfsx->f_umeta);
	printf("vmeta:      %lu bytes \n", qstfsx->f_vmeta);
	printf("vdata:      %lu bytes \n", qstfsx->f_vdata);
}

static void show_statx(void)
{
	struct silofs_ioc_query query = { .qtype = SILOFS_QUERY_STATX };
	const struct silofs_query_statx *qstatx = &query.u.statx;
	const struct statx *stx = &query.u.statx.stx;

	show_do_ioctl_query(&query);
	printf("blksize:    %ld \n", (long)stx->stx_blksize);
	printf("nlink:      %u  \n",  stx->stx_nlink);
	printf("uid:        %u  \n",  stx->stx_uid);
	printf("gid:        %u  \n",  stx->stx_gid);
	printf("mode:       0%o \n",  stx->stx_mode);
	printf("ino:        %ld \n", (long)stx->stx_ino);
	printf("size:       %ld \n", (long)stx->stx_size);
	printf("blocks:     %ld \n", (long)stx->stx_blocks);
	printf("mnt_id:     %ld \n", (long)stx->stx_mnt_id);
	printf("iflags:     %x  \n",  qstatx->stx_iflags);
	printf("dirflags:   %x  \n",  qstatx->stx_dirflags);
}

static void show_execute(void)
{
	switch (show_subcmd_qtype()) {
	case SILOFS_QUERY_VERSION:
		show_version();
		break;
	case SILOFS_QUERY_REPO:
		show_repo();
		break;
	case SILOFS_QUERY_FSNAME:
		show_fsname();
		break;
	case SILOFS_QUERY_STATFSX:
		show_statfsx();
		break;
	case SILOFS_QUERY_STATX:
		show_statx();
		break;
	case SILOFS_QUERY_NONE:
	default:
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_execute_show(void)
{
	/* Do all cleanups upon exits */
	show_start();

	/* Parse command's arguments */
	show_getopt();

	/* Verify user's arguments */
	show_setup_check_params();

	/* Do actual query + show */
	show_execute();

	/* Post execution cleanups */
	show_finalize();
}


