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
#include <sys/mount.h>
#include "cmd.h"

static const char *cmd_show_usage[] = {
	"show <subcmd> <pathname>",
	"",
	"sub commands:",
	"  version      Show mounted file-system's version",
	"  reponame     Show back-end repo dir-path and fs-name",
	"  statfsx      Show extended file-system info",
	"  statx        Show extended file stats",
	NULL
};

struct cmd_show_args {
	char   *pathname;
	char   *pathname_real;
	char   *subcmd;
};

struct cmd_show_ctx {
	struct cmd_show_args    args;
	struct silofs_ioc_query query;
	enum silofs_query_type  qtype;
};

static struct cmd_show_ctx *cmd_show_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_show_getopt(struct cmd_show_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("h", opts);
		if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_show_usage);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("subcmd", &ctx->args.subcmd);
	cmd_getarg_or_cwd("pathname", &ctx->args.pathname);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *cmd_show_subcommands[] = {
	[SILOFS_QUERY_VERSION]  = "version",
	[SILOFS_QUERY_REPONAME] = "reponame",
	[SILOFS_QUERY_STATFSX]  = "statfsx",
	[SILOFS_QUERY_STATX]    = "statx",
};

static enum silofs_query_type cmd_show_qtype_by_subcmd(const char *subcmd)
{
	const int nelems = (int)SILOFS_ARRAY_SIZE(cmd_show_subcommands);

	for (int qtype = 0; qtype < nelems; ++qtype) {
		if ((cmd_show_subcommands[qtype] != NULL) &&
		    !strcmp(cmd_show_subcommands[qtype], subcmd)) {
			return (enum silofs_query_type)qtype;
		}
	}
	return SILOFS_QUERY_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_show_finalize(struct cmd_show_ctx *ctx)
{
	cmd_pstrfree(&ctx->args.pathname_real);
	cmd_pstrfree(&ctx->args.subcmd);
	cmd_pstrfree(&ctx->args.pathname);
	cmd_show_ctx = NULL;
}

static void cmd_show_atexit(void)
{
	if (cmd_show_ctx != NULL) {
		cmd_show_finalize(cmd_show_ctx);
	}
}

static void cmd_show_start(struct cmd_show_ctx *ctx)
{
	cmd_show_ctx = ctx;
	atexit(cmd_show_atexit);
}

static void cmd_show_prepare(struct cmd_show_ctx *ctx)
{
	cmd_realpath(ctx->args.pathname, &ctx->args.pathname_real);
	cmd_check_reg_or_dir(ctx->args.pathname_real);
}

static void cmd_show_resolve_subcmd(struct cmd_show_ctx *ctx)
{
	ctx->qtype = cmd_show_qtype_by_subcmd(ctx->args.subcmd);
	if (ctx->qtype == SILOFS_QUERY_NONE) {
		cmd_dief(0, "unknown sub-command %s", ctx->args.subcmd);
	}
	ctx->query.qtype = ctx->qtype;
}

static void cmd_show_do_ioctl_query(struct cmd_show_ctx *ctx)
{
	int fd = -1;
	int err;

	err = silofs_sys_open(ctx->args.pathname_real, O_RDONLY, 0, &fd);
	if (err) {
		cmd_dief(err, "failed to open: %s", ctx->args.pathname_real);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_FS_IOC_QUERY, &ctx->query);
	if (err) {
		cmd_dief(err, "ioctl error: %s", ctx->args.pathname_real);
	}
	silofs_sys_close(fd);
}

static void cmd_show_version(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	printf("%s\n", ctx->query.u.version.string);
}

static void cmd_show_repo(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	printf("%s/%s\n", ctx->query.u.reponame.repodir,
	       ctx->query.u.reponame.name);
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

static void cmd_show_statfsx(struct cmd_show_ctx *ctx)
{
	char mntfstr[128] = "";
	const struct silofs_query_statfsx *qstfsx = &ctx->query.u.statfsx;

	cmd_show_do_ioctl_query(ctx);
	msflags_str(qstfsx->msflags, mntfstr, sizeof(mntfstr) - 1);
	printf("mountf:     %s \n", mntfstr);
	printf("uptime:     %ld seconds \n", qstfsx->uptime);
	printf("bsize:      %lu bytes \n", qstfsx->bsize);
	printf("bused:      %lu bytes \n", qstfsx->bused);
	printf("ilimit:     %lu inodes \n", qstfsx->ilimit);
	printf("icurr:      %lu inodes \n", qstfsx->icurr);
	printf("umeta:      %lu bytes \n", qstfsx->umeta);
	printf("vmeta:      %lu bytes \n", qstfsx->vmeta);
	printf("vdata:      %lu bytes \n", qstfsx->vdata);
}

static void cmd_show_statx(struct cmd_show_ctx *ctx)
{
	const struct silofs_query_statx *qstatx = &ctx->query.u.statx;
	const struct statx *stx = &qstatx->stx;

	cmd_show_do_ioctl_query(ctx);
	printf("blksize:    %ld \n", (long)stx->stx_blksize);
	printf("nlink:      %u  \n",  stx->stx_nlink);
	printf("uid:        %u  \n",  stx->stx_uid);
	printf("gid:        %u  \n",  stx->stx_gid);
	printf("mode:       0%o \n",  stx->stx_mode);
	printf("ino:        %ld \n", (long)stx->stx_ino);
	printf("size:       %ld \n", (long)stx->stx_size);
	printf("blocks:     %ld \n", (long)stx->stx_blocks);
	/* printf("mnt_id:     %ld \n", (long)stx->stx_mnt_id); */
	printf("iflags:     %x  \n",  qstatx->iflags);
	printf("dirflags:   %x  \n",  qstatx->dirflags);
}

static void cmd_show_execute(struct cmd_show_ctx *ctx)
{
	switch (ctx->qtype) {
	case SILOFS_QUERY_VERSION:
		cmd_show_version(ctx);
		break;
	case SILOFS_QUERY_REPONAME:
		cmd_show_repo(ctx);
		break;
	case SILOFS_QUERY_STATFSX:
		cmd_show_statfsx(ctx);
		break;
	case SILOFS_QUERY_STATX:
		cmd_show_statx(ctx);
		break;
	case SILOFS_QUERY_NONE:
	default:
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_show(void)
{
	struct cmd_show_ctx ctx = {
		.qtype = SILOFS_QUERY_NONE
	};

	/* Do all cleanups upon exits */
	cmd_show_start(&ctx);

	/* Parse command's arguments */
	cmd_show_getopt(&ctx);

	/* Verify user's arguments */
	cmd_show_prepare(&ctx);

	/* Resolve sub-command to query-type */
	cmd_show_resolve_subcmd(&ctx);

	/* Do actual query + show */
	cmd_show_execute(&ctx);

	/* Post execution cleanups */
	cmd_show_finalize(&ctx);
}


