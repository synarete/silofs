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
#include "cmd.h"

static const char *cmd_lsmnt_help_desc[] = {
	"lsmnt [options]",
	"",
	"options:",
	"  -l, --long                   Long listing format",
	NULL
};

struct cmd_lsmnt_in_args {
	char   *mntpoint;
	char   *mntpoint_real;
	bool    long_listing;
};

struct cmd_lsmnt_ctx {
	struct cmd_lsmnt_in_args in_args;
	struct silofs_ioc_query  ioc_qry;
};

static struct cmd_lsmnt_ctx *cmd_lsmnt_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_lsmnt_getopt(struct cmd_lsmnt_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "long", no_argument, NULL, 'l' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("lh", opts);
		if (opt_chr == 'l') {
			ctx->in_args.long_listing = true;
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_lsmnt_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_lsmnt_finalize(struct cmd_lsmnt_ctx *ctx)
{
	memset(&ctx->ioc_qry, 0, sizeof(ctx->ioc_qry));
	cmd_lsmnt_ctx = NULL;
}

static void cmd_lsmnt_atexit(void)
{
	if (cmd_lsmnt_ctx != NULL) {
		cmd_lsmnt_finalize(cmd_lsmnt_ctx);
	}
}

static void cmd_lsmnt_start(struct cmd_lsmnt_ctx *ctx)
{
	cmd_lsmnt_ctx = ctx;
	atexit(cmd_lsmnt_atexit);
}

static void cmd_lsmnt_prepare(struct cmd_lsmnt_ctx *ctx)
{
	memset(&ctx->ioc_qry, 0, sizeof(ctx->ioc_qry));
}

static void cmd_lsmnt_exec_mi(struct cmd_lsmnt_ctx *ctx,
                              const struct cmd_proc_mntinfo *mi)
{
	struct silofs_ioc_query *qry = &ctx->ioc_qry;
	const char *repodir = "";
	const char *name = "";
	char sep = ' ';
	int o_flags;
	int dfd = -1;
	int err = 0;

	if (!ctx->in_args.long_listing) {
		goto out;
	}
	o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	err = silofs_sys_openat(AT_FDCWD, mi->mntdir, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}
	qry->qtype = SILOFS_QUERY_BOOT;
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	repodir = qry->u.bootrec.repo;
	name = qry->u.bootrec.name;
	sep = '/';
out:
	silofs_sys_closefd(&dfd);
	printf("%-16s %s%c%s\n", mi->mntdir, repodir, sep, name);
}

static void cmd_lsmnt_execute(struct cmd_lsmnt_ctx *ctx)
{
	struct cmd_proc_mntinfo *mi_list = NULL;
	const struct cmd_proc_mntinfo *mi_iter = NULL;

	mi_list = cmd_parse_mountinfo();
	for (mi_iter = mi_list; mi_iter != NULL; mi_iter = mi_iter->next) {
		cmd_lsmnt_exec_mi(ctx, mi_iter);
	}
	cmd_free_mountinfo(mi_list);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_lsmnt(void)
{
	struct cmd_lsmnt_ctx ctx = {
		.ioc_qry.qtype = 0,
	};

	/* Do all cleanups upon exits */
	cmd_lsmnt_start(&ctx);

	/* Parse command's arguments */
	cmd_lsmnt_getopt(&ctx);

	/* Verify user's arguments */
	cmd_lsmnt_prepare(&ctx);

	/* Read mount info and print */
	cmd_lsmnt_execute(&ctx);

	/* Post execution cleanups */
	cmd_lsmnt_finalize(&ctx);
}

