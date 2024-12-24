/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#define _GNU_SOURCE 1
#include "cmd.h"

static const char *cmd_lsmnt_help_desc =
	"lsmnt [options]                                                 \n"
	"                                                                \n"
	"options:                                                        \n"
	"  -l, --long                   Long listing format              \n";

struct cmd_lsmnt_in_args {
	char *mntpoint;
	char *mntpoint_real;
	bool long_listing;
};

struct cmd_lsmnt_ctx {
	struct cmd_lsmnt_in_args in_args;
	struct silofs_ioc_query ioc_qry;
	FILE *out_fp;
};

static struct cmd_lsmnt_ctx *cmd_lsmnt_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_lsmnt_parse_optargs(struct cmd_lsmnt_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "long", 'l', 0 },
		{ "help", 'h', 0 },
		{ NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'l':
			ctx->in_args.long_listing = true;
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_lsmnt_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
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

static void cmd_lsmnt_short(const struct cmd_lsmnt_ctx *ctx,
                            const struct cmd_proc_mntinfo *mi)
{
	fprintf(ctx->out_fp, "%s\n", mi->mntdir);
}

static void
cmd_lsmnt_long(struct cmd_lsmnt_ctx *ctx, const struct cmd_proc_mntinfo *mi)
{
	struct silofs_ioc_query *qry = &ctx->ioc_qry;
	char *mntd_path = NULL;
	char *repo_path = NULL;
	char *boot_name = NULL;
	char *boot_addr = NULL;
	char *fs_uuid = NULL;
	const int o_flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_DIRECTORY;
	int dfd = -1;
	int err = 0;

	mntd_path = cmd_strdup(mi->mntdir);
	err = silofs_sys_openat(AT_FDCWD, mntd_path, o_flags, 0, &dfd);
	if (err) {
		goto out;
	}

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_REPO;
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	repo_path = cmd_strdup(qry->u.repo.path);

	silofs_memzero(qry, sizeof(*qry));
	qry->qtype = SILOFS_QUERY_BOOT;
	err = silofs_sys_ioctlp(dfd, SILOFS_IOC_QUERY, qry);
	if (err) {
		goto out;
	}
	boot_name = cmd_strdup(qry->u.boot.name);
	boot_addr = cmd_strdup(qry->u.boot.addr);
	fs_uuid = cmd_struuid(qry->u.boot.fs_uuid);

	fprintf(ctx->out_fp, "%s %s/%s %s %s", mntd_path, repo_path, boot_name,
	        boot_addr, fs_uuid);
out:
	fputs("\n", ctx->out_fp);
	fflush(ctx->out_fp);
	silofs_sys_closefd(&dfd);
	cmd_pstrfree(&mntd_path);
	cmd_pstrfree(&repo_path);
	cmd_pstrfree(&boot_name);
	cmd_pstrfree(&boot_addr);
	cmd_pstrfree(&fs_uuid);
}

static void cmd_lsmnt_execute(struct cmd_lsmnt_ctx *ctx)
{
	struct cmd_proc_mntinfo *mi_list = NULL;
	const struct cmd_proc_mntinfo *mi_iter = NULL;

	mi_list = cmd_parse_mountinfo();
	for (mi_iter = mi_list; mi_iter != NULL; mi_iter = mi_iter->next) {
		if (ctx->in_args.long_listing) {
			cmd_lsmnt_long(ctx, mi_iter);
		} else {
			cmd_lsmnt_short(ctx, mi_iter);
		}
	}
	cmd_free_mountinfo(mi_list);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_lsmnt(void)
{
	struct cmd_lsmnt_ctx ctx = {
		.ioc_qry.qtype = SILOFS_QUERY_NONE,
		.out_fp = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_lsmnt_start(&ctx);

	/* Parse command's arguments */
	cmd_lsmnt_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_lsmnt_prepare(&ctx);

	/* Read mount info and print */
	cmd_lsmnt_execute(&ctx);

	/* Post execution cleanups */
	cmd_lsmnt_finalize(&ctx);
}
