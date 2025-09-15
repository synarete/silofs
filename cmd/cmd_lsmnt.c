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

static const char *const cmd_lsmnt_help_desc =
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

static struct cmd_lsmnt_ctx *cmd_lsmnt_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_lsmnt_parse_optargs(struct cmd_lsmnt_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "long", 'l', 0 },
		{ "help", 'h', 0 },
		{ nullptr, 0, 0 },
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
	cmd_lsmnt_ctx_p = nullptr;
}

static void cmd_lsmnt_atexit(void)
{
	struct cmd_lsmnt_ctx *ctx = cmd_lsmnt_ctx_p;

	if (ctx != nullptr) {
		cmd_lsmnt_finalize(ctx);
	}
}

static void cmd_lsmnt_start(struct cmd_lsmnt_ctx *ctx)
{
	cmd_lsmnt_ctx_p = ctx;
	cmd_atexit(cmd_lsmnt_atexit);
}

static void cmd_lsmnt_prepare(struct cmd_lsmnt_ctx *ctx)
{
	memset(&ctx->ioc_qry, 0, sizeof(ctx->ioc_qry));
}

static void cmd_lsmnt_short(const struct cmd_lsmnt_ctx *ctx,
                            const struct silofs_mntinfo *mi)
{
	fprintf(ctx->out_fp, "%s\n", mi->mntdir);
}

static void
cmd_lsmnt_long(struct cmd_lsmnt_ctx *ctx, const struct silofs_mntinfo *mi)
{
	struct silofs_ioc_query *qry = &ctx->ioc_qry;
	char *mntd_path = nullptr;
	char *repo_path = nullptr;
	char *boot_name = nullptr;
	char *boot_addr = nullptr;
	char *root_blobid = nullptr;
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
	boot_addr = cmd_strdup(qry->u.boot.xref);
	root_blobid = cmd_strdup(qry->u.boot.root_blobid);

	fprintf(ctx->out_fp, "%s %s/%s %s %s", mntd_path, repo_path, boot_name,
	        boot_addr, root_blobid);
out:
	fputs("\n", ctx->out_fp);
	fflush(ctx->out_fp);
	silofs_sys_closefd(&dfd);
	cmd_pstrfree(&mntd_path);
	cmd_pstrfree(&repo_path);
	cmd_pstrfree(&boot_name);
	cmd_pstrfree(&boot_addr);
	cmd_pstrfree(&root_blobid);
}

static void cmd_lsmnt_execute(struct cmd_lsmnt_ctx *ctx)
{
	struct silofs_mntinfos *minfos = nullptr;

	minfos = cmd_parse_mountinfo();
	for (size_t i = 0; i < minfos->ninfos; ++i) {
		if (ctx->in_args.long_listing) {
			cmd_lsmnt_long(ctx, &minfos->infos[i]);
		} else {
			cmd_lsmnt_short(ctx, &minfos->infos[i]);
		}
	}
	cmd_free_mountinfo(minfos);
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
