/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

static const char *cmd_tune_help_desc[] = {
	"tune --ftype=1|2 <dirpath>",
	"",
	"options:",
	"  -t, --ftype=1|2              Sub-type to assign to child files",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_tune_in_args {
	char   *dirpath;
	char   *dirpath_real;
	unsigned int ftype;
};

struct cmd_tune_ctx {
	struct cmd_tune_in_args in_args;
	union silofs_ioc_u     *ioc;
	enum silofs_inodef      iflags_want;
	enum silofs_inodef      iflags_dont;
};

static struct cmd_tune_ctx *cmd_tune_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_tune_parse_optargs(struct cmd_tune_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		{ "ftype", 't', 1 },
		{ "loglevel", 'L', 1 },
		{ "help", 'h', 0 },
		{ NULL, 0, 0 },
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_init(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 't':
			ctx->in_args.ftype =
			        cmd_optargs_curr_as_u32v(&opa, 1, 2);
			break;
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_tune_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}

	ctx->in_args.dirpath = cmd_optargs_getarg(&opa, "dirpath");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_tune_finalize(struct cmd_tune_ctx *ctx)
{
	cmd_pstrfree(&ctx->in_args.dirpath_real);
	cmd_pstrfree(&ctx->in_args.dirpath);
	cmd_del_iocp(&ctx->ioc);
	cmd_tune_ctx = NULL;
}

static void cmd_tune_atexit(void)
{
	if (cmd_tune_ctx != NULL) {
		cmd_tune_finalize(cmd_tune_ctx);
	}
}

static void cmd_tune_start(struct cmd_tune_ctx *ctx)
{
	cmd_tune_ctx = ctx;
	atexit(cmd_tune_atexit);
}

static void cmd_tune_prepare(struct cmd_tune_ctx *ctx)
{
	ctx->ioc = cmd_new_ioc();
	cmd_realpath_dir(ctx->in_args.dirpath, &ctx->in_args.dirpath_real);
	cmd_check_fusefs(ctx->in_args.dirpath_real);
}

static void cmd_tune_set_iflags(struct cmd_tune_ctx *ctx)
{
	if (ctx->in_args.ftype == 2) {
		ctx->iflags_want = SILOFS_INODEF_FTYPE2;
	} else if (ctx->in_args.ftype == 1) {
		ctx->iflags_dont = SILOFS_INODEF_FTYPE2;
	} else {
		cmd_die(0, "must provide ftype: %s", "1|2");
	}
}

static void cmd_tune_execute(struct cmd_tune_ctx *ctx)
{
	const char *dirpath = ctx->in_args.dirpath_real;
	int fd = -1;
	int err;

	ctx->ioc->tune.iflags_want = ctx->iflags_want;
	ctx->ioc->tune.iflags_dont = ctx->iflags_dont;
	err = silofs_sys_open(dirpath, O_RDONLY | O_DIRECTORY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", dirpath);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_IOC_TUNE, &ctx->ioc->tune);
	if (err) {
		cmd_die(err, "ioctl error: %s", dirpath);
	}
	silofs_sys_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_tune(void)
{
	struct cmd_tune_ctx ctx = {
		.ioc = NULL,
		.iflags_want = 0,
		.iflags_dont = 0,
	};

	/* Do all cleanups upon exits */
	cmd_tune_start(&ctx);

	/* Parse command's arguments */
	cmd_tune_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_tune_prepare(&ctx);

	/* Require valid iflags masks */
	cmd_tune_set_iflags(&ctx);

	/* Do actual tune */
	cmd_tune_execute(&ctx);

	/* Post execution cleanups */
	cmd_tune_finalize(&ctx);
}
