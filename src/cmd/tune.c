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

static void cmd_tune_getopt(struct cmd_tune_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "ftype", required_argument, NULL, 't' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("t:L:h", opts);
		if (opt_chr == 't') {
			ctx->in_args.ftype =
			        cmd_parse_str_as_uint32_within(optarg, 1, 2);
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_tune_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg_or_cwd("dirpath", &ctx->in_args.dirpath);
	cmd_endargs();
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
	cmd_realpath(ctx->in_args.dirpath, &ctx->in_args.dirpath_real);
	cmd_check_isdir(ctx->in_args.dirpath_real, true);
	cmd_check_fusefs(ctx->in_args.dirpath_real);
}

static void cmd_tune_set_iflags(struct cmd_tune_ctx *ctx)
{
	if (ctx->in_args.ftype == 2) {
		ctx->iflags_want = SILOFS_INODEF_FTYPE2;
	} else if (ctx->in_args.ftype == 1) {
		ctx->iflags_dont = SILOFS_INODEF_FTYPE2;
	} else {
		cmd_dief(0, "must provide ftype: %s", "1|2");
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
		cmd_dief(err, "failed to open: %s", dirpath);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_IOC_TUNE, &ctx->ioc->tune);
	if (err) {
		cmd_dief(err, "ioctl error: %s", dirpath);
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
	cmd_tune_getopt(&ctx);

	/* Verify user's arguments */
	cmd_tune_prepare(&ctx);

	/* Require valid iflags masks */
	cmd_tune_set_iflags(&ctx);

	/* Do actual tune */
	cmd_tune_execute(&ctx);

	/* Post execution cleanups */
	cmd_tune_finalize(&ctx);
}


