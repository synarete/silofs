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

static const char *cmd_sync_help_desc[] = {
	"sync [<pathname>]",
	"",
	"options:",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_sync_in_args {
	char   *pathname;
	char   *pathname_real;
};

struct cmd_sync_ctx {
	struct cmd_sync_in_args in_args;
	union silofs_ioc_u     *ioc;
};

static struct cmd_sync_ctx *cmd_sync_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_sync_parse_optargs(struct cmd_sync_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
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
		case 'L':
			cmd_optargs_set_loglevel(&opa);
			break;
		case 'h':
			cmd_print_help_and_exit(cmd_sync_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}
	ctx->in_args.pathname = cmd_optargs_getarg(&opa, "pathname");
	cmd_optargs_endargs(&opa);
	cmd_optargs_fini(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_sync_finalize(struct cmd_sync_ctx *ctx)
{
	cmd_pstrfree(&ctx->in_args.pathname_real);
	cmd_pstrfree(&ctx->in_args.pathname);
	cmd_del_iocp(&ctx->ioc);
	cmd_sync_ctx = NULL;
}

static void cmd_sync_atexit(void)
{
	if (cmd_sync_ctx != NULL) {
		cmd_sync_finalize(cmd_sync_ctx);
	}
}

static void cmd_sync_start(struct cmd_sync_ctx *ctx)
{
	cmd_sync_ctx = ctx;
	atexit(cmd_sync_atexit);
}

static void cmd_sync_prepare(struct cmd_sync_ctx *ctx)
{
	ctx->ioc = cmd_new_ioc();
	cmd_realpath(ctx->in_args.pathname, &ctx->in_args.pathname_real);
	cmd_check_reg_or_dir(ctx->in_args.pathname_real);
	cmd_check_fusefs(ctx->in_args.pathname_real);
}

static void cmd_sync_execute(struct cmd_sync_ctx *ctx)
{
	const char *pathname = ctx->in_args.pathname_real;
	int fd = -1;
	int err;

	cmd_reset_ioc(ctx->ioc);
	err = silofs_sys_open(pathname, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", pathname);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_IOC_SYNCFS, &ctx->ioc->syncfs);
	if (err) {
		cmd_die(err, "ioctl error: %s", pathname);
	}
	silofs_sys_close(fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_sync(void)
{
	struct cmd_sync_ctx ctx = {
		.ioc = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_sync_start(&ctx);

	/* Parse command's arguments */
	cmd_sync_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_sync_prepare(&ctx);

	/* Do actual sync(fs) */
	cmd_sync_execute(&ctx);

	/* Post execution cleanups */
	cmd_sync_finalize(&ctx);
}
