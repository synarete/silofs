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
#include "cmd.h"

static const char *cmd_export_help_desc[] = {
	"export --ref=id <repodir> [--outfile=path]",
	"",
	"options:",
	"  -r, --ref=id                 Reference id",
	"  -f, --outfile=path           Output file (default: stdout)",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_export_in_args {
	char   *repodir;
	char   *repodir_real;
	char   *outfile;
	char   *ref;
};

struct cmd_export_ctx {
	struct cmd_export_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	struct silofs_laddr     refid;
	FILE *output;
	bool has_repolock;
};

static struct cmd_export_ctx *cmd_export_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_export_getopt(struct cmd_export_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "ref", required_argument, NULL, 'r' },
		{ "outfile", required_argument, NULL, 'f' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("r:f:L:h", opts);
		if (opt_chr == 'r') {
			ctx->in_args.ref = cmd_strdup(optarg);
		} else if (opt_chr == 'f') {
			ctx->in_args.outfile = cmd_strdup(optarg);
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_export_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir", &ctx->in_args.repodir);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_export_lock_repo(struct cmd_export_ctx *ctx)
{
	if (!ctx->has_repolock) {
		/* TODO: lock-repo */
		ctx->has_repolock = true;
	}
}

static void cmd_export_unlock_repo(struct cmd_export_ctx *ctx)
{
	if (ctx->has_repolock) {
		/* TODO: unlock-repo */
		ctx->has_repolock = false;
	}
}

static void cmd_export_open_output(struct cmd_export_ctx *ctx)
{
	if (ctx->in_args.outfile != NULL) {
		ctx->output = fopen(ctx->in_args.outfile, "w+");
		if (ctx->output == NULL) {
			cmd_dief(errno, "failed to open output: %s",
			         ctx->in_args.outfile);
		}
	} else {
		ctx->output = stdout;
	}
}

static void cmd_export_close_output(struct cmd_export_ctx *ctx)
{
	if ((ctx->output != NULL) && (ctx->output != stdout)) {
		if (fclose(ctx->output) != 0) {
			cmd_dief(errno, "failed to close output: %s",
			         ctx->in_args.outfile);
		}
		ctx->output = NULL;
	}
}

static void cmd_export_destroy_fs_ctx(struct cmd_export_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_export_finalize(struct cmd_export_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_bconf_reset(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.ref);
	cmd_pstrfree(&ctx->in_args.outfile);
	cmd_export_ctx = NULL;
}

static void cmd_export_atexit(void)
{
	if (cmd_export_ctx != NULL) {
		cmd_export_unlock_repo(cmd_export_ctx);
		cmd_export_close_output(cmd_export_ctx);
		cmd_export_finalize(cmd_export_ctx);
	}
}

static void cmd_export_start(struct cmd_export_ctx *ctx)
{
	cmd_export_ctx = ctx;
	atexit(cmd_export_atexit);
}

static void cmd_export_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_export_prepare(struct cmd_export_ctx *ctx)
{
	cmd_parse_str_as_refid(ctx->in_args.ref, &ctx->refid);
	cmd_check_exists(ctx->in_args.repodir);
	cmd_check_nonemptydir(ctx->in_args.repodir, false);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
}

static void cmd_export_setup_fs_args(struct cmd_export_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	fs_args->repodir = ctx->in_args.repodir_real;
}

static void cmd_export_setup_fs_ctx(struct cmd_export_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_export_open_repo(struct cmd_export_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_export_close_repo(struct cmd_export_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_export_load_seg(const struct cmd_export_ctx *ctx,
                                const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(ctx->fs_ctx->repo, laddr, seg);
	if (err) {
		cmd_dief(err, "failed to read: ltype=%d len=%zu",
		         laddr->ltype, laddr->len);
	}
}

static void cmd_export_load_brec(const struct cmd_export_ctx *ctx,
                                 const struct silofs_laddr *laddr,
                                 struct silofs_bootrec1k *out_brec1k)
{
	int err;

	err = silofs_repo_load_obj(ctx->fs_ctx->repo, laddr, out_brec1k);
	if (err) {
		cmd_dief(err, "failed to load: ltype=%d len=%zu",
		         laddr->ltype, laddr->len);
	}
}

static void cmd_export_print_seg(const struct cmd_export_ctx *ctx,
                                 const void *seg, size_t seg_len)
{
	const size_t enc_len = silofs_base64_encode_len(seg_len) + 1;
	size_t len = 0;
	char *enc = NULL;
	int err;

	enc = cmd_zalloc(enc_len);
	err = silofs_base64_encode(seg, seg_len, enc, enc_len, &len);
	if (err) {
		cmd_dief(err, "base64 encode failure");
	}
	enc[len] = '\0';
	fputs(enc, ctx->output);
	cmd_zfree(enc, enc_len);
}

static void cmd_export_segdata(const struct cmd_export_ctx *ctx,
                               const struct silofs_laddr *laddr)
{
	const size_t seg_len = laddr->len;
	void *seg = NULL;

	seg = cmd_zalloc(seg_len);
	cmd_export_load_seg(ctx, laddr, seg);
	cmd_export_print_seg(ctx, seg, seg_len);
	cmd_zfree(seg, seg_len);
}

static void cmd_export_bootrec(const struct cmd_export_ctx *ctx,
                               const struct silofs_laddr *laddr)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 0xFFFFFFFF };

	cmd_export_load_brec(ctx, laddr, &brec1k);
	cmd_export_print_seg(ctx, &brec1k, sizeof(brec1k));
}

static void cmd_export_ref(const struct cmd_export_ctx *ctx)
{
	const struct silofs_laddr *laddr = &ctx->refid;

	if (laddr->ltype == SILOFS_LTYPE_BOOTREC) {
		cmd_export_bootrec(ctx, laddr);
	} else {
		cmd_export_segdata(ctx, laddr);
	}
	fputs("\n", ctx->output);
	fflush(ctx->output);
}

static void cmd_export_execute(struct cmd_export_ctx *ctx)
{
	cmd_export_open_output(ctx);
	cmd_export_ref(ctx);
	cmd_export_close_output(ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_export(void)
{
	struct cmd_export_ctx ctx = {
		.fs_ctx = NULL,
		.output = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_export_start(&ctx);

	/* Parse command's arguments */
	cmd_export_getopt(&ctx);

	/* Verify user's arguments */
	cmd_export_prepare(&ctx);

	/* Run with signals */
	cmd_export_enable_signals();

	/* Acquire global repo-lock */
	cmd_export_lock_repo(&ctx);

	/* Setup input arguments */
	cmd_export_setup_fs_args(&ctx);

	/* Setup execution environment */
	cmd_export_setup_fs_ctx(&ctx);

	/* Open repository */
	cmd_export_open_repo(&ctx);

	/* Do actual export */
	cmd_export_execute(&ctx);

	/* Close repository */
	cmd_export_close_repo(&ctx);

	/* Destroy environment instance */
	cmd_export_destroy_fs_ctx(&ctx);

	/* Release global-repo lock */
	cmd_export_unlock_repo(&ctx);

	/* Post execution cleanups */
	cmd_export_finalize(&ctx);
}

