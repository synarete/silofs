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

static const char *cmd_import_help_desc[] = {
	"import --ref=id [--infile=path] <repodir>",
	"",
	"options:",
	"  -r, --ref=id                 Reference id",
	"  -f, --infile=path            Input file (default: stdin)",
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_import_in_args {
	char   *repodir;
	char   *repodir_real;
	char   *infile;
	char   *ref;
};

struct cmd_import_ctx {
	struct cmd_import_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	struct silofs_laddr     refid;
	FILE *input;
	int repolock_fd;
	bool has_repolock;
};

static struct cmd_import_ctx *cmd_import_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_import_getopt(struct cmd_import_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "ref", required_argument, NULL, 'r' },
		{ "infile", required_argument, NULL, 'f' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("r:f:L:h", opts);
		if (opt_chr == 'r') {
			ctx->in_args.ref = cmd_strdup(optarg);
		} else if (opt_chr == 'f') {
			ctx->in_args.infile = cmd_strdup(optarg);
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_import_help_desc);
		} else if (opt_chr > 0) {
			cmd_getopt_unrecognized();
		}
	}
	cmd_getopt_getarg("repodir", &ctx->in_args.repodir);
	cmd_getopt_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_import_lock_repo(struct cmd_import_ctx *ctx)
{
	if (!ctx->has_repolock) {
		cmd_wrlock_repo(ctx->in_args.repodir, &ctx->repolock_fd);
		ctx->has_repolock = true;
	}
}

static void cmd_import_unlock_repo(struct cmd_import_ctx *ctx)
{
	if (ctx->has_repolock) {
		cmd_unlock_repo(ctx->in_args.repodir, &ctx->repolock_fd);
		ctx->has_repolock = false;
	}
}

static void cmd_import_open_input(struct cmd_import_ctx *ctx)
{
	if (ctx->in_args.infile != NULL) {
		ctx->input = fopen(ctx->in_args.infile, "r");
		if (ctx->input == NULL) {
			cmd_dief(errno, "failed to open input: %s",
			         ctx->in_args.infile);
		}
	} else {
		ctx->input = stdin;
	}
}

static void cmd_import_close_input(struct cmd_import_ctx *ctx)
{
	if ((ctx->input != NULL) && (ctx->input != stdin)) {
		if (fclose(ctx->input) != 0) {
			cmd_dief(errno, "failed to close input: %s",
			         ctx->in_args.infile);
		}
		ctx->input = NULL;
	}
}

static void cmd_import_destroy_fs_ctx(struct cmd_import_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_import_finalize(struct cmd_import_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_bconf_reset(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.ref);
	cmd_pstrfree(&ctx->in_args.infile);
	cmd_import_ctx = NULL;
}

static void cmd_import_atexit(void)
{
	if (cmd_import_ctx != NULL) {
		cmd_import_unlock_repo(cmd_import_ctx);
		cmd_import_close_input(cmd_import_ctx);
		cmd_import_finalize(cmd_import_ctx);
	}
}

static void cmd_import_start(struct cmd_import_ctx *ctx)
{
	cmd_import_ctx = ctx;
	atexit(cmd_import_atexit);
}

static void cmd_import_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_import_prepare(struct cmd_import_ctx *ctx)
{
	cmd_parse_str_as_refid(ctx->in_args.ref, &ctx->refid);
	cmd_check_exists(ctx->in_args.repodir);
	cmd_check_nonemptydir(ctx->in_args.repodir, false);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
}

static void cmd_import_setup_fs_args(struct cmd_import_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	fs_args->repodir = ctx->in_args.repodir_real;
}

static void cmd_import_setup_fs_ctx(struct cmd_import_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_import_open_repo(struct cmd_import_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_import_close_repo(struct cmd_import_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

static void cmd_import_save_seg(const struct cmd_import_ctx *ctx,
                                const struct silofs_laddr *laddr, void *seg)
{
	const struct iovec iov = {
		.iov_base = seg,
		.iov_len = laddr->len
	};
	int err;

	err = silofs_repo_writev_at(ctx->fs_ctx->repo, laddr, &iov, 1);
	if (err) {
		cmd_dief(err, "failed to save: ltype=%d len=%zu",
		         laddr->ltype, laddr->len);
	}
}

static void cmd_import_save_brec(const struct cmd_import_ctx *ctx,
                                 const struct silofs_laddr *laddr,
                                 const struct silofs_bootrec1k *brec1k)
{
	int err;

	err = silofs_repo_save_obj(ctx->fs_ctx->repo, laddr, brec1k);
	if (err) {
		cmd_dief(err, "failed to save: ltype=%d len=%zu",
		         laddr->ltype, laddr->len);
	}
}

static const char *cmd_import_infile_name(const struct cmd_import_ctx *ctx)
{
	const char *infile = ctx->in_args.infile;

	return (infile != NULL) ? infile : "stdin";
}

static void cmd_import_fetch_seg(const struct cmd_import_ctx *ctx,
                                 void *seg, size_t seg_len)
{
	const char *input_name = cmd_import_infile_name(ctx);
	const size_t enc_len = silofs_base64_encode_len(seg_len) + 2;
	size_t len = 0;
	size_t nrd = 0;
	char *enc = NULL;
	int err;

	enc = cmd_zalloc(enc_len);
	len = fread(enc, 1, enc_len, ctx->input);
	err = ferror(ctx->input);
	if (err) {
		cmd_dief(err, "input error: %s", input_name);
	}
	if ((len < 1024) || (len >= enc_len)) {
		cmd_dief(0, "illegal input length: len=%zu %s",
		         len, input_name);
	}
	err = silofs_base64_decode(enc, len, seg, seg_len, &len, &nrd);
	if (err) {
		cmd_dief(err, "base64 decode failure: %s", input_name);
	}
	if (len != seg_len) {
		cmd_dief(0, "bad input length: len=%zu %s",
		         len, input_name);
	}
	cmd_zfree(enc, enc_len);
}

static void cmd_import_segdata(const struct cmd_import_ctx *ctx,
                               const struct silofs_laddr *laddr)
{
	const size_t seg_len = laddr->len;
	void *seg = NULL;

	seg = cmd_zalloc(seg_len);
	cmd_import_fetch_seg(ctx, seg, seg_len);
	cmd_import_save_seg(ctx, laddr, seg);
	cmd_zfree(seg, seg_len);
}

static void cmd_import_bootrec(const struct cmd_import_ctx *ctx,
                               const struct silofs_laddr *laddr)
{
	struct silofs_bootrec1k brec1k = { .br_magic = 0xFFFFFFFF };

	cmd_import_fetch_seg(ctx, &brec1k, sizeof(brec1k));
	cmd_import_save_brec(ctx, laddr, &brec1k);
}

static void cmd_import_ref(const struct cmd_import_ctx *ctx)
{
	const struct silofs_laddr *laddr = &ctx->refid;

	if (laddr->ltype == SILOFS_LTYPE_BOOTREC) {
		cmd_import_bootrec(ctx, laddr);
	} else {
		cmd_import_segdata(ctx, laddr);
	}
}

static void cmd_import_execute(struct cmd_import_ctx *ctx)
{
	cmd_import_open_input(ctx);
	cmd_import_ref(ctx);
	cmd_import_close_input(ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_import(void)
{
	struct cmd_import_ctx ctx = {
		.fs_ctx = NULL,
		.input = stdout,
		.repolock_fd = -1,
	};

	/* Do all cleanups upon exits */
	cmd_import_start(&ctx);

	/* Parse command's arguments */
	cmd_import_getopt(&ctx);

	/* Verify user's arguments */
	cmd_import_prepare(&ctx);

	/* Run with signals */
	cmd_import_enable_signals();

	/* Acquire global repo-lock */
	cmd_import_lock_repo(&ctx);

	/* Setup input arguments */
	cmd_import_setup_fs_args(&ctx);

	/* Setup execution environment */
	cmd_import_setup_fs_ctx(&ctx);

	/* Open repository */
	cmd_import_open_repo(&ctx);

	/* Do actual import */
	cmd_import_execute(&ctx);

	/* Close repository */
	cmd_import_close_repo(&ctx);

	/* Destroy environment instance */
	cmd_import_destroy_fs_ctx(&ctx);

	/* Release global-repo lock */
	cmd_import_unlock_repo(&ctx);

	/* Post execution cleanups */
	cmd_import_finalize(&ctx);
}

