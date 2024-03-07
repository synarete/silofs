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

static const char *cmd_xsend_help_desc[] = {
	"xsend [options] <repodir/name>",
	"",
	"options:",
	"  -V, --view                   Display only logical addresses"
	"  -L, --loglevel=level         Logging level (rfc5424)",
	NULL
};

struct cmd_xsend_in_args {
	char   *repodir_name;
	char   *repodir;
	char   *repodir_real;
	char   *name;
	char   *password;
	bool    viewonly;
};

struct cmd_xsend_ctx {
	struct cmd_xsend_in_args in_args;
	struct silofs_fs_args   fs_args;
	struct silofs_fs_ctx   *fs_ctx;
	FILE *out_fp;
	bool has_lockfile;
};

static struct cmd_xsend_ctx *cmd_xsend_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_xsend_getopt(struct cmd_xsend_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "view", no_argument, NULL, 'V' },
		{ "password", required_argument, NULL, 'p' },
		{ "loglevel", required_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("Vp:L:h", opts);
		if (opt_chr == 'V') {
			ctx->in_args.viewonly = true;
		} else if (opt_chr == 'p') {
			cmd_getoptarg("--password", &ctx->in_args.password);
		} else if (opt_chr == 'L') {
			cmd_set_log_level_by(optarg);
		} else if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_xsend_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("repodir/name", &ctx->in_args.repodir_name);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_xsend_acquire_lockfile(struct cmd_xsend_ctx *ctx)
{
	if (!ctx->has_lockfile) {
		cmd_lockfile_acquire1(ctx->in_args.repodir_real,
		                      ctx->in_args.name);
		ctx->has_lockfile = true;
	}
}

static void cmd_xsend_release_lockfile(struct cmd_xsend_ctx *ctx)
{
	if (ctx->has_lockfile) {
		cmd_lockfile_release(ctx->in_args.repodir_real,
		                     ctx->in_args.name);
		ctx->has_lockfile = false;
	}
}

static void cmd_xsend_destroy_fs_ctx(struct cmd_xsend_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
}

static void cmd_xsend_finalize(struct cmd_xsend_ctx *ctx)
{
	cmd_del_fs_ctx(&ctx->fs_ctx);
	cmd_bconf_reset(&ctx->fs_args.bconf);
	cmd_pstrfree(&ctx->in_args.repodir_name);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.name);
	cmd_delpass(&ctx->in_args.password);
	cmd_xsend_ctx = NULL;
}

static void cmd_xsend_atexit(void)
{
	if (cmd_xsend_ctx != NULL) {
		cmd_xsend_release_lockfile(cmd_xsend_ctx);
		cmd_xsend_finalize(cmd_xsend_ctx);
	}
}

static void cmd_xsend_start(struct cmd_xsend_ctx *ctx)
{
	cmd_xsend_ctx = ctx;
	atexit(cmd_xsend_atexit);
}

static void cmd_xsend_enable_signals(void)
{
	cmd_register_sigactions(NULL);
}

static void cmd_xsend_prepare(struct cmd_xsend_ctx *ctx)
{
	cmd_check_exists(ctx->in_args.repodir_name);
	cmd_check_isreg(ctx->in_args.repodir_name, false);
	cmd_split_path(ctx->in_args.repodir_name,
	               &ctx->in_args.repodir, &ctx->in_args.name);
	cmd_check_nonemptydir(ctx->in_args.repodir, false);
	cmd_realpath(ctx->in_args.repodir, &ctx->in_args.repodir_real);
	cmd_check_repopath(ctx->in_args.repodir_real);
	cmd_check_fsname(ctx->in_args.name);
}

static void cmd_xsend_getpass(struct cmd_xsend_ctx *ctx)
{
	if (ctx->in_args.password == NULL) {
		cmd_getpass(NULL, &ctx->in_args.password);
	}
}

static void cmd_xsend_setup_fs_args(struct cmd_xsend_ctx *ctx)
{
	struct silofs_fs_args *fs_args = &ctx->fs_args;

	cmd_init_fs_args(fs_args);
	cmd_bconf_set_name(&fs_args->bconf, ctx->in_args.name);
	fs_args->passwd = ctx->in_args.password;
	fs_args->repodir = ctx->in_args.repodir_real;
	fs_args->name = ctx->in_args.name;
}

static void cmd_xsend_load_bconf(struct cmd_xsend_ctx *ctx)
{
	cmd_bconf_load(&ctx->fs_args.bconf, ctx->in_args.repodir_real);
}

static void cmd_xsend_setup_fs_ctx(struct cmd_xsend_ctx *ctx)
{
	cmd_new_fs_ctx(&ctx->fs_ctx, &ctx->fs_args);
}

static void cmd_xsend_open_repo(struct cmd_xsend_ctx *ctx)
{
	cmd_open_repo(ctx->fs_ctx);
}

static void cmd_xsend_require_brec(struct cmd_xsend_ctx *ctx)
{
	cmd_require_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_xsend_boot_fs(struct cmd_xsend_ctx *ctx)
{
	cmd_boot_fs(ctx->fs_ctx, &ctx->fs_args.bconf);
}

static void cmd_xsend_open_fs(struct cmd_xsend_ctx *ctx)
{
	cmd_open_fs(ctx->fs_ctx);
}

static void cmd_xsend_segaddr(const struct cmd_xsend_ctx *ctx,
                              const struct silofs_laddr *laddr)
{
	struct silofs_strbuf sbuf;

	silofs_laddr_to_base64(laddr, &sbuf);
	fputs(sbuf.str, ctx->out_fp);
	fputs(" ", ctx->out_fp);
}

static void cmd_xsend_load_seg(const struct cmd_xsend_ctx *ctx,
                               const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(ctx->fs_ctx->repo, laddr, seg);
	if (err) {
		cmd_dief(err, "failed to read: ltype=%d", laddr->ltype);
	}
}

static void cmd_xsend_load_brec(const struct cmd_xsend_ctx *ctx,
                                const struct silofs_laddr *laddr,
                                struct silofs_bootrec1k *out_brec1k)
{
	int err;

	err = silofs_repo_load_obj(ctx->fs_ctx->repo, laddr, out_brec1k);
	if (err) {
		cmd_dief(err, "failed to load: ltype=%d", laddr->ltype);
	}
}

static void cmd_xsend_print_seg(const struct cmd_xsend_ctx *ctx,
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
	fputs(enc, ctx->out_fp);
	cmd_zfree(enc, enc_len);
}

static void cmd_xsend_segdata(const struct cmd_xsend_ctx *ctx,
                              const struct silofs_laddr *laddr)
{
	const size_t seg_len = laddr->len;
	void *seg = NULL;

	seg = cmd_zalloc(seg_len);
	cmd_xsend_load_seg(ctx, laddr, seg);
	cmd_xsend_print_seg(ctx, seg, seg_len);
	cmd_zfree(seg, seg_len);
}

static void cmd_xsend_bootrec(const struct cmd_xsend_ctx *ctx,
                              const struct silofs_laddr *laddr)
{
	struct silofs_bootrec1k brec1k;

	cmd_xsend_load_brec(ctx, laddr, &brec1k);
	cmd_xsend_print_seg(ctx, &brec1k, sizeof(brec1k));
}

static void cmd_xsend_callback(void *user_ctx,
                               const struct silofs_laddr *laddr)
{
	const struct cmd_xsend_ctx *ctx = user_ctx;

	cmd_xsend_segaddr(ctx, laddr);
	if (!ctx->in_args.viewonly) {
		if (laddr->ltype == SILOFS_LTYPE_BOOTREC) {
			cmd_xsend_bootrec(ctx, laddr);
		} else {
			cmd_xsend_segdata(ctx, laddr);
		}
	}
	fputs("\n", ctx->out_fp);
	fflush(ctx->out_fp);
}

static void cmd_xsend_execute(struct cmd_xsend_ctx *ctx)
{
	cmd_inspect_fs(ctx->fs_ctx, cmd_xsend_callback, ctx);
}

static void cmd_xsend_close_repo(struct cmd_xsend_ctx *ctx)
{
	cmd_close_repo(ctx->fs_ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_execute_xsend(void)
{
	struct cmd_xsend_ctx ctx = {
		.fs_ctx = NULL,
		.out_fp = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_xsend_start(&ctx);

	/* Parse command's arguments */
	cmd_xsend_getopt(&ctx);

	/* Verify user's arguments */
	cmd_xsend_prepare(&ctx);

	/* Require password */
	cmd_xsend_getpass(&ctx);

	/* Run with signals */
	cmd_xsend_enable_signals();

	/* Setup input arguments */
	cmd_xsend_setup_fs_args(&ctx);

	/* Require ids-map */
	cmd_xsend_load_bconf(&ctx);

	/* Setup execution environment */
	cmd_xsend_setup_fs_ctx(&ctx);

	/* Acquire lock */
	cmd_xsend_acquire_lockfile(&ctx);

	/* Open repository */
	cmd_xsend_open_repo(&ctx);

	/* Require valid boot-record */
	cmd_xsend_require_brec(&ctx);

	/* Require boot-able file-system */
	cmd_xsend_boot_fs(&ctx);

	/* Open file-system */
	cmd_xsend_open_fs(&ctx);

	/* Do actual xsend */
	cmd_xsend_execute(&ctx);

	/* Close repository */
	cmd_xsend_close_repo(&ctx);

	/* Release lock */
	cmd_xsend_release_lockfile(&ctx);

	/* Destroy environment instance */
	cmd_xsend_destroy_fs_ctx(&ctx);

	/* Post execution cleanups */
	cmd_xsend_finalize(&ctx);
}

