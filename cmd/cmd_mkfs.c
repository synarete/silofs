/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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

static const char *const cmd_mkfs_help_desc = {
	"mkfs --size=fssize [--name=fsname] [options...] <repodir>         \n"
	"                                                                  \n"
	"options:                                                          \n"
	"  -s, --size=nbytes            Capacity size limit                \n"
	"  -n, --name=fsname            File-system's name (default: main) \n"
	"  -u, --user=username          Primary user-name (fs owner)       \n"
	"  -G, --sup-groups             Allow owner's supplementary groups \n"
	"  -R, --allow-root             Allow root user and group          \n"
	"  -N, --no-utf8-names          Do not force UTF8 file names       \n"
	"  -L, --loglevel=level         Logging level (rfc5424)            \n"
};

struct cmd_mkfs_in_args {
	char *repodir;
	char *repodir_real;
	char *fsname;
	char *password;
	char *username;
	size_t fs_size;
	int flags;
	bool with_sup_groups;
	bool with_root_user;
};

struct cmd_mkfs_ctx {
	struct cmd_mkfs_in_args in_args;
	struct silofs_spec spec;
	struct silofs_env *env;
	int fslock;
	bool format_repo;
};

static struct cmd_mkfs_ctx *cmd_mkfs_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool
cmd_mkfs_parse_optarg_by(struct cmd_mkfs_ctx *ctx,
                         const struct cmd_optargs *opa, int opt_chr)
{
	bool done = false;

	switch (opt_chr) {
	case 's':
		ctx->in_args.fs_size = cmd_optargs_curr_as_size(opa);
		break;
	case 'n':
		ctx->in_args.fsname = cmd_optarg_getcurr2(opa, "name");
		break;
	case 'u':
		ctx->in_args.username = cmd_optarg_getcurr2(opa, "user");
		break;
	case 'G':
		ctx->in_args.with_sup_groups = true;
		break;
	case 'R':
		ctx->in_args.with_root_user = true;
		break;
	case 'p':
		ctx->in_args.password = cmd_optargs_getpass(opa);
		break;
	case 'N':
		ctx->in_args.flags &= ~SILOFS_F_UTF8NAMES;
		break;
	case 'X':
		cmd_global_params.developer_mode = true;
		break;
	case 'L':
		cmd_optargs_set_loglevel(opa);
		break;
	case 'h':
		cmd_print_help_and_exit(cmd_mkfs_help_desc);
		break;
	default:
		done = true;
		break;
	}
	return done;
}

static void cmd_mkfs_parse_optargs(struct cmd_mkfs_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		CMD_OPTDESC("size", 's', 1),
		CMD_OPTDESC("name", 'n', 1),
		CMD_OPTDESC("user", 'u', 1),
		CMD_OPTDESC("sup-groups", 'G', 0),
		CMD_OPTDESC("allow-root", 'R', 0),
		CMD_OPTDESC("password", 'p', 1),
		CMD_OPTDESC("no-utf8-names", 'N', 0),
		CMD_OPTDESC("developer-mode", 'X', 0),
		CMD_OPTDESC("loglevel", 'L', 1),
		CMD_OPTDESC("help", 'h', 0),
		CMD_OPTDESC_LAST,
	};
	struct cmd_optargs opa;
	int opt_chr   = 1;
	bool opa_done = false;

	cmd_optargs_setup(&opa, ods);
	while (!opa.opa_done && !opa_done) {
		opt_chr  = cmd_optargs_parse(&opa);
		opa_done = cmd_mkfs_parse_optarg_by(ctx, &opa, opt_chr);
	}
	cmd_require_arg_size("size", ctx->in_args.fs_size);

	ctx->in_args.repodir = cmd_optargs_getarg(&opa, "repodir");
	cmd_optargs_cleanup(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_mkfs_acquire_fslock(struct cmd_mkfs_ctx *ctx)
{
	cmd_fslock_acquirex(ctx->in_args.repodir_real, //
	                    ctx->in_args.fsname,       //
	                    &ctx->fslock);
}

static void cmd_mkfs_release_fslock(struct cmd_mkfs_ctx *ctx)
{
	cmd_fslock_release(ctx->in_args.repodir_real, //
	                   ctx->in_args.fsname,       //
	                   &ctx->fslock);
}

static void cmd_mkfs_destroy_env(struct cmd_mkfs_ctx *ctx)
{
	cmd_env_destroy(&ctx->env);
}

static void cmd_mkfs_finalize(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_destroy_env(ctx);
	cmd_mkfs_release_fslock(ctx);
	cmd_pstrfree(&ctx->in_args.fsname);
	cmd_pstrfree(&ctx->in_args.repodir);
	cmd_pstrfree(&ctx->in_args.repodir_real);
	cmd_pstrfree(&ctx->in_args.username);
	cmd_delpass(&ctx->in_args.password);
	cmd_spec_reset(&ctx->spec);
	cmd_mkfs_ctx_p = nullptr;
}

static void cmd_mkfs_atexit(void)
{
	struct cmd_mkfs_ctx *ctx = cmd_mkfs_ctx_p;

	if (ctx != nullptr) {
		cmd_mkfs_finalize(ctx);
	}
}

static void cmd_mkfs_start(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkfs_ctx_p = ctx;
	cmd_atexit(cmd_mkfs_atexit);
}

static void cmd_mkfs_require_fsname(struct cmd_mkfs_ctx *ctx)
{
	cmd_require_fsname(&ctx->in_args.fsname);
}

static void cmk_mkfs_sense_dotsdir(struct cmd_mkfs_ctx *ctx)
{
	struct stat st = {};
	char *repodir  = ctx->in_args.repodir;
	char *path     = cmd_path_join(repodir, SILOFS_REPO_DOTSDIR_NAME);
	int err;

	err = silofs_sys_stat(path, &st);
	if (!err) {
		ctx->format_repo = false;
	} else if (err == -ENOENT) {
		ctx->format_repo = true;
	} else {
		cmd_die(err, "failed to stat meta-dir: %s", path);
	}
	cmd_strfree(path);
}

static void cmk_mkfs_sense_repodir(struct cmd_mkfs_ctx *ctx)
{
	struct stat st;
	char *repodir = ctx->in_args.repodir;
	int err;

	err = silofs_sys_stat(repodir, &st);
	if (!err) {
		cmk_mkfs_sense_dotsdir(ctx);
	} else if (err == -ENOENT) {
		ctx->format_repo = true;
	} else {
		cmd_die(err, "failed to stat repo-dir: %s", repodir);
	}
}

static void cmd_mkfs_format_repodir(struct cmd_mkfs_ctx *ctx)
{
	cmd_mkdirp(ctx->in_args.repodir, 0700);
	cmd_resolve_repodir(ctx->in_args.repodir, true,
	                    &ctx->in_args.repodir_real);
	cmd_check_emptydir(ctx->in_args.repodir_real, true);
}

static void cmd_mkfs_reload_repodir(struct cmd_mkfs_ctx *ctx)
{
	cmd_resolve_repodir(ctx->in_args.repodir, true,
	                    &ctx->in_args.repodir_real);
	cmd_check_nonemptydir(ctx->in_args.repodir_real, true);
}

static void cmd_mkfs_require_repodir(struct cmd_mkfs_ctx *ctx)
{
	cmk_mkfs_sense_repodir(ctx);
	if (ctx->format_repo) {
		cmd_mkfs_format_repodir(ctx);
	} else {
		cmd_mkfs_reload_repodir(ctx);
	}
}

static void cmd_mkfs_require_unique(const struct cmd_mkfs_ctx *ctx)
{
	cmd_check_notexists2(ctx->in_args.repodir_real, ctx->in_args.fsname);
}

static void cmd_mkfs_restrict_process(const struct cmd_mkfs_ctx *ctx)
{
	cmd_restrict_process(ctx->in_args.repodir_real, true);
}

static void cmd_mkfs_require_username(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->in_args.username == nullptr) {
		ctx->in_args.username = cmd_getusername();
	}
}

static void cmd_mkfs_getpass(struct cmd_mkfs_ctx *ctx)
{
	if (ctx->in_args.password == nullptr) {
		cmd_getpass2(nullptr, true, &ctx->in_args.password);
	}
}

static void cmd_mkfs_setup_spec(struct cmd_mkfs_ctx *ctx)
{
	cmd_spec_setup2(&ctx->spec, ctx->in_args.fs_size, ctx->in_args.flags);
	cmd_spec_own_passwd(&ctx->spec, &ctx->in_args.password);
	cmd_spec_set_baseref(&ctx->spec, ctx->in_args.repodir_real,
	                     ctx->in_args.fsname);
}

static void cmd_mkfs_setup_fsids(struct cmd_mkfs_ctx *ctx)
{
	cmd_spec_update_owner(&ctx->spec, ctx->in_args.username,
	                      ctx->in_args.with_sup_groups);
	if (ctx->in_args.with_root_user) {
		cmd_spec_append_user(&ctx->spec, "root");
	}
}

static void cmd_mkfs_setup_env(struct cmd_mkfs_ctx *ctx)
{
	cmd_env_setup(&ctx->spec, &ctx->env);
}

static void cmd_mkfs_format_repo(const struct cmd_mkfs_ctx *ctx)
{
	if (ctx->format_repo) {
		cmd_format_repo(ctx->env);
	}
}

static void cmd_mkfs_format_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_format_fs(ctx->env, &ctx->spec.fsref);
}

static void cmd_mkfs_save_spec(struct cmd_mkfs_ctx *ctx)
{
	cmd_spec_jsave(&ctx->spec);
}

static void cmd_mkfs_unload_fs(struct cmd_mkfs_ctx *ctx)
{
	cmd_unload_fs(ctx->env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_mkfs(void)
{
	struct cmd_mkfs_ctx ctx = {
		.env           = nullptr,
		.in_args.flags = SILOFS_F_UTF8NAMES,
		.fslock        = -1,
	};

	/* Do all cleanups upon exits */
	cmd_mkfs_start(&ctx);

	/* Parse command's arguments */
	cmd_mkfs_parse_optargs(&ctx);

	/* Require valid file-system name */
	cmd_mkfs_require_fsname(&ctx);

	/* Require or create valid repo-dir */
	cmd_mkfs_require_repodir(&ctx);

	/* Require unique fsname within repo-dir */
	cmd_mkfs_require_unique(&ctx);

	/* Restrict process access */
	cmd_mkfs_restrict_process(&ctx);

	/* Have proper file-system owner username */
	cmd_mkfs_require_username(&ctx);

	/* Require password */
	cmd_mkfs_getpass(&ctx);

	/* Setup input arguments */
	cmd_mkfs_setup_spec(&ctx);

	/* Setup fs owner and ids */
	cmd_mkfs_setup_fsids(&ctx);

	/* Prepare environment */
	cmd_mkfs_setup_env(&ctx);

	/* Format new repo (if needed) */
	cmd_mkfs_format_repo(&ctx);

	/* Create fs-lock */
	cmd_mkfs_acquire_fslock(&ctx);

	/* Format file-system layer */
	cmd_mkfs_format_fs(&ctx);

	/* Save fs spec */
	cmd_mkfs_save_spec(&ctx);

	/* Post-format cleanups */
	cmd_mkfs_unload_fs(&ctx);

	/* Release fs-lock */
	cmd_mkfs_release_fslock(&ctx);

	/* Post execution cleanups */
	cmd_mkfs_finalize(&ctx);
}
