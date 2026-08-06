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
#include <sys/mount.h>

static const char *const cmd_show_help_desc = {
	"show <subcmd> <pathname>                                        \n"
	"                                                                \n"
	"sub commands:                                                   \n"
	"  version      Show mounted file-system's version               \n"
	"  repo         Show back-end repository dir-path                \n"
	"  boot         Show file-system name and id                     \n"
	"  proc         Show state of active mount daemon                \n"
	"  spstats      Show space-allocations stats                     \n"
	"  statx        Show extended file stats                         \n"
};

struct cmd_show_in_args {
	char *pathname;
	char *pathname_real;
	char *subcmd;
};

struct cmd_show_ctx {
	struct cmd_show_in_args in_args;
	union silofs_ioc_u *ioc;
	enum silofs_query_type qtype;
	FILE *out_fp;
};

static struct cmd_show_ctx *cmd_show_ctx_p;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_show_parse_optargs(struct cmd_show_ctx *ctx)
{
	const struct cmd_optdesc ods[] = {
		CMD_OPTDESC("help", 'h', 0),
		CMD_OPTDESC_LAST,
	};
	struct cmd_optargs opa;
	int opt_chr = 1;

	cmd_optargs_setup(&opa, ods);
	while (!opa.opa_done && (opt_chr > 0)) {
		opt_chr = cmd_optargs_parse(&opa);
		switch (opt_chr) {
		case 'h':
			cmd_print_help_and_exit(cmd_show_help_desc);
			break;
		default:
			opt_chr = 0;
			break;
		}
	}

	ctx->in_args.subcmd   = cmd_optargs_getarg(&opa, "subcmd");
	ctx->in_args.pathname = cmd_optargs_getarg(&opa, "pathname");

	cmd_optargs_cleanup(&opa);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *cmd_show_subcommands[] = {
	[SILOFS_QUERY_VERSION] = "version", [SILOFS_QUERY_REPO] = "repo",
	[SILOFS_QUERY_BOOT] = "boot",       [SILOFS_QUERY_PROC] = "proc",
	[SILOFS_QUERY_SPSTATS] = "spstats", [SILOFS_QUERY_STATX] = "statx",
};

static enum silofs_query_type cmd_show_qtype_by_subcmd(const char *subcmd)
{
	const int nelems = (int)SILOFS_ARRAY_SIZE(cmd_show_subcommands);

	for (int qtype = 0; qtype < nelems; ++qtype) {
		if ((cmd_show_subcommands[qtype] != nullptr) &&
		    !strcmp(cmd_show_subcommands[qtype], subcmd)) {
			return (enum silofs_query_type)qtype;
		}
	}
	return SILOFS_QUERY_NONE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_show_finalize(struct cmd_show_ctx *ctx)
{
	cmd_pstrfree(&ctx->in_args.pathname_real);
	cmd_pstrfree(&ctx->in_args.subcmd);
	cmd_pstrfree(&ctx->in_args.pathname);
	cmd_del_iocp(&ctx->ioc);
	cmd_show_ctx_p = nullptr;
}

static void cmd_show_atexit(void)
{
	struct cmd_show_ctx *ctx = cmd_show_ctx_p;

	if (ctx != nullptr) {
		cmd_show_finalize(ctx);
	}
}

static void cmd_show_start(struct cmd_show_ctx *ctx)
{
	cmd_show_ctx_p = ctx;
	cmd_atexit(cmd_show_atexit);
}

static void cmd_show_enable_signals(void)
{
	cmd_register_sigactions(nullptr);
}

static void cmd_show_prepare(struct cmd_show_ctx *ctx)
{
	ctx->ioc = cmd_new_ioc();
	cmd_realpath_rdir(ctx->in_args.pathname, &ctx->in_args.pathname_real);
	cmd_check_reg_or_dir(ctx->in_args.pathname_real);
	cmd_check_fusefs(ctx->in_args.pathname_real);
}

static void cmd_show_resolve_subcmd(struct cmd_show_ctx *ctx)
{
	ctx->qtype = cmd_show_qtype_by_subcmd(ctx->in_args.subcmd);
	if (ctx->qtype == SILOFS_QUERY_NONE) {
		cmd_diez("unknown sub-command %s", ctx->in_args.subcmd);
	}
	ctx->ioc->query.qtype = (int32_t)ctx->qtype;
}

static void cmd_show_do_ioctl_query(struct cmd_show_ctx *ctx)
{
	int fd = -1;
	int err;

	err = silofs_sys_open(ctx->in_args.pathname_real, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", ctx->in_args.pathname_real);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_IOC_QUERY, &ctx->ioc->query);
	if (err) {
		cmd_die(err, "ioctl error: %s", ctx->in_args.pathname_real);
	}
	silofs_sys_close(fd);
}

static void cmd_show_version(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	fprintf(ctx->out_fp, "%s\n", ctx->ioc->query.u.version.string);
}

static void cmd_show_repo(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	fprintf(ctx->out_fp, "%s\n", ctx->ioc->query.u.repo.path);
}

static void cmd_show_boot(struct cmd_show_ctx *ctx)
{
	struct silofs_ioc_query *qry = &ctx->ioc->query;
	char *boot_name              = nullptr;

	cmd_show_do_ioctl_query(ctx);

	boot_name = cmd_strvdup(qry->u.boot.name, sizeof(qry->u.boot.name));
	fprintf(ctx->out_fp, "%s %s\n", boot_name,
	        qry->u.boot.fsref.mbaddr.mba);
	cmd_pstrfree(&boot_name);
}

struct silofs_msflag_name {
	unsigned long ms_flag;
	const char *name;
};

static void msflags_str(unsigned long msflags, char *buf, size_t bsz)
{
	const char *end                            = buf + bsz;
	const struct silofs_msflag_name *ms_name   = nullptr;
	const struct silofs_msflag_name ms_names[] = {
		{ MS_RDONLY, "rdonly" },     { MS_NODEV, "nodev" },
		{ MS_NOSUID, "nosuid" },     { MS_NOEXEC, "noexec" },
		{ MS_MANDLOCK, "mandlock" }, { MS_NOATIME, "noatime" },
	};
	size_t len = 0;
	bool first = true;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(ms_names); ++i) {
		ms_name = &ms_names[i];
		len     = strlen(ms_name->name);
		if (!(msflags & ms_name->ms_flag)) {
			continue;
		}
		if ((buf + len + 2) < end) {
			memcpy(buf, ms_names[i].name, len);
			buf += len;
			if (!first) {
				buf[len] = ',';
				buf += 1;
			}
			buf[0] = '\0';
			first  = false;
		}
	}
}

static void
cmd_show_msflags(const struct cmd_show_ctx *ctx, unsigned long msflags)
{
	char mntfstr[128] = "";

	msflags_str(msflags, mntfstr, sizeof(mntfstr) - 1);
	fprintf(ctx->out_fp, "mount-flags: %s\n", mntfstr);
}

static void
cmd_show_pid(const struct cmd_show_ctx *ctx, const char *name, pid_t pid)
{
	fprintf(ctx->out_fp, "%s: %ld\n", name, (long)pid);
}

static void
cmd_show_time(const struct cmd_show_ctx *ctx, const char *name, time_t tm)
{
	fprintf(ctx->out_fp, "%s: %ld\n", name, tm);
}

static void
cmd_show_counter(const struct cmd_show_ctx *ctx, const char *prefix,
                 const char *name, uint64_t val)
{
	if (prefix && strlen(prefix)) {
		fprintf(ctx->out_fp, "%s.%s: %zd\n", prefix, name, val);
	} else {
		fprintf(ctx->out_fp, "%s: %zd\n", name, val);
	}
}

static void
cmd_show_ucounter(const struct cmd_show_ctx *ctx, const char *name, size_t val)
{
	fprintf(ctx->out_fp, "%s: %lu\n", name, val);
}

static void cmd_show_proc(struct cmd_show_ctx *ctx)
{
	const struct silofs_query_proc *qpr = &ctx->ioc->query.u.proc;

	cmd_show_do_ioctl_query(ctx);
	cmd_show_pid(ctx, "pid", (pid_t)qpr->pid);
	cmd_show_time(ctx, "uptime", (time_t)qpr->uptime);
	cmd_show_msflags(ctx, qpr->msflags);
	cmd_show_ucounter(ctx, "memsz_max", qpr->memsz_max);
	cmd_show_ucounter(ctx, "memsz_cur", qpr->memsz_cur);
	cmd_show_ucounter(ctx, "bopen_cur", qpr->bopen_cur);
	cmd_show_ucounter(ctx, "iopen_max", qpr->iopen_max);
	cmd_show_ucounter(ctx, "iopen_cur", qpr->iopen_cur);
}

static void cmd_show_spacestats(const struct cmd_show_ctx *ctx)
{
	const struct silofs_space_stats1k *spst =
		&ctx->ioc->query.u.spstats.spst;
	const char *prefix = nullptr;

	prefix = "";
	cmd_show_time(ctx, "btime", (time_t)spst->sp_btime);
	cmd_show_time(ctx, "ctime", (time_t)spst->sp_ctime);
	cmd_show_counter(ctx, prefix, "capacity", spst->sp_capacity);
	cmd_show_counter(ctx, prefix, "vspacesize", spst->sp_vspacesize);
	/* TODO: complete */
}

static void cmd_show_spstats(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	cmd_show_spacestats(ctx);
}

static void cmd_show_statx(struct cmd_show_ctx *ctx)
{
	const struct silofs_query_statx *qstatx = &ctx->ioc->query.u.statx;
	const struct statx *stx                 = &qstatx->stx;

	cmd_show_do_ioctl_query(ctx);
	fprintf(ctx->out_fp, "blksize: %ld\n", (long)stx->stx_blksize);
	fprintf(ctx->out_fp, "nlink: %u\n", stx->stx_nlink);
	fprintf(ctx->out_fp, "uid: %u\n", stx->stx_uid);
	fprintf(ctx->out_fp, "gid: %u\n", stx->stx_gid);
	fprintf(ctx->out_fp, "mode: 0%o\n", stx->stx_mode);
	fprintf(ctx->out_fp, "ino: %ld\n", (long)stx->stx_ino);
	fprintf(ctx->out_fp, "size: %ld\n", (long)stx->stx_size);
	fprintf(ctx->out_fp, "blocks: %ld\n", (long)stx->stx_blocks);
	fprintf(ctx->out_fp, "iflags: %x\n", qstatx->iflags);
	fprintf(ctx->out_fp, "dirflags: %x\n", qstatx->dirflags);
}

static void cmd_show_execute(struct cmd_show_ctx *ctx)
{
	switch (ctx->qtype) {
	case SILOFS_QUERY_VERSION:
		cmd_show_version(ctx);
		break;
	case SILOFS_QUERY_REPO:
		cmd_show_repo(ctx);
		break;
	case SILOFS_QUERY_BOOT:
		cmd_show_boot(ctx);
		break;
	case SILOFS_QUERY_PROC:
		cmd_show_proc(ctx);
		break;
	case SILOFS_QUERY_SPSTATS:
		cmd_show_spstats(ctx);
		break;
	case SILOFS_QUERY_STATX:
		cmd_show_statx(ctx);
		break;
	case SILOFS_QUERY_NONE:
	default:
		break;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_execute_show(void)
{
	struct cmd_show_ctx ctx = {
		.qtype  = SILOFS_QUERY_NONE,
		.ioc    = nullptr,
		.out_fp = stdout,
	};

	/* Do all cleanups upon exits */
	cmd_show_start(&ctx);

	/* Parse command's arguments */
	cmd_show_parse_optargs(&ctx);

	/* Verify user's arguments */
	cmd_show_prepare(&ctx);

	/* Resolve sub-command to query-type */
	cmd_show_resolve_subcmd(&ctx);

	/* Run with signals */
	cmd_show_enable_signals();

	/* Do actual query + show */
	cmd_show_execute(&ctx);

	/* Post execution cleanups */
	cmd_show_finalize(&ctx);
}
