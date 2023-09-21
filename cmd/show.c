/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

static const char *cmd_show_help_desc[] = {
	"show <subcmd> <pathname>",
	"",
	"sub commands:",
	"  version      Show mounted file-system's version",
	"  boot         Show back-end repo dir-path and fs-name",
	"  proc         Show state of active mount daemon",
	"  spstats      Show space-allocations stats",
	"  statx        Show extended file stats",
	NULL
};

struct cmd_show_in_args {
	char   *pathname;
	char   *pathname_real;
	char   *subcmd;
};

struct cmd_show_ctx {
	struct cmd_show_in_args in_args;
	union silofs_ioc_u     *ioc;
	enum silofs_query_type  qtype;
};

static struct cmd_show_ctx *cmd_show_ctx;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_show_getopt(struct cmd_show_ctx *ctx)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = cmd_getopt("h", opts);
		if (opt_chr == 'h') {
			cmd_print_help_and_exit(cmd_show_help_desc);
		} else if (opt_chr > 0) {
			cmd_fatal_unsupported_opt();
		}
	}
	cmd_getarg("subcmd", &ctx->in_args.subcmd);
	cmd_getarg_or_cwd("pathname", &ctx->in_args.pathname);
	cmd_endargs();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *cmd_show_subcommands[] = {
	[SILOFS_QUERY_VERSION]  = "version",
	[SILOFS_QUERY_BOOTSEC]  = "boot",
	[SILOFS_QUERY_PROC]     = "proc",
	[SILOFS_QUERY_SPSTATS]  = "spstats",
	[SILOFS_QUERY_STATX]    = "statx",
};

static enum silofs_query_type cmd_show_qtype_by_subcmd(const char *subcmd)
{
	const int nelems = (int)SILOFS_ARRAY_SIZE(cmd_show_subcommands);

	for (int qtype = 0; qtype < nelems; ++qtype) {
		if ((cmd_show_subcommands[qtype] != NULL) &&
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
	cmd_show_ctx = NULL;
}

static void cmd_show_atexit(void)
{
	if (cmd_show_ctx != NULL) {
		cmd_show_finalize(cmd_show_ctx);
	}
}

static void cmd_show_start(struct cmd_show_ctx *ctx)
{
	cmd_show_ctx = ctx;
	atexit(cmd_show_atexit);
}

static void cmd_show_prepare(struct cmd_show_ctx *ctx)
{
	ctx->ioc = cmd_new_ioc();
	cmd_realpath(ctx->in_args.pathname, &ctx->in_args.pathname_real);
	cmd_check_reg_or_dir(ctx->in_args.pathname_real);
	cmd_check_fusefs(ctx->in_args.pathname_real);
}

static void cmd_show_resolve_subcmd(struct cmd_show_ctx *ctx)
{
	ctx->qtype = cmd_show_qtype_by_subcmd(ctx->in_args.subcmd);
	if (ctx->qtype == SILOFS_QUERY_NONE) {
		cmd_dief(0, "unknown sub-command %s", ctx->in_args.subcmd);
	}
	ctx->ioc->query.qtype = (int32_t)ctx->qtype;
}

static void cmd_show_do_ioctl_query(struct cmd_show_ctx *ctx)
{
	int fd = -1;
	int err;

	err = silofs_sys_open(ctx->in_args.pathname_real, O_RDONLY, 0, &fd);
	if (err) {
		cmd_dief(err, "failed to open: %s",
		         ctx->in_args.pathname_real);
	}
	err = silofs_sys_ioctlp(fd, SILOFS_IOC_QUERY, &ctx->ioc->query);
	if (err) {
		cmd_dief(err, "ioctl error: %s", ctx->in_args.pathname_real);
	}
	silofs_sys_close(fd);
}

static void cmd_show_version(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	printf("%s\n", ctx->ioc->query.u.version.string);
}

static void cmd_show_boot(struct cmd_show_ctx *ctx)
{
	cmd_show_do_ioctl_query(ctx);
	printf("%s/%s\n", ctx->ioc->query.u.bootrec.repo,
	       ctx->ioc->query.u.bootrec.name);
}

struct silofs_msflag_name {
	unsigned long ms_flag;
	const char *name;
};

static void msflags_str(unsigned long msflags, char *buf, size_t bsz)
{
	bool first = true;
	size_t len;
	const char *end = buf + bsz;
	const struct silofs_msflag_name *ms_name = NULL;
	const struct silofs_msflag_name ms_names[] = {
		{ MS_RDONLY,    "rdonly" },
		{ MS_NODEV,     "nodev" },
		{ MS_NOSUID,    "nosuid" },
		{ MS_NOEXEC,    "noexec" },
		{ MS_MANDLOCK,  "mandlock" },
		{ MS_NOATIME,   "noatime" },
	};

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(ms_names); ++i) {
		ms_name = &ms_names[i];
		len = strlen(ms_name->name);
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
			first = false;
		}
	}
}

static void print_msflags(unsigned long msflags)
{
	char mntfstr[128] = "";

	msflags_str(msflags, mntfstr, sizeof(mntfstr) - 1);
	printf("mount-flags: %s\n", mntfstr);
}

static void print_pid(const char *name, pid_t pid)
{
	printf("%s: %ld\n", name, (long)pid);
}

static void print_time(const char *name, time_t tm)
{
	printf("%s: %ld\n", name, tm);
}

static void print_count(const char *prefix, const char *name, ssize_t cnt)
{
	if (prefix && strlen(prefix)) {
		printf("%s.%s: %ld\n", prefix, name, cnt);
	} else {
		printf("%s: %ld\n", name, cnt);
	}
}

static void print_count1(const char *name, size_t cnt)
{
	printf("%s: %lu\n", name, cnt);
}

static void cmd_show_proc(struct cmd_show_ctx *ctx)
{
	const struct silofs_query_proc *qpr = &ctx->ioc->query.u.proc;

	cmd_show_do_ioctl_query(ctx);
	print_pid("pid", (pid_t)qpr->pid);
	print_time("uptime", (time_t)qpr->uptime);
	print_msflags(qpr->msflags);
	print_count1("memsz_max", qpr->memsz_max);
	print_count1("memsz_cur", qpr->memsz_cur);
	print_count1("bopen_cur", qpr->bopen_cur);
	print_count1("iopen_max", qpr->iopen_max);
	print_count1("iopen_cur", qpr->iopen_cur);
}

static void print_spacestats(const struct silofs_spacestats *spst)
{
	const char *prefix;

	prefix = "";
	print_time("btime", spst->btime);
	print_time("ctime", spst->ctime);
	print_count(prefix, "capacity", (ssize_t)spst->capacity);
	print_count(prefix, "vspacesize", (ssize_t)spst->vspacesize);
	prefix = "blobs";
	print_count(prefix, "ndata1k", spst->blobs.ndata1k);
	print_count(prefix, "ndata4k", spst->blobs.ndata4k);
	print_count(prefix, "ndatabk", spst->blobs.ndatabk);
	print_count(prefix, "nsuper", spst->blobs.nsuper);
	print_count(prefix, "nspnode", spst->blobs.nspnode);
	print_count(prefix, "nspleaf", spst->blobs.nspleaf);
	print_count(prefix, "ninode", spst->blobs.ninode);
	print_count(prefix, "nxanode", spst->blobs.nxanode);
	print_count(prefix, "ndtnode", spst->blobs.ndtnode);
	print_count(prefix, "nftnode", spst->blobs.nftnode);
	print_count(prefix, "nsymval", spst->blobs.nsymval);
	prefix = "bks";
	print_count(prefix, "ndata1k", spst->bks.ndata1k);
	print_count(prefix, "ndata4k", spst->bks.ndata4k);
	print_count(prefix, "ndatabk", spst->bks.ndatabk);
	print_count(prefix, "nsuper", spst->bks.nsuper);
	print_count(prefix, "nspnode", spst->bks.nspnode);
	print_count(prefix, "nspleaf", spst->bks.nspleaf);
	print_count(prefix, "ninode", spst->bks.ninode);
	print_count(prefix, "nxanode", spst->bks.nxanode);
	print_count(prefix, "ndtnode", spst->bks.ndtnode);
	print_count(prefix, "nftnode", spst->bks.nftnode);
	print_count(prefix, "nsymval", spst->bks.nsymval);
	prefix = "objs";
	print_count(prefix, "ndata1k", spst->objs.ndata1k);
	print_count(prefix, "ndata4k", spst->objs.ndata4k);
	print_count(prefix, "ndatabk", spst->objs.ndatabk);
	print_count(prefix, "nsuper", spst->objs.nsuper);
	print_count(prefix, "nspnode", spst->objs.nspnode);
	print_count(prefix, "nspleaf", spst->objs.nspleaf);
	print_count(prefix, "ninode", spst->objs.ninode);
	print_count(prefix, "nxanode", spst->objs.nxanode);
	print_count(prefix, "ndtnode", spst->objs.ndtnode);
	print_count(prefix, "nftnode", spst->objs.nftnode);
	print_count(prefix, "nsymval", spst->objs.nsymval);
}

static void cmd_show_spstats(struct cmd_show_ctx *ctx)
{
	struct silofs_spacestats spst;

	cmd_show_do_ioctl_query(ctx);
	silofs_spacestats_import(&spst, &ctx->ioc->query.u.spstats.spst);
	print_spacestats(&spst);
}

static void cmd_show_statx(struct cmd_show_ctx *ctx)
{
	const struct silofs_query_statx *qstatx = &ctx->ioc->query.u.statx;
	const struct statx *stx = &qstatx->stx;

	cmd_show_do_ioctl_query(ctx);
	printf("blksize: %ld\n", (long)stx->stx_blksize);
	printf("nlink: %u\n",  stx->stx_nlink);
	printf("uid: %u\n",  stx->stx_uid);
	printf("gid: %u\n",  stx->stx_gid);
	printf("mode: 0%o\n",  stx->stx_mode);
	printf("ino: %ld\n", (long)stx->stx_ino);
	printf("size: %ld\n", (long)stx->stx_size);
	printf("blocks: %ld\n", (long)stx->stx_blocks);
	/* printf("mnt_id:     %ld \n", (long)stx->stx_mnt_id); */
	printf("iflags: %x\n",  qstatx->iflags);
	printf("dirflags: %x\n",  qstatx->dirflags);
}

static void cmd_show_execute(struct cmd_show_ctx *ctx)
{
	switch (ctx->qtype) {
	case SILOFS_QUERY_VERSION:
		cmd_show_version(ctx);
		break;
	case SILOFS_QUERY_BOOTSEC:
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
		.qtype = SILOFS_QUERY_NONE,
		.ioc = NULL,
	};

	/* Do all cleanups upon exits */
	cmd_show_start(&ctx);

	/* Parse command's arguments */
	cmd_show_getopt(&ctx);

	/* Verify user's arguments */
	cmd_show_prepare(&ctx);

	/* Resolve sub-command to query-type */
	cmd_show_resolve_subcmd(&ctx);

	/* Do actual query + show */
	cmd_show_execute(&ctx);

	/* Post execution cleanups */
	cmd_show_finalize(&ctx);
}


