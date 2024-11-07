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

#define _GNU_SOURCE 1
#include <unistd.h>
#include <getopt.h>
#include "cmd.h"


silofs_attr_noreturn
static void cmd_fatal_missing_arg(const char *s)
{
	cmd_die(0, "missing argument: '%s'", s);
}

silofs_attr_noreturn
static void cmd_fatal_redundant_arg(const char *s)
{
	cmd_die(0, "redundant argument: '%s'", s);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define CMD_ARRAY_SIZE(x_) SILOFS_ARRAY_SIZE(x_)

struct cmd_getopt_info {
	char sopts[64];
	struct option lopts[32];
	size_t nopts;
};

static void getopti_pre_add(const struct cmd_getopt_info *goi)
{
	const char *sopt = goi->sopts;
	const char *send = goi->sopts + CMD_ARRAY_SIZE(goi->sopts);
	const size_t slen = silofs_str_length(goi->sopts);
	const size_t nopts_max = CMD_ARRAY_SIZE(goi->lopts);

	if (((sopt + slen + 3) > send) || ((goi->nopts + 1) >= nopts_max)) {
		cmd_die(0, "too many options");
	}
}

static void getopti_add(struct cmd_getopt_info *goi,
                        const struct cmd_optdesc *od)
{
	struct option *lopt = goi->lopts + goi->nopts;
	char *sopt = goi->sopts + silofs_str_length(goi->sopts);

	lopt->name = od->lopt;
	lopt->flag = NULL;
	lopt->has_arg = od->has_arg ? required_argument : no_argument;
	lopt->val = od->sopt;

	*sopt = (char)(od->sopt);
	sopt++;
	if (lopt->has_arg != no_argument) {
		*sopt = ':';
		sopt++;
	}
	*sopt = '\0';

	goi->nopts++;
}

static void getopti_init(struct cmd_getopt_info *goi,
                         const struct cmd_optdesc *ods)
{
	const struct cmd_optdesc *od = ods;

	goi->nopts = 0;
	while (od->lopt) {
		getopti_pre_add(goi);
		getopti_add(goi, od++);
	}
}

static struct cmd_getopt_info *getopti_new(const struct cmd_optdesc *ods)
{
	struct cmd_getopt_info *goi = NULL;

	goi = cmd_zalloc(sizeof(*goi));
	getopti_init(goi, ods);
	return goi;
}

static void getopti_del(struct cmd_getopt_info *goi)
{
	if (goi != NULL) {
		cmd_zfree(goi, sizeof(*goi));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_optargs_init(struct cmd_optargs *opa, const struct cmd_optdesc *ods)
{
	memset(opa, 0, sizeof(*opa));
	opa->opa_goi = getopti_new(ods);
	opa->opa_cmd_argc = cmd_globals.argc - 1;
	opa->opa_cmd_argv = cmd_globals.argv + 1;
	opa->opa_optind = optind = 1;
	opa->opa_opterr = opterr = 0;
	opa->opa_optarg = optarg = NULL;
	opa->opa_optidx = 0;
	opa->opa_done = false;
}

void cmd_optargs_fini(struct cmd_optargs *opa)
{
	getopti_del(opa->opa_goi);
	memset(opa, 0xFF, sizeof(*opa));
}

static void cmd_optargs_update(struct cmd_optargs *opa)
{
	opa->opa_optarg = optarg;
	opa->opa_optind = optind;
	opa->opa_opterr = opterr;
}

static void cmd_optargs_update_next(struct cmd_optargs *opa)
{
	optind++;
	cmd_optargs_update(opa);
}

static const char *cmd_optargs_by_ind(const struct cmd_optargs *opa)
{
	const char *opt = NULL;

	if ((opa->opa_optind > 0) && (opa->opa_optind <= opa->opa_cmd_argc)) {
		opt = opa->opa_cmd_argv[opa->opa_optind - 1];
	}
	return opt;
}


static const char *cmd_optargs_curr(const struct cmd_optargs *opa)
{
	const char *opt = NULL;

	if (opa->opa_optarg != NULL) {
		opt = opa->opa_optarg;
	} else if ((opa->opa_optind > 0) &&
	           (opa->opa_optind <= opa->opa_cmd_argc)) {
		opt = opa->opa_cmd_argv[opa->opa_optind - 1];
	}
	return opt;
}

silofs_attr_noreturn
static void cmd_optargs_die_unrecognized(const struct cmd_optargs *opa)
{
	const char *opt = cmd_optargs_by_ind(opa);

	cmd_die(0, "unrecognized option: '%s'", opt ? opt : "");
}

silofs_attr_noreturn
static void cmd_optargs_die_missing(const struct cmd_optargs *opa)
{
	const char *opt = cmd_optargs_by_ind(opa);

	cmd_die(0, "missing argument for: '%s'", opt ? opt : "");
}

int cmd_optargs_parse(struct cmd_optargs *opa)
{
	int ret;

	ret = getopt_long(opa->opa_cmd_argc,
	                  opa->opa_cmd_argv,
	                  opa->opa_goi->sopts,
	                  opa->opa_goi->lopts,
	                  &opa->opa_optidx);

	cmd_optargs_update(opa);
	if (ret == '?') {
		cmd_optargs_die_unrecognized(opa);
	}
	if (ret == ':') {
		cmd_optargs_die_missing(opa);
	}
	if (ret == -1) {
		opa->opa_done = true;
	}
	return ret;
}

char *cmd_optargs_dupcurr(const struct cmd_optargs *opa)
{
	return cmd_strdup(cmd_optargs_curr(opa));
}

char *cmd_optarg_dupoptarg(const struct cmd_optargs *opa, const char *id)
{
	if (!silofs_str_length(opa->opa_optarg)) {
		cmd_die(0, "missing option argument: %s", id);
	}
	return cmd_optargs_dupcurr(opa);
}

char *cmd_optargs_getarg(struct cmd_optargs *opa, const char *arg_name)
{
	const char *arg = opa->opa_cmd_argv[opa->opa_optind];

	if (opa->opa_optind > opa->opa_cmd_argc) {
		cmd_fatal_missing_arg(arg_name);
	}
	if ((opa->opa_optind == opa->opa_cmd_argc) || (arg == NULL)) {
		cmd_fatal_missing_arg(arg_name);
	}
	cmd_optargs_update_next(opa);
	return cmd_strdup(arg);
}

char *cmd_optargs_getarg2(struct cmd_optargs *opa,
                          const char *arg_name, const char *default_val)
{
	const char *arg = NULL;

	if (opa->opa_optind > opa->opa_cmd_argc) {
		cmd_fatal_missing_arg(arg_name);
	}
	arg = opa->opa_cmd_argv[opa->opa_optind];
	if ((opa->opa_optind == opa->opa_cmd_argc) || (arg == NULL)) {
		arg = default_val;
	} else {
		arg = opa->opa_cmd_argv[opa->opa_optind];
		cmd_optargs_update_next(opa);
	}
	return cmd_strdup(arg);
}

void cmd_optargs_endargs(const struct cmd_optargs *opa)
{
	if (opa->opa_optind < opa->opa_cmd_argc) {
		cmd_fatal_redundant_arg(cmd_optargs_curr(opa));
	}
}

void cmd_optargs_set_loglevel(const struct cmd_optargs *opa)
{
	cmd_set_log_level_by(opa->opa_optarg);
}

char *cmd_optargs_getpass(const struct cmd_optargs *opa)
{
	char *opt = cmd_optarg_dupoptarg(opa, "--password");
	char *pas = cmd_duppass(opt);

	cmd_pstrfree(&opt);
	return pas;
}

bool cmd_optargs_curr_as_bool(const struct cmd_optargs *opa)
{
	return cmd_parse_str_as_bool(opa->opa_optarg);
}

long cmd_optargs_curr_as_size(const struct cmd_optargs *opa)
{
	return cmd_parse_str_as_size(opa->opa_optarg);
}

uint32_t cmd_optargs_curr_as_u32v(const struct cmd_optargs *opa,
                                  uint32_t vmin, uint32_t vmax)
{
	return cmd_parse_str_as_u32v(opa->opa_optarg, vmin, vmax);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void cmd_require_arg(const char *arg_name, const void *arg_val)
{
	if (arg_val == NULL) {
		cmd_fatal_missing_arg(arg_name);
	}
}

void cmd_require_arg_size(const char *arg_name, long val)
{
	if (val < 0) {
		cmd_fatal_missing_arg(arg_name);
	}
}
