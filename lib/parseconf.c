/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/mntsvc.h>
#include "uidgid.h"

struct silofs_mntconf_ctx {
	struct silofs_alloc *alloc;
	struct silofs_strview conf;
	struct silofs_strview line;
	const char *file;
	int line_no;
};

static void
mntc_setup(struct silofs_mntconf_ctx *mntc, struct silofs_alloc *alloc,
           const char *file, const char *conf)
{
	mntc->alloc = alloc;
	silofs_strview_init(&mntc->conf, conf);
	silofs_strview_initz(&mntc->line);
	mntc->file = (file != NULL) ? file : "";
	mntc->line_no = 0;
}

static void mntc_update_line(struct silofs_mntconf_ctx *mntc,
                             const struct silofs_strview *line)
{
	silofs_strview_init_by(&mntc->line, line);
}

static void mntc_update_next_line(struct silofs_mntconf_ctx *mntc,
                                  const struct silofs_strview *line)
{
	mntc_update_line(mntc, line);
	mntc->line_no++;
}

static int mntc_bad_conf(const struct silofs_mntconf_ctx *mntc,
                         const struct silofs_strview *val, const char *msg)
{
	if (val != NULL) {
		log_err("bad mntconf: %s: '%.*s' (%s:%d)", msg, (int)val->len,
		        val->str, mntc->file, mntc->line_no);
	} else {
		log_err("bad mntconf: %s (%s:%d)", msg, mntc->file,
		        mntc->line_no);
	}
	return -SILOFS_EINVAL;
}

static int mntc_bad_val(const struct silofs_mntconf_ctx *mntc,
                        const struct silofs_strview *val, const char *tag)
{
	log_err("illegal mntconf %s value: '%.*s' (%s:%d)", tag, (int)val->len,
	        val->str, mntc->file, mntc->line_no);
	return -SILOFS_EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mntc_parse_bool(const struct silofs_mntconf_ctx *mntc,
                           const struct silofs_strview *sv, bool *out_val)
{
	if (silofs_strview_isequal(sv, "1") ||
	    silofs_strview_isequal(sv, "true")) {
		*out_val = true;
		return 0;
	}
	if (silofs_strview_isequal(sv, "0") ||
	    silofs_strview_isequal(sv, "false")) {
		*out_val = false;
		return 0;
	}
	return mntc_bad_val(mntc, sv, "boolean");
}

static int mntc_parse_long(const struct silofs_mntconf_ctx *mntc,
                           const struct silofs_strview *sv, long *out_val)
{
	char str[80] = "";
	char *endptr = NULL;
	long val = 0;

	if (sv->len >= sizeof(str)) {
		return mntc_bad_val(mntc, sv, "integer");
	}
	silofs_strview_copyto(sv, str, sizeof(str));

	errno = 0;
	val = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		return mntc_bad_val(mntc, sv, "integer");
	}
	if (strlen(endptr) > 1) {
		return mntc_bad_val(mntc, sv, "integer");
	}
	*out_val = val;
	return 0;
}

static int mntc_parse_int(const struct silofs_mntconf_ctx *mntc,
                          const struct silofs_strview *sv, int *out_val)

{
	long num = 0;
	int err;

	err = mntc_parse_long(mntc, sv, &num);
	if (err) {
		return err;
	}
	if ((num > INT_MAX) || (num < INT_MIN)) {
		return mntc_bad_val(mntc, sv, "int");
	}
	*out_val = (int)num;
	return 0;
}

static int mntc_parse_uid(const struct silofs_mntconf_ctx *mntc,
                          const struct silofs_strview *sv, uid_t *out_val)
{
	int val = -1;
	int err;

	err = mntc_parse_int(mntc, sv, &val);
	if (err) {
		return err;
	}
	if ((val < 0) || (val > (INT_MAX / 2))) {
		return mntc_bad_val(mntc, sv, "uid");
	}
	*out_val = (uid_t)val;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mntc_parse_rule_args(const struct silofs_mntconf_ctx *mntc,
                                const struct silofs_strview *args,
                                struct silofs_mntrule *mntrule)
{
	struct silofs_strview_pair key_val;
	struct silofs_strview_pair ss_pair;
	struct silofs_strview *key = &key_val.first;
	struct silofs_strview *val = &key_val.second;
	struct silofs_strview *carg = &ss_pair.first;
	struct silofs_strview *tail = &ss_pair.second;
	const char *seps = " \t";
	int err = 0;

	mntrule->uid = (uid_t)(-1);
	mntrule->recursive = false;

	silofs_strview_split(args, seps, &ss_pair);
	while (!silofs_strview_isempty(carg) ||
	       !silofs_strview_isempty(tail)) {
		silofs_strview_split_chr(carg, '=', &key_val);
		if (silofs_strview_isempty(key) ||
		    silofs_strview_isempty(val)) {
			return mntc_bad_conf(mntc, carg, "illegal key-value");
		}
		if (silofs_strview_isequal(key, "recursive")) {
			err = mntc_parse_bool(mntc, val, &mntrule->recursive);
			if (err) {
				return err;
			}
		} else if (silofs_strview_isequal(key, "uid")) {
			err = mntc_parse_uid(mntc, val, &mntrule->uid);
			if (err) {
				return err;
			}
		} else {
			return mntc_bad_conf(mntc, key, "unknown key");
		}
		silofs_strview_split(tail, seps, &ss_pair);
	}
	return 0;
}

static int mntc_strdup(const struct silofs_mntconf_ctx *mntc,
                       const struct silofs_strview *sv, char **out_str)
{
	const size_t n = sv->len + 1;
	char *s;

	s = silofs_memalloc(mntc->alloc, n, SILOFS_ALLOCF_BZERO);
	if (s == NULL) {
		return -SILOFS_ENOMEM;
	}
	silofs_strview_copyto(sv, s, n);
	*out_str = s;
	return 0;
}

static void mntc_strfree(const struct silofs_mntconf_ctx *mntc, char *s)
{
	const size_t len = silofs_str_length(s);

	silofs_memfree(mntc->alloc, s, len + 1, 0);
}

static int resolve_dir_realpath(const char *path, char **out_rpath)
{
	struct stat st = { .st_size = -1 };
	char *rpath = NULL;
	int err;

	rpath = realpath(path, NULL);
	if (rpath == NULL) {
		return -errno;
	}
	err = silofs_sys_stat(rpath, &st);
	if (err) {
		free(rpath);
		return err;
	}
	if (!S_ISDIR(st.st_mode)) {
		free(rpath);
		return -ENOTDIR;
	}
	*out_rpath = rpath;
	return 0;
}

static int
mntc_parse_rule_path(const struct silofs_mntconf_ctx *mntc,
                     const struct silofs_strview *path, char **out_rpath)
{
	struct silofs_strview sv;
	char *dpath = NULL;
	char *rpath = NULL;
	int err;

	err = mntc_strdup(mntc, path, &dpath);
	if (err) {
		return err;
	}
	err = resolve_dir_realpath(dpath, &rpath);
	mntc_strfree(mntc, dpath);
	if (err) {
		return err;
	}
	silofs_strview_init(&sv, rpath);
	err = mntc_strdup(mntc, &sv, out_rpath);
	mntc_strfree(mntc, rpath);
	if (err) {
		return err;
	}
	return 0;
}

static void mntc_release_rule(const struct silofs_mntconf_ctx *mntc,
                              struct silofs_mntrule *mntrule)
{
	if (mntrule->path != NULL) {
		mntc_strfree(mntc, mntrule->path);
		mntrule->path = NULL;
	}
	mntrule->uid = silofs_uid_nobody();
}

static int mntc_parse_rule(const struct silofs_mntconf_ctx *mntc,
                           const struct silofs_strview *path,
                           const struct silofs_strview *args,
                           struct silofs_mntrules *mrules)
{
	const size_t max_rules = ARRAY_SIZE(mrules->rules);
	struct silofs_mntrule *mntrule = NULL;
	int err;

	if (mrules->nrules >= max_rules) {
		return mntc_bad_conf(mntc, NULL, "too many mount-rules");
	}
	mntrule = &mrules->rules[mrules->nrules];
	err = mntc_parse_rule_path(mntc, path, &mntrule->path);
	if (err) {
		return err;
	}
	err = mntc_parse_rule_args(mntc, args, mntrule);
	if (err) {
		mntc_release_rule(mntc, mntrule);
		return err;
	}
	mrules->nrules++;
	return 0;
}

static int mntc_parse_line(const struct silofs_mntconf_ctx *mntc,
                           struct silofs_mntrules *mrules)
{
	struct silofs_strview sline;
	struct silofs_strview_pair svp;
	const char *seps = " \t";
	int err;

	silofs_strview_split_chr(&mntc->line, '#', &svp);
	silofs_strview_strip_ws(&svp.first, &sline);
	if (!silofs_strview_isempty(&sline)) {
		silofs_strview_split(&sline, seps, &svp);
		err = mntc_parse_rule(mntc, &svp.first, &svp.second, mrules);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int mntc_parse_rules(struct silofs_mntconf_ctx *mntc,
                            struct silofs_mntrules *mrules)
{
	struct silofs_strview_pair svp;
	const struct silofs_strview *line = &svp.first;
	const struct silofs_strview *tail = &svp.second;
	int err;

	mntc->line_no = 0;
	silofs_strview_split_chr(&mntc->conf, '\n', &svp);
	while (!silofs_strview_isempty(line) ||
	       !silofs_strview_isempty(tail)) {
		mntc->line_no++;
		mntc_update_next_line(mntc, line);
		err = mntc_parse_line(mntc, mrules);
		if (err) {
			return err;
		}
		silofs_strview_split_chr(&svp.second, '\n', &svp);
	}
	return 0;
}

static void mntc_release_rules(struct silofs_mntconf_ctx *mntc,
                               struct silofs_mntrules *mrules)
{
	for (size_t i = 0; i < mrules->nrules; ++i) {
		mntc_release_rule(mntc, &mrules->rules[i]);
	}
	mrules->nrules = 0;
}

int silofs_parse_mntrules(struct silofs_mntrules *mrules,
                          struct silofs_alloc *alloc, const char *file,
                          const char *conf)
{
	struct silofs_mntconf_ctx mntc;
	int err;

	mntc_setup(&mntc, alloc, file, conf);
	err = mntc_parse_rules(&mntc, mrules);
	if (err) {
		mntc_release_rules(&mntc, mrules);
		return err;
	}
	return 0;
}

void silofs_release_mntrules(struct silofs_mntrules *mrules,
                             struct silofs_alloc *alloc)
{
	struct silofs_mntconf_ctx mntc;

	mntc_setup(&mntc, alloc, NULL, NULL);
	mntc_release_rules(&mntc, mrules);
}
