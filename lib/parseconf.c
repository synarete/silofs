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

struct silofs_conf_parser {
	struct silofs_alloc *alloc;
	struct silofs_strview data;
	struct silofs_strview line;
	int line_no;
};

static void cpr_setup(struct silofs_conf_parser *cpr,
                      struct silofs_alloc *alloc, const char *data)
{
	silofs_strview_init(&cpr->data, data);
	silofs_strview_initz(&cpr->line);
	cpr->alloc = alloc;
	cpr->line_no = 0;
}

static void cpr_reset_line(struct silofs_conf_parser *cpr)
{
	silofs_strview_initz(&cpr->line);
	cpr->line_no = 0;
}

static void cpr_update_line(struct silofs_conf_parser *cpr,
                            const struct silofs_strview *line)
{
	silofs_strview_init_by(&cpr->line, line);
}

static void cpr_update_next_line(struct silofs_conf_parser *cpr,
                                 const struct silofs_strview *line)
{
	cpr_update_line(cpr, line);
	cpr->line_no++;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
cpr_zalloc(const struct silofs_conf_parser *cpr, size_t nbytes, void **out_ptr)
{
	void *p;

	p = silofs_memalloc(cpr->alloc, nbytes, SILOFS_ALLOCF_BZERO);
	if (p == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_ptr = p;
	return 0;
}

static void
cpr_zfree(const struct silofs_conf_parser *cpr, void *ptr, size_t nbytes)
{
	silofs_memfree(cpr->alloc, ptr, nbytes, SILOFS_ALLOCF_BZERO);
}

static int cpr_strdup(const struct silofs_conf_parser *cpr,
                      const struct silofs_strview *sv, char **out_str)
{
	const size_t n = sv->len + 1;
	void *p = NULL;
	int err;

	err = cpr_zalloc(cpr, n, &p);
	if (err) {
		return err;
	}
	*out_str = (char *)p;
	silofs_strview_copyto(sv, *out_str, n);
	return 0;
}

static void cpr_strfree(const struct silofs_conf_parser *cpr, char **str)
{
	if ((str != NULL) && (*str != NULL)) {
		const size_t len = silofs_str_length(*str);

		cpr_zfree(cpr, str, len + 1);
		*str = NULL;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cpr_bad_conf(const struct silofs_conf_parser *cpr,
                        const struct silofs_strview *val, const char *msg)
{
	if (val != NULL) {
		log_err("invalid config data: %s: '%.*s' (line: %d)", msg,
		        (int)val->len, val->str, cpr->line_no);
	} else {
		log_err("invalid config file: %s (line: %d)", msg,
		        cpr->line_no);
	}
	return -SILOFS_EINVAL;
}

static int cpr_bad_val(const struct silofs_conf_parser *cpr,
                       const struct silofs_strview *val, const char *tag)
{
	log_err("illegal %s value: '%.*s' (line: %d)", tag, (int)val->len,
	        val->str, cpr->line_no);
	return -SILOFS_EINVAL;
}

static int cpr_parse_bool(const struct silofs_conf_parser *cpr,
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
	return cpr_bad_val(cpr, sv, "boolean");
}

static int cpr_parse_long(const struct silofs_conf_parser *cpr,
                          const struct silofs_strview *sv, long *out_val)
{
	char str[80] = "";
	char *endptr = NULL;
	long val = 0;

	if (sv->len >= sizeof(str)) {
		return cpr_bad_val(cpr, sv, "integer");
	}
	silofs_strview_copyto(sv, str, sizeof(str));

	errno = 0;
	val = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		return cpr_bad_val(cpr, sv, "integer");
	}
	if (strlen(endptr) > 1) {
		return cpr_bad_val(cpr, sv, "integer");
	}
	*out_val = val;
	return 0;
}

static int cpr_parse_int(const struct silofs_conf_parser *cpr,
                         const struct silofs_strview *sv, int *out_val)

{
	long num = 0;
	int err;

	err = cpr_parse_long(cpr, sv, &num);
	if (err) {
		return err;
	}
	if ((num > INT_MAX) || (num < INT_MIN)) {
		return cpr_bad_val(cpr, sv, "int");
	}
	*out_val = (int)num;
	return 0;
}

static int cpr_parse_uid(const struct silofs_conf_parser *cpr,
                         const struct silofs_strview *sv, uid_t *out_val)
{
	int val = -1;
	int err;

	err = cpr_parse_int(cpr, sv, &val);
	if (err) {
		return err;
	}
	if ((val < 0) || (val > (INT_MAX / 2))) {
		return cpr_bad_val(cpr, sv, "uid");
	}
	*out_val = (uid_t)val;
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_mntconf_parser {
	struct silofs_conf_parser cpr;
};

static void mpr_setup(struct silofs_mntconf_parser *mpr,
                      struct silofs_alloc *alloc, const char *data)
{
	cpr_setup(&mpr->cpr, alloc, data);
}

static int mpr_parse_rule_args(const struct silofs_mntconf_parser *mpr,
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
			return cpr_bad_conf(&mpr->cpr, carg,
			                    "illegal key-value");
		}
		if (silofs_strview_isequal(key, "recursive")) {
			err = cpr_parse_bool(&mpr->cpr, val,
			                     &mntrule->recursive);
			if (err) {
				return err;
			}
		} else if (silofs_strview_isequal(key, "uid")) {
			err = cpr_parse_uid(&mpr->cpr, val, &mntrule->uid);
			if (err) {
				return err;
			}
		} else {
			return cpr_bad_conf(&mpr->cpr, key, "unknown key");
		}
		silofs_strview_split(tail, seps, &ss_pair);
	}
	return 0;
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
mpr_parse_rule_path(const struct silofs_mntconf_parser *mpr,
                    const struct silofs_strview *path, char **out_rpath)
{
	struct silofs_strview sv;
	char *dpath = NULL;
	char *rpath = NULL;
	int err;

	err = cpr_strdup(&mpr->cpr, path, &dpath);
	if (err) {
		return err;
	}
	err = resolve_dir_realpath(dpath, &rpath);
	cpr_strfree(&mpr->cpr, &dpath);
	if (err) {
		return err;
	}
	silofs_strview_init(&sv, rpath);
	err = cpr_strdup(&mpr->cpr, &sv, out_rpath);
	cpr_strfree(&mpr->cpr, &rpath);
	if (err) {
		return err;
	}
	return 0;
}

static void mpr_release_rule(const struct silofs_mntconf_parser *mpr,
                             struct silofs_mntrule *mntrule)
{
	cpr_strfree(&mpr->cpr, &mntrule->path);
	mntrule->uid = silofs_uid_nobody();
}

static int mpr_parse_rule(const struct silofs_mntconf_parser *mpr,
                          const struct silofs_strview *path,
                          const struct silofs_strview *args,
                          struct silofs_mntrules *mrules)
{
	const size_t max_rules = ARRAY_SIZE(mrules->rules);
	struct silofs_mntrule *mntrule = NULL;
	int err;

	if (mrules->nrules >= max_rules) {
		return cpr_bad_conf(&mpr->cpr, NULL, "too many mount-rules");
	}
	mntrule = &mrules->rules[mrules->nrules];
	err = mpr_parse_rule_path(mpr, path, &mntrule->path);
	if (err) {
		return err;
	}
	err = mpr_parse_rule_args(mpr, args, mntrule);
	if (err) {
		mpr_release_rule(mpr, mntrule);
		return err;
	}
	mrules->nrules++;
	return 0;
}

static int mpr_parse_line(const struct silofs_mntconf_parser *mpr,
                          struct silofs_mntrules *mrules)
{
	struct silofs_strview sline;
	struct silofs_strview_pair svp;
	const char *seps = " \t";
	int err;

	silofs_strview_split_chr(&mpr->cpr.line, '#', &svp);
	silofs_strview_strip_ws(&svp.first, &sline);
	if (!silofs_strview_isempty(&sline)) {
		silofs_strview_split(&sline, seps, &svp);
		err = mpr_parse_rule(mpr, &svp.first, &svp.second, mrules);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int mpr_parse_rules(struct silofs_mntconf_parser *mpr,
                           struct silofs_mntrules *mrules)
{
	struct silofs_strview_pair svp;
	const struct silofs_strview *line = &svp.first;
	const struct silofs_strview *tail = &svp.second;
	int err;

	cpr_reset_line(&mpr->cpr);
	silofs_strview_split_chr(&mpr->cpr.data, '\n', &svp);
	while (!silofs_strview_isempty(line) ||
	       !silofs_strview_isempty(tail)) {
		cpr_update_next_line(&mpr->cpr, line);
		err = mpr_parse_line(mpr, mrules);
		if (err) {
			return err;
		}
		silofs_strview_split_chr(&svp.second, '\n', &svp);
	}
	return 0;
}

static void mpr_release_rules(struct silofs_mntconf_parser *mpr,
                              struct silofs_mntrules *mrules)
{
	for (size_t i = 0; i < mrules->nrules; ++i) {
		mpr_release_rule(mpr, &mrules->rules[i]);
	}
	mrules->nrules = 0;
}

int silofs_parse_mntrules(struct silofs_mntrules *mrules,
                          struct silofs_alloc *alloc, const char *conf)
{
	struct silofs_mntconf_parser mpr;
	int err;

	mpr_setup(&mpr, alloc, conf);
	err = mpr_parse_rules(&mpr, mrules);
	if (err) {
		mpr_release_rules(&mpr, mrules);
		return err;
	}
	return 0;
}

void silofs_release_mntrules(struct silofs_mntrules *mrules,
                             struct silofs_alloc *alloc)
{
	struct silofs_mntconf_parser mpr;

	mpr_setup(&mpr, alloc, NULL);
	mpr_release_rules(&mpr, mrules);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
