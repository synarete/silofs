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
#include "mountd.h"


static void *zalloc(size_t nbytes)
{
	int err;
	void *ptr = NULL;

	err = silofs_zmalloc(nbytes, &ptr);
	if (err) {
		silofs_die(err, "malloc failure: nbytes=%lu", nbytes);
	}
	return ptr;
}

static char *dup_strview(const struct silofs_strview *sv)
{
	char *s;

	s = zalloc(sv->len + 1);
	silofs_strview_copyto(sv, s, sv->len);
	return s;
}

static char *realpath_of(const struct silofs_strview *path)
{
	char *rpath;
	char *cpath;

	cpath = dup_strview(path);
	rpath = realpath(cpath, NULL);
	if (rpath == NULL) {
		return cpath; /* no realpath (now) */
	}
	free(cpath);
	return rpath;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct mntconf_ctx {
	struct silofs_strview file;
	struct silofs_strview conf;
	struct silofs_strview line;
	int line_no;
};

static void mntc_setup(struct mntconf_ctx *mntc,
                       const char *file, const char *conf)
{
	silofs_strview_init(&mntc->file, file);
	silofs_strview_init(&mntc->conf, conf);
	silofs_strview_initz(&mntc->line);
	mntc->line_no = 0;
}

static void mntc_update_line(struct mntconf_ctx *mntc,
                             const struct silofs_strview *line)
{
	silofs_strview_init_by(&mntc->line, line);
}

static void mntc_update_next_line(struct mntconf_ctx *mntc,
                                  const struct silofs_strview *line)
{
	mntc_update_line(mntc, line);
	mntc->line_no++;
}

silofs_attr_noreturn
static void mntc_die_bad_conf(const struct mntconf_ctx *mntc,
                              const struct silofs_strview *val,
                              const char *msg)
{
	if (val != NULL) {
		silofs_die_at(EINVAL, mntc->file.str, mntc->line_no,
		              "bad mntconf: %s: '%.*s'",
		              msg, val->len, val->str);
	} else {
		silofs_die_at(EINVAL, mntc->file.str, mntc->line_no,
		              "bad mntconf: %s", msg);
	}
}

silofs_attr_noreturn
static void mntc_die_bad_val(const struct mntconf_ctx *mntc,
                             const struct silofs_strview *val, const char *tag)
{
	silofs_die_at(EINVAL, mntc->file.str, mntc->line_no,
	              "illegal mntconf %s value: '%.*s'",
	              tag, val->len, val->str);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool mntc_parse_bool(const struct mntconf_ctx *mntc,
                            const struct silofs_strview *sv)
{
	if (silofs_strview_isequal(sv, "1") ||
	    silofs_strview_isequal(sv, "true")) {
		return true;
	}
	if (silofs_strview_isequal(sv, "0") ||
	    silofs_strview_isequal(sv, "false")) {
		return false;
	}
	mntc_die_bad_val(mntc, sv, "boolean");
	return false; /* make clangscan happy */
}

static long mntc_parse_long(const struct mntconf_ctx *mntc,
                            const struct silofs_strview *sv)
{
	char str[80] = "";
	char *endptr = NULL;
	long val = 0;

	if (sv->len >= sizeof(str)) {
		mntc_die_bad_val(mntc, sv, "integer");
	}
	silofs_strview_copyto(sv, str, sizeof(str));

	errno = 0;
	val = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		mntc_die_bad_val(mntc, sv, "integer");
	}
	if (strlen(endptr) > 1) {
		mntc_die_bad_val(mntc, sv, "integer");
	}
	return val;
}

static int mntc_parse_int(const struct mntconf_ctx *mntc,
                          const struct silofs_strview *sv)

{
	long num;

	num = mntc_parse_long(mntc, sv);
	if ((num > INT_MAX) || (num < INT_MIN)) {
		mntc_die_bad_val(mntc, sv, "int");
	}
	return (int)num;
}

static uid_t mntc_parse_uid(const struct mntconf_ctx *mntc,
                            const struct silofs_strview *sv)
{
	int val;

	val = mntc_parse_int(mntc, sv);
	if ((val < 0) || (val > (INT_MAX / 2))) {
		mntc_die_bad_val(mntc, sv, "uid");
	}
	return (uid_t)val;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mntc_parse_rule_args(const struct mntconf_ctx *mntc,
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

	mntrule->uid = (uid_t)(-1);
	mntrule->recursive = false;

	silofs_strview_split(args, seps, &ss_pair);
	while (!silofs_strview_isempty(carg) ||
	       !silofs_strview_isempty(tail)) {
		silofs_strview_split_chr(carg, '=', &key_val);
		if (silofs_strview_isempty(key) ||
		    silofs_strview_isempty(val)) {
			mntc_die_bad_conf(mntc, carg, "illegal key-value");
		}
		if (silofs_strview_isequal(key, "recursive")) {
			mntrule->recursive = mntc_parse_bool(mntc, val);
		} else if (silofs_strview_isequal(key, "uid")) {
			mntrule->uid = mntc_parse_uid(mntc, val);
		} else {
			mntc_die_bad_conf(mntc, key, "unknown key");
		}
		silofs_strview_split(tail, seps, &ss_pair);
	}
}

static void mntc_parse_rule(const struct mntconf_ctx *mntc,
                            const struct silofs_strview *path,
                            const struct silofs_strview *args,
                            struct silofs_mntrules *mrules)
{
	const size_t max_rules = SILOFS_ARRAY_SIZE(mrules->rules);
	struct silofs_mntrule *mntrule = NULL;

	if (mrules->nrules < max_rules) {
		mntrule = &mrules->rules[mrules->nrules++];
		mntrule->path = realpath_of(path);
		mntc_parse_rule_args(mntc, args, mntrule);
	} else {
		mntc_die_bad_conf(mntc, NULL, "too many mount-rules");
	}
}

static void mntc_parse_line(const struct mntconf_ctx *mntc,
                            struct silofs_mntrules *mrules)
{
	struct silofs_strview sline;
	struct silofs_strview_pair svp;
	const char *seps = " \t";

	silofs_strview_split_chr(&mntc->line, '#', &svp);
	silofs_strview_strip_ws(&svp.first, &sline);
	if (!silofs_strview_isempty(&sline)) {
		silofs_strview_split(&sline, seps, &svp);
		mntc_parse_rule(mntc, &svp.first, &svp.second, mrules);
	}
}

static void mntc_parse_rules(struct mntconf_ctx *mntc,
                             struct silofs_mntrules *mrules)
{
	struct silofs_strview_pair svp;
	const struct silofs_strview *line = &svp.first;
	const struct silofs_strview *tail = &svp.second;

	mntc->line_no = 0;
	silofs_strview_split_chr(&mntc->conf, '\n', &svp);
	while (!silofs_strview_isempty(line) ||
	       !silofs_strview_isempty(tail)) {
		mntc->line_no++;
		mntc_update_next_line(mntc, line);
		mntc_parse_line(mntc, mrules);
		silofs_strview_split_chr(&svp.second, '\n', &svp);
	}
}

static void parse_mntrules(const char *path, const char *conf,
                           struct silofs_mntrules *mrules)
{
	struct mntconf_ctx mntc;

	mntc_setup(&mntc, path, conf);
	mntc_parse_rules(&mntc, mrules);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *read_mntconf_file(const char *path)
{
	struct stat st = { .st_size = -1 };
	size_t size = 0;
	char *conf = NULL;
	int fd = -1;
	int err;

	err = silofs_sys_stat(path, &st);
	if (err) {
		silofs_die(err, "stat failure: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		silofs_die(0, "not a regular file: %s", path);
	}
	if (st.st_size > SILOFS_MEGA) {
		silofs_die(-EFBIG, "illegal mntconf file: %s", path);
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "can not open mntconf file %s", path);
	}
	size = (size_t)st.st_size;
	conf = zalloc(size + 1);
	err = silofs_sys_readn(fd, conf, size);
	if (err) {
		silofs_die(err, "failed to read mntconf file %s", path);
	}
	silofs_sys_close(fd);

	return conf;
}

static struct silofs_mntrules *new_mntrules(void)
{
	struct silofs_mntrules *mrules;

	mrules = zalloc(sizeof(*mrules));
	mrules->nrules = 0;

	return mrules;
}

static void del_mntrules(struct silofs_mntrules *mrules)
{
	for (size_t i = 0; i < mrules->nrules; ++i) {
		free(mrules->rules[i].path);
		mrules->rules[i].path = NULL;
	}
	mrules->nrules = 0;
	free(mrules);
}

struct silofs_mntrules *mountd_parse_mntrules(const char *path)
{
	struct silofs_mntrules *mntrules = new_mntrules();
	char *conf = NULL;

	conf = read_mntconf_file(path);
	parse_mntrules(path, conf, mntrules);
	free(conf);

	return mntrules;
}

void mountd_free_mntrules(struct silofs_mntrules *mntrules)
{
	if (mntrules != NULL) {
		del_mntrules(mntrules);
	}
}
