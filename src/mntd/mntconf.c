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

#define die_illegal_conf(fl_, fmt_, ...) \
	silofs_die_at(errno, (fl_)->file, (fl_)->line, fmt_, __VA_ARGS__)


#define die_illegal_value(fl_, ss_, tag_) \
	die_illegal_conf(fl_, "illegal %s: '%.*s'", \
	                 tag_, (ss_)->len, (ss_)->str)


struct silofs_fileline {
	const char *file;
	int line;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static bool parse_bool(const struct silofs_fileline *fl,
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
	die_illegal_value(fl, sv, "boolean");
	return false; /* make clangscan happy */
}

static long parse_long(const struct silofs_fileline *fl,
                       const struct silofs_strview *sv)
{
	long val = 0;
	char *endptr = NULL;
	char str[64] = "";

	if (sv->len >= sizeof(str)) {
		die_illegal_value(fl, sv, "integer");
	}
	silofs_strview_copyto(sv, str, sizeof(str));

	errno = 0;
	val = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		die_illegal_value(fl, sv, "integer");
	}
	if (strlen(endptr) > 1) {
		die_illegal_value(fl, sv, "integer");
	}
	return val;
}

static int parse_int(const struct silofs_fileline *fl,
                     const struct silofs_strview *sv)

{
	long num;

	num = parse_long(fl, sv);
	if ((num > INT_MAX) || (num < INT_MIN)) {
		die_illegal_value(fl, sv, "int");
	}
	return (int)num;
}

static uid_t parse_uid(const struct silofs_fileline *fl,
                       const struct silofs_strview *sv)
{
	int val;

	val = parse_int(fl, sv);
	if ((val < 0) || (val > (INT_MAX / 2))) {
		die_illegal_value(fl, sv, "uid");
	}
	return (uid_t)val;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static void parse_mntconf_rule_args(const struct silofs_fileline *fl,
                                    const struct silofs_strview *args,
                                    struct silofs_mntrule *mntr)
{
	struct silofs_strview_pair key_val;
	struct silofs_strview_pair ss_pair;
	struct silofs_strview *key = &key_val.first;
	struct silofs_strview *val = &key_val.second;
	struct silofs_strview *carg = &ss_pair.first;
	struct silofs_strview *tail = &ss_pair.second;
	const char *seps = " \t";

	mntr->uid = (uid_t)(-1);
	mntr->recursive = false;

	silofs_strview_split(args, seps, &ss_pair);
	while (!silofs_strview_isempty(carg) ||
	       !silofs_strview_isempty(tail)) {
		silofs_strview_split_chr(carg, '=', &key_val);
		if (silofs_strview_isempty(key) ||
		    silofs_strview_isempty(val)) {
			die_illegal_conf(fl, "illegal key-value: '%.*s'",
			                 carg->len, carg->str);
		}
		if (silofs_strview_isequal(key, "recursive")) {
			mntr->recursive = parse_bool(fl, val);
		} else if (silofs_strview_isequal(key, "uid")) {
			mntr->uid = parse_uid(fl, val);
		} else {
			die_illegal_conf(fl, "unknown key: '%.*s'",
			                 key->len, key->str);
		}
		silofs_strview_split(tail, seps, &ss_pair);
	}
}

static void parse_mntconf_rule(const struct silofs_fileline *fl,
                               const struct silofs_strview *path,
                               const struct silofs_strview *args,
                               struct silofs_mntrules *mrules)
{
	struct silofs_mntrule *mntr;
	const size_t max_rules = SILOFS_ARRAY_SIZE(mrules->rules);

	if (mrules->nrules >= max_rules) {
		die_illegal_conf(fl, "too many mount-rules "\
		                 "(max-rules=%lu)", max_rules);
	}
	mntr = &mrules->rules[mrules->nrules++];
	mntr->path = realpath_of(path);
	parse_mntconf_rule_args(fl, args, mntr);
}

static void parse_mntconf_line(const struct silofs_fileline *fl,
                               const struct silofs_strview *line,
                               struct silofs_mntrules *mrules)
{
	struct silofs_strview sline;
	struct silofs_strview_pair svp;
	const char *seps = " \t";

	silofs_strview_split_chr(line, '#', &svp);
	silofs_strview_strip_ws(&svp.first, &sline);
	if (!silofs_strview_isempty(&sline)) {
		silofs_strview_split(&sline, seps, &svp);
		parse_mntconf_rule(fl, &svp.first, &svp.second, mrules);
	}
}

static void parse_mntconf(const struct silofs_strview *conf,
                          const char *path, struct silofs_mntrules *mrules)
{
	struct silofs_strview_pair svp;
	struct silofs_strview *line = &svp.first;
	struct silofs_strview *tail = &svp.second;
	struct silofs_fileline fl = {
		.file = path,
		.line = 0
	};

	silofs_strview_split_chr(conf, '\n', &svp);
	while (!silofs_strview_isempty(line) ||
	       !silofs_strview_isempty(tail)) {
		fl.line++;
		parse_mntconf_line(&fl, line, mrules);
		silofs_strview_split_chr(tail, '\n', &svp);
	}
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

static void del_mnt_conf(struct silofs_mntrules *mrules)
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
	char *conf;
	struct silofs_strview ss_conf;
	struct silofs_mntrules *mrules;

	errno = 0;
	conf = read_mntconf_file(path);
	silofs_strview_init(&ss_conf, conf);
	mrules = new_mntrules();
	parse_mntconf(&ss_conf, path, mrules);
	free(conf);

	return mrules;
}

void mountd_free_mntrules(struct silofs_mntrules *mnt_conf)
{
	if (mnt_conf != NULL) {
		del_mnt_conf(mnt_conf);
	}
}
