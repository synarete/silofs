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

static bool ss_equals(const struct silofs_substr *ss, const char *s)
{
	return silofs_substr_isequal(ss, s);
}

static bool ss_isempty(const struct silofs_substr *ss)
{
	return silofs_substr_isempty(ss);
}

static void ss_split_by(const struct silofs_substr *ss, char sep,
                        struct silofs_substr_pair *out_ss_pair)
{
	silofs_substr_split_chr(ss, sep, out_ss_pair);
}

static void ss_split_by_nl(const struct silofs_substr *ss,
                           struct silofs_substr_pair *out_ss_pair)
{
	ss_split_by(ss, '\n', out_ss_pair);
}

static void ss_split_by_ws(const struct silofs_substr *ss,
                           struct silofs_substr_pair *out_ss_pair)
{
	silofs_substr_split(ss, " \t", out_ss_pair);
}

static void ss_strip_ws(const struct silofs_substr *ss,
                        struct silofs_substr *out_ss)
{
	silofs_substr_strip_ws(ss, out_ss);
}

static void ss_copyto(const struct silofs_substr *ss, char *s, size_t n)
{
	silofs_substr_copyto(ss, s, n);
}

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
                       const struct silofs_substr *ss)
{
	if (ss_equals(ss, "1") || ss_equals(ss, "true")) {
		return true;
	}
	if (ss_equals(ss, "0") || ss_equals(ss, "false")) {
		return false;
	}
	die_illegal_value(fl, ss, "boolean");
	return false; /* make clangscan happy */
}

static long parse_long(const struct silofs_fileline *fl,
                       const struct silofs_substr *ss)
{
	long val = 0;
	char *endptr = NULL;
	char str[64] = "";

	if (ss->len >= sizeof(str)) {
		die_illegal_value(fl, ss, "integer");
	}
	silofs_substr_copyto(ss, str, sizeof(str));

	errno = 0;
	val = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		die_illegal_value(fl, ss, "integer");
	}
	if (strlen(endptr) > 1) {
		die_illegal_value(fl, ss, "integer");
	}
	return val;
}

static int parse_int(const struct silofs_fileline *fl,
                     const struct silofs_substr *ss)

{
	long num;

	num = parse_long(fl, ss);
	if ((num > INT_MAX) || (num < INT_MIN)) {
		die_illegal_value(fl, ss, "int");
	}
	return (int)num;
}

static uid_t parse_uid(const struct silofs_fileline *fl,
                       const struct silofs_substr *ss)
{
	int val;

	val = parse_int(fl, ss);
	if ((val < 0) || (val > (INT_MAX / 2))) {
		die_illegal_value(fl, ss, "uid");
	}
	return (uid_t)val;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *dup_substr(const struct silofs_substr *ss)
{
	char *s;

	s = zalloc(ss->len + 1);
	ss_copyto(ss, s, ss->len);
	return s;
}

static char *realpath_of(const struct silofs_substr *path)
{
	char *rpath;
	char *cpath;

	cpath = dup_substr(path);
	rpath = realpath(cpath, NULL);
	if (rpath == NULL) {
		return cpath; /* no realpath (now) */
	}
	free(cpath);
	return rpath;
}

static void parse_mntconf_rule_args(const struct silofs_fileline *fl,
                                    const struct silofs_substr *args,
                                    struct silofs_mntrule *mntr)
{
	struct silofs_substr_pair key_val;
	struct silofs_substr_pair ss_pair;
	struct silofs_substr *key = &key_val.first;
	struct silofs_substr *val = &key_val.second;
	struct silofs_substr *carg = &ss_pair.first;
	struct silofs_substr *tail = &ss_pair.second;

	mntr->uid = (uid_t)(-1);
	mntr->recursive = false;

	ss_split_by_ws(args, &ss_pair);
	while (!ss_isempty(carg) || !ss_isempty(tail)) {
		ss_split_by(carg, '=', &key_val);
		if (ss_isempty(key) || ss_isempty(val)) {
			die_illegal_conf(fl, "illegal key-value: '%.*s'",
			                 carg->len, carg->str);
		}
		if (ss_equals(key, "recursive")) {
			mntr->recursive = parse_bool(fl, val);
		} else if (ss_equals(key, "uid")) {
			mntr->uid = parse_uid(fl, val);
		} else {
			die_illegal_conf(fl, "unknown key: '%.*s'",
			                 key->len, key->str);
		}
		ss_split_by_ws(tail, &ss_pair);
	}
}

static void parse_mntconf_rule(const struct silofs_fileline *fl,
                               const struct silofs_substr *path,
                               const struct silofs_substr *args,
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
                               const struct silofs_substr *line,
                               struct silofs_mntrules *mrules)
{
	struct silofs_substr sline;
	struct silofs_substr_pair ssp;

	ss_split_by(line, '#', &ssp);
	ss_strip_ws(&ssp.first, &sline);
	if (!ss_isempty(&sline)) {
		ss_split_by_ws(&sline, &ssp);
		parse_mntconf_rule(fl, &ssp.first, &ssp.second, mrules);
	}
}

static void parse_mntconf(const struct silofs_substr *ss_conf,
                          const char *path, struct silofs_mntrules *mrules)
{
	struct silofs_substr_pair ss_pair;
	struct silofs_substr *line = &ss_pair.first;
	struct silofs_substr *tail = &ss_pair.second;
	struct silofs_fileline fl = {
		.file = path,
		.line = 0
	};

	ss_split_by_nl(ss_conf, &ss_pair);
	while (!ss_isempty(line) || !ss_isempty(tail)) {
		fl.line++;
		parse_mntconf_line(&fl, line, mrules);
		ss_split_by_nl(tail, &ss_pair);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *read_mntconf_file(const char *path)
{
	struct stat st;
	size_t size;
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
	struct silofs_substr ss_conf;
	struct silofs_mntrules *mrules;

	errno = 0;
	conf = read_mntconf_file(path);
	silofs_substr_init(&ss_conf, conf);
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

