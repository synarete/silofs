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
#include <silofs/configs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

#include <silofs/types.h>
#include <silofs/errors.h>
#include <silofs/mntsvc.h>
#include <silofs/appexec.h>
#include <silofs/base.h>
#include <silofs/str.h>
#include <silofs/fs.h>

static bool strview_isempty(const struct silofs_strview *sv)
{
	return silofs_strview_isempty(sv);
}

static bool strview_isequal(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_isequal(sv, s);
}

static void
strview_copyto(const struct silofs_strview *sv, void *buf, size_t n)
{
	(void)silofs_strview_copyto(sv, buf, n);
}

static void strview_strip_ws(const struct silofs_strview *sv,
                             struct silofs_strview *out_sv)
{
	silofs_strview_strip_ws(sv, out_sv);
}

static void strview_split(const struct silofs_strview *sv, const char *s,
                          struct silofs_strview_pair *out_svp)
{
	silofs_strview_split(sv, s, out_svp);
}

static void strview_split_chr(const struct silofs_strview *sv, char sep,
                              struct silofs_strview_pair *out_svp)
{
	silofs_strview_split_chr(sv, sep, out_svp);
}

static char strview_chr_at(const struct silofs_strview *sv, size_t n)
{
	return *silofs_strview_at(sv, n);
}

static bool strview_has_substr(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_find(sv, s) < silofs_strview_size(sv);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_conf_parser {
	struct silofs_alloc *alloc;
	struct silofs_strview conf;
	struct silofs_strview line;
	int line_no;
};

static void cpr_setup(struct silofs_conf_parser *cpr,
                      struct silofs_alloc *alloc, const char *data)
{
	silofs_strview_init(&cpr->conf, data);
	silofs_strview_initz(&cpr->line);
	cpr->alloc   = (alloc != nullptr) ? alloc : silofs_default_alloc;
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
	if (line != nullptr) {
		strview_strip_ws(line, &cpr->line);
	} else {
		silofs_strview_initz(&cpr->line);
	}
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
	if (p == nullptr) {
		return -SILOFS_ENOMEM;
	}
	*out_ptr = p;
	return 0;
}

static void
cpr_zfree(const struct silofs_conf_parser *cpr, void *ptr, size_t nbytes)
{
	if ((ptr != nullptr) && (nbytes > 0)) {
		silofs_memfree(cpr->alloc, ptr, nbytes, SILOFS_ALLOCF_BZERO);
	}
}

static int cpr_strdup(const struct silofs_conf_parser *cpr,
                      const struct silofs_strview *sv, char **out_str)
{
	const size_t n = sv->len + 1;
	void *p        = nullptr;
	int err;

	err = cpr_zalloc(cpr, n, &p);
	if (err) {
		return err;
	}
	*out_str = (char *)p;
	strview_copyto(sv, *out_str, n);
	return 0;
}

static void cpr_strfree(const struct silofs_conf_parser *cpr, char **str)
{
	if ((str != nullptr) && (*str != nullptr)) {
		const size_t len = silofs_str_length(*str);

		cpr_zfree(cpr, *str, len + 1);
		*str = nullptr;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cpr_bad_conf(const struct silofs_conf_parser *cpr,
                        const struct silofs_strview *val, const char *msg)
{
	if (val != nullptr) {
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
	if (strview_isequal(sv, "1") || strview_isequal(sv, "true")) {
		*out_val = true;
		return 0;
	}
	if (strview_isequal(sv, "0") || strview_isequal(sv, "false")) {
		*out_val = false;
		return 0;
	}
	return cpr_bad_val(cpr, sv, "boolean");
}

static int cpr_parse_long(const struct silofs_conf_parser *cpr,
                          const struct silofs_strview *sv, long *out_val)
{
	char str[80] = "";
	char *endptr = nullptr;
	long val     = 0;

	if (sv->len >= sizeof(str)) {
		return cpr_bad_val(cpr, sv, "integer");
	}
	strview_copyto(sv, str, sizeof(str));

	errno = 0;
	val   = strtol(str, &endptr, 0);
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
                         const struct silofs_strview *sv, uid_t *out_uid)
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
	*out_uid = (uid_t)val;
	return 0;
}

static int cpr_require_ascii(const struct silofs_conf_parser *cpr)
{
	if (!silofs_strview_isascii(&cpr->conf)) {
		return cpr_bad_conf(cpr, nullptr, "non-ascii");
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_mntconf_parser {
	struct silofs_conf_parser cpr;
};

static void mcp_setup(struct silofs_mntconf_parser *mcp,
                      struct silofs_alloc *alloc, const char *data)
{
	cpr_setup(&mcp->cpr, alloc, data);
}

static int mcp_require_ascii(const struct silofs_mntconf_parser *mcp)
{
	return cpr_require_ascii(&mcp->cpr);
}

static int mcp_parse_rule_args(const struct silofs_mntconf_parser *mcp,
                               const struct silofs_strview *args,
                               struct silofs_mntrule *mntrule)
{
	struct silofs_strview_pair key_val;
	struct silofs_strview_pair ss_pair;
	struct silofs_strview *key  = &key_val.first;
	struct silofs_strview *val  = &key_val.second;
	struct silofs_strview *carg = &ss_pair.first;
	struct silofs_strview *tail = &ss_pair.second;
	const char *seps            = " \t";
	int err                     = 0;

	mntrule->uid       = (uid_t)(-1);
	mntrule->recursive = false;

	strview_split(args, seps, &ss_pair);
	while (!strview_isempty(carg) || !strview_isempty(tail)) {
		strview_split_chr(carg, '=', &key_val);
		if (strview_isempty(key) || strview_isempty(val)) {
			return cpr_bad_conf(&mcp->cpr, carg,
			                    "illegal key-value");
		}
		if (strview_isequal(key, "recursive")) {
			err = cpr_parse_bool(&mcp->cpr, val,
			                     &mntrule->recursive);
			if (err) {
				return err;
			}
		} else if (strview_isequal(key, "uid")) {
			err = cpr_parse_uid(&mcp->cpr, val, &mntrule->uid);
			if (err) {
				return err;
			}
		} else {
			return cpr_bad_conf(&mcp->cpr, key, "unknown key");
		}
		strview_split(tail, seps, &ss_pair);
	}
	return 0;
}

static int mcp_check_rule_path(const struct silofs_mntconf_parser *mcp,
                               const struct silofs_strview *path)
{
	const char *tag = "path";

	if (strview_isempty(path)) {
		return cpr_bad_val(&mcp->cpr, path, tag);
	}
	if (strview_chr_at(path, 0) != '/') {
		return cpr_bad_val(&mcp->cpr, path, tag);
	}
	if (strview_has_substr(path, "..")) {
		return cpr_bad_val(&mcp->cpr, path, tag);
	}
	return 0;
}

static int
mcp_parse_rule_path(const struct silofs_mntconf_parser *mcp,
                    const struct silofs_strview *path, char **out_rpath)
{
	int err;

	err = mcp_check_rule_path(mcp, path);
	if (err) {
		return err;
	}
	err = cpr_strdup(&mcp->cpr, path, out_rpath);
	if (err) {
		return err;
	}
	return 0;
}

static void mcp_release_rule(const struct silofs_mntconf_parser *mcp,
                             struct silofs_mntrule *mntrule)
{
	cpr_strfree(&mcp->cpr, &mntrule->path);
	mntrule->uid = silofs_uid_nobody();
}

static int mcp_parse_rule(const struct silofs_mntconf_parser *mcp,
                          const struct silofs_strview *path,
                          const struct silofs_strview *args,
                          struct silofs_mntrules *mrules)
{
	constexpr size_t max_rules     = ARRAY_SIZE(mrules->rules);
	struct silofs_mntrule *mntrule = nullptr;
	int err;

	if (mrules->nrules >= max_rules) {
		return cpr_bad_conf(&mcp->cpr, nullptr,
		                    "too many mount-rules");
	}
	mntrule = &mrules->rules[mrules->nrules];
	err     = mcp_parse_rule_path(mcp, path, &mntrule->path);
	if (err) {
		return err;
	}
	err = mcp_parse_rule_args(mcp, args, mntrule);
	if (err) {
		mcp_release_rule(mcp, mntrule);
		return err;
	}
	mrules->nrules++;
	return 0;
}

static int mcp_parse_line(const struct silofs_mntconf_parser *mcp,
                          struct silofs_mntrules *mrules)
{
	struct silofs_strview sline;
	struct silofs_strview_pair svp;

	strview_split_chr(&mcp->cpr.line, '#', &svp);
	strview_strip_ws(&svp.first, &sline);
	if (strview_isempty(&sline)) {
		return 0;
	}
	strview_split(&sline, " \t", &svp);
	return mcp_parse_rule(mcp, &svp.first, &svp.second, mrules);
}

static int mcp_parse_rules(struct silofs_mntconf_parser *mcp,
                           struct silofs_mntrules *mrules)
{
	struct silofs_strview_pair svp;
	const struct silofs_strview *line = &svp.first;
	const struct silofs_strview *tail = &svp.second;
	int err;

	cpr_reset_line(&mcp->cpr);
	strview_split_chr(&mcp->cpr.conf, '\n', &svp);
	while (!strview_isempty(line) || !strview_isempty(tail)) {
		cpr_update_next_line(&mcp->cpr, line);
		err = mcp_parse_line(mcp, mrules);
		if (err) {
			return err;
		}
		strview_split_chr(&svp.second, '\n', &svp);
	}
	return 0;
}

static void mcp_release_rules(const struct silofs_mntconf_parser *mcp,
                              struct silofs_mntrules *mrules)
{
	for (size_t i = 0; i < mrules->nrules; ++i) {
		mcp_release_rule(mcp, &mrules->rules[i]);
	}
	mrules->nrules = 0;
}

int silofs_parse_mntrules(struct silofs_mntrules *mrules,
                          struct silofs_alloc *alloc, const char *conf)
{
	struct silofs_mntconf_parser mcp;
	int err;

	mcp_setup(&mcp, alloc, conf);
	err = mcp_require_ascii(&mcp);
	if (err) {
		mcp_release_rules(&mcp, mrules);
		return err;
	}
	err = mcp_parse_rules(&mcp, mrules);
	if (err) {
		mcp_release_rules(&mcp, mrules);
		return err;
	}
	return 0;
}

void silofs_release_mntrules(struct silofs_mntrules *mrules,
                             struct silofs_alloc *alloc)
{
	struct silofs_mntconf_parser mcp;

	mcp_setup(&mcp, alloc, nullptr);
	mcp_release_rules(&mcp, mrules);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_mountinfo_parser {
	struct silofs_conf_parser cpr;
};

static void mip_setup(struct silofs_mountinfo_parser *mip,
                      struct silofs_alloc *alloc, const char *data)
{
	cpr_setup(&mip->cpr, alloc, data);
}

static void mip_parse_field(const struct silofs_mountinfo_parser *mip,
                            size_t idx, struct silofs_strview *out_field)
{
	struct silofs_strview_pair svp;
	struct silofs_strview *word = &svp.first;
	struct silofs_strview *tail = &svp.second;

	silofs_strview_init(out_field, "");
	strview_split(&mip->cpr.line, " \t\v", &svp);
	while (!strview_isempty(word) || !strview_isempty(tail)) {
		if (idx == 0) {
			strview_strip_ws(word, out_field);
			break;
		}
		silofs_strview_split(tail, " \t\v", &svp);
		idx--;
	}
}

static bool mip_isfusesilofs_line(const struct silofs_mountinfo_parser *mip)
{
	return strview_has_substr(&mip->cpr.line, " - ") &&
	       strview_has_substr(&mip->cpr.line, "fuse.silofs");
}

static int mip_parse_mntinfo(const struct silofs_mountinfo_parser *mip,
                             struct silofs_mntinfos *minfos)
{
	constexpr size_t max_infos = ARRAY_SIZE(minfos->mntd);
	struct silofs_strview mntdir;
	int err;

	if (minfos->nmntd >= max_infos) {
		return cpr_bad_conf(&mip->cpr, nullptr,
		                    "too many mountinfo entries");
	}
	mip_parse_field(mip, 4, &mntdir);
	if (strview_isempty(&mntdir)) {
		return 0;
	}
	err = cpr_strdup(&mip->cpr, &mntdir, &minfos->mntd[minfos->nmntd]);
	if (err) {
		return err;
	}
	minfos->nmntd++;
	return 0;
}

static int mip_parse_line(struct silofs_mountinfo_parser *mip,
                          struct silofs_mntinfos *minfos)
{
	struct silofs_strview sline;
	struct silofs_strview_pair svp;

	strview_split_chr(&mip->cpr.line, '#', &svp);
	strview_strip_ws(&svp.first, &sline);
	if (strview_isempty(&sline)) {
		return 0;
	}
	cpr_update_line(&mip->cpr, &sline);
	if (!mip_isfusesilofs_line(mip)) {
		return 0;
	}
	return mip_parse_mntinfo(mip, minfos);
}

static int mip_parse_infos(struct silofs_mountinfo_parser *mip,
                           struct silofs_mntinfos *minfos)
{
	struct silofs_strview_pair svp;
	const struct silofs_strview *line = &svp.first;
	const struct silofs_strview *tail = &svp.second;
	int err;

	cpr_reset_line(&mip->cpr);
	strview_split_chr(&mip->cpr.conf, '\n', &svp);
	while (!strview_isempty(line) || !strview_isempty(tail)) {
		cpr_update_next_line(&mip->cpr, line);
		err = mip_parse_line(mip, minfos);
		if (err) {
			return err;
		}
		strview_split_chr(tail, '\n', &svp);
	}
	return 0;
}

static void
mip_release_mntd(const struct silofs_mountinfo_parser *mip, char **mntd)
{
	cpr_strfree(&mip->cpr, mntd);
}

static void mip_release_mntds(const struct silofs_mountinfo_parser *mip,
                              struct silofs_mntinfos *minfos)
{
	for (size_t i = 0; i < minfos->nmntd; ++i) {
		mip_release_mntd(mip, &minfos->mntd[i]);
	}
	minfos->nmntd = 0;
}

int silofs_parse_mntinfos(struct silofs_mntinfos *minfos,
                          struct silofs_alloc *alloc, const char *conf)
{
	struct silofs_mountinfo_parser mip;

	mip_setup(&mip, alloc, conf);
	return mip_parse_infos(&mip, minfos);
}

void silofs_release_mntinfos(struct silofs_mntinfos *minfos,
                             struct silofs_alloc *alloc)
{
	struct silofs_mountinfo_parser mip;

	mip_setup(&mip, alloc, nullptr);
	mip_release_mntds(&mip, minfos);
}
