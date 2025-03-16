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
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <silofs/types.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/mntsvc.h>
#include <silofs/appexec.h>
#include "uidgid.h"

static bool strview_isempty(const struct silofs_strview *sv)
{
	return silofs_strview_isempty(sv);
}

static bool strview_isequal(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_isequal(sv, s);
}

static bool strview_hasdata(const struct silofs_strview *sv)
{
	return !strview_isempty(sv);
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

static void strview_split_chr(const struct silofs_strview *sv, char sep,
                              struct silofs_strview_pair *out_sv_pair)
{
	silofs_strview_split_chr(sv, sep, out_sv_pair);
}

static char strview_chr_at(const struct silofs_strview *sv, size_t n)
{
	return *silofs_strview_at(sv, n);
}

static bool strview_has_substr(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_find(sv, s) < silofs_strview_size(sv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
strspan_append(struct silofs_strspan *ss, const struct silofs_strview *sv)
{
	size_t n;

	n = silofs_strspan_nappend(ss, sv->str, sv->len);
	return (n == sv->len) ? 0 : -SILOFS_ENOSPC;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_conf_parser {
	struct silofs_alloc *alloc;
	struct silofs_strspan wcfg;
	struct silofs_strview rcfg;
	struct silofs_strview line;
	int line_no;
};

static void cpr_rsetup(struct silofs_conf_parser *cpr,
                       struct silofs_alloc *alloc, const char *data)
{
	silofs_strspan_initz(&cpr->wcfg);
	silofs_strview_init(&cpr->rcfg, data);
	silofs_strview_initz(&cpr->line);
	cpr->alloc = alloc;
	cpr->line_no = 0;
}

static void cpr_wsetup(struct silofs_conf_parser *cpr,
                       struct silofs_alloc *alloc, char *buf, size_t n)
{
	silofs_strspan_initk(&cpr->wcfg, buf, 0, n);
	silofs_strview_initz(&cpr->rcfg);
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
	if (line != NULL) {
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
	if (p == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_ptr = p;
	return 0;
}

static void
cpr_zfree(const struct silofs_conf_parser *cpr, void *ptr, size_t nbytes)
{
	if ((ptr != NULL) && (nbytes > 0)) {
		silofs_memfree(cpr->alloc, ptr, nbytes, SILOFS_ALLOCF_BZERO);
	}
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
	strview_copyto(sv, *out_str, n);
	return 0;
}

static void cpr_strfree(const struct silofs_conf_parser *cpr, char **str)
{
	if ((str != NULL) && (*str != NULL)) {
		const size_t len = silofs_str_length(*str);

		cpr_zfree(cpr, *str, len + 1);
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

#define cpr_printf silofs_attr_printf(2, 3)

cpr_printf static int
cpr_bad_input(const struct silofs_conf_parser *cpr, const char *fmt, ...)
{
	char msg[256] = "";
	va_list ap;
	const int ret = errno ? -errno : -SILOFS_EINVAL;

	va_start(ap, fmt);
	(void)vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	log_err("%s (line: %d)", msg, cpr->line_no);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	char *endptr = NULL;
	long val = 0;

	if (sv->len >= sizeof(str)) {
		return cpr_bad_val(cpr, sv, "integer");
	}
	strview_copyto(sv, str, sizeof(str));

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

static int cpr_parse_gid(const struct silofs_conf_parser *cpr,
                         const struct silofs_strview *sv, gid_t *out_gid)
{
	int val = -1;
	int err;

	err = cpr_parse_int(cpr, sv, &val);
	if (err) {
		return err;
	}
	if ((val < 0) || (val > (INT_MAX / 2))) {
		return cpr_bad_val(cpr, sv, "gid");
	}
	*out_gid = (gid_t)val;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sysconf_u32(int key, uint32_t *out_val)
{
	long ret;

	ret = sysconf(key);
	if (ret < 0) {
		ret = errno ? -errno : -EINVAL;
		log_err("sysconf error: key=%d ret=%ld", key, ret);
		return (int)ret;
	}
	if (ret > UINT32_MAX) {
		return -ERANGE;
	}
	*out_val = (uint32_t)ret;
	return 0;
}

static int getxx_bsz(size_t *out_bsz)
{
	const size_t align = 1024;
	uint32_t bsz1 = 0;
	uint32_t bsz2 = 0;
	uint32_t bsz;
	int err;

	err = sysconf_u32(_SC_GETPW_R_SIZE_MAX, &bsz1);
	if (err) {
		return err;
	}
	err = sysconf_u32(_SC_GETGR_R_SIZE_MAX, &bsz2);
	if (err) {
		return err;
	}

	bsz = (bsz1 > bsz2) ? bsz1 : bsz2;
	*out_bsz = (((size_t)bsz + align - 1) / align) * align;
	return 0;
}

static int cpr_resolve_uid_by_name(const struct silofs_conf_parser *cpr,
                                   const char *name, uid_t *out_uid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	void *buf = NULL;
	size_t bsz = 0;
	int err;

	err = getxx_bsz(&bsz);
	if (err) {
		goto out;
	}
	err = cpr_zalloc(cpr, bsz, &buf);
	if (err) {
		goto out;
	}
	errno = 0;
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		err = cpr_bad_input(cpr, "failed to resolve user: %s", name);
		goto out;
	}
	if (pw == NULL) {
		err = cpr_bad_input(cpr, "unknown user: %s", name);
		goto out;
	}
	*out_uid = pw->pw_uid;
out:
	cpr_zfree(cpr, buf, bsz);
	return err;
}

static int cpr_resolve_uid_to_name(const struct silofs_conf_parser *cpr,
                                   uid_t uid, char *name, size_t nsz)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	void *buf = NULL;
	size_t bsz = 0;
	size_t len = 0;
	int err;

	err = getxx_bsz(&bsz);
	if (err) {
		goto out;
	}
	err = cpr_zalloc(cpr, bsz, &buf);
	if (err) {
		goto out;
	}
	errno = 0;
	err = getpwuid_r(uid, &pwd, buf, bsz, &pw);
	if (err) {
		err = cpr_bad_input(cpr, "failed to resolve uid: %u", uid);
		goto out;
	}
	if ((pw == NULL) || (pw->pw_name == NULL)) {
		err = cpr_bad_input(cpr, "unknown uid: %u", uid);
		goto out;
	}
	len = silofs_str_length(pw->pw_name);
	if (!len || (len >= nsz)) {
		cpr_bad_input(cpr, "bad user name: %s", pw->pw_name);
		err = -SILOFS_ENAMETOOLONG;
		goto out;
	}
	silofs_str_copy(name, pw->pw_name, len + 1);
out:
	cpr_zfree(cpr, buf, bsz);
	return err;
}

static int cpr_resolve_gid_by_name(const struct silofs_conf_parser *cpr,
                                   const char *name, gid_t *out_gid)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = NULL;
	void *buf = NULL;
	size_t bsz = 0;
	int err;

	err = getxx_bsz(&bsz);
	if (err) {
		goto out;
	}
	err = cpr_zalloc(cpr, bsz, &buf);
	if (err) {
		goto out;
	}
	errno = 0;
	err = getgrnam_r(name, &grp, buf, bsz, &gr);
	if (err) {
		err = cpr_bad_input(cpr, "failed to resolve group: %s", name);
		goto out;
	}
	if (gr == NULL) {
		err = cpr_bad_input(cpr, "unknown group name: %s", name);
		goto out;
	}
	*out_gid = gr->gr_gid;
out:
	cpr_zfree(cpr, buf, bsz);
	return err;
}

static int cpr_resolve_gid_to_name(const struct silofs_conf_parser *cpr,
                                   gid_t gid, char *name, size_t nsz)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = NULL;
	void *buf = NULL;
	size_t bsz = 0;
	size_t len = 0;
	int err;

	err = getxx_bsz(&bsz);
	if (err) {
		goto out;
	}
	err = cpr_zalloc(cpr, bsz, &buf);
	if (err) {
		goto out;
	}
	errno = 0;
	err = getgrgid_r(gid, &grp, buf, bsz, &gr);
	if (err) {
		err = cpr_bad_input(cpr, "failed to resolve gid: %u", gid);
		goto out;
	}
	if ((gr == NULL) || (gr->gr_name == NULL)) {
		err = cpr_bad_input(cpr, "unknown gid: %u", gid);
		goto out;
	}
	len = silofs_str_length(gr->gr_name);
	if (!len || (len >= nsz)) {
		cpr_bad_input(cpr, "bad group name: %s", gr->gr_name);
		err = -SILOFS_ENAMETOOLONG;
		goto out;
	}
	silofs_str_copy(name, gr->gr_name, len + 1);
out:
	cpr_zfree(cpr, buf, bsz);
	return err;
}

static int cpr_resolve_uidgid(const struct silofs_conf_parser *cpr,
                              const char *name, uid_t *out_uid, gid_t *out_gid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	void *buf = NULL;
	size_t bsz = 0;
	int err;

	err = getxx_bsz(&bsz);
	if (err) {
		goto out;
	}
	err = cpr_zalloc(cpr, bsz, &buf);
	if (err) {
		goto out;
	}
	errno = 0;
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		err = cpr_bad_input(cpr, "failed to resolve user: %s", name);
		goto out;
	}
	if (pw == NULL) {
		err = cpr_bad_input(cpr, "unknown user: %s", name);
		goto out;
	}
	*out_uid = pw->pw_uid;
	*out_gid = pw->pw_gid;
out:
	cpr_zfree(cpr, buf, bsz);
	return err;
}

static int cpr_require_ascii(const struct silofs_conf_parser *cpr)
{
	if (!silofs_strview_isascii(&cpr->rcfg)) {
		return cpr_bad_conf(cpr, NULL, "non-ascii");
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_mntconf_parser {
	struct silofs_conf_parser cpr;
};

static void mpr_setup(struct silofs_mntconf_parser *mpr,
                      struct silofs_alloc *alloc, const char *data)
{
	cpr_rsetup(&mpr->cpr, alloc, data);
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
	while (!strview_isempty(carg) || !strview_isempty(tail)) {
		strview_split_chr(carg, '=', &key_val);
		if (strview_isempty(key) || strview_isempty(val)) {
			return cpr_bad_conf(&mpr->cpr, carg,
			                    "illegal key-value");
		}
		if (strview_isequal(key, "recursive")) {
			err = cpr_parse_bool(&mpr->cpr, val,
			                     &mntrule->recursive);
			if (err) {
				return err;
			}
		} else if (strview_isequal(key, "uid")) {
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

static int mpr_check_rule_path(const struct silofs_mntconf_parser *mpr,
                               const struct silofs_strview *path)
{
	const char *tag = "path";

	if (strview_isempty(path)) {
		return cpr_bad_val(&mpr->cpr, path, tag);
	}
	if (strview_chr_at(path, 0) != '/') {
		return cpr_bad_val(&mpr->cpr, path, tag);
	}
	if (strview_has_substr(path, "..")) {
		return cpr_bad_val(&mpr->cpr, path, tag);
	}
	return 0;
}

static int
mpr_parse_rule_path(const struct silofs_mntconf_parser *mpr,
                    const struct silofs_strview *path, char **out_rpath)
{
	int err;

	err = mpr_check_rule_path(mpr, path);
	if (err) {
		return err;
	}
	err = cpr_strdup(&mpr->cpr, path, out_rpath);
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

	strview_split_chr(&mpr->cpr.line, '#', &svp);
	strview_strip_ws(&svp.first, &sline);
	if (!strview_isempty(&sline)) {
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
	strview_split_chr(&mpr->cpr.rcfg, '\n', &svp);
	while (!strview_isempty(line) || !strview_isempty(tail)) {
		cpr_update_next_line(&mpr->cpr, line);
		err = mpr_parse_line(mpr, mrules);
		if (err) {
			return err;
		}
		strview_split_chr(&svp.second, '\n', &svp);
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

enum silofs_idsconf_sec {
	SILOFS_IDSCONF_SEC_NIL,
	SILOFS_IDSCONF_SEC_USERS,
	SILOFS_IDSCONF_SEC_GROUPS,
};

static const char *s_idsconf_sec_name[] = {
	[SILOFS_IDSCONF_SEC_NIL] = "",
	[SILOFS_IDSCONF_SEC_USERS] = "users",
	[SILOFS_IDSCONF_SEC_GROUPS] = "groups",
};

static enum silofs_idsconf_sec
idsconf_sec_by_name(const struct silofs_strview *sv)
{
	const char *sec_name;

	for (int i = 0; i < (int)ARRAY_SIZE(s_idsconf_sec_name); ++i) {
		sec_name = s_idsconf_sec_name[i];
		if (strview_isequal(sv, sec_name)) {
			return (enum silofs_idsconf_sec)i;
		}
	}
	return SILOFS_IDSCONF_SEC_NIL;
}

static const char *idsconf_sec_to_name(enum silofs_idsconf_sec sec)
{
	const char *sec_name = "";

	if (sec < ARRAY_SIZE(s_idsconf_sec_name)) {
		sec_name = s_idsconf_sec_name[sec];
	}
	return sec_name;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_idsconf_parser {
	struct silofs_conf_parser cpr;
	enum silofs_idsconf_sec sec;
};

static void ipr_rsetup(struct silofs_idsconf_parser *ipr,
                       struct silofs_alloc *alloc, const char *data)
{
	cpr_rsetup(&ipr->cpr, alloc, data);
	ipr->sec = SILOFS_IDSCONF_SEC_NIL;
}

static void ipr_wsetup(struct silofs_idsconf_parser *ipr,
                       struct silofs_alloc *alloc, char *buf, size_t n)
{
	cpr_wsetup(&ipr->cpr, alloc, buf, n);
	ipr->sec = SILOFS_IDSCONF_SEC_NIL;
}

static int ipr_malloc_uids(const struct silofs_idsconf_parser *ipr,
                           size_t nuids, struct silofs_uids **out_uids)
{
	void *ptr = NULL;
	int err;

	err = cpr_zalloc(&ipr->cpr, nuids * sizeof((*out_uids)[0]), &ptr);
	if (err) {
		return err;
	}
	*out_uids = ptr;
	return 0;
}

static void ipr_free_uids(const struct silofs_idsconf_parser *ipr,
                          struct silofs_uids *uids, size_t nuids)
{
	cpr_zfree(&ipr->cpr, uids, nuids * sizeof(uids[0]));
}

static void ipr_pfree_uids(const struct silofs_idsconf_parser *ipr,
                           struct silofs_uids **puids, size_t *pnuids)
{
	if ((*puids != NULL) && (*pnuids > 0)) {
		ipr_free_uids(ipr, *puids, *pnuids);
		*puids = NULL;
		*pnuids = 0;
	}
}

static void copy_uids(struct silofs_uids *uids_dst,
                      const struct silofs_uids *uids_src, size_t nuids)
{
	if (uids_src && nuids) {
		memcpy(uids_dst, uids_src, nuids * sizeof(uids_dst[0]));
	}
}

static int
ipr_extend_uids(const struct silofs_idsconf_parser *ipr,
                struct silofs_uids **puids, size_t *pnuids, size_t cnt)
{
	struct silofs_uids *uids = NULL;
	size_t nuids = *pnuids + cnt;
	int err;

	err = ipr_malloc_uids(ipr, nuids, &uids);
	if (err) {
		return err;
	}
	copy_uids(uids, *puids, *pnuids);
	ipr_pfree_uids(ipr, puids, pnuids);
	*puids = uids;
	*pnuids = nuids;
	return 0;
}

static int ipr_append_uids1(const struct silofs_idsconf_parser *ipr,
                            struct silofs_uids **puids, size_t *pnuids,
                            const struct silofs_uids *uids)
{
	int err;

	err = ipr_extend_uids(ipr, puids, pnuids, 1);
	if (err) {
		return err;
	}
	copy_uids(&(*puids)[*pnuids - 1], uids, 1);
	return 0;
}

static int ipr_malloc_gids(const struct silofs_idsconf_parser *ipr,
                           size_t ngids, struct silofs_gids **out_gids)
{
	void *ptr = NULL;
	int err;

	err = cpr_zalloc(&ipr->cpr, ngids * sizeof((*out_gids)[0]), &ptr);
	if (err) {
		return err;
	}
	*out_gids = ptr;
	return 0;
}

static void ipr_free_gids(const struct silofs_idsconf_parser *ipr,
                          struct silofs_gids *gids, size_t ngids)
{
	cpr_zfree(&ipr->cpr, gids, ngids * sizeof(gids[0]));
}

static void ipr_pfree_gids(const struct silofs_idsconf_parser *ipr,
                           struct silofs_gids **pgids, size_t *pngids)
{
	if ((*pgids != NULL) && (*pngids > 0)) {
		ipr_free_gids(ipr, *pgids, *pngids);
		*pgids = NULL;
		*pngids = 0;
	}
}

static void copy_gids(struct silofs_gids *gids_dst,
                      const struct silofs_gids *gids_src, size_t ngids)
{
	if (gids_src && ngids) {
		memcpy(gids_dst, gids_src, ngids * sizeof(gids_dst[0]));
	}
}

static int
ipr_extend_gids(const struct silofs_idsconf_parser *ipr,
                struct silofs_gids **pgids, size_t *pngids, size_t cnt)
{
	struct silofs_gids *gids = NULL;
	size_t ngids = *pngids + cnt;
	int err;

	err = ipr_malloc_gids(ipr, ngids, &gids);
	if (err) {
		return err;
	}
	copy_gids(gids, *pgids, *pngids);
	ipr_pfree_gids(ipr, pgids, pngids);
	*pgids = gids;
	*pngids = ngids;
	return 0;
}

static int ipr_append_gids1(const struct silofs_idsconf_parser *ipr,
                            struct silofs_gids **pgids, size_t *pngids,
                            const struct silofs_gids *gids)
{
	int err;

	err = ipr_extend_gids(ipr, pgids, pngids, 1);
	if (err) {
		return err;
	}
	copy_gids(&(*pgids)[*pngids - 1], gids, 1);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
ipr_parse_uid_by_name(const struct silofs_idsconf_parser *ipr,
                      const struct silofs_strview *name, uid_t *out_uid)
{
	char buf[NAME_MAX + 1] = "";
	int ret;

	errno = 0;
	if (name->len < sizeof(buf)) {
		strview_copyto(name, buf, sizeof(buf) - 1);
		ret = cpr_resolve_uid_by_name(&ipr->cpr, buf, out_uid);
	} else {
		ret = cpr_bad_input(&ipr->cpr, "illegal user name: %.*s",
		                    (int)name->len, name->str);
	}
	return ret;
}

static int
ipr_parse_uid_by_value(const struct silofs_idsconf_parser *ipr,
                       const struct silofs_strview *name, uid_t *out_uid)
{
	return cpr_parse_uid(&ipr->cpr, name, out_uid);
}

static int
ipr_parse_gid_by_name(const struct silofs_idsconf_parser *ipr,
                      const struct silofs_strview *name, gid_t *out_gid)
{
	char buf[NAME_MAX + 1] = "";
	int ret;

	if (name->len < sizeof(buf)) {
		strview_copyto(name, buf, sizeof(buf) - 1);
		ret = cpr_resolve_gid_by_name(&ipr->cpr, buf, out_gid);
	} else {
		ret = cpr_bad_input(&ipr->cpr, "illegal group name: %.*s",
		                    (int)name->len, name->str);
	}
	return ret;
}

static int
ipr_parse_gid_by_value(const struct silofs_idsconf_parser *ipr,
                       const struct silofs_strview *name, gid_t *out_gid)
{
	return cpr_parse_gid(&ipr->cpr, name, out_gid);
}

static int
ipr_parse_uids(const struct silofs_idsconf_parser *ipr,
               const struct silofs_strview *name,
               const struct silofs_strview *suid, struct silofs_uids *out_uids)
{
	int err;

	err = ipr_parse_uid_by_name(ipr, name, &out_uids->host_uid);
	if (err) {
		return err;
	}
	err = ipr_parse_uid_by_value(ipr, suid, &out_uids->fs_uid);
	if (err) {
		return err;
	}
	return 0;
}

static int
ipr_parse_gids(const struct silofs_idsconf_parser *ipr,
               const struct silofs_strview *name,
               const struct silofs_strview *sgid, struct silofs_gids *out_gids)
{
	int err;

	err = ipr_parse_gid_by_name(ipr, name, &out_gids->host_gid);
	if (err) {
		return err;
	}
	err = ipr_parse_gid_by_value(ipr, sgid, &out_gids->fs_gid);
	if (err) {
		return err;
	}
	return 0;
}

static void ipr_split_line(const struct silofs_idsconf_parser *ipr, char sep,
                           struct silofs_strview *out_first,
                           struct silofs_strview *out_second)
{
	struct silofs_strview_pair svp;

	strview_split_chr(&ipr->cpr.line, sep, &svp);
	if (out_first != NULL) {
		strview_strip_ws(&svp.first, out_first);
	}
	if (out_second != NULL) {
		strview_strip_ws(&svp.second, out_second);
	}
}

static int ipr_parse_user_conf(const struct silofs_idsconf_parser *ipr,
                               struct silofs_uids **p_uids_arr, size_t *nuids)
{
	struct silofs_strview name;
	struct silofs_strview suid;
	struct silofs_uids uids;
	int err;

	ipr_split_line(ipr, '=', &name, &suid);
	if (strview_isempty(&name) || strview_isempty(&suid)) {
		return cpr_bad_input(&ipr->cpr, "missing user mapping");
	}
	err = ipr_parse_uids(ipr, &name, &suid, &uids);
	if (err) {
		return err;
	}
	err = ipr_append_uids1(ipr, p_uids_arr, nuids, &uids);
	if (err) {
		return err;
	}
	return 0;
}

static int ipr_parse_group_conf(const struct silofs_idsconf_parser *ipr,
                                struct silofs_gids **p_gids_arr, size_t *ngids)
{
	struct silofs_strview name;
	struct silofs_strview sgid;
	struct silofs_gids gids;
	int err;

	ipr_split_line(ipr, '=', &name, &sgid);
	if (strview_isempty(&name) || strview_isempty(&sgid)) {
		return cpr_bad_input(&ipr->cpr, "missing group mapping");
	}
	err = ipr_parse_gids(ipr, &name, &sgid, &gids);
	if (err) {
		return err;
	}
	err = ipr_append_gids1(ipr, p_gids_arr, ngids, &gids);
	if (err) {
		return err;
	}
	return 0;
}

static int ipr_parse_curr_line(const struct silofs_idsconf_parser *ipr,
                               struct silofs_ugids *ugids)
{
	struct silofs_users_ids *users = &ugids->users;
	struct silofs_groups_ids *groups = &ugids->groups;
	int ret = 0;

	switch (ipr->sec) {
	case SILOFS_IDSCONF_SEC_NIL:
		break;
	case SILOFS_IDSCONF_SEC_USERS:
		ret = ipr_parse_user_conf(ipr, &users->uids, &users->nuids);
		break;
	case SILOFS_IDSCONF_SEC_GROUPS:
		ret = ipr_parse_group_conf(ipr, &groups->gids, &groups->ngids);
		break;
	default:
		ret = cpr_bad_input(&ipr->cpr, "illegal config");
		break;
	}
	return ret;
}

static enum silofs_idsconf_sec
ipr_parse_sec_state(const struct silofs_idsconf_parser *ipr)
{
	struct silofs_strview sv = { .str = NULL };
	enum silofs_idsconf_sec sec = SILOFS_IDSCONF_SEC_NIL;

	strview_strip_ws(&ipr->cpr.line, &sv);
	if (silofs_strview_starts_with(&sv, '[') &&
	    silofs_strview_ends_with(&sv, ']')) {
		silofs_strview_strip_any_of(&sv, "[]", &sv);
		strview_strip_ws(&sv, &sv);
		sec = idsconf_sec_by_name(&sv);
	}
	return sec;
}

static void ipr_split_data(struct silofs_idsconf_parser *ipr)
{
	struct silofs_strview_pair svp;
	struct silofs_strview sline;

	strview_split_chr(&ipr->cpr.rcfg, '\n', &svp);
	strview_strip_ws(&svp.second, &ipr->cpr.rcfg);

	strview_split_chr(&svp.first, '#', &svp);
	strview_strip_ws(&svp.first, &sline);
	cpr_update_next_line(&ipr->cpr, &sline);
}

static int
ipr_parse_ugids(struct silofs_idsconf_parser *ipr, struct silofs_ugids *ugids)
{
	enum silofs_idsconf_sec sec_next;
	int err = 0;

	ipr_split_data(ipr);
	while (strview_hasdata(&ipr->cpr.line) ||
	       strview_hasdata(&ipr->cpr.rcfg)) {
		sec_next = ipr_parse_sec_state(ipr);
		if ((sec_next != SILOFS_IDSCONF_SEC_NIL) &&
		    (sec_next != ipr->sec)) {
			ipr->sec = sec_next;
		} else if (!strview_isempty(&ipr->cpr.line)) {
			err = ipr_parse_curr_line(ipr, ugids);
			if (err) {
				return err;
			}
		}
		ipr_split_data(ipr);
	}
	return 0;
}

static void ipr_release_ugids(struct silofs_idsconf_parser *ipr,
                              struct silofs_ugids *ugids)
{
	ipr_pfree_uids(ipr, &ugids->users.uids, &ugids->users.nuids);
	ipr_pfree_gids(ipr, &ugids->groups.gids, &ugids->groups.ngids);
}

static int check_empty_ugids(const struct silofs_ugids *ugids)
{
	const struct silofs_users_ids *users = &ugids->users;
	const struct silofs_groups_ids *groups = &ugids->groups;

	if ((users->uids != NULL) || (users->nuids != 0)) {
		return -SILOFS_EINVAL;
	}
	if ((groups->gids != NULL) || (groups->ngids != 0)) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

int silofs_parse_fsids(struct silofs_ugids *ugids, struct silofs_alloc *alloc,
                       const char *data)
{
	struct silofs_idsconf_parser ipr;
	int err;

	err = check_empty_ugids(ugids);
	if (err) {
		return err;
	}
	ipr_rsetup(&ipr, alloc, data);
	err = cpr_require_ascii(&ipr.cpr);
	if (err) {
		ipr_release_ugids(&ipr, ugids);
		return err;
	}
	err = ipr_parse_ugids(&ipr, ugids);
	if (err) {
		ipr_release_ugids(&ipr, ugids);
		return err;
	}
	return 0;
}

void silofs_release_fsids(struct silofs_ugids *ugids,
                          struct silofs_alloc *alloc)
{
	struct silofs_idsconf_parser ipr;

	ipr_rsetup(&ipr, alloc, "");
	ipr_release_ugids(&ipr, ugids);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ipr_append_cfgline(struct silofs_idsconf_parser *ipr,
                              const struct silofs_strview *sv)
{
	struct silofs_strview nl;
	int err;

	silofs_strview_init(&nl, "\n");
	err = strspan_append(&ipr->cpr.wcfg, sv);
	if (err) {
		return err;
	}
	err = strspan_append(&ipr->cpr.wcfg, &nl);
	if (err) {
		return err;
	}
	return 0;
}

static int ipr_append_newline(struct silofs_idsconf_parser *ipr)
{
	struct silofs_strview el;

	silofs_strview_initz(&el);
	return ipr_append_cfgline(ipr, &el);
}

static int ipr_append_section(struct silofs_idsconf_parser *ipr,
                              enum silofs_idsconf_sec sec_id)
{
	char sec[64] = { 0 };
	struct silofs_strview sv;

	snprintf(sec, sizeof(sec) - 1, "[%s]", idsconf_sec_to_name(sec_id));
	silofs_strview_init(&sv, sec);
	return ipr_append_cfgline(ipr, &sv);
}

static int
ipr_append_id(struct silofs_idsconf_parser *ipr, const char *name, uint32_t id)
{
	char dat[512] = { 0 };
	struct silofs_strview sv;

	snprintf(dat, sizeof(dat) - 1, "%s = %u", name, id);
	silofs_strview_init(&sv, dat);
	return ipr_append_cfgline(ipr, &sv);
}

static int ipr_append_user(struct silofs_idsconf_parser *ipr,
                           const struct silofs_uids *uids)
{
	char s[NAME_MAX + 1] = { 0 };
	int err;

	err = cpr_resolve_uid_to_name(&ipr->cpr, uids->host_uid, s, sizeof(s));
	return err ? err : ipr_append_id(ipr, s, uids->fs_uid);
}

static int ipr_append_group(struct silofs_idsconf_parser *ipr,
                            const struct silofs_gids *gids)
{
	char s[NAME_MAX + 1] = { 0 };
	int err;

	err = cpr_resolve_gid_to_name(&ipr->cpr, gids->host_gid, s, sizeof(s));
	return err ? err : ipr_append_id(ipr, s, gids->fs_gid);
}

static int ipr_unparse_users(struct silofs_idsconf_parser *ipr,
                             const struct silofs_ugids *ugids)

{
	int err;

	err = ipr_append_section(ipr, SILOFS_IDSCONF_SEC_USERS);
	for (size_t i = 0; !err && (i < ugids->users.nuids); ++i) {
		err = ipr_append_user(ipr, &ugids->users.uids[i]);
	}
	return err ? err : ipr_append_newline(ipr);
}

static int ipr_unparse_groups(struct silofs_idsconf_parser *ipr,
                              const struct silofs_ugids *ugids)

{
	int err;

	err = ipr_append_section(ipr, SILOFS_IDSCONF_SEC_GROUPS);
	for (size_t i = 0; !err && (i < ugids->groups.ngids); ++i) {
		err = ipr_append_group(ipr, &ugids->groups.gids[i]);
	}
	return err ? err : ipr_append_newline(ipr);
}

static int ipr_unparse_ugids(struct silofs_idsconf_parser *ipr,
                             const struct silofs_ugids *ugids)

{
	int err;

	err = ipr_unparse_users(ipr, ugids);
	if (err) {
		return err;
	}
	err = ipr_unparse_groups(ipr, ugids);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_unparse_fsids(const struct silofs_ugids *ugids,
                         struct silofs_alloc *alloc, char *buf, size_t n)
{
	struct silofs_idsconf_parser ipr;

	ipr_wsetup(&ipr, alloc, buf, n);
	return ipr_unparse_ugids(&ipr, ugids);
}

static bool ugids_has_host_gid(const struct silofs_ugids *ugids, gid_t gid)
{
	for (size_t i = 0; i < ugids->groups.ngids; ++i) {
		if (ugids->groups.gids[i].host_gid == gid) {
			return true;
		}
	}
	return false;
}

static int ipr_resolve_uids_gids(const struct silofs_idsconf_parser *ipr,
                                 const char *user, struct silofs_uids *uids,
                                 struct silofs_gids *gids)
{
	uid_t uid = (uid_t)(-1);
	gid_t gid = (gid_t)(-1);
	int err;

	err = cpr_resolve_uidgid(&ipr->cpr, user, &uid, &gid);
	if (err) {
		return err;
	}
	uids->fs_uid = uids->host_uid = uid;
	gids->fs_gid = gids->host_gid = gid;
	return 0;
}

static int ipr_extend_ugids(struct silofs_idsconf_parser *ipr,
                            struct silofs_ugids *ugids, const char *user)
{
	struct silofs_uids uids;
	struct silofs_gids gids;
	int err;

	err = ipr_resolve_uids_gids(ipr, user, &uids, &gids);
	if (err) {
		return err;
	}
	err = ipr_append_uids1(ipr, &ugids->users.uids, &ugids->users.nuids,
	                       &uids);
	if (err) {
		return err;
	}
	err = ipr_append_gids1(ipr, &ugids->groups.gids, &ugids->groups.ngids,
	                       &gids);
	if (err) {
		return err;
	}
	return 0;
}

static int ipr_extend_supgr(struct silofs_idsconf_parser *ipr,
                            struct silofs_ugids *ugids, const char *user)
{
	struct silofs_gids gids;
	gid_t groups[64] = { (gid_t)(-1) };
	gid_t gid = (gid_t)(-1);
	int ngroups = (int)ARRAY_SIZE(groups);
	int err;

	errno = 0;
	err = getgrouplist(user, gid, groups, &ngroups);
	if (err < 0) {
		return cpr_bad_input(&ipr->cpr, "getgrouplist failure");
	}
	for (int i = 0; i < ngroups; ++i) {
		gid = groups[i];
		if (gid == (gid_t)(-1)) {
			continue;
		}
		if (ugids_has_host_gid(ugids, gid)) {
			continue;
		}
		gids.host_gid = gids.fs_gid = gid;
		err = ipr_append_gids1(ipr, &ugids->groups.gids,
		                       &ugids->groups.ngids, &gids);
		if (err) {
			return err;
		}
	}
	return 0;
}

int silofs_extend_fsids(struct silofs_ugids *ugids, struct silofs_alloc *alloc,
                        const char *user, bool with_sup_groups)
{
	struct silofs_idsconf_parser ipr;
	int err;

	ipr_rsetup(&ipr, alloc, "");
	err = ipr_extend_ugids(&ipr, ugids, user);
	if (!err && with_sup_groups) {
		err = ipr_extend_supgr(&ipr, ugids, user);
	}
	return err;
}
