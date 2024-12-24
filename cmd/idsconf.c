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
#define _GNU_SOURCE 1
#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include "cmd.h"

static void strview_init(struct silofs_strview *sv, const char *s)
{
	silofs_strview_init(sv, s);
}

static void strview_initn(struct silofs_strview *sv, const char *s, size_t n)
{
	silofs_strview_initn(sv, s, n);
}

static bool strview_isempty(const struct silofs_strview *sv)
{
	return silofs_strview_isempty(sv);
}

static void strview_split_by(const struct silofs_strview *sv, char sep,
                             struct silofs_strview_pair *out_sv_pair)
{
	silofs_strview_split_chr(sv, sep, out_sv_pair);
}

static void strview_split_by_nl(const struct silofs_strview *sv,
                                struct silofs_strview_pair *out_sv_pair)
{
	strview_split_by(sv, '\n', out_sv_pair);
}

static void strview_strip_ws(const struct silofs_strview *sv,
                             struct silofs_strview *out_sv)
{
	silofs_strview_strip_ws(sv, out_sv);
}

static void strview_strip_any(const struct silofs_strview *sv, const char *set,
                              struct silofs_strview *out_sv)
{
	silofs_strview_strip_any_of(sv, set, out_sv);
}

static void strview_copyto(const struct silofs_strview *sv, char *s, size_t n)
{
	silofs_strview_copyto(sv, s, n);
}

static bool strview_isascii(const struct silofs_strview *sv)
{
	return silofs_strview_isascii(sv);
}

static bool strview_isequal(const struct silofs_strview *sv, const char *s)
{
	return silofs_strview_isequal(sv, s);
}

static bool strview_starts_with(const struct silofs_strview *sv, char c)
{
	return silofs_strview_starts_with(sv, c);
}

static bool strview_ends_with(const struct silofs_strview *sv, char c)
{
	return silofs_strview_ends_with(sv, c);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

enum idsconf_sec {
	IDSCONF_SEC_NIL,
	IDSCONF_SEC_USERS,
	IDSCONF_SEC_GROUPS,
};

static const char *s_idsconf_sec_name[] = {
	[IDSCONF_SEC_NIL] = "",
	[IDSCONF_SEC_USERS] = "users",
	[IDSCONF_SEC_GROUPS] = "groups",
};

struct idsconf_ctx {
	char *path;
	char *text;
	int line_no;
	enum idsconf_sec sec;
	const struct silofs_strview *line;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

silofs_attr_noreturn static void
cmd_die_by(const struct idsconf_ctx *ctx, const char *msg)
{
	if (ctx && ctx->line_no && ctx->path) {
		cmd_die(errno, "%s (%s:%d)", msg, ctx->path, ctx->line_no);
	} else {
		cmd_die(errno, "%s", msg);
	}
	silofs_unreachable();
}

static void
cmd_parse_uid_by_value(const struct idsconf_ctx *ctx,
                       const struct silofs_strview *ss, uid_t *out_uid)
{
	char str[64] = "";

	if (ss->len >= sizeof(str)) {
		cmd_die_by(ctx, "not an integer");
	}
	strview_copyto(ss, str, sizeof(str));
	*out_uid = cmd_parse_str_as_uid(str);
}

static void
cmd_parse_gid_by_value(const struct idsconf_ctx *ctx,
                       const struct silofs_strview *ss, gid_t *out_gid)
{
	char str[64] = "";

	if (ss->len >= sizeof(str)) {
		cmd_die_by(ctx, "not an integer");
	}
	strview_copyto(ss, str, sizeof(str));
	*out_gid = cmd_parse_str_as_gid(str);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t cmd_sysconf(int key)
{
	long ret;

	ret = sysconf(key);
	if (ret < 0) {
		cmd_die(errno, "sysconf error: key=%d", key);
	}
	return (size_t)key;
}

static size_t cmd_getxx_bsz(void)
{
	const size_t bsz1 = cmd_sysconf(_SC_GETPW_R_SIZE_MAX);
	const size_t bsz2 = cmd_sysconf(_SC_GETGR_R_SIZE_MAX);
	const size_t align = 1024;
	size_t bsz;

	bsz = (bsz1 > bsz2) ? bsz1 : bsz2;
	bsz = ((bsz + align - 1) / align) * align;
	return bsz;
}

static void cmd_resolve_uid_by_name(const char *name, uid_t *out_uid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(err, "failed to resolve user name: %s", name);
	}
	if (pw == NULL) {
		cmd_die(0, "unknown user name: %s", name);
	}
	*out_uid = pw->pw_uid;
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_gid_by_name(const char *name, gid_t *out_gid)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getgrnam_r(name, &grp, buf, bsz, &gr);
	if (err) {
		cmd_die(err, "failed to resolve group name: %s", name);
	}
	if (gr == NULL) {
		cmd_die(0, "unknown group name: %s", name);
	}
	*out_gid = gr->gr_gid;
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_uid_to_name(uid_t uid, char *name, size_t nsz)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	size_t len;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwuid_r(uid, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(err, "failed to resolve uid: %u", uid);
	}
	if ((pw == NULL) || (pw->pw_name == NULL)) {
		cmd_die(0, "unknown uid: %u", uid);
	}
	len = strlen(pw->pw_name);
	if (!len || (len >= nsz)) {
		cmd_die(-ENAMETOOLONG, "bad user name: %s", pw->pw_name);
	}
	strncpy(name, pw->pw_name, nsz);
	cmd_zfree(buf, bsz);
}

static void cmd_resolve_gid_to_name(gid_t gid, char *name, size_t nsz)
{
	struct group grp = { .gr_gid = (gid_t)(-1) };
	struct group *gr = NULL;
	char *buf = NULL;
	size_t bsz;
	size_t len;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getgrgid_r(gid, &grp, buf, bsz, &gr);
	if (err) {
		cmd_die(err, "failed to resolve gid: %u", gid);
	}
	if ((gr == NULL) || (gr->gr_name == NULL)) {
		cmd_die(0, "unknown gid: %u", gid);
	}
	len = strlen(gr->gr_name);
	if (!len || (len >= nsz)) {
		cmd_die(-ENAMETOOLONG, "bad group name: %s", gr->gr_name);
	}
	strncpy(name, gr->gr_name, nsz);
	cmd_zfree(buf, bsz);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_uids *cmd_malloc_uids(size_t nuids)
{
	struct silofs_uids *uids;

	uids = cmd_zalloc(nuids * sizeof(uids[0]));
	return uids;
}

static void cmd_free_uids(struct silofs_uids *uids, size_t nuids)
{
	cmd_zfree(uids, nuids * sizeof(uids[0]));
}

static void cmd_pfree_uids(struct silofs_uids **puids, size_t *pnuids)
{
	if (*puids && *pnuids) {
		cmd_free_uids(*puids, *pnuids);
		*puids = NULL;
		*pnuids = 0;
	}
}

static void cmd_copy_uids(struct silofs_uids *uids_dst,
                          const struct silofs_uids *uids_src, size_t nuids)
{
	if (uids_src && nuids) {
		memcpy(uids_dst, uids_src, nuids * sizeof(uids_dst[0]));
	}
}

static void
cmd_extend_uids(struct silofs_uids **puids, size_t *pnuids, size_t cnt)
{
	struct silofs_uids *uids = NULL;
	size_t nuids = *pnuids + cnt;

	uids = cmd_malloc_uids(nuids);
	cmd_copy_uids(uids, *puids, *pnuids);
	cmd_pfree_uids(puids, pnuids);
	*puids = uids;
	*pnuids = nuids;
}

static void cmd_append_uids1(struct silofs_uids **puids, size_t *pnuids,
                             const struct silofs_uids *uids)
{
	cmd_extend_uids(puids, pnuids, 1);
	cmd_copy_uids(&(*puids)[*pnuids - 1], uids, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_gids *cmd_malloc_gids(size_t ngids)
{
	struct silofs_gids *gids;

	gids = cmd_zalloc(ngids * sizeof(gids[0]));
	return gids;
}

static void cmd_free_gids(struct silofs_gids *gids, size_t ngids)
{
	cmd_zfree(gids, ngids * sizeof(gids[0]));
}

static void cmd_pfree_gids(struct silofs_gids **pgids, size_t *pngids)
{
	if (*pgids && *pngids) {
		cmd_free_gids(*pgids, *pngids);
		*pgids = NULL;
		*pngids = 0;
	}
}

static void cmd_copy_gids(struct silofs_gids *gids_dst,
                          const struct silofs_gids *gids_src, size_t ngids)
{
	if (gids_src && ngids) {
		memcpy(gids_dst, gids_src, ngids * sizeof(gids_dst[0]));
	}
}

static void
cmd_extend_gids(struct silofs_gids **pgids, size_t *pngids, size_t cnt)
{
	struct silofs_gids *gids = NULL;
	size_t ngids = *pngids + cnt;

	gids = cmd_malloc_gids(ngids);
	cmd_copy_gids(gids, *pgids, *pngids);
	cmd_pfree_gids(pgids, pngids);
	*pgids = gids;
	*pngids = ngids;
}

static void cmd_append_gids1(struct silofs_gids **pgids, size_t *pngids,
                             const struct silofs_gids *gids)
{
	cmd_extend_gids(pgids, pngids, 1);
	cmd_copy_gids(&(*pgids)[*pngids - 1], gids, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
cmd_parse_uid_by_name(const struct idsconf_ctx *ctx,
                      const struct silofs_strview *name, uid_t *out_uid)
{
	char buf[NAME_MAX + 1] = "";

	if (name->len >= sizeof(buf)) {
		cmd_die_by(ctx, "illegal user name");
	}
	strview_copyto(name, buf, sizeof(buf) - 1);
	cmd_resolve_uid_by_name(buf, out_uid);
}

static void
cmd_parse_gid_by_name(const struct idsconf_ctx *ctx,
                      const struct silofs_strview *name, gid_t *out_gid)
{
	char buf[NAME_MAX + 1] = "";

	if (name->len >= sizeof(buf)) {
		cmd_die_by(ctx, "illegal group name");
	}
	strview_copyto(name, buf, sizeof(buf) - 1);
	cmd_resolve_gid_by_name(buf, out_gid);
}

static void
cmd_parse_uids(const struct idsconf_ctx *ctx,
               const struct silofs_strview *name,
               const struct silofs_strview *suid, struct silofs_uids *out_uids)
{
	cmd_parse_uid_by_name(ctx, name, &out_uids->fs_uid);
	cmd_parse_uid_by_value(ctx, suid, &out_uids->host_uid);
}

static void
cmd_parse_gids(const struct idsconf_ctx *ctx,
               const struct silofs_strview *name,
               const struct silofs_strview *sgid, struct silofs_gids *out_gids)
{
	cmd_parse_gid_by_name(ctx, name, &out_gids->host_gid);
	cmd_parse_gid_by_value(ctx, sgid, &out_gids->fs_gid);
}

static void cmd_parse_user_conf(const struct idsconf_ctx *ctx,
                                struct silofs_uids **uids, size_t *nuids)
{
	struct silofs_strview_pair ssp;
	struct silofs_strview name;
	struct silofs_strview suid;
	struct silofs_uids uid;

	strview_split_by(ctx->line, '=', &ssp);
	strview_strip_ws(&ssp.first, &name);
	strview_strip_ws(&ssp.second, &suid);

	if (strview_isempty(&name) || strview_isempty(&suid)) {
		cmd_die_by(ctx, "missing user mapping");
	}
	cmd_parse_uids(ctx, &name, &suid, &uid);
	cmd_append_uids1(uids, nuids, &uid);
}

static void cmd_parse_group_conf(const struct idsconf_ctx *ctx,
                                 struct silofs_gids **gids, size_t *ngids)
{
	struct silofs_strview_pair ssp;
	struct silofs_strview name;
	struct silofs_strview sgid;
	struct silofs_gids gid;

	strview_split_by(ctx->line, '=', &ssp);
	strview_strip_ws(&ssp.first, &name);
	strview_strip_ws(&ssp.second, &sgid);

	if (strview_isempty(&name) || strview_isempty(&sgid)) {
		cmd_die_by(ctx, "missing group mapping");
	}
	cmd_parse_gids(ctx, &name, &sgid, &gid);
	cmd_append_gids1(gids, ngids, &gid);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cmd_append_cfgline(char **pcfg_curr, const char *line)
{
	const size_t line_len = strlen(line);
	const size_t conf_len = *pcfg_curr ? strlen(*pcfg_curr) : 0;
	char *pcfg_next = NULL;

	pcfg_next = cmd_zalloc(conf_len + line_len + 1);
	if (*pcfg_curr != NULL) {
		memcpy(pcfg_next, *pcfg_curr, conf_len);
		cmd_pstrfree(pcfg_curr);
	}
	memcpy(pcfg_next + conf_len, line, line_len);
	*pcfg_curr = pcfg_next;
}

static void cmd_append_newline(char **pcfg)
{
	cmd_append_cfgline(pcfg, "\n");
}

static void cmd_append_section(const char *name, char **ptext)
{
	char line[256] = "";

	snprintf(line, sizeof(line) - 1, "[%s]\n", name);
	cmd_append_cfgline(ptext, line);
}

static void cmd_append_id(const char *name, uint32_t id, char **conf)
{
	char line[512] = "";

	snprintf(line, sizeof(line) - 1, "%s = %u\n", name, id);
	cmd_append_cfgline(conf, line);
}

static void cmd_append_user(const struct silofs_uids *uid, char **conf)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_uid_to_name(uid->host_uid, name, sizeof(name));
	cmd_append_id(name, uid->fs_uid, conf);
}

static void cmd_append_group(const struct silofs_gids *gid, char **conf)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_gid_to_name(gid->fs_gid, name, sizeof(name));
	cmd_append_id(name, gid->host_gid, conf);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool isascii_idsconf(const char *txt, size_t size)
{
	struct silofs_strview ss;

	strview_initn(&ss, txt, size);
	return strview_isascii(&ss);
}

static void cmd_load_idsconf_file(const char *pathname, char **out_txt)
{
	struct stat st = { .st_mode = 0 };
	size_t size = 0;
	char *txt = NULL;
	int fd = -1;
	int err;

	err = silofs_sys_stat(pathname, &st);
	if (err) {
		cmd_die(err, "stat failure: %s", pathname);
	}
	if (!S_ISREG(st.st_mode)) {
		cmd_die(0, "not a regular file: %s", pathname);
	}
	size = (size_t)st.st_size;
	if (size >= SILOFS_MEGA) {
		cmd_die(-EFBIG, "illegal ids-config file: %s", pathname);
	}
	err = silofs_sys_open(pathname, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "failed to open: %s", pathname);
	}

	txt = cmd_zalloc(size + 1);
	err = silofs_sys_readn(fd, txt, size);
	if (err) {
		cmd_die(err, "failed to read: %s", pathname);
	}
	silofs_sys_close(fd);

	if (!isascii_idsconf(txt, size)) {
		cmd_die(0, "non-ascii character in: %s", pathname);
	}
	*out_txt = txt;
}

static void cmd_save_idsconf_file(const char *pathname, const char *txt)
{
	const size_t len = txt ? strlen(txt) : 0;
	int fd = -1;
	int err;

	err = silofs_sys_open(pathname, O_CREAT | O_RDWR | O_TRUNC,
	                      S_IRUSR | S_IWUSR | S_IRGRP, &fd);
	if (err) {
		cmd_die(err, "failed to create ids-config: %s", pathname);
	}

	err = silofs_sys_writen(fd, txt, len);
	if (err) {
		cmd_die(err, "failed to write ids-config: %s", pathname);
	}
	silofs_sys_closefd(&fd);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *idsconf_sec_to_name(enum idsconf_sec sec)
{
	const char *sec_name = "";

	if (sec < SILOFS_ARRAY_SIZE(s_idsconf_sec_name)) {
		sec_name = s_idsconf_sec_name[sec];
	}
	return sec_name;
}

static enum idsconf_sec idsconf_sec_by_name(const struct silofs_strview *sv)
{
	const char *sec_name;

	for (int i = 0; i < (int)SILOFS_ARRAY_SIZE(s_idsconf_sec_name); ++i) {
		sec_name = s_idsconf_sec_name[i];
		if (strview_isequal(sv, sec_name)) {
			return (enum idsconf_sec)i;
		}
	}
	return IDSCONF_SEC_NIL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fs_ids_parse_user_conf(struct silofs_fs_ids *ids,
                                   const struct idsconf_ctx *ctx)
{
	cmd_parse_user_conf(ctx, &ids->users.uids, &ids->users.nuids);
}

static void fs_ids_parse_group_conf(struct silofs_fs_ids *ids,
                                    const struct idsconf_ctx *ctx)
{
	cmd_parse_group_conf(ctx, &ids->groups.gids, &ids->groups.ngids);
}

static void
fs_ids_parse_line(struct silofs_fs_ids *ids, const struct idsconf_ctx *ctx)
{
	switch (ctx->sec) {
	case IDSCONF_SEC_NIL:
		break;
	case IDSCONF_SEC_USERS:
		fs_ids_parse_user_conf(ids, ctx);
		break;
	case IDSCONF_SEC_GROUPS:
		fs_ids_parse_group_conf(ids, ctx);
		break;
	default:
		cmd_die_by(ctx, "illegal config");
		break;
	}
}

static enum idsconf_sec cmd_parse_sec_state(const struct silofs_strview *line)
{
	struct silofs_strview sv = { .str = NULL };
	enum idsconf_sec sec = IDSCONF_SEC_NIL;

	strview_strip_ws(line, &sv);
	if (strview_starts_with(&sv, '[') && strview_ends_with(&sv, ']')) {
		strview_strip_any(&sv, "[]", &sv);
		strview_strip_ws(&sv, &sv);
		sec = idsconf_sec_by_name(&sv);
	}
	return sec;
}

static void fs_ids_parse(struct silofs_fs_ids *ids, struct idsconf_ctx *ctx)
{
	struct silofs_strview data;
	struct silofs_strview_pair pair;
	struct silofs_strview_pair pair2;
	struct silofs_strview *line = &pair.first;
	struct silofs_strview *tail = &pair.second;
	struct silofs_strview sline;
	enum idsconf_sec sec_next = IDSCONF_SEC_NIL;

	strview_init(&data, ctx->text);
	ctx->line_no = 0;
	ctx->line = line;
	ctx->sec = IDSCONF_SEC_NIL;

	strview_split_by_nl(&data, &pair);
	while (!strview_isempty(line) || !strview_isempty(tail)) {
		ctx->line_no++;
		ctx->line = line;

		strview_split_by(line, '#', &pair2);
		strview_strip_ws(&pair2.first, &sline);

		sec_next = cmd_parse_sec_state(&sline);
		if ((sec_next != IDSCONF_SEC_NIL) && (sec_next != ctx->sec)) {
			ctx->sec = sec_next;
		} else if (!strview_isempty(&sline)) {
			ctx->line = &sline;
			fs_ids_parse_line(ids, ctx);
		}
		strview_split_by_nl(tail, &pair);
	}
	ctx->line = NULL;
}

static void
fs_ids_unparse(const struct silofs_fs_ids *ids, struct idsconf_ctx *ctx)
{
	const char *sec_name = NULL;
	char *text = NULL;

	sec_name = idsconf_sec_to_name(IDSCONF_SEC_USERS);
	cmd_append_section(sec_name, &text);
	for (size_t i = 0; i < ids->users.nuids; ++i) {
		cmd_append_user(&ids->users.uids[i], &text);
	}
	cmd_append_newline(&text);

	sec_name = idsconf_sec_to_name(IDSCONF_SEC_GROUPS);
	cmd_append_section(sec_name, &text);
	for (size_t j = 0; j < ids->groups.ngids; ++j) {
		cmd_append_group(&ids->groups.gids[j], &text);
	}
	cmd_append_newline(&text);
	ctx->text = text;
}

static void
fs_ids_append_uids(struct silofs_fs_ids *ids, const struct silofs_uids *uids)
{
	cmd_append_uids1(&ids->users.uids, &ids->users.nuids, uids);
}

static void
fs_ids_append_gids(struct silofs_fs_ids *ids, const struct silofs_gids *gids)
{
	cmd_append_gids1(&ids->groups.gids, &ids->groups.ngids, gids);
}

static bool fs_ids_has_host_uid(const struct silofs_fs_ids *ids, uid_t uid)
{
	for (size_t i = 0; i < ids->users.nuids; ++i) {
		if (ids->users.uids[i].host_uid == uid) {
			return true;
		}
	}
	return false;
}

static bool fs_ids_has_host_gid(const struct silofs_fs_ids *ids, gid_t gid)
{
	for (size_t i = 0; i < ids->groups.ngids; ++i) {
		if (ids->groups.gids[i].host_gid == gid) {
			return true;
		}
	}
	return false;
}

static void fs_ids_add_supgr(struct silofs_fs_ids *ids, const char *user)
{
	struct silofs_gids gids;
	gid_t groups[64] = { (gid_t)(-1) };
	gid_t gid = (gid_t)(-1);
	int ngroups = (int)SILOFS_ARRAY_SIZE(groups);
	int ret;

	ret = getgrouplist(user, gid, groups, &ngroups);
	if (ret < 0) {
		cmd_die(errno, "getgrouplist failure: ret=%d", ret);
	}
	for (int i = 0; i < ngroups; ++i) {
		gid = groups[i];
		if (gid == (gid_t)(-1)) {
			continue;
		}
		if (fs_ids_has_host_gid(ids, gid)) {
			continue;
		}
		gids.host_gid = gids.fs_gid = gid;
		fs_ids_append_gids(ids, &gids);
	}
}

void cmd_fs_ids_add_user(struct silofs_fs_ids *ids, const char *user,
                         bool with_sup_groups)
{
	struct silofs_uids uids;
	struct silofs_gids gids;
	uid_t uid = (uid_t)(-1);
	gid_t gid = (gid_t)(-1);

	cmd_resolve_uidgid(user, &uid, &gid);
	uids.host_uid = uids.fs_uid = uid;
	fs_ids_append_uids(ids, &uids);
	gids.host_gid = gids.fs_gid = gid;
	fs_ids_append_gids(ids, &gids);
	if (with_sup_groups) {
		fs_ids_add_supgr(ids, user);
	}
}

void cmd_fs_ids_init(struct silofs_fs_ids *ids)
{
	ids->users.uids = NULL;
	ids->users.nuids = 0;
	ids->groups.gids = NULL;
	ids->groups.ngids = 0;
}

void cmd_fs_ids_fini(struct silofs_fs_ids *ids)
{
	cmd_fs_ids_reset(ids);
	ids->users.uids = NULL;
	ids->users.nuids = 0;
	ids->groups.gids = NULL;
	ids->groups.ngids = 0;
}

void cmd_fs_ids_assign(struct silofs_fs_ids *ids,
                       const struct silofs_fs_ids *other)
{
	cmd_fs_ids_reset(ids);
	for (size_t i = 0; i < other->users.nuids; ++i) {
		fs_ids_append_uids(ids, &ids->users.uids[i]);
	}
	for (size_t j = 0; j < other->groups.ngids; ++j) {
		fs_ids_append_gids(ids, &ids->groups.gids[j]);
	}
}

void cmd_fs_ids_reset(struct silofs_fs_ids *ids)
{
	cmd_pfree_uids(&ids->users.uids, &ids->users.nuids);
	cmd_pfree_gids(&ids->groups.gids, &ids->groups.ngids);
}

static void cmd_fs_ids_pathname(const char *basedir, char **out_pathname)
{
	cmd_join_path(basedir, "fsids.conf", out_pathname);
}

void cmd_fs_ids_load(struct silofs_fs_ids *ids, const char *basedir)
{
	struct idsconf_ctx ctx = { .line_no = 0 };

	cmd_fs_ids_reset(ids);
	cmd_fs_ids_pathname(basedir, &ctx.path);
	cmd_load_idsconf_file(ctx.path, &ctx.text);
	fs_ids_parse(ids, &ctx);
	cmd_pstrfree(&ctx.text);
	cmd_pstrfree(&ctx.path);
}

void cmd_fs_ids_save(const struct silofs_fs_ids *ids, const char *basedir)
{
	struct idsconf_ctx ctx = { .line_no = 0 };

	fs_ids_unparse(ids, &ctx);
	cmd_fs_ids_pathname(basedir, &ctx.path);
	cmd_save_idsconf_file(ctx.path, ctx.text);
	cmd_pstrfree(&ctx.text);
	cmd_pstrfree(&ctx.path);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void cmd_resolve_uidgid(const char *name, uid_t *out_uid, gid_t *out_gid)
{
	struct passwd pwd = { .pw_uid = (uid_t)(-1) };
	struct passwd *pw = NULL;
	char *buf = NULL;
	size_t bsz;
	int err;

	bsz = cmd_getxx_bsz();
	buf = cmd_zalloc(bsz);
	err = getpwnam_r(name, &pwd, buf, bsz, &pw);
	if (err) {
		cmd_die(err, "getpwnam failed: %s", name);
	}
	if (pw == NULL) {
		cmd_die(0, "unknown user name: %s", name);
	}
	*out_uid = pw->pw_uid;
	*out_gid = pw->pw_gid;
	cmd_zfree(buf, bsz);
}

void cmd_require_uidgid(const struct silofs_fs_ids *ids, const char *name,
                        uid_t *out_uid, gid_t *out_gid)
{
	cmd_resolve_uidgid(name, out_uid, out_gid);
	if (!fs_ids_has_host_uid(ids, *out_uid)) {
		cmd_die(0, "missing uid-mapping for user: '%s'", name);
	}
	if (!fs_ids_has_host_gid(ids, *out_gid)) {
		cmd_die(0, "missing gid-mapping for user: '%s'", name);
	}
}

static char *cmd_getlogin(void)
{
	char name[LOGIN_NAME_MAX + 1] = "";
	int err;

	err = getlogin_r(name, sizeof(name) - 1);
	if (err) {
		return NULL;
	}
	if (!strlen(name)) {
		return NULL;
	}
	return cmd_strdup(name);
}

char *cmd_getpwuid(uid_t uid)
{
	char name[NAME_MAX + 1] = "";

	cmd_resolve_uid_to_name(uid, name, sizeof(name) - 1);
	return cmd_strdup(name);
}

static char *cmd_getpwuid_self(void)
{
	return cmd_getpwuid(geteuid());
}

char *cmd_getusername(void)
{
	char *name = cmd_getlogin();

	return name ? name : cmd_getpwuid_self();
}
