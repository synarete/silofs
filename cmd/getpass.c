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
#include <termios.h>
#include <ctype.h>
#include "cmd.h"

static void write_stdout(const char *msg)
{
	size_t nwr;
	int fd_out = STDOUT_FILENO;

	silofs_sys_write(fd_out, msg, strlen(msg), &nwr);
	silofs_sys_fsync(fd_out);
}

static void write_newline(void)
{
	write_stdout("\n");
}

static void check_password_char(int ch)
{
	if (!isascii(ch)) {
		cmd_die(-EINVAL, "non ASCII char in password");
	}
	if (iscntrl(ch)) {
		cmd_die(-EINVAL, "control char in password");
	}
	if (isspace(ch)) {
		cmd_die(-EINVAL, "space char in password");
	}
	if (!isprint(ch)) {
		cmd_die(-EINVAL, "non printable char in password");
	}
	if (!isalnum(ch) && !ispunct(ch)) {
		cmd_die(-EINVAL, "illegal char in password");
	}
}

static int isskip(int ch)
{
	return !ch || isspace(ch);
}

static char *parse_dup_password(const char *buf, size_t bsz)
{
	size_t len = bsz;
	const char *str = buf;

	while (len && isskip(*str)) {
		str++;
		len--;
	}
	while (len && isskip(str[len - 1])) {
		len--;
	}
	if (len == 0) {
		cmd_die(-EINVAL, "zero length password");
	}
	if (len > SILOFS_PASSWORD_MAX) {
		cmd_die(-EINVAL, "password too long");
	}
	for (size_t i = 0; i < len; ++i) {
		check_password_char(str[i]);
	}
	return cmd_strndup(str, len);
}
static void
read_password_buf_from_fd(int fd, void *buf, size_t bsz, size_t *out_len)
{
	size_t nrd = 0;
	char ch = 0;
	int err;

	err = silofs_sys_read(fd, buf, bsz, out_len);
	if (err) {
		cmd_die(err, "failed to read password");
	}
	if (*out_len == 0) {
		cmd_die(-EINVAL, "zero-length password");
	}
	if (*out_len == bsz) {
		err = silofs_sys_read(fd, &ch, 1, &nrd);
		if (!err && (nrd > 0)) {
			cmd_die(-EINVAL, "password too long");
		}
	}
}

static void
read_password_from_file(int fd, void *buf, size_t bsz, size_t *out_len)
{
	struct stat st;
	int err;

	err = silofs_sys_fstat(fd, &st);
	if (err) {
		cmd_die(err, "fstat failed");
	}
	if (!st.st_size) {
		cmd_die(-EINVAL, "zero-length password file");
	}
	if (st.st_size > (loff_t)bsz) {
		cmd_die(-EFBIG, "illegal password file size");
	}
	read_password_buf_from_fd(fd, buf, (size_t)st.st_size, out_len);
}

static void
read_password_from_tty(int fd, void *buf, size_t bsz, size_t *out_len)
{
	struct termios tr_old;
	struct termios tr_new;
	char *pass = NULL;
	int read_err;
	int err;

	err = tcgetattr(fd, &tr_old);
	if (err) {
		cmd_die(errno, "tcgetattr fd=%d", fd);
	}
	memcpy(&tr_new, &tr_old, sizeof(tr_new));
	tr_new.c_lflag &= ~((tcflag_t)ECHO);
	tr_new.c_lflag |= ICANON;
	tr_new.c_lflag |= ISIG;
	tr_new.c_cc[VMIN] = 1;
	tr_new.c_cc[VTIME] = 0;
	err = tcsetattr(fd, TCSANOW, &tr_new);
	if (err) {
		cmd_die(errno, "tcsetattr fd=%d", fd);
	}

	read_err = silofs_sys_read(fd, buf, bsz, out_len);
	write_newline();

	err = tcsetattr(fd, TCSANOW, &tr_old);
	if (err) {
		cmd_die(errno, "tcsetattr fd=%d", fd);
	}

	err = read_err;
	if (err) {
		cmd_die(err, "read password error");
	}
	if (*out_len == 0) {
		cmd_die(-EINVAL, "read zero-length password");
	}
	pass = buf;
	if (pass[*out_len - 1] != '\n') {
		cmd_die(-EINVAL, "password too long");
	}
}

static int isregfd(int fd)
{
	struct stat st = { .st_mode = 0 };
	int err;

	err = silofs_sys_fstat(fd, &st);
	return !err && S_ISREG(st.st_mode);
}

static void read_password_from(int fd, void *buf, size_t bsz, size_t *out_len)
{
	if (isatty(fd)) {
		read_password_from_tty(fd, buf, bsz, out_len);
	} else if (isregfd(fd)) {
		read_password_from_file(fd, buf, bsz, out_len);
	} else {
		read_password_buf_from_fd(fd, buf, bsz, out_len);
	}
}

static int open_password_fd(const char *path)
{
	int err;
	int fd = -1;

	if (path == NULL) {
		return STDIN_FILENO;
	}
	err = silofs_sys_access(path, R_OK);
	if (err) {
		cmd_die(err, "no read access to password file %s", path);
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		cmd_die(err, "can not open password file %s", path);
	}
	return fd;
}

static void close_password_fd(int fd, const char *path)
{
	int err;

	if (path != NULL) {
		err = silofs_sys_close(fd);
		if (err) {
			cmd_die(err, "close failed: %s", path);
		}
	}
}

static char *getpass_from(const char *path)
{
	char buf[1024] = "";
	size_t len = 0;
	int fd;

	fd = open_password_fd(path);
	read_password_from(fd, buf, sizeof(buf), &len);
	close_password_fd(fd, path);
	return parse_dup_password(buf, len);
}

static char *do_getpass(const char *path, bool with_prompt, bool repeat)
{
	char *pass = NULL;
	char *pass2 = NULL;

	if (path) {
		return getpass_from(path);
	}
	if (with_prompt) {
		write_stdout("enter password: ");
	}
	pass = getpass_from(NULL);
	if (!repeat) {
		return pass;
	}
	if (with_prompt) {
		write_stdout("re-enter password: ");
	}
	pass2 = getpass_from(NULL);
	if (strcmp(pass, pass2) != 0) {
		cmd_delpass(&pass);
		cmd_delpass(&pass2);
		cmd_die(0, "password not equal");
	}
	cmd_delpass(&pass2);
	return pass;
}

void cmd_getpass(const char *path, bool with_prompt, char **out_pass)
{
	*out_pass = do_getpass(path, with_prompt, false);
}

void cmd_getpass2(const char *path, bool with_prompt, char **out_pass)
{
	*out_pass = do_getpass(path, with_prompt, true);
}

void cmd_getpass_simple(bool no_prompt, char **out_pass)
{
	cmd_getpass(NULL, !no_prompt, out_pass);
}

char *cmd_duppass(const char *pass)
{
	return parse_dup_password(pass, strlen(pass));
}

void cmd_delpass(char **pass)
{
	if (pass && *pass) {
		silofs_memffff(*pass, strlen(*pass));
		cmd_pstrfree(pass);
	}
}
