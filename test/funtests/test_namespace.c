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
#include "funtests.h"

/* TODO: Also readdir */
struct ft_ns_ctx {
	struct ft_env *fte;
	const char *root_path;
	size_t depth_max;
	size_t dirs_per_level;
	size_t files_per_level;
};

static char *make_path(const struct ft_ns_ctx *ns_ctx, const char *parent_dir,
		       const char *prefix, size_t depth, size_t idx)
{
	const char *name = ft_strfmt(ns_ctx->fte, "%s_%lu_%lu", prefix,
				     depth + 1, idx + 1);

	return ft_new_path_nested(ns_ctx->fte, parent_dir, name);
}

static char *make_dirpath(const struct ft_ns_ctx *ns_ctx,
			  const char *parent_dir, size_t depth, size_t idx)
{
	return make_path(ns_ctx, parent_dir, "dir", depth, idx);
}

static char *make_filepath(const struct ft_ns_ctx *ns_ctx,
			   const char *parent_dir, size_t depth, size_t idx)
{
	return make_path(ns_ctx, parent_dir, "file", depth, idx);
}

static void test_mktree_recursive(const struct ft_ns_ctx *ns_ctx,
				  const char *parent_dir, size_t depth)
{
	int fd;
	char *path;

	if (depth >= ns_ctx->depth_max) {
		return;
	}
	for (size_t i = 0; i < ns_ctx->dirs_per_level; ++i) {
		path = make_dirpath(ns_ctx, parent_dir, depth, i);
		ft_mkdir(path, 0700);
		test_mktree_recursive(ns_ctx, path, depth + 1);
	}
	for (size_t j = 0; j < ns_ctx->files_per_level; ++j) {
		path = make_filepath(ns_ctx, parent_dir, depth, j);
		ft_open(path, O_CREAT | O_WRONLY, 0600, &fd);
		ft_close(fd);
	}
}

static void test_rmtree_recursive(const struct ft_ns_ctx *ns_ctx,
				  const char *parent_dir, size_t depth)
{
	char *path;

	if (depth >= ns_ctx->depth_max) {
		return;
	}
	for (size_t j = 0; j < ns_ctx->files_per_level; ++j) {
		path = make_filepath(ns_ctx, parent_dir, depth, j);
		ft_unlink(path);
	}
	for (size_t i = 0; i < ns_ctx->dirs_per_level; ++i) {
		path = make_dirpath(ns_ctx, parent_dir, depth, i);
		test_rmtree_recursive(ns_ctx, path, depth + 1);
		ft_rmdir(path);
	}
}

static void test_namespace_(struct ft_ns_ctx *ns_ctx)
{
	struct ft_env *fte = ns_ctx->fte;
	const char *path = ft_new_path_unique(fte);

	ns_ctx->root_path = path;
	ft_mkdir(path, 0700);
	test_mktree_recursive(ns_ctx, path, 0);
	test_rmtree_recursive(ns_ctx, path, 0);
	ft_rmdir(path);
}

static void test_namespace_simple(struct ft_env *fte)
{
	struct ft_ns_ctx ns_ctx = { .fte = fte,
				    .depth_max = 4,
				    .dirs_per_level = 4,
				    .files_per_level = 4 };

	test_namespace_(&ns_ctx);
}

static void test_namespace_deep(struct ft_env *fte)
{
	struct ft_ns_ctx ns_ctx = { .fte = fte,
				    .depth_max = 12,
				    .dirs_per_level = 2,
				    .files_per_level = 4 };

	test_namespace_(&ns_ctx);
}

static void test_namespace_wide(struct ft_env *fte)
{
	struct ft_ns_ctx ns_ctx = { .fte = fte,
				    .depth_max = 2,
				    .dirs_per_level = 128,
				    .files_per_level = 16 };

	test_namespace_(&ns_ctx);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ft_tdef ft_local_tests[] = {
	FT_DEFTEST(test_namespace_simple),
	FT_DEFTEST(test_namespace_deep),
	FT_DEFTEST(test_namespace_wide),
};

const struct ft_tests ft_test_namespace = FT_DEFTESTS(ft_local_tests);
