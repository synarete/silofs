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
#ifndef SILOFS_AVL_H_
#define SILOFS_AVL_H_

#include <silofs/ccattr.h>
#include <stdlib.h>
#include <stdbool.h>

struct silofs_avl_node;

/* Get key-ref of tree-node */
typedef const void *(*silofs_avl_getkey_fn)(const struct silofs_avl_node *);

/* 3-way compare function-pointer */
typedef long (*silofs_avl_keycmp_fn)(const void *, const void *);

/* Node operator */
typedef void (*silofs_avl_node_fn)(struct silofs_avl_node *, void *);

struct silofs_avl_node_functor {
	silofs_avl_node_fn fn;
	void              *ctx;
};

/* AVL-tree node */
struct silofs_avl_node {
	struct silofs_avl_node *parent;
	struct silofs_avl_node *left;
	struct silofs_avl_node *right;
	int32_t                 balance;
	int32_t                 magic;
} silofs_attr_aligned32;

/* "Iterators" range a-la STL pair */
struct silofs_avl_range {
	struct silofs_avl_node *first;
	struct silofs_avl_node *second;
};

/*
 * AVL: self-balancing binary-search-tree. Holds reference to user-provided
 * nodes (intrusive container).
 */
struct silofs_avl {
	silofs_avl_getkey_fn   getkey;
	silofs_avl_keycmp_fn   keycmp;
	struct silofs_avl_node head;
	size_t                 size;
	void                  *userp;
};

void silofs_avl_node_init(struct silofs_avl_node *x);

void silofs_avl_node_fini(struct silofs_avl_node *x);

void silofs_avl_init(struct silofs_avl *avl, silofs_avl_getkey_fn getkey,
		     silofs_avl_keycmp_fn keycmp, void *userp);

void silofs_avl_fini(struct silofs_avl *avl);

size_t silofs_avl_size(const struct silofs_avl *avl);

bool silofs_avl_isempty(const struct silofs_avl *avl);

struct silofs_avl_node *silofs_avl_begin(const struct silofs_avl *avl);

struct silofs_avl_node *silofs_avl_rbegin(const struct silofs_avl *avl);

silofs_attr_const const struct silofs_avl_node *
silofs_avl_end(const struct silofs_avl *avl);

struct silofs_avl_node *
silofs_avl_next(const struct silofs_avl *avl, const struct silofs_avl_node *x);

struct silofs_avl_node *
silofs_avl_prev(const struct silofs_avl *avl, const struct silofs_avl_node *x);

struct silofs_avl_node *
silofs_avl_find(const struct silofs_avl *avl, const void *k);

struct silofs_avl_node *
silofs_avl_find_first(const struct silofs_avl *avl, const void *k);

size_t silofs_avl_count(const struct silofs_avl *avl, const void *k);

struct silofs_avl_node *
silofs_avl_lower_bound(const struct silofs_avl *avl, const void *k);

struct silofs_avl_node *
silofs_avl_upper_bound(const struct silofs_avl *avl, const void *k);

void silofs_avl_equal_range(const struct silofs_avl *avl, const void *k,
			    struct silofs_avl_range *out_r);

void silofs_avl_insert(struct silofs_avl *avl, struct silofs_avl_node *z);

int silofs_avl_insert_unique(struct silofs_avl      *avl,
			     struct silofs_avl_node *z);

struct silofs_avl_node *
silofs_avl_insert_replace(struct silofs_avl *avl, struct silofs_avl_node *z);

void silofs_avl_remove(struct silofs_avl *avl, struct silofs_avl_node *x);

void silofs_avl_remove_range(struct silofs_avl                    *avl,
			     struct silofs_avl_node               *first,
			     const struct silofs_avl_node         *last,
			     const struct silofs_avl_node_functor *fn);

void silofs_avl_clear(struct silofs_avl                    *avl,
		      const struct silofs_avl_node_functor *fn);

#endif /* SILOFS_AVL_H_ */
