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
#include <silofs/configs.h>
#include <silofs/macros.h>
#include <silofs/infra/panic.h>
#include <silofs/infra/avl.h>

#define AVL_MAGIC 0x6176

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
    See: Corman, Leiserson, Rivest, Stein, "INTRODUCTION TO ALGORITHMS",
    2nd ed., The MIT Press, Ch. 12 "Binary Search Trees".

    Rotate-Left-Right:
                |                               |
                a                               c
               / \                             / \
              /   \        ==>                /   \
             b    [g]                        b     a
            / \                             / \   / \
          [d]  c                          [d] e  f  [g]
              / \
             e   f


    Rotate-Right-Left:
                |                               |
                a                               c
               / \                             / \
              /   \                           /   \
            [d]   b        ==>               a     b
                 / \                        / \   / \
                c  [g]                    [d] e  f  [g]
               / \
              e  f

 */

struct silofs_avl_pos {
	struct silofs_avl_node *parent;
	struct silofs_avl_node **pnode;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void avl_node_init(struct silofs_avl_node *x)
{
	x->left = NULL;
	x->right = NULL;
	x->parent = NULL;
	x->balance = 0;
	x->magic = AVL_MAGIC;
}

static void avl_node_reset(struct silofs_avl_node *x)
{
	x->left = NULL;
	x->parent = NULL;
	x->right = NULL;
	x->balance = 0;
	x->magic = AVL_MAGIC;
}

static void avl_node_destroy(struct silofs_avl_node *x)
{
	avl_node_reset(x);
	x->balance = -333;
	x->magic = -666;
}

static void avl_node_swap_balance(struct silofs_avl_node *x,
                                  struct silofs_avl_node *y)
{
	int balance;

	balance = x->balance;
	x->balance = y->balance;
	y->balance = balance;
}

static struct silofs_avl_node *
avl_node_unconst(const struct silofs_avl_node *x)
{
	union _avl_unconst {
		void *p;
		const struct silofs_avl_node *y;
	} uu = {
		.y = x
	};
	return uu.p;
}

static void avl_node_verify(const struct silofs_avl_node *x)
{
	if ((x->magic != AVL_MAGIC) ||
	    silofs_unlikely((x->balance) > 1) ||
	    silofs_unlikely((x->balance) < -1)) {
		silofs_panic("illegal avl-node: %p balance=%d magic=0x%x",
		             x, (int)x->balance, (int)x->magic);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_avl_node *
bst_minimum(const struct silofs_avl_node *x)
{
	while (x->left) {
		x = x->left;
	}
	return x;
}

static const struct silofs_avl_node *
bst_maximum(const struct silofs_avl_node *x)
{
	while (x->right) {
		x = x->right;
	}
	return x;
}

static struct silofs_avl_node *
bst_successor(const struct silofs_avl_node *x)
{
	const struct silofs_avl_node *y;

	if (x->right) {
		y = bst_minimum(x->right);
	} else {
		y = x->parent;
		while (y && (x == y->right)) {
			x = y;
			y = y->parent;
		}
	}
	return avl_node_unconst(y);
}

static struct silofs_avl_node *
bst_predecessor(const struct silofs_avl_node *x)
{
	const struct silofs_avl_node *y;

	if (x->left) {
		y = bst_maximum(x->left);
	} else {
		y = x->parent;
		while (y && (x == y->left)) {
			x = y;
			y = y->parent;
		}
	}
	return avl_node_unconst(y);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
bst_rotate_left(struct silofs_avl_node *x, struct silofs_avl_node **root)
{
	struct silofs_avl_node *y = x->right;

	x->right = y->left;
	if (y->left != NULL) {
		y->left->parent = x;
	}
	y->parent = x->parent;
	if (x == *root) {
		*root = y;
	} else if (x == x->parent->left) {
		x->parent->left = y;
	} else {
		x->parent->right = y;
	}
	y->left = x;
	x->parent = y;
}

static void
bst_rotate_right(struct silofs_avl_node *x, struct silofs_avl_node **root)
{
	struct silofs_avl_node *y = x->left;

	x->left = y->right;
	if (y->right != NULL) {
		y->right->parent = x;
	}
	y->parent = x->parent;
	if (x == *root) {
		*root = y;
	} else if (x == x->parent->right) {
		x->parent->right = y;
	} else {
		x->parent->left = y;
	}
	y->right = x;
	x->parent = y;
}

static void
bst_rotate_left_right(struct silofs_avl_node *a, struct silofs_avl_node **root)
{
	struct silofs_avl_node *b = a->left;
	struct silofs_avl_node *c = b->right;

	a->left = c->right;
	b->right = c->left;

	c->right = a;
	c->left = b;

	c->parent = a->parent;
	a->parent = b->parent = c;

	if (a->left) {
		a->left->parent = a;
	}
	if (b->right) {
		b->right->parent = b;
	}

	if (a == *root) {
		*root = c;
	} else {
		if (a == c->parent->left) {
			c->parent->left = c;
		} else {
			c->parent->right = c;
		}
	}
}

static void bst_rotate_right_left(struct silofs_avl_node *a,
                                  struct silofs_avl_node **root)
{
	struct silofs_avl_node *b = a->right;
	struct silofs_avl_node *c = b->left;

	a->right = c->left;
	b->left = c->right;

	c->left = a;
	c->right = b;

	c->parent = a->parent;
	a->parent = b->parent = c;

	if (a->right) {
		a->right->parent = a;
	}
	if (b->left) {
		b->left->parent = b;
	}
	if (a == *root) {
		*root = c;
	} else {
		if (a == c->parent->left) {
			c->parent->left = c;
		} else {
			c->parent->right = c;
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void avl_rotate_left(struct silofs_avl_node *x,
                            struct silofs_avl_node **root)
{
	struct silofs_avl_node *y = x->right;

	avl_node_verify(x);
	avl_node_verify(y);

	bst_rotate_left(x, root);

	if (y->balance == 1) {
		x->balance = 0;
		y->balance = 0;
	} else {
		x->balance = 1;
		y->balance = -1;
	}
}

static void avl_rotate_right(struct silofs_avl_node *x,
                             struct silofs_avl_node **root)
{
	struct silofs_avl_node *y = x->left;

	avl_node_verify(x);
	avl_node_verify(y);

	bst_rotate_right(x, root);

	if (y->balance == -1) {
		x->balance = 0;
		y->balance = 0;
	} else {
		x->balance = -1;
		y->balance = 1;
	}
}

static void avl_rotate_left_right(struct silofs_avl_node *a,
                                  struct silofs_avl_node **root)
{
	struct silofs_avl_node *b = a->left;
	struct silofs_avl_node *c = b->right;

	avl_node_verify(a);
	avl_node_verify(b);
	avl_node_verify(c);

	bst_rotate_left_right(a, root);

	a->balance = (c->balance == -1) ? 1 : 0;
	b->balance = (c->balance == 1) ? -1 : 0;
	c->balance = 0;
}

static void avl_rotate_right_left(struct silofs_avl_node *a,
                                  struct silofs_avl_node **root)
{
	struct silofs_avl_node *b = a->right;
	struct silofs_avl_node *c = b->left;

	avl_node_verify(a);
	avl_node_verify(b);
	avl_node_verify(c);

	bst_rotate_right_left(a, root);

	a->balance = (c->balance == 1) ? -1 : 0;
	b->balance = (c->balance == -1) ? 1 : 0;
	c->balance = 0;
}

static bool left_child(const struct silofs_avl_node *x_parent,
                       const struct silofs_avl_node *x)
{
	return (x_parent->left == x);
}

static bool right_child(const struct silofs_avl_node *x_parent,
                        const struct silofs_avl_node *x)
{
	return (x_parent->right == x);
}

static void avl_insert_fixup(struct silofs_avl_node *x,
                             struct silofs_avl_node **root)
{
	struct silofs_avl_node *x_parent;

	while (x != *root) {
		x_parent = x->parent;
		avl_node_verify(x_parent);

		if (x_parent->balance == 1) {
			if (left_child(x_parent, x)) {
				x_parent->balance = 0;
			} else {
				if (x->balance == -1) {
					avl_rotate_right_left(x_parent, root);
				} else {
					avl_rotate_left(x_parent, root);
				}
			}
			break;
		}
		if (x_parent->balance == -1) {
			if (left_child(x_parent, x)) {
				if (x->balance == 1) {
					avl_rotate_left_right(x_parent, root);
				} else {
					avl_rotate_right(x_parent, root);
				}
			} else {
				x_parent->balance = 0;
			}
			break;
		}
		x_parent->balance = left_child(x_parent, x) ? -1 : 1;
		x = x_parent;
	}
}

static void avl_delete_fixup(struct silofs_avl_node *x,
                             struct silofs_avl_node *x_parent,
                             struct silofs_avl_node **root)
{
	struct silofs_avl_node *y = NULL;

	while (x != *root) {
		avl_node_verify(x_parent);

		if (x_parent->balance == 0) {
			x_parent->balance = right_child(x_parent, x) ? -1 : 1;
			return;
		}

		if (x_parent->balance == -1) {
			if (x == x_parent->left) {
				x_parent->balance = 0; /* balanced */
				x = x_parent;
				x_parent = x_parent->parent;
			} else {
				y = x_parent->left;
				if (y->balance == 1) {
					avl_rotate_left_right(x_parent, root);
					x = x_parent->parent;
					x_parent = x_parent->parent->parent;
				} else {
					avl_rotate_right(x_parent, root);
					x = x_parent->parent;
					x_parent = x_parent->parent->parent;
				}
				if (x->balance == 1) {
					break;
				}
			}
		} else {
			/* (x_parent->balance == 1) */
			if (x == x_parent->right) {
				x_parent->balance = 0; /* balanced */
				x = x_parent;
				x_parent = x_parent->parent;
			} else {
				y = x_parent->right;
				if (y->balance == -1) {
					avl_rotate_right_left(x_parent, root);
					x = x_parent->parent;
					x_parent = x_parent->parent->parent;
				} else {
					avl_rotate_left(x_parent, root);
					x = x_parent->parent;
					x_parent = x_parent->parent->parent;
				}
				if (x->balance == -1) {
					break;
				}
			}
		}
	}
}

static void avl_delete(struct silofs_avl_node *z,
                       struct silofs_avl_node **root)
{
	struct silofs_avl_node *x = NULL;
	struct silofs_avl_node *y = NULL;
	struct silofs_avl_node *x_parent = NULL;

	if (z->left == NULL) {
		y = z;
		x = z->right;
	} else if (z->right == NULL) {
		y = z;
		x = z->left;
	} else {
		y = bst_successor(z);
		x = y->right;
	}
	if (y != z) {
		/* z has two non-null childrens and y is z's successor */
		/* relink y in place of z */
		z->left->parent = y;
		y->left = z->left;

		if (y != z->right) {
			x_parent = y->parent;
			if (x != NULL) {
				x->parent = y->parent;
			}
			y->parent->left = x; /* y must be a child of left */
			y->right = z->right;
			z->right->parent = y;
		} else {
			x_parent = y;
		}
		if (*root == z) {
			*root = y;
		} else if (left_child(z->parent, z)) {
			z->parent->left = y;
		} else {
			z->parent->right = y;
		}
		y->parent = z->parent;
		avl_node_swap_balance(y, z);
		/* y now points to node to be actually deleted */
	} else {
		/* y == z    --> z has only one child, or none */
		x_parent = y->parent;
		if (x != NULL) {
			/* if z has at least one child, new parent is now y */
			x->parent = y->parent;
		}
		if (*root == z) {
			*root = x;
		} else if (left_child(z->parent, z)) {
			z->parent->left = x;
		} else {
			z->parent->right = x;
		}
	}
	avl_delete_fixup(x, x_parent, root);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_avl_node *avl_head(const struct silofs_avl *avl)
{
	return avl_node_unconst(&avl->head);
}

static struct silofs_avl_node **avl_root_p(const struct silofs_avl *avl)
{
	return &avl_head(avl)->parent;
}

static struct silofs_avl_node **avl_leftmost_p(const struct silofs_avl *avl)
{
	return &avl_head(avl)->left; /* minimal element */
}

static struct silofs_avl_node **avl_rightmost_p(const struct silofs_avl *avl)
{
	return &avl_head(avl)->right; /* maximal element */
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_avl_size(const struct silofs_avl *avl)
{
	return avl->size;
}

bool silofs_avl_isempty(const struct silofs_avl *avl)
{
	return (avl->size == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_avl_node *avl_end(const struct silofs_avl *avl)
{
	return avl_head(avl);
}

static struct silofs_avl_node *avl_begin(const struct silofs_avl *avl)
{
	struct silofs_avl_node **leftmost = avl_leftmost_p(avl);

	return *leftmost ? *leftmost : avl_end(avl);
}

static struct silofs_avl_node *avl_rbegin(const struct silofs_avl *avl)
{
	struct silofs_avl_node **rightmost = avl_rightmost_p(avl);

	return *rightmost ? *rightmost : avl_end(avl);
}

const struct silofs_avl_node *silofs_avl_end(const struct silofs_avl *avl)
{
	return avl_end(avl);
}

struct silofs_avl_node *silofs_avl_begin(const struct silofs_avl *avl)
{
	return avl_begin(avl);
}

struct silofs_avl_node *silofs_avl_rbegin(const struct silofs_avl *avl)
{
	return avl_rbegin(avl);
}

static struct silofs_avl_node *
avl_next(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	const struct silofs_avl_node *y;
	const struct silofs_avl_node *h = avl_head(avl);

	avl_node_verify(x);
	if (x != h) {
		y = bst_successor(x);
		if (y == NULL) {
			y = h;
		}
	} else {
		y = h->left;
	}
	return avl_node_unconst(y);
}

static struct silofs_avl_node *
avl_prev(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	const struct silofs_avl_node *y;
	const struct silofs_avl_node *h = avl_head(avl);

	avl_node_verify(x);
	if (x != h) {
		y = bst_predecessor(x);
		if (y == NULL) {
			y = h;
		}
	} else {
		y = h->right;
	}
	return avl_node_unconst(y);
}

struct silofs_avl_node *
silofs_avl_next(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	return avl_next(avl, x);
}

struct silofs_avl_node *
silofs_avl_prev(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	return avl_prev(avl, x);
}

static struct silofs_avl_node *
avl_insert_root(struct silofs_avl *avl, struct silofs_avl_node *x)
{
	avl_node_init(x);
	*avl_leftmost_p(avl) = x;
	*avl_rightmost_p(avl) = x;
	*avl_root_p(avl) = x;
	return x;
}

static const void *avl_keyof(const struct silofs_avl *avl,
                             const struct silofs_avl_node *x)
{
	return avl->getkey(x);
}

static long avl_keycmp(const struct silofs_avl *avl,
                       const void *kx, const void *ky)
{
	return avl->keycmp(kx, ky);
}

static bool avl_less_than(const struct silofs_avl *avl,
                          const struct silofs_avl_node *x, const void *k)
{
	return avl_keycmp(avl, avl_keyof(avl, x), k) > 0;
}

static bool avl_less_than2(const struct silofs_avl *avl,
                           const void *k, const struct silofs_avl_node *x)
{
	return avl_keycmp(avl, k, avl_keyof(avl, x)) > 0;
}

static long avl_compare_to(const struct silofs_avl *avl,
                           const struct silofs_avl_node *x, const void *k)
{
	return avl_keycmp(avl, avl_keyof(avl, x), k);
}

static long avl_compare(const struct silofs_avl *avl,
                        const struct silofs_avl_node *x,
                        const struct silofs_avl_node *y)
{
	return avl_compare_to(avl, x, avl_keyof(avl, y));
}

static void avl_pos_setup(struct silofs_avl_pos *pos,
                          struct silofs_avl_node *p, bool isleft)
{
	if (p == NULL) {
		pos->parent = NULL;
		pos->pnode = NULL;
	} else if (isleft) {
		pos->parent = p;
		pos->pnode = &p->left;
	} else {
		pos->parent = p;
		pos->pnode = &p->right;
	}
}

static int avl_search_uniq_ipos(struct silofs_avl *avl,
                                const struct silofs_avl_node *z,
                                struct silofs_avl_pos *out_pos)
{
	long cmp;
	bool left_child = false;
	struct silofs_avl_node *p = NULL;
	struct silofs_avl_node *x = *avl_root_p(avl);

	while (x != NULL) {
		cmp = avl_compare(avl, x, z);
		if (cmp > 0) {
			p = x;
			x = x->right;
			left_child = false;
		} else if (cmp < 0) {
			p = x;
			x = x->left;
			left_child = true;
		} else {
			return -1; /* not unique */
		}
	}
	avl_pos_setup(out_pos, p, left_child);
	return 0;
}

static int avl_search_leaf_ipos(struct silofs_avl *avl,
                                const struct silofs_avl_node *z,
                                struct silofs_avl_pos *out_pos)
{
	struct silofs_avl_node *p = NULL;
	struct silofs_avl_node *x = *avl_root_p(avl);
	long cmp;
	bool isleft = false;

	while (x != NULL) {
		cmp = avl_compare(avl, x, z);
		if (cmp < 0) {
			p = x;
			x = x->left;
			isleft = true;
		} else {
			p = x;
			x = x->right;
			isleft = false;
		}
	}
	avl_pos_setup(out_pos, p, isleft);
	return 0;
}

static int avl_search_insert_pos(struct silofs_avl *avl,
                                 const struct silofs_avl_node *x, bool unique,
                                 struct silofs_avl_pos *out_pos)
{
	int ret;

	if (unique) {
		ret = avl_search_uniq_ipos(avl, x, out_pos);
	} else {
		ret = avl_search_leaf_ipos(avl, x, out_pos);
	}
	return ret;
}

static struct silofs_avl_node *
avl_insert_leaf_at(struct silofs_avl *avl, struct silofs_avl_node *x,
                   const struct silofs_avl_pos *pos)
{
	x->parent = pos->parent;
	*pos->pnode = x;

	avl_insert_fixup(x, avl_root_p(avl));
	return x;
}

static void avl_post_insert_fixup(struct silofs_avl *avl)
{
	struct silofs_avl_node *prev;
	struct silofs_avl_node *next;
	struct silofs_avl_node **link;

	link = avl_leftmost_p(avl);
	prev = bst_predecessor(*link);
	if (prev != NULL) {
		*link = prev;
	}

	link = avl_rightmost_p(avl);
	next = bst_successor(*link);
	if (next != NULL) {
		*link = next;
	}
}

static struct silofs_avl_node *
avl_insert_leaf(struct silofs_avl *avl, struct silofs_avl_node *x, int unique)
{
	int err;
	struct silofs_avl_pos pos;

	err = avl_search_insert_pos(avl, x, unique, &pos);
	if (err) {
		return NULL; /* not unique */
	}
	if (pos.parent && pos.pnode) { /* make gcc-analyzer happy */
		avl_node_init(x);
		avl_insert_leaf_at(avl, x, &pos);
	}
	avl_post_insert_fixup(avl);
	return x;
}

static bool avl_insert(struct silofs_avl *avl,
                       struct silofs_avl_node *x, bool unique)
{
	bool ret = false;
	struct silofs_avl_node *y;

	if (avl->size > 0) {
		y = avl_insert_leaf(avl, x, unique);
	} else {
		y = avl_insert_root(avl, x);
	}
	if (y != NULL) {
		avl->size += 1;
		ret = true;
	}
	return ret;
}

void silofs_avl_insert(struct silofs_avl *avl, struct silofs_avl_node *z)
{
	avl_insert(avl, z, false);
}

int silofs_avl_insert_unique(struct silofs_avl *avl, struct silofs_avl_node *z)
{
	return avl_insert(avl, z, true) ? 0 : -1;
}

static void avl_reset(struct silofs_avl *avl)
{
	avl_node_reset(avl_head(avl));
	avl->size = 0;
}

static void avl_remove_last(struct silofs_avl *avl,
                            struct silofs_avl_node *x)
{
	avl_reset(avl);
	avl_node_reset(x);
}

static void avl_remove_rebalance(struct silofs_avl *avl,
                                 struct silofs_avl_node *x)
{
	struct silofs_avl_node **root = avl_root_p(avl);
	struct silofs_avl_node **pmin = avl_leftmost_p(avl);
	struct silofs_avl_node **pmax = avl_rightmost_p(avl);

	if (*pmin == x) {
		*pmin = bst_successor(x);
	}
	if (*pmax == x) {
		*pmax = bst_predecessor(x);
	}
	avl_delete(x, root);
	avl->size -= 1;
}

static void avl_remove(struct silofs_avl *avl, struct silofs_avl_node *x)
{
	if (avl->size > 1) {
		avl_remove_rebalance(avl, x);
	} else {
		avl_remove_last(avl, x);
	}
}

void silofs_avl_remove(struct silofs_avl *avl, struct silofs_avl_node *x)
{
	avl_node_verify(x);
	avl_remove(avl, x);
	avl_node_reset(x);
}

static struct silofs_avl_node *
avl_unlinkall(struct silofs_avl *avl)
{
	struct silofs_avl_node *x = NULL;
	struct silofs_avl_node *y = NULL;
	struct silofs_avl_node *list = NULL;

	x = *avl_root_p(avl);
	while (x != NULL) {
		y = x->parent;

		if (x->left) {
			x = x->left;
		} else if (x->right) {
			x = x->right;
		} else {
			/* Leaf */
			if (y != NULL) {
				if (y->left == x) {
					y->left = NULL;
				} else if (y->right == x) {
					y->right = NULL;
				}
			}

			/* Link removed node in list */
			avl_node_reset(x);
			x->right = list;
			list = x;

			x = y;
		}
	}
	return list;
}

static void avl_node_noop(struct silofs_avl_node *an, void *p)
{
	silofs_unused(an);
	silofs_unused(p);
}

static const struct silofs_avl_node_functor avl_noop_functor = {
	.fn = avl_node_noop,
	.ctx = NULL
};

static void avl_foreach_unlinked(struct silofs_avl_node *lst,
                                 const struct silofs_avl_node_functor *fn)
{
	struct silofs_avl_node *nxt = NULL;
	struct silofs_avl_node *itr = lst;

	while (itr != NULL) {
		nxt = itr->right;
		fn->fn(itr, fn->ctx);
		itr = nxt;
	}
}

static void
avl_apply_foreach_unlinked(struct silofs_avl *avl,
                           const struct silofs_avl_node_functor *fn)
{
	if (fn != NULL) {
		avl_foreach_unlinked(avl_unlinkall(avl), fn);
	}
}

void silofs_avl_clear(struct silofs_avl *avl,
                      const struct silofs_avl_node_functor *fn)
{
	avl_apply_foreach_unlinked(avl, fn);
	avl_reset(avl);
}

static void avl_remove_range(struct silofs_avl *avl,
                             struct silofs_avl_node *first,
                             const struct silofs_avl_node *last,
                             const struct silofs_avl_node_functor *fn)
{
	struct silofs_avl_node *nxt;
	struct silofs_avl_node *itr = first;

	while (itr != last) {
		nxt = avl_next(avl, itr);

		avl_remove(avl, itr);
		avl_node_reset(itr);
		fn->fn(itr, fn->ctx);
		itr = nxt;
	}
}

void silofs_avl_remove_range(struct silofs_avl *avl,
                             struct silofs_avl_node *first,
                             const struct silofs_avl_node *last,
                             const struct silofs_avl_node_functor *fn)
{
	avl_remove_range(avl, first, last, fn ? fn : &avl_noop_functor);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_avl_node *
avl_iterator(const struct silofs_avl *avl, const struct silofs_avl_node *x)
{
	return (x != NULL) ? avl_node_unconst(x) : avl_end(avl);
}

static void avl_range_setup(const struct silofs_avl *avl,
                            struct silofs_avl_range *r,
                            const struct silofs_avl_node *x,
                            const struct silofs_avl_node *y)
{
	r->first = avl_iterator(avl, x);
	r->second = avl_iterator(avl, y);
}

static size_t avl_distance(const struct silofs_avl *avl,
                           const struct silofs_avl_node *x,
                           const struct silofs_avl_node *y)
{
	size_t n = 0;

	while (x != y) {
		n += 1;
		x = avl_next(avl, x);
	}
	return n;
}

/* Find the first element whose key is not less than k (greater or equal-to) */
static const struct silofs_avl_node *
avl_lower_bound(const struct silofs_avl *avl,
                const struct silofs_avl_node *x,
                const struct silofs_avl_node *y, const void *k)
{
	while (x != NULL) {
		if (!avl_less_than(avl, x, k)) { /* !(x < k) */
			y = x;
			x = x->left;
		} else {
			x = x->right;
		}
	}
	return y;
}

/* Find the first element whose key is greater than k */
static const struct silofs_avl_node *
avl_upper_bound(const struct silofs_avl *avl,
                const struct silofs_avl_node *x,
                const struct silofs_avl_node *y,
                const void *k)
{
	while (x != NULL) {
		if (avl_less_than2(avl, k, x)) { /* k < x */
			y = x;
			x = x->left;
		} else {
			x = x->right;
		}
	}
	return y;
}

static void avl_equal_range(const struct silofs_avl *avl,
                            const struct silofs_avl_node *x,
                            const struct silofs_avl_node *y,
                            const void *k, struct silofs_avl_range *out_r)
{
	long cmp;
	const struct silofs_avl_node *xu = NULL;
	const struct silofs_avl_node *yu = NULL;
	const struct silofs_avl_node *z = y;
	const struct silofs_avl_node *w = y;

	while (x != NULL) {
		cmp = avl_compare_to(avl, x, k);
		if (cmp > 0) {
			x = x->right;
		} else if (cmp < 0) {
			y = x;
			x = x->left;
		} else {
			xu = x->right;
			yu = y;

			y = x;
			x = x->left;

			w = avl_lower_bound(avl, x, y, k);
			z = avl_upper_bound(avl, xu, yu, k);
			break;
		}
	}

	avl_range_setup(avl, out_r, w, z);
}

static const struct silofs_avl_node *
avl_find(const struct silofs_avl *avl, const void *k)
{
	long cmp;
	const struct silofs_avl_node *x = *avl_root_p(avl);

	while (x != NULL) {
		cmp = avl_compare_to(avl, x, k);
		if (cmp < 0) {
			x = x->left;
		} else if (cmp > 0) {
			x = x->right;
		} else {
			break; /* Bingo! */
		}
	}
	return x;
}

struct silofs_avl_node *
silofs_avl_find(const struct silofs_avl *avl, const void *k)
{
	const struct silofs_avl_node *x = NULL;

	if (avl->size > 0) {
		x = avl_find(avl, k);
	}
	return avl_node_unconst(x);
}

static const struct silofs_avl_node *
avl_find_first_ge(const struct silofs_avl *avl, const void *k)
{
	return avl_lower_bound(avl, *avl_root_p(avl), NULL, k);
}

static const struct silofs_avl_node *
avl_find_first_eq(const struct silofs_avl *avl, const void *k)
{
	long cmp;
	const struct silofs_avl_node *x;

	x = avl_find_first_ge(avl, k);
	if (x == NULL) {
		return NULL;
	}
	cmp = avl_compare_to(avl, x, k);
	if (cmp) {
		return NULL;
	}
	return x;
}

struct silofs_avl_node *
silofs_avl_find_first(const struct silofs_avl *avl, const void *k)
{
	const struct silofs_avl_node *x = NULL;

	if (avl->size > 0) {
		x = avl_find_first_eq(avl, k);
	}
	return avl_node_unconst(x);
}

size_t silofs_avl_count(const struct silofs_avl *avl, const void *k)
{
	struct silofs_avl_range r;

	silofs_avl_equal_range(avl, k, &r);

	return avl_distance(avl, r.first, r.second);
}

struct silofs_avl_node *
silofs_avl_lower_bound(const struct silofs_avl *avl, const void *k)
{
	const struct silofs_avl_node *x = NULL;

	if (avl->size > 0) {
		x = avl_lower_bound(avl, *avl_root_p(avl), NULL, k);
	}
	return avl_node_unconst(x);
}

struct silofs_avl_node *
silofs_avl_upper_bound(const struct silofs_avl *avl, const void *k)
{
	const struct silofs_avl_node *x = NULL;

	if (avl->size > 0) {
		x = avl_upper_bound(avl, *avl_root_p(avl), x, k);
	}
	return avl_node_unconst(x);
}

void silofs_avl_equal_range(const struct silofs_avl *avl, const void *k,
                            struct silofs_avl_range *out_r)
{
	if (avl->size > 0) {
		avl_equal_range(avl, *avl_root_p(avl), NULL, k, out_r);
	} else {
		avl_range_setup(avl, out_r, NULL, NULL);
	}
}

static void avl_replace_fixup(struct silofs_avl *avl,
                              struct silofs_avl_node *y,
                              struct silofs_avl_node *z)
{
	struct silofs_avl_node **root = avl_root_p(avl);
	struct silofs_avl_node **pmin = avl_leftmost_p(avl);
	struct silofs_avl_node **pmax = avl_rightmost_p(avl);

	if (*root == y) {
		*root = z;
	}
	if (*pmin == y) {
		*pmin = z;
	}
	if (*pmax == y) {
		*pmax = z;
	}
}

static void avl_node_exchange(struct silofs_avl_node *y,
                              struct silofs_avl_node *z)
{
	z->parent = y->parent;
	z->left = y->left;
	z->right = y->right;
	z->balance = y->balance;

	if (y->parent != NULL) {
		if (y->parent->left == y) {
			y->parent->left = z;
		} else {
			y->parent->right = z;
		}
	}
	if (y->left != NULL) {
		y->left->parent = z;
	}
	if (y->right != NULL) {
		y->right->parent = z;
	}
}

static void avl_replace_exists(struct silofs_avl *avl,
                               struct silofs_avl_node *y,
                               struct silofs_avl_node *z)
{
	avl_node_verify(y);
	avl_node_init(z);
	avl_node_exchange(y, z);
	avl_replace_fixup(avl, y, z);
	avl_node_destroy(y);
}

struct silofs_avl_node *
silofs_avl_insert_replace(struct silofs_avl *avl, struct silofs_avl_node *z)
{
	struct silofs_avl_node *y;

	y = silofs_avl_find(avl, avl_keyof(avl, z));
	if (y == NULL) {
		silofs_avl_insert(avl, z);
	} else if (y != z) {
		avl_replace_exists(avl, y, z);
	} else {
		y = NULL;
	}
	return y;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_avl_node_init(struct silofs_avl_node *x)
{
	avl_node_init(x);
}

void silofs_avl_node_fini(struct silofs_avl_node *x)
{
	avl_node_destroy(x);
}

void silofs_avl_init(struct silofs_avl *avl, silofs_avl_getkey_fn getkey,
                     silofs_avl_keycmp_fn keycmp, void *userp)
{
	avl_node_reset(&avl->head);
	avl->getkey = getkey;
	avl->keycmp = keycmp;
	avl->size = 0;
	avl->userp = userp;
}

void silofs_avl_fini(struct silofs_avl *avl)
{
	avl_reset(avl);
	avl->getkey = NULL;
	avl->keycmp = NULL;
	avl->userp = NULL;
}
