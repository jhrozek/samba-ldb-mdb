/*
   Common functionality for message modification

   Copyright (C) Jakub Hrozek 2015

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LDB_MSG_MOD_H_
#define _LDB_MSG_MOD_H_

#include "ldb_private.h"

bool el_single_valued(const struct ldb_schema_attribute *a,
		      struct ldb_message_element *el);

long el_dupval_index(struct ldb_message_element *el);

int add_element(struct ldb_message *msg,
		struct ldb_message_element *el);

int del_element(struct ldb_message *msg,
		struct ldb_message_element *el);

int del_element_value(struct ldb_context *ldb,
		struct ldb_message *msg,
		const char *name,
		const struct ldb_val *del_val);

int extend_element(struct ldb_message *msg,
		struct ldb_message_element *orig,
		struct ldb_message_element *add_el);

int find_element_by_name(struct ldb_message *msg,
		const char *name);

int find_element(struct ldb_message *msg,
		 struct ldb_message_element *el);

int filter_duplicates(struct ldb_message_element *haystack,
		      struct ldb_message_element *needle,
		      bool permissive);

struct ldb_message_element *
el_shallow_copy(TALLOC_CTX *mem_ctx,
		const struct ldb_message_element *el);

#endif /* _LDB_MSG_MOD_H_ */
