/*
   Helper functions for LDB back ends built over key-value

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

#ifndef _LDB_KEYVAL_H_
#define _LDB_KEYVAL_H_

#include "ldb_private.h"

struct ldb_tv_module;

/* Any key-value module needs to support these operations. Ideally, the
 * ldb_request structure should be totally opaque to the operations and
 * its data accessed only through getters
 */
struct ldb_tv_ops {
	int (*search)(struct ldb_tv_module *,
		      struct ldb_request *,
		      struct ldb_search *);

	int (*add)(struct ldb_tv_module *,
		   struct ldb_request *,
		   struct ldb_add *);

	int (*modify)(struct ldb_tv_module *,
		      struct ldb_request *,
		      struct ldb_modify *);

	int (*del)(struct ldb_tv_module *,
		   struct ldb_request *,
		   struct ldb_delete *);

	int (*rename)(struct ldb_tv_module *,
		      struct ldb_request *,
		      struct ldb_rename *);

	int (*extended)(struct ldb_tv_module *,
			struct ldb_request *,
			struct ldb_extended *);

	int (*start_transaction)(struct ldb_tv_module *);

	int (*prepare_transaction)(struct ldb_tv_module *);

	int (*end_transaction)(struct ldb_tv_module *);

	int (*del_transaction)(struct ldb_tv_module *);
};

int ldb_tv_register(TALLOC_CTX *mem_ctx,
		    struct ldb_context *ldb,
		    const char *name,
		    const struct ldb_tv_ops *ops,
		    void *kv_mod_data,
		    struct ldb_tv_module **_kv_mod);

struct ldb_module *ldb_tv_get_ldb_module(struct ldb_tv_module *kv_mod);

struct ldb_context *ldb_tv_get_ldb_ctx(struct ldb_tv_module *kv_mod);

void *ldb_tv_get_mod_data(struct ldb_tv_module *kv_mod);

#endif /* _LDB_KEYVAL_H_ */
