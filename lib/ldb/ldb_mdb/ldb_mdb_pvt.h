/*
   ldb database library using mdb back end

   Copyright (C) Jakub Hrozek 2014

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

#ifndef _LDB_MDB_PVT_H_
#define _LDB_MDB_PVT_H_

#include <lmdb.h>

#include "ldb_private.h"
#include "ldb_tev_wrap.h"

struct lmdb_private {
	struct ldb_context *ldb; // Do we need this member to be visible??
	MDB_env *env;

	struct lmdb_trans *txlist;
};

/* == Module operations == */
int ldb_mdb_add_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_add *add_ctx);

int ldb_mdb_search_op(struct ldb_tv_module *tv_mod,
		      struct ldb_request *req,
		      struct ldb_search *search);

int ldb_mdb_del_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_delete *del_ctx);

int ldb_mdb_mod_op(struct ldb_tv_module *tv_mod,
                   struct ldb_request *req,
                   struct ldb_modify *mod_ctx);

int ldb_mdb_rename_op(struct ldb_tv_module *tv_mod,
                      struct ldb_request *req,
                      struct ldb_rename *rename_ctx);

int ldb_mdb_trans_start(struct ldb_tv_module *tv_mod);
int ldb_mdb_trans_prepare(struct ldb_tv_module *tv_mod);
int ldb_mdb_trans_commit(struct ldb_tv_module *tv_mod);
int ldb_mdb_trans_cancel(struct ldb_tv_module *tv_mod);
#endif /* _LDB_MDB_PVT_H_ */
