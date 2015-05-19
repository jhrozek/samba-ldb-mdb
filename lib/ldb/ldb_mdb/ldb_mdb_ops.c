/*
   ldb database library using mdb back end - keyval operations

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

#include <errno.h>
#include <string.h>

#include "ldb_tev_wrap.h"
#include "ldb_mdb_pvt.h"
#include "ldb_mdb_util.h"

/* Does it make sense to pass the request as an ephemeral memory context? */
int ldb_mdb_add_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_add *add_ctx)
{
	struct lmdb_private *lmdb;
	struct ldb_context *ldb;
	MDB_env *mdb_env;
	MDB_dbi mdb_dbi = 0;
	MDB_txn *mdb_txn = NULL;
	int ret;

	if (tv_mod == NULL || req == NULL || add_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	mdb_env = lmdb->env;

	mdb_dbi = 0;

	ret = mdb_txn_begin(mdb_env, NULL, 0, &mdb_txn);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "mdb_txn_begin failed: %s\n",
				       mdb_strerror(ret));
		ret = ldb_mdb_err_map(ret);
		goto done;
	}

	ret = mdb_dbi_open(mdb_txn, NULL, 0, &mdb_dbi);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "mdb_dbi_open failed: %s\n",
				       mdb_strerror(ret));
		ret = ldb_mdb_err_map(ret);
		goto done;
	}

	ret = ldb_mdb_msg_store(ldb, mdb_txn, mdb_dbi,
				add_ctx->message,
				MDB_NOOVERWRITE);
	if (ret != 0) {
		goto done;
	}

	mdb_dbi_close(mdb_env, mdb_dbi);
	mdb_dbi = 0;

	ret = mdb_txn_commit(mdb_txn);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "mdb_txn_commit failed: %s\n",
				       mdb_strerror(ret));
		ret = ldb_mdb_err_map(ret);
		goto done;
	}
	mdb_txn = NULL;

	ret = LDB_SUCCESS;
done:
	if (mdb_dbi) {
		mdb_dbi_close(mdb_env, mdb_dbi);
	}

	if (mdb_txn != NULL) {
		mdb_txn_abort(mdb_txn);
	}

	return ret;
}
