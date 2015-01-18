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

int ldb_mdb_del_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_delete *del_ctx)
{
	struct ldb_context *ldb;
	struct lmdb_private *lmdb;
	MDB_env *mdb_env;
	MDB_txn *mdb_txn = NULL;
	MDB_dbi mdb_dbi = 0;
	int ret;

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	mdb_env = lmdb->env;

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

	ret = ldb_mdb_dn_delete(ldb, mdb_txn, mdb_dbi, del_ctx->dn);
	if (ret != LDB_SUCCESS) {
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

static int keyval_matches(struct ldb_context *ldb,
			  MDB_val mdb_key,
			  MDB_val mdb_val,
			  const struct ldb_parse_tree *tree,
			  struct ldb_dn *base,
			  enum ldb_scope scope,
			  struct ldb_message *msg)
{
	/* Move to a separate function */
	struct ldb_val ldb_value;
	bool matched;
	int ret;

	ldb_value.length = mdb_val.mv_size;
	ldb_value.data = mdb_val.mv_data;

	/* ldb_value allocated on top of msg */
	ret = ldb_unpack_data(ldb, &ldb_value, msg);
	if (ret != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (msg->dn == NULL) {
		/* Handles PACKING_FORMAT_NODN */
		msg->dn = ldb_dn_new(msg, ldb, (char *) mdb_key.mv_data + 3);
		if (msg->dn == NULL) {
			return ENOMEM;
		}
	}

	/* see if it matches the given expression */
	ret = ldb_match_msg_error(ldb, msg, tree, base, scope, &matched);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (!matched) {
		talloc_free_children(msg);
		return LDB_ERR_COMPARE_FALSE;
	}

	return LDB_ERR_COMPARE_TRUE;
}

int ldb_mdb_search_op(struct ldb_tv_module *tv_mod,
		      struct ldb_request *req,
		      struct ldb_search *search)
{
	struct ldb_message *msg;
	struct ldb_context *ldb;
	int ret;
	struct lmdb_private *lmdb;
	MDB_txn *mdb_txn = NULL;
	MDB_env *mdb_env;
	MDB_dbi mdb_dbi = 0;
	MDB_val mdb_key;
	MDB_val mdb_val;
	MDB_cursor *cursor = NULL;

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	mdb_env = lmdb->env;

	ret = mdb_txn_begin(mdb_env, NULL, MDB_RDONLY, &mdb_txn);
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

	/* FIXME - might not need cursor at all. Might just use mdb_get. Need to
	 * check implementation
	 */
	ret = mdb_cursor_open(mdb_txn, mdb_dbi, &cursor);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "mdb_cursor_open failed: %s\n",
				       mdb_strerror(ret));
		ret = ldb_mdb_err_map(ret);
		goto done;
	}

	msg = ldb_msg_new(req);
	if (msg == NULL) {
		ret = ENOMEM;
		goto done;
	}

	while ((ret = mdb_cursor_get(cursor, &mdb_key,
				     &mdb_val, MDB_NEXT)) == 0) {
		ret = keyval_matches(ldb, mdb_key, mdb_val,
				     search->tree, search->base,
				     search->scope, msg);
		if (ret == LDB_ERR_COMPARE_FALSE) {
			/* No error, just didn't match. */
			continue;
		} else if (ret != LDB_ERR_COMPARE_TRUE) {
			/* Fatal error, abort */
			goto done;
		}

		/* An entry was found */
		ret = ldb_module_send_entry(req, msg, NULL);
		if (ret != LDB_SUCCESS) {
			/* the callback failed, abort the operation */
			/* FIXME - test this failure, LB-TDB sets the request as handled here */
			ret = LDB_ERR_OPERATIONS_ERROR;
			goto done;
		}

		/* msg is now owned by the caller */
		msg = ldb_msg_new(req);
		if (msg == NULL) {
			ret = ENOMEM;
			goto done;
		}
	}

	if (ret != MDB_NOTFOUND) {
		ret = ldb_mdb_err_map(ret);
		goto done;
	}
	ret = LDB_SUCCESS;
done:
	if (cursor) {
		mdb_cursor_close(cursor);
	}

	if (mdb_dbi) {
		mdb_dbi_close(mdb_env, mdb_dbi);
	}

	if (mdb_txn != NULL) {
		mdb_txn_commit(mdb_txn);
	}
	return ret;
}
