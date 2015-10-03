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

/* Transaction API to be used by LDB users. Hooks into the ldb_tv_
 * interface
 */
int ldb_mdb_trans_start(struct ldb_tv_module *tv_mod)
{
	struct lmdb_private *lmdb;

	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return lmdb_private_trans_start(lmdb);
}

int ldb_mdb_trans_prepare(struct ldb_tv_module *tv_mod)
{
	return LDB_SUCCESS;
}

int ldb_mdb_trans_commit(struct ldb_tv_module *tv_mod)
{
	struct lmdb_private *lmdb;

	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return lmdb_private_trans_commit(lmdb);
}

int ldb_mdb_trans_cancel(struct ldb_tv_module *tv_mod)
{
	struct lmdb_private *lmdb;

	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return lmdb_private_trans_cancel(lmdb);
}

/* Helpers to manage transactions and main db handles at the same time */
static struct lmdb_db_op *ldb_mdb_op_start(struct lmdb_private *lmdb)
{
	int ret;
	struct lmdb_trans *ltx;

	ret = lmdb_private_trans_start(lmdb);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot start transaction\n");
		return NULL;
	}

	ltx = lmdb_private_trans_head(lmdb);
	if (ltx == NULL) {
		/* Huh? Try to roll back..*/
		lmdb_private_trans_cancel(lmdb);
		return NULL;
	}

	ret = lmdb_db_op_start(ltx);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot start db operation\n");
		lmdb_private_trans_cancel(lmdb);
		return NULL;
	}

	return lmdb_db_op_get(ltx);
}

static int ldb_mdb_op_commit(struct lmdb_private *lmdb,
			     struct lmdb_db_op *op)
{
	int ret;

	ret = lmdb_db_op_finish(op);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot finish db operation\n");
		lmdb_private_trans_cancel(lmdb);
		return ret;
	}

	ret = lmdb_private_trans_commit(lmdb);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot commit db transaction\n");
		lmdb_private_trans_cancel(lmdb);
		return ret;
	}

	return LDB_SUCCESS;
}

static int ldb_mdb_op_cancel(struct lmdb_private *lmdb,
			     struct lmdb_db_op *op)
{
	int ret;

	ret = lmdb_db_op_finish(op);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot finish db operation\n");
		lmdb_private_trans_cancel(lmdb);
		return ret;
	}

	ret = lmdb_private_trans_cancel(lmdb);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot cancel db transaction\n");
		return ret;
	}

	return LDB_SUCCESS;
}

/* Does it make sense to pass the request as an ephemeral memory context? */
int ldb_mdb_add_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_add *add_ctx)
{
	struct lmdb_private *lmdb;
	struct ldb_context *ldb;
	int ret;
	struct lmdb_db_op *op = NULL;

	if (tv_mod == NULL || req == NULL || add_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	op = ldb_mdb_op_start(lmdb);
	if (op == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mdb_msg_store(ldb,
				op,
				add_ctx->message,
				MDB_NOOVERWRITE);
	if (ret != 0) {
		goto done;
	}

	ret = ldb_mdb_op_commit(lmdb, op);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	op = NULL;

	ret = LDB_SUCCESS;
done:
	if (op != NULL) {
		ldb_mdb_op_cancel(lmdb, op);
	}

	return ret;
}

int ldb_mdb_del_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_delete *del_ctx)
{
	struct ldb_context *ldb;
	struct lmdb_private *lmdb;
	int ret;
	struct lmdb_db_op *op = NULL;

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	op = ldb_mdb_op_start(lmdb);
	if (op == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mdb_dn_delete(ldb, op, del_ctx->dn);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ldb_mdb_op_commit(lmdb, op);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	op = NULL;

	ret = LDB_SUCCESS;
done:
	if (op != NULL) {
		ldb_mdb_op_cancel(lmdb, op);
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
	MDB_dbi mdb_dbi = 0;
	MDB_val mdb_key;
	MDB_val mdb_val;
	MDB_cursor *cursor = NULL;
	struct lmdb_db_op *op = NULL;

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	op = ldb_mdb_op_start(lmdb);
	if (op == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	mdb_dbi = lmdb_db_op_get_handle(op);
	mdb_txn = lmdb_db_op_get_tx(op);

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

	ret = ldb_mdb_op_commit(lmdb, op);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	op = NULL;

	ret = LDB_SUCCESS;
done:
	if (cursor) {
		mdb_cursor_close(cursor);
	}

	if (op != NULL) {
		ldb_mdb_op_cancel(lmdb, op);
	}

	return ret;
}

int ldb_mdb_mod_op(struct ldb_tv_module *tv_mod,
		   struct ldb_request *req,
		   struct ldb_modify *mod_ctx)
{
	int ret;
	struct ldb_context *ldb;
	struct lmdb_private *lmdb;
	struct ldb_message *db_msg;
	TALLOC_CTX *mod_op_ctx = NULL;
	struct lmdb_db_op *op = NULL;

	ldb = ldb_tv_get_ldb_ctx(tv_mod);
	lmdb = ldb_tv_get_mod_data(tv_mod);
	if (ldb == NULL || lmdb == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	mod_op_ctx = talloc_new(req);
	if (mod_op_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto done;
	}

	op = ldb_mdb_op_start(lmdb);
	if (op == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mdb_msg_get(mod_op_ctx,
			      ldb, op,
			      mod_ctx->message->dn,
			      &db_msg);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	if (db_msg->dn == NULL) {
		/* Handles PACKING_FORMAT_NODN */
		db_msg->dn = mod_ctx->message->dn;
	}

	/* Mutate db_msg according to the modifications in mod_msg */
	ret = ldb_msg_modify(ldb, mod_ctx->message, db_msg);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	/* Store updated db_msg in the database */
	ret = ldb_mdb_msg_store(ldb, op, db_msg, 0);
	if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ldb_mdb_op_commit(lmdb, op);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	op = NULL;

	ret = LDB_SUCCESS;
done:
	if (op != NULL) {
		ldb_mdb_op_cancel(lmdb, op);
	}

	talloc_free(mod_op_ctx);
	return ret;
}
