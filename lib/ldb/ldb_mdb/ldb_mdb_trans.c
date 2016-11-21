/*
   ldb database library using mdb back end - transaction operations

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

#include <errno.h>
#include "ldb_mdb_pvt.h"
#include "ldb_mdb_util.h"

#include "ldb_tev_wrap.h"
#include "include/dlinklist.h"

/* Internal transaction handling. Separate because there may be multiple
 * databases */
struct lmdb_db_op {
	/* Keep a backlink to the transaction so that we can
	 * only pass the lmdb_db_op to functions
	 */
	struct lmdb_trans *ltx;
	MDB_dbi mdb_dbi;
};

struct lmdb_trans {
	struct lmdb_trans *next;
	struct lmdb_trans *prev;

	struct lmdb_private *lmdb;

	MDB_txn *tx;
	/* DB op on the default, unnamed database. Add more ops for
	 * other databases (indexes?)
	 */
	struct lmdb_db_op *db_op;
};

static MDB_txn *lmdb_trans_get_tx(struct lmdb_trans *ltx)
{
	if (ltx == NULL) {
		return NULL;
	}

	return ltx->tx;
}

static void trans_push(struct lmdb_private *lmdb, struct lmdb_trans *ltx)
{
	if (lmdb->txlist) {
		talloc_steal(lmdb->txlist, ltx);
	}

	DLIST_ADD(lmdb->txlist, ltx);
}

static void trans_finished(struct lmdb_private *lmdb, struct lmdb_trans *ltx)
{
	ltx->tx = NULL; /* Neutralize destructor */
	DLIST_REMOVE(lmdb->txlist, ltx);
	talloc_free(ltx);
}

static int ldb_mdb_trans_destructor(struct lmdb_trans *ltx)
{
	if (ltx != NULL && ltx->tx != NULL) {
		mdb_txn_abort(ltx->tx);
	}
	return 0;
}

static struct lmdb_trans *lmdb_private_trans_head(struct lmdb_private *lmdb)
{
	struct lmdb_trans *ltx;

	ltx = lmdb->txlist;
	return ltx;
}

int lmdb_private_trans_start(struct lmdb_private *lmdb)
{
	int ret;
	struct lmdb_trans *ltx;
	struct lmdb_trans *ltx_head;
	MDB_txn *tx_parent;

	ltx = talloc_zero(lmdb, struct lmdb_trans);
	if (ltx == NULL) {
		return ldb_oom(lmdb->ldb);
	}
	talloc_set_destructor(ltx, ldb_mdb_trans_destructor);

	ltx->db_op = talloc_zero(ltx, struct lmdb_db_op);
	if (ltx->db_op  == NULL) {
		talloc_free(ltx);
		return ldb_oom(lmdb->ldb);
	}

	ltx->lmdb = lmdb;
	ltx->db_op->mdb_dbi = 0;
	ltx->db_op->ltx = ltx;

	ltx_head = lmdb_private_trans_head(lmdb);
	tx_parent = lmdb_trans_get_tx(ltx_head);

	ret = mdb_txn_begin(lmdb->env, tx_parent, 0, &ltx->tx);
	if (ret != 0) {
		ldb_asprintf_errstring(lmdb->ldb,
				       "mdb_txn_begin failed: %s\n",
				       mdb_strerror(ret));
		talloc_free(ltx);
		return ldb_mdb_err_map(ret);
	}

	trans_push(lmdb, ltx);
	return LDB_SUCCESS;
}

int lmdb_private_trans_commit(struct lmdb_private *lmdb)
{
	int ret;
	struct lmdb_trans *ltx;

	ltx = lmdb_private_trans_head(lmdb);
	if (ltx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = mdb_txn_commit(ltx->tx);
	trans_finished(lmdb, ltx);
	if (ret != 0) {
		ldb_asprintf_errstring(lmdb->ldb,
				       "mdb_txn_commit failed: %s\n",
				       mdb_strerror(ret));
		return ldb_mdb_err_map(ret);
	}

	return LDB_SUCCESS;
}

int lmdb_private_trans_cancel(struct lmdb_private *lmdb)
{
	struct lmdb_trans *ltx;

	ltx = lmdb_private_trans_head(lmdb);
	if (ltx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	mdb_txn_abort(ltx->tx);
	trans_finished(lmdb, ltx);
	return LDB_SUCCESS;
}

static int lmdb_named_db_op_start(struct lmdb_trans *ltx,
				  const char *name,
				  int flags)
{
	int ret;
	MDB_txn *mdb_txn;

	mdb_txn = lmdb_trans_get_tx(ltx);
	if (mdb_txn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = mdb_dbi_open(mdb_txn, NULL, 0, &ltx->db_op->mdb_dbi);
	if (ret != 0) {
		ldb_asprintf_errstring(ltx->lmdb->ldb,
				       "mdb_dbi_open failed: %s\n",
				       mdb_strerror(ret));
		return ldb_mdb_err_map(ret);
	}

	return LDB_SUCCESS;
}

static int lmdb_db_op_finish(struct lmdb_db_op *op)
{
	struct lmdb_private *lmdb;

	if (op == NULL) {
		return EINVAL;
	}
	lmdb = op->ltx->lmdb;

	if (op->ltx->tx == NULL) {
		ldb_asprintf_errstring(lmdb->ldb,
				       "Not in transaction?\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (op->mdb_dbi == 0) {
		ldb_asprintf_errstring(lmdb->ldb,
				       "DB handle not ready?\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* ldmb.h documentation says closing a handle should not even
	 * be necessary..*/
	mdb_dbi_close(lmdb->env, op->mdb_dbi);
	op->mdb_dbi = 0;

	return LDB_SUCCESS;
}

MDB_dbi lmdb_db_op_get_handle(struct lmdb_db_op *op)
{
	struct lmdb_private *lmdb;

	if (op == NULL) {
		return 0;
	}
	lmdb = op->ltx->lmdb;

	if (op->mdb_dbi == 0) {
		ldb_asprintf_errstring(lmdb->ldb,
				       "DB handle not ready?\n");
		return 0;
	}

	return op->mdb_dbi;
}

MDB_txn *lmdb_db_op_get_tx(struct lmdb_db_op *op)
{
	if (op == NULL) {
		return NULL;
	}
	return op->ltx->tx;
}

/* Helpers to manage transactions and main db handles at the same time */
/* FIXME - should the ldb_mdb_op_start API also have a talloc_ctx?
 * Looks like we're leaking the context now...
 */
struct lmdb_db_op *ldb_mdb_op_start(struct lmdb_private *lmdb)
{
	int ret;
	struct lmdb_trans *ltx;

	ltx = lmdb_private_trans_head(lmdb);
	if (ltx == NULL) {
		return NULL;
	}

	ret = lmdb_named_db_op_start(ltx, NULL, 0);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot start db operation\n");
		return NULL;
	}

	return ltx->db_op;
}

int ldb_mdb_op_commit(struct lmdb_private *lmdb,
		      struct lmdb_db_op *op)
{
	int ret;

	ret = lmdb_db_op_finish(op);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot finish db operation\n");
		return ret;
	}

	return LDB_SUCCESS;
}

int ldb_mdb_op_cancel(struct lmdb_private *lmdb,
		      struct lmdb_db_op *op)
{
	int ret;

	ret = lmdb_db_op_finish(op);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(lmdb->ldb, "Cannot finish db operation\n");
		return ret;
	}

	return LDB_SUCCESS;
}
