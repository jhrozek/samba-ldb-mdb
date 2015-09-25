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

/* Internal transaction handling */
struct lmdb_trans {
	struct lmdb_trans *next;
	struct lmdb_trans *prev;

	MDB_txn *tx;
};

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
	if (ltx && ltx->tx) {
		mdb_txn_abort(ltx->tx);
	}
	return 0;
}

struct lmdb_trans *lmdb_private_trans_head(struct lmdb_private *lmdb)
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
		return ENOMEM;
	}
	talloc_set_destructor(ltx, ldb_mdb_trans_destructor);

	ltx_head = lmdb_private_trans_head(lmdb);
	tx_parent = lmdb_trans_get_tx(ltx_head);

	ret = mdb_txn_begin(lmdb->env, tx_parent, 0, &ltx->tx);
	if (ret != 0) {
		ldb_asprintf_errstring(lmdb->ldb,
				       "mdb_txn_begin failed: %s\n",
				       mdb_strerror(ret));
		talloc_free(ltx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	trans_push(lmdb, ltx);
	return 0;
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
		return LDB_ERR_OPERATIONS_ERROR;
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

MDB_txn *lmdb_trans_get_tx(struct lmdb_trans *ltx)
{
	if (ltx == NULL) {
		return NULL;
	}

	return ltx->tx;
}
