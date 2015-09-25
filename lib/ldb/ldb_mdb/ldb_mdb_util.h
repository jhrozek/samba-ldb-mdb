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

#ifndef _LDB_MDB_UTIL_H_
#define _LDB_MDB_UTIL_H_

#include <lmdb.h>

#include "ldb_private.h"
#include "ldb_mdb_pvt.h"
/* We need the discard_const() macros */
#include "replace.h"

/* Map lmdb errors to ldb error codes */
int ldb_mdb_err_map(int lmdb_err);

/* Opaque structure that holds info about mdb database operation.
 * Use lmdb_db_op_* to access the internal data fields
 */
struct lmdb_db_op;

/* Fills structure key with folded data from ldb_dn. The data is owned by
 * mem_ctx. Use ldb_mdb_key_free() to free the resources.
 */
int ldb_mdb_dn_to_key(TALLOC_CTX *mem_ctx,
		      struct ldb_dn *dn,
		      struct MDB_val *key);

void ldb_mdb_key_free(MDB_val *key);

/* Fills structure value with data from ldb_message. The data is owned by
 * mem_ctx. Use ldb_mdb_value_free() to free the resources.
 */
int ldb_mdb_msg_to_value(TALLOC_CTX *mem_ctx,
			 struct ldb_context *ldb,
			 struct ldb_message *msg,
			 MDB_val *value);

int ldb_mdb_value_to_msg(TALLOC_CTX *mem_ctx,
			 struct ldb_context *ldb,
			 MDB_val *value,
			 struct ldb_message **_msg);

void ldb_mdb_value_free(MDB_val *value);

int ldb_mdb_msg_store(struct ldb_context *ldb,
		      struct lmdb_db_op *op,
		      struct ldb_message *msg,
		      int flags);

int ldb_mdb_dn_delete(struct ldb_context *ldb,
		      struct lmdb_db_op *op,
		      struct ldb_dn *dn);

/* internal transaction API */
int lmdb_private_trans_start(struct lmdb_private *lmdb);
int lmdb_private_trans_commit(struct lmdb_private *lmdb);
int lmdb_private_trans_cancel(struct lmdb_private *lmdb);
struct lmdb_trans *lmdb_private_trans_head(struct lmdb_private *lmdb);
MDB_txn *lmdb_trans_get_tx(struct lmdb_trans *ltx);

/* internal DB operation API */

int lmdb_db_op_start(struct lmdb_trans *ltx);
struct lmdb_db_op *lmdb_db_op_get(struct lmdb_trans *ltx);
int lmdb_db_op_finish(struct lmdb_db_op *op);

MDB_dbi lmdb_db_op_get_handle(struct lmdb_db_op *op);
MDB_txn *lmdb_db_op_get_tx(struct lmdb_db_op *op);

#endif /* _LDB_MDB_UTIL_H_ */
