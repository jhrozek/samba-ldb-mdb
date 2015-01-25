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

#include <errno.h>
#include <string.h>
#include <talloc.h>

#include "ldb_mdb_util.h"

#define	DN_PREFIX	"DN="

int ldb_mdb_err_map(int lmdb_err)
{
	switch (lmdb_err) {
	case MDB_SUCCESS:
		return LDB_SUCCESS;
	case MDB_INCOMPATIBLE:
	case MDB_CORRUPTED:
	case MDB_INVALID:
	case EIO:
		return LDB_ERR_OPERATIONS_ERROR;
	case MDB_BAD_TXN:
	case MDB_BAD_VALSIZE:
	case MDB_BAD_DBI:
	case MDB_PANIC:
	case EINVAL:
		return LDB_ERR_PROTOCOL_ERROR;
	case MDB_MAP_FULL:
	case MDB_DBS_FULL:
	case MDB_READERS_FULL:
	case MDB_TLS_FULL:
	case MDB_TXN_FULL:
	case EAGAIN:
		return LDB_ERR_BUSY;
	case MDB_KEYEXIST:
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	case MDB_NOTFOUND:
	case ENOENT:
		return LDB_ERR_NO_SUCH_OBJECT;
	case EACCES:
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	default:
		break;
	}
	return LDB_ERR_OTHER;
}

int ldb_mdb_dn_to_key(TALLOC_CTX *mem_ctx,
		      struct ldb_dn *dn,
		      struct MDB_val *key)
{
	char *key_str = NULL;
	const char *dn_folded = NULL;
	int ret;

	if (dn == NULL || key == NULL) {
		ret = EINVAL;
		goto done;
	}

	memset(key, 0, sizeof(MDB_val));

	/* dn_folded hangs off dn now, but it's often useful later, so we might
	 * rather keep it than allocate over and over again
	 */
	dn_folded = ldb_dn_get_casefold(dn);
	if (dn_folded == NULL) {
		ret = ENOMEM;
		goto done;
	}

	key_str = talloc_asprintf(mem_ctx, DN_PREFIX"%s", dn_folded);
	if (key_str == NULL) {
		ret = ENOMEM;
		goto done;
	}

	key->mv_size = strlen(key_str) + 1;
	key->mv_data = key_str;

	ret = LDB_SUCCESS;
done:
	return ret;
}

static inline void free_mdb_val(MDB_val *value)
{
	if (value == NULL) {
		return;
	}

	talloc_free(value->mv_data);
	memset(value, 0, sizeof(MDB_val));
}

void ldb_mdb_key_free(MDB_val *value)
{
	return free_mdb_val(value);
}

int ldb_mdb_msg_to_value(TALLOC_CTX *mem_ctx,
			 struct ldb_context *ldb,
			 struct ldb_message *msg,
			 MDB_val *value)
{
	struct ldb_val ldb_value;
	int ret;

	if (ldb == NULL || msg == NULL || value == NULL) {
		ret = EINVAL;
		goto done;
	}

	memset(value, 0, sizeof(MDB_val));

	/* ldb_value.data is allocated on ldb */
	ret = ldb_pack_data(ldb, msg, &ldb_value);
	if (ret != 0) {
		goto done;
	}

	value->mv_size = ldb_value.length;
	value->mv_data = talloc_steal(mem_ctx, ldb_value.data);

	ret = LDB_SUCCESS;
done:
	return ret;
}

void ldb_mdb_value_free(MDB_val *value)
{
	return free_mdb_val(value);
}

int ldb_mdb_msg_store(struct ldb_context *ldb,
		      MDB_txn *mdb_txn, MDB_dbi mdb_dbi,
		      struct ldb_message *msg,
		      int flags)
{
	int ret;
	MDB_val mdb_key;
	MDB_val mdb_val;

	memset(&mdb_key, 0, sizeof(MDB_val));
	memset(&mdb_val, 0, sizeof(MDB_val));

	ret = ldb_mdb_dn_to_key(msg, msg->dn, &mdb_key);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb,
				       "Cannot construct key from %s\n",
				       ldb_dn_get_linearized(msg->dn));
		goto done;
	}

	ret = ldb_mdb_msg_to_value(msg, ldb, msg, &mdb_val);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "Cannot construct value from %s\n",
				       ldb_dn_get_linearized(msg->dn));
		goto done;
	}

	ret = mdb_put(mdb_txn, mdb_dbi, &mdb_key, &mdb_val, flags);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "mdb_put failed: %s\n",
				       mdb_strerror(ret));
		ret = ldb_mdb_err_map(ret);
		goto done;
	}

	ret = LDB_SUCCESS;
done:
	ldb_mdb_key_free(&mdb_key);
	ldb_mdb_value_free(&mdb_val);
	return ret;
}
