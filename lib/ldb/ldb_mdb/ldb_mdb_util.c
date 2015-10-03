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

	dn_folded = ldb_dn_get_casefold(dn);
	if (dn_folded == NULL) {
		ret = ENOMEM;
		goto done;
	}

	key_str = talloc_asprintf(mem_ctx, DN_PREFIX"%s", dn_folded);
	/* Otherwise dn owns dn_folded.. */
	talloc_free(discard_const_p(char, dn_folded));
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
