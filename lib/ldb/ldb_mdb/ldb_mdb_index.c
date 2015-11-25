/*
   ldb database library using mdb back end - indexing

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
#include <talloc.h>

#include "ldb_mdb_index.h"

int ldb_mdb_filter_candidate_list(struct ldb_context *ldb,
				  struct ldb_request *req,
				  struct lmdb_db_op *op,
				  struct ldb_search *search,
				  struct ldb_val *candidate_dn_list,
				  size_t *returned_entries)
{
	size_t list_size, i;
	struct ldb_message *msg;
	struct ldb_dn *dn;
	bool matched;
	int ret;

	msg = ldb_msg_new(req);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}

	list_size = talloc_array_length(candidate_dn_list);
	for (i = 0; i < list_size; i++) {

		dn = ldb_dn_from_ldb_val(msg, ldb, &candidate_dn_list[i]);
		if (dn == NULL) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = ldb_mdb_msg_get(req, ldb, op, dn, &msg);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			continue;
		} else if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* see if it matches the given expression */
		ret = ldb_match_msg_error(ldb, msg,
					  search->tree, search->base, search->scope,
					  &matched);
		if (ret != LDB_SUCCESS) {
			talloc_free(msg);
			return ret;
		}

		if (!matched) {
			continue;
		}

		msg = ldb_msg_filter_attrs(msg, search->attrs);
		if (msg == NULL) {
			talloc_free(msg);
			return ldb_oom(ldb);
		}

		/* An entry was found */
		ret = ldb_module_send_entry(req, msg, NULL);
		if (ret != LDB_SUCCESS) {
			/* the callback failed, abort the operation */
			/* FIXME - test this failure, LB-TDB sets the request as handled here */
			talloc_free(msg);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (returned_entries) {
			(*returned_entries)++;
		}
	}

	return LDB_SUCCESS;
}
