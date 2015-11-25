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

#ifndef _LDB_MDB_INDEX_H_
#define _LDB_MDB_INDEX_H_

#include "ldb_mdb_pvt.h"
#include "ldb_mdb_util.h"

int ldb_mdb_filter_candidate_list(struct ldb_context *ldb,
				  struct ldb_request *req,
				  struct lmdb_db_op *op,
				  struct ldb_search *search,
				  struct ldb_val *candidate_dn_list,
				  size_t *returned_entries);

#endif /* _LDB_MDB_INDEX_H_ */
