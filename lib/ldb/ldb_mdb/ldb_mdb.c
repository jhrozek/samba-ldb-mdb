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

#include <lmdb.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "ldb_mdb_pvt.h"
#include "ldb_tev_wrap.h"

#define MDB_URL_PREFIX		"mdb://"
#define MDB_URL_PREFIX_SIZE	(sizeof(MDB_URL_PREFIX)-1)

static const struct ldb_tv_ops lmdb_ops = {
	.search			= ldb_mdb_search_op,
	.add			= ldb_mdb_add_op,
	.del			= ldb_mdb_del_op,
	.modify			= ldb_mdb_mod_op,

	.start_transaction	= ldb_mdb_trans_start,
	.prepare_transaction	= ldb_mdb_trans_prepare,
	.end_transaction	= ldb_mdb_trans_commit,
	.del_transaction	= ldb_mdb_trans_cancel,
};

static int lmdb_pvt_destructor(struct lmdb_private *lmdb)
{
	mdb_env_close(lmdb->env);
	return 0;
}

static struct lmdb_private *lmdb_pvt_create(TALLOC_CTX *mem_ctx,
					    struct ldb_context *ldb,
					    const char *path)
{
	struct lmdb_private *lmdb;
	int ret;

	lmdb = talloc_zero(ldb, struct lmdb_private);
	if (lmdb == NULL) {
		return NULL;
	}
	lmdb->ldb = ldb;

	ret = mdb_env_create(&lmdb->env);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				"Could not create MDB environment %s: %s\n",
				path, mdb_strerror(ret));
		talloc_free(lmdb);
		return NULL;
	}

	/* Close when lmdb is released */
	talloc_set_destructor(lmdb, lmdb_pvt_destructor);

	/* MDB_NOSUBDIR implies there is a separate file called path and a
	 * separate lockfile called path-lock
	 */
	ret = mdb_env_open(lmdb->env, path, MDB_NOSUBDIR, 0644);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				"Could not open DB %s: %s\n",
				path, mdb_strerror(ret));
		talloc_free(lmdb);
		return NULL;
	}

	return lmdb;
}

static const char *lmdb_get_path(const char *url)
{
	const char *path;

	/* parse the url */
	if (strchr(url, ':')) {
		if (strncmp(url, MDB_URL_PREFIX, MDB_URL_PREFIX_SIZE) != 0) {
			return NULL;
		}
		path = url + MDB_URL_PREFIX_SIZE;
	} else {
		path = url;
	}

	return path;
}

static int lmdb_connect(struct ldb_context *ldb, const char *url,
			unsigned int flags, const char *options[],
			struct ldb_module **_module)
{
	int ret;
	const char *path;
	struct ldb_tv_module *kv_mod;
	struct lmdb_private *lmdb;

	path = lmdb_get_path(url);
	if (path == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid mdb URL '%s'", url);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lmdb = lmdb_pvt_create(ldb, ldb, path);
	if (lmdb == NULL) {
		return ldb_oom(ldb);
	}

	ret = ldb_tv_register(lmdb, ldb, "ldb_mdb",
			      &lmdb_ops, lmdb, &kv_mod);
	if (ret != LDB_SUCCESS) {
		talloc_free(lmdb);
		return ret;
	}

	*_module = ldb_tv_get_ldb_module(kv_mod);
	return LDB_SUCCESS;
}

int ldb_mdb_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_backend("mdb", lmdb_connect, false);
}