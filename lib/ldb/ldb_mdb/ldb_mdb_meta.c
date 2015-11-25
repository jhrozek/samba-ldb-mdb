/*
   ldb database library using mdb back end - internal records

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

#include <string.h>
#include <time.h>

#include "ldb_tev_wrap.h"
#include "ldb_mdb_pvt.h"
#include "ldb_mdb_util.h"

#define LDB_MDB_BASEINFO   "@BASEINFO"
#define LDB_MDB_BASEINFO_SEQNUM	    "sequenceNumber"
#define LDB_MDB_BASEINFO_MODSTAMP   "whenChanged"

#define LDB_MDB_ATTRIBUTES  "@ATTRIBUTES"

#define LDB_MDB_FLAG_CASE_INSENSITIVE (1<<0)
#define LDB_MDB_FLAG_INTEGER          (1<<1)
#define LDB_MDB_FLAG_HIDDEN           (1<<2)

/* valid attribute flags */
static const struct {
	const char *name;
	int value;
} ldb_mdb_valid_attr_flags[] = {
	{ "CASE_INSENSITIVE", LDB_MDB_FLAG_CASE_INSENSITIVE },
	{ "INTEGER", LDB_MDB_FLAG_INTEGER },
	{ "HIDDEN", LDB_MDB_FLAG_HIDDEN },
	{ "NONE", 0 },
	{ NULL, 0 }
};

static int baseinfo_msg_add_seqnum(struct ldb_message *msg,
				   unsigned seqnum)
{
	return ldb_msg_add_fmt(msg, LDB_MDB_BASEINFO_SEQNUM,
			       "%u", seqnum);
}

static int baseinfo_msg_add_now(struct ldb_message *msg)
{
	char *s = NULL;
	time_t now = time(NULL);
	struct ldb_val val_time;

	s = ldb_timestring(msg, now);
	if (s == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	val_time.data = (uint8_t *) s;
	val_time.length = strlen(s);

	return ldb_msg_add_value(msg, LDB_MDB_BASEINFO_MODSTAMP,
				 &val_time, NULL);
}

/* If ldb_tdb and ldb_mdb agree on using the same baseinfo, then this
 * could be split to a common module
 */
static struct ldb_message *update_baseinfo_msg(TALLOC_CTX *mem_ctx,
					       struct ldb_context *ldb,
					       unsigned seqnum)
{
	int ret;
	struct ldb_message *msg;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NULL;
	}

	msg->dn = ldb_dn_new(msg, ldb, LDB_MDB_BASEINFO);
	if (msg->dn == NULL) {
		talloc_free(msg);
		return NULL;
	}

	ret = baseinfo_msg_add_seqnum(msg, seqnum);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NULL;
	}

	ret = baseinfo_msg_add_now(msg);
	if (ret != LDB_SUCCESS) {
		talloc_free(msg);
		return NULL;
	}

	return msg;
}

/* Store an updated baseinfo record with increased lmdb->seqnum */
static int ldb_mdb_seqnum_inc(struct lmdb_private *lmdb,
			      struct lmdb_db_op *op)
{
	int ret;
	struct ldb_message *msg;
	struct ldb_context *ldb;

	ldb = lmdb->ldb;

	/* FIXME - if lmdb->meta == NULL, then init()? */

	msg = update_baseinfo_msg(op, ldb, lmdb->meta->seqnum);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mdb_msg_store(lmdb->ldb, op, msg, 0);
	talloc_free(msg);
	if (ret == LDB_SUCCESS) {
		lmdb->meta->seqnum += 1;
	}

	return ret;
}

static int ldb_mdb_seqnum_get(struct lmdb_private *lmdb,
			      struct lmdb_db_op *op,
			      unsigned *_seq)
{
	int ret;
	struct ldb_dn *dn;
	struct ldb_context *ldb;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = NULL;

	ldb = lmdb->ldb;

	tmp_ctx = talloc_new(op);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	dn = ldb_dn_new(tmp_ctx, ldb, LDB_MDB_BASEINFO);
	if (dn == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = ldb_mdb_msg_get(tmp_ctx, ldb, op, dn, &msg);
	if (ret != LDB_SUCCESS) {
		/* Includes LDB_ERR_NO_SUCH_OBJECT, the caller should
		 * initialize the baseinfo record
		 */
		goto done;
	}

	*_seq = ldb_msg_find_attr_as_uint(msg, LDB_MDB_BASEINFO_SEQNUM, 0);
	ret = LDB_SUCCESS;
done:
	talloc_free(tmp_ctx);
	return ret;
}

static struct ldb_mdb_metadata *ldb_mdb_meta_new(TALLOC_CTX *mem_ctx)
{
	struct ldb_mdb_metadata *meta;

	meta = talloc_zero(mem_ctx, struct ldb_mdb_metadata);
	if (meta == NULL) {
		return NULL;
	}

	meta->seqnum = 1;	    /* FIXME - or zero?? */
	meta->attributes = ldb_msg_new(meta);
	if (meta->attributes == NULL) {
		talloc_free(meta);
		return NULL;
	}

	return meta;
}

/* refactor when tested */
static int ldb_mdb_baseinfo_init(struct lmdb_private *lmdb,
			         struct lmdb_db_op *op)
{
	int ret;
	struct ldb_message *msg;
	struct ldb_context *ldb;

	ldb = lmdb->ldb;

	if (lmdb->meta == NULL) {
		lmdb->meta = ldb_mdb_meta_new(lmdb);
		if (lmdb->meta == NULL) {
			return ldb_oom(ldb);
		}
	}

	msg = update_baseinfo_msg(op, ldb, lmdb->meta->seqnum);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mdb_msg_store(lmdb->ldb, op, msg, MDB_NOOVERWRITE);
	talloc_free(msg);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	lmdb->meta->seqnum += 1;
	return LDB_SUCCESS;
}

static void schema_unload(struct ldb_context *ldb,
			  struct ldb_message *schema_msg)
{
	size_t i;

	for (i=0; i < schema_msg->num_elements; i++) {
		ldb_schema_attribute_remove(ldb,
					    schema_msg->elements[i].name);
	}

	talloc_free(schema_msg);
}

/* Unregister attribute handlers */
static void ldb_mdb_schema_unload(struct lmdb_private *lmdb)
{
	if (lmdb->meta->attributes == NULL) {
		/* no previously loaded attributes */
		return;
	}

	schema_unload(lmdb->ldb, lmdb->meta->attributes);
	lmdb->meta->attributes = NULL;
}

static int ldb_mdb_attr_sch_flags(struct ldb_message_element *el,
				  unsigned *v)
{
	size_t i;
	size_t j;
	unsigned value = 0;

	for (i=0; i < el->num_values; i++) {
		for (j=0; ldb_mdb_valid_attr_flags[j].name; j++) {
			if (strcmp(ldb_mdb_valid_attr_flags[j].name,
				   (char *)el->values[i].data) == 0) {
				value |= ldb_mdb_valid_attr_flags[j].value;
				break;
			}
		}

		if (ldb_mdb_valid_attr_flags[j].name == NULL) {
			return -1;
		}
	}

	*v = value;
	return 0;
}

static int ldb_mdb_attr_to_schema(struct ldb_context *ldb,
			          struct ldb_message_element *el)
{
	int ret;
	unsigned flags;
	const char *syntax;
	const struct ldb_schema_syntax *s;

	if (ldb_mdb_attr_sch_flags(el, &flags) != 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Invalid @ATTRIBUTES element for '%s'", el->name);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	switch (flags & ~LDB_MDB_FLAG_HIDDEN) {
	case 0:
		syntax = LDB_SYNTAX_OCTET_STRING;
		break;
	case LDB_MDB_FLAG_CASE_INSENSITIVE:
		syntax = LDB_SYNTAX_DIRECTORY_STRING;
		break;
	case LDB_MDB_FLAG_INTEGER:
		syntax = LDB_SYNTAX_INTEGER;
		break;
	default:
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Invalid flag 0x%x for '%s' in @ATTRIBUTES",
			  flags, el->name);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	s = ldb_standard_syntax_by_name(ldb, syntax);
	if (s == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Invalid attr syntax '%s' for '%s' in @ATTRIBUTES",
			  syntax, el->name);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	flags |= LDB_ATTR_FLAG_ALLOCATED;
	ret = ldb_schema_attribute_add_with_syntax(ldb, el->name, flags, s);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int ldb_mdb_schema_load(struct lmdb_private *lmdb,
			       struct lmdb_db_op *op)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	int ret;
	size_t i;
	struct ldb_message *msg;
	TALLOC_CTX *tmp_ctx = NULL;

	ldb = lmdb->ldb;

	if (ldb->schema.attribute_handler_override) {
		/* we skip loading the @ATTRIBUTES record when a module is supplying
		   its own attribute handling */
		return LDB_SUCCESS;
	}

	tmp_ctx = talloc_new(lmdb);
	if (tmp_ctx == NULL) {
		return ldb_oom(ldb);
	}

	dn = ldb_dn_new(tmp_ctx, ldb, LDB_MDB_ATTRIBUTES);
	if (dn == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_mdb_msg_get(tmp_ctx, ldb, op, dn, &msg);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		/* not finding the old record is not an error */
		ret = LDB_SUCCESS;
		goto done;
	} else if (ret != LDB_SUCCESS) {
		goto done;
	}

	/* mapping these flags onto ldap 'syntaxes' isn't strictly correct,
	 *  but it was close enough for so long it's probably OK..
	 */
	for (i=0; i < msg->num_elements; i++) {
		ret = ldb_mdb_attr_to_schema(ldb, &msg->elements[i]);
		if (ret != LDB_SUCCESS) {
			continue;
		}
	}

	ret = LDB_SUCCESS;
done:
	talloc_free(tmp_ctx);
	return ret;
}

int ldb_mdb_meta_load_op(struct lmdb_private *lmdb,
		         struct lmdb_db_op *op)
{
	unsigned dbseq;
	int ret;

	ret = ldb_mdb_seqnum_get(lmdb, op, &dbseq);
	/* Explicitly don't handle LDB_ERR_NO_SUCH_OBJECT, this
	 * error should only happen during initialization
	 */
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* a very fast check to avoid extra database reads */
	if (lmdb->meta != NULL && \
	    lmdb->meta->seqnum == dbseq) {
		return LDB_SUCCESS;
	}

	/* FIXME - what to do if seqnum is higer than dbseq? Did it just
	 * wrap? Corrupt DB? */

	ret = ldb_mdb_schema_load(lmdb, op);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/* Contrary to others, we can't rely on autotransaction here
 * FIXME - merge load and init, they always come together..
 */
int ldb_mdb_meta_connect(struct lmdb_private *lmdb)
{
	int ret;
	struct lmdb_db_op *op = NULL;
	bool in_transaction;

	in_transaction = false;
	ret = lmdb_private_trans_start(lmdb);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	in_transaction = true;

	op = ldb_mdb_op_start(lmdb);
	if (op == NULL) {
		goto done;
	}

	ret = ldb_mdb_meta_load_op(lmdb, op);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		ret = ldb_mdb_baseinfo_init(lmdb, op);
		if (ret != LDB_SUCCESS) {
			goto done;
		}
	} else if (ret != LDB_SUCCESS) {
		goto done;
	}

	ret = ldb_mdb_op_commit(lmdb, op);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	op = NULL;

	ret = lmdb_private_trans_commit(lmdb);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	in_transaction = false;

	ret = LDB_SUCCESS;
done:
	if (op != NULL) {
		ldb_mdb_op_cancel(lmdb, op);
	}

	if (in_transaction) {
		lmdb_private_trans_cancel(lmdb);
	}

	return ret;
}
