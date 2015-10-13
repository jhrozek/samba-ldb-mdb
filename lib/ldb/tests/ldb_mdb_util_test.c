/*
   tests for ldb database library using mdb back end

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

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <cmocka.h>

#include <errno.h>
#include <unistd.h>
#include <talloc.h>
#include <ldb.h>
#include <string.h>

/* The interface under test */
#include "../ldb_mdb/ldb_mdb_util.h"
#include "ldb_msg_mod.h"

struct ldb_mdb_util_test_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;
};

static struct ldb_mdb_util_test_ctx *
ldb_mdb_util_test_ctx_new(TALLOC_CTX *mem_ctx)
{
	struct ldb_mdb_util_test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct ldb_mdb_util_test_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	return test_ctx;
}

static int ldb_mdb_util_test_setup(void **state)
{
	struct ldb_mdb_util_test_ctx *test_ctx;

	test_ctx = ldb_mdb_util_test_ctx_new(NULL);
	*state = test_ctx;
	return 0;
}

static int ldb_mdb_util_test_teardown(void **state)
{
	struct ldb_mdb_util_test_ctx *test_ctx = \
		talloc_get_type_abort(*state, struct ldb_mdb_util_test_ctx);

	talloc_free(test_ctx);
	return 0;
}

static void test_ldb_mdb_dn_to_key(void **state)
{
	struct ldb_mdb_util_test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldb_mdb_util_test_ctx);
	struct ldb_dn *basedn;
	TALLOC_CTX *mem_ctx;
	struct MDB_val key;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	basedn = ldb_dn_new_fmt(mem_ctx, test_ctx->ldb, "dc=test");
	assert_non_null(basedn);

	rv = ldb_mdb_dn_to_key(mem_ctx, basedn, &key);
	assert_int_equal(rv, LDB_SUCCESS);
	assert_string_equal(key.mv_data, "DN=DC=TEST");

	ldb_mdb_key_free(&key);
	assert_null(key.mv_data);

	talloc_free(mem_ctx);
}

static struct ldb_message *test_msg_to_msg(TALLOC_CTX *mem_ctx,
					   struct ldb_context *ldb,
					   struct ldb_message *msg_in)
{
	struct ldb_message *msg_out;
	struct MDB_val value;
	int rv;

	rv = ldb_mdb_msg_to_value(mem_ctx, ldb, msg_in, &value);
	assert_int_equal(rv, LDB_SUCCESS);

	rv = ldb_mdb_value_to_msg(mem_ctx, ldb, &value, &msg_out);
	ldb_mdb_value_free(&value);
	assert_int_equal(rv, LDB_SUCCESS);

	return msg_out;
}

static void test_ldb_mdb_msg_to_value(void **state)
{
	struct ldb_mdb_util_test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct ldb_mdb_util_test_ctx);
	struct ldb_message *msg_in;
	struct ldb_message *msg_out;
	struct ldb_message_element *el;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	/* No elements first */
	msg_in = ldb_msg_new(mem_ctx);
	assert_non_null(msg_in);

	msg_in->dn = ldb_dn_new_fmt(msg_in, test_ctx->ldb, "dc=test");
	assert_non_null(msg_in->dn);

	msg_out = test_msg_to_msg(mem_ctx, test_ctx->ldb, msg_in);
	assert_non_null(msg_out);

	assert_int_equal(msg_out->num_elements, 0);
	talloc_free(msg_out);

	/* non-empty message */
	rv = ldb_msg_add_string(msg_in, "cn", "test_cn_val1");
	assert_int_equal(rv, 0);
	rv = ldb_msg_add_string(msg_in, "cn", "test_cn_val2");
	assert_int_equal(rv, 0);
	rv = ldb_msg_add_string(msg_in, "foo", "bar");
	assert_int_equal(rv, 0);

	msg_out = test_msg_to_msg(mem_ctx, test_ctx->ldb, msg_in);
	assert_non_null(msg_out);

	assert_int_equal(msg_out->num_elements, 2);

	el = ldb_msg_find_element(msg_out, "cn");
	assert_non_null(el);
	assert_int_equal(el->num_values, 2);
	assert_string_equal(el->values[0].data, "test_cn_val1");
	assert_string_equal(el->values[1].data, "test_cn_val2");

	el = ldb_msg_find_element(msg_out, "foo");
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, "bar");
	talloc_free(msg_out);

	talloc_free(mem_ctx);
}

static void single_val_test(const int afl, const int efl, const bool expected)
{
	struct ldb_message_element e;
	struct ldb_schema_attribute a;
	bool is_single;

	a.flags = afl;
	e.flags = efl;
	is_single = el_single_valued(&a, &e);
	assert_true(is_single == expected);
}

static void test_el_single_valued(void **state)
{
	bool is_single;

	single_val_test(0, 0, false);
	single_val_test(LDB_ATTR_FLAG_SINGLE_VALUE, 0, true);

	single_val_test(LDB_ATTR_FLAG_SINGLE_VALUE,
			LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK, false);
	single_val_test(0, LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK, false);

	single_val_test(LDB_ATTR_FLAG_SINGLE_VALUE,
			LDB_FLAG_INTERNAL_FORCE_SINGLE_VALUE_CHECK, true);
	single_val_test(0, LDB_FLAG_INTERNAL_FORCE_SINGLE_VALUE_CHECK, true);

	is_single = el_single_valued(NULL, NULL);
	assert_true(is_single == false);
}

static void test_el_dupval_index(void **state)
{
	struct ldb_message_element *el;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	int rv;
	long dupindex;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, 0);
	rv = ldb_msg_add_string(msg, "cn", "test_cn_val2");
	assert_int_equal(rv, 0);
	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, 0);

	rv = ldb_msg_add_string(msg, "foo", "bar");
	assert_int_equal(rv, 0);
	rv = ldb_msg_add_string(msg, "foo", "baz");
	assert_int_equal(rv, 0);

	rv = ldb_msg_add_string(msg, "spam", "eggs");
	assert_int_equal(rv, 0);

	el = ldb_msg_find_element(msg, "cn");
	dupindex = el_dupval_index(el);
	assert_int_equal(dupindex, 2);

	el = ldb_msg_find_element(msg, "foo");
	dupindex = el_dupval_index(el);
	assert_int_equal(dupindex, -1);

	el = ldb_msg_find_element(msg, "spam");
	dupindex = el_dupval_index(el);
	assert_int_equal(dupindex, -1);
}

static void test_add_element(void **state)
{
	struct ldb_message_element *el;
	struct ldb_message_element *el2;
	struct ldb_message *msg;
	struct ldb_message *msg2;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);

	msg2 = ldb_msg_new(mem_ctx);
	assert_non_null(msg2);

	el2 = ldb_msg_find_element(msg2, "cn");
	assert_null(el2);

	el = ldb_msg_find_element(msg, "cn");
	assert_non_null(el);

	rv = add_element(msg2, el);
	assert_int_equal(rv, LDB_SUCCESS);

	el2 = ldb_msg_find_element(msg2, "cn");
	assert_non_null(el2);
	assert_int_equal(el2->num_values, 1);
	assert_string_equal(el2->values[0].data, "test_cn_val1");
}

static void remove_el(struct ldb_message *msg,
		const char *name)
{
	struct ldb_message_element *el;
	int nel;
	int rv;

	nel = msg->num_elements;
	el = ldb_msg_find_element(msg, name);
	assert_non_null(el);

	rv = del_element(msg, el);
	assert_int_equal(rv, LDB_SUCCESS);
	assert_int_equal(msg->num_elements, nel - 1);

	el = ldb_msg_find_element(msg, name);
	assert_null(el);
}

static void test_del_element(void **state)
{
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg, "foo", "bar");
	assert_int_equal(rv, 0);
	assert_int_equal(msg->num_elements, 2);

	remove_el(msg, "cn");
	remove_el(msg, "foo");

	/* NULL element is an error */
	rv = del_element(msg, NULL);
	assert_int_equal(rv, LDB_ERR_OTHER);
}

static void test_extend_element(void **state)
{
	struct ldb_message_element *el;
	struct ldb_message_element *el2;
	struct ldb_message *msg;
	struct ldb_message *msg2;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	el = ldb_msg_find_element(msg, "cn");
	assert_non_null(el);

	msg2 = ldb_msg_new(mem_ctx);
	assert_non_null(msg2);

	rv = ldb_msg_add_string(msg2, "cn", "test_cn_val2");
	assert_int_equal(rv, LDB_SUCCESS);
	el2 = ldb_msg_find_element(msg2, "cn");
	assert_non_null(el2);

	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, "test_cn_val1");

	rv = extend_element(msg, el, el2);
	assert_int_equal(rv, LDB_SUCCESS);

	assert_int_equal(el->num_values, 2);
	assert_string_equal(el->values[0].data, "test_cn_val1");
	assert_string_equal(el->values[1].data, "test_cn_val2");
}

static void test_find_element(void **state)
{
	struct ldb_message_element *el;
	struct ldb_message *msg;
	struct ldb_message *msg2;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	el = ldb_msg_find_element(msg, "cn");
	assert_non_null(el);

	msg2 = ldb_msg_new(mem_ctx);
	assert_non_null(msg2);

	rv = find_element(msg2, el);
	assert_int_equal(rv, -1);

	rv = ldb_msg_add_string(msg2, "cn", "test_cn_val2");
	assert_int_equal(rv, LDB_SUCCESS);

	rv = find_element(msg2, el);
	assert_int_equal(rv, 0);
}

static void test_filter_duplicates(void **state)
{
	struct ldb_message_element *el;
	struct ldb_message_element *el2;
	struct ldb_message *msg;
	struct ldb_message *msg2;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	el = ldb_msg_find_element(msg, "cn");
	assert_non_null(el);

	msg2 = ldb_msg_new(mem_ctx);
	assert_non_null(msg2);

	rv = ldb_msg_add_string(msg2, "cn", "test_cn_val2");
	assert_int_equal(rv, LDB_SUCCESS);
	el2 = ldb_msg_find_element(msg2, "cn");
	assert_non_null(el2);

	rv = filter_duplicates(el, el2, false);
	assert_int_equal(rv, LDB_SUCCESS);

	rv = ldb_msg_add_string(msg2, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	el2 = ldb_msg_find_element(msg2, "cn");
	assert_non_null(el2);

	rv = filter_duplicates(el, el2, false);
	assert_int_equal(rv, LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS);

	assert_int_equal(el2->num_values, 2);
	rv = filter_duplicates(el, el2, true);
	assert_int_equal(rv, LDB_SUCCESS);
	assert_int_equal(el2->num_values, 1);
	assert_string_equal(el2->values[0].data, "test_cn_val2");

	rv = ldb_msg_add_string(msg, "uid", "test_uid_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg, "uid", "test_uid_val2");
	assert_int_equal(rv, LDB_SUCCESS);
	el = ldb_msg_find_element(msg, "uid");
	assert_non_null(el);

	msg2 = ldb_msg_new(mem_ctx);
	assert_non_null(msg2);

	rv = ldb_msg_add_string(msg2, "uid", "test_uid_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg2, "uid", "test_uid_val2");
	assert_int_equal(rv, LDB_SUCCESS);
	el2 = ldb_msg_find_element(msg2, "uid");
	assert_non_null(el2);

	assert_int_equal(el2->num_values, 2);
	rv = filter_duplicates(el, el2, true);
	assert_int_equal(rv, LDB_SUCCESS);
	assert_int_equal(el2->num_values, 0);
}

static void test_el_shallow_copy(void **state)
{
	struct ldb_message_element *el;
	struct ldb_message_element *copy;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg, "cn", "test_cn_val2");
	assert_int_equal(rv, LDB_SUCCESS);
	el = ldb_msg_find_element(msg, "cn");
	assert_non_null(el);

	copy = el_shallow_copy(mem_ctx, el);
	assert_non_null(copy);
	assert_int_equal(copy->flags, el->flags);
	assert_string_equal(copy->name, el->name);
	assert_int_equal(copy->num_values, el->num_values);

	assert_ptr_equal(copy->values[0].data, el->values[0].data);
	assert_ptr_equal(copy->values[1].data, el->values[1].data);
}

static void test_del_element_value(void **state)
{
	struct ldb_mdb_util_test_ctx *test_ctx \
		= talloc_get_type_abort(*state, struct ldb_mdb_util_test_ctx);
	struct ldb_message_element *el;
	struct ldb_message *msg;
	struct ldb_val *del_val;
	TALLOC_CTX *mem_ctx;
	int rv;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg, "cn", "test_cn_val2");
	assert_int_equal(rv, LDB_SUCCESS);

	del_val = talloc(mem_ctx, struct ldb_val);
	del_val->data = (uint8_t *) talloc_strdup(del_val, "test_cn_val2");
	assert_non_null(del_val->data);
	del_val->length = strlen((const char *) del_val->data);

	rv = del_element_value(test_ctx->ldb, msg, "cn", del_val);
	assert_int_equal(rv, LDB_SUCCESS);

	el = ldb_msg_find_element(msg, "cn");
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, "test_cn_val1");

	talloc_free(mem_ctx);
}

static struct ldb_message *prep_filter_msg(TALLOC_CTX *mem_ctx,
					   struct ldb_context *ldb)
{
	struct ldb_message *msg;
	int rv;

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, ldb, "dc=test");
	assert_non_null(msg->dn);

	rv = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg, "cn", "test_cn_val2");
	assert_int_equal(rv, LDB_SUCCESS);

	rv = ldb_msg_add_string(msg, "uid", "test_uid_val1");
	assert_int_equal(rv, LDB_SUCCESS);
	rv = ldb_msg_add_string(msg, "uid", "test_uid_val2");
	assert_int_equal(rv, LDB_SUCCESS);

	return msg;
}

static void assert_both_cn(struct ldb_message *msg)
{
	struct ldb_message_element *cn;

	cn = ldb_msg_find_element(msg, "cn");
	assert_non_null(cn);

	assert_int_equal(cn->num_values, 2);
	assert_string_equal(cn->values[0].data, "test_cn_val1");
	assert_string_equal(cn->values[1].data, "test_cn_val2");
}

static void assert_no_cn(struct ldb_message *msg)
{
	struct ldb_message_element *cn;

	cn = ldb_msg_find_element(msg, "cn");
	assert_null(cn);
}

static void assert_both_uid(struct ldb_message *msg)
{
	struct ldb_message_element *uid;

	uid = ldb_msg_find_element(msg, "uid");
	assert_non_null(uid);

	assert_int_equal(uid->num_values, 2);
	assert_string_equal(uid->values[0].data, "test_uid_val1");
	assert_string_equal(uid->values[1].data, "test_uid_val2");
}

static void assert_no_uid(struct ldb_message *msg)
{
	struct ldb_message_element *uid;

	uid = ldb_msg_find_element(msg, "uid");
	assert_null(uid);
}

static void assert_no_dn(struct ldb_message *msg)
{
	struct ldb_message_element *dn;

	dn = ldb_msg_find_element(msg, "distinguishedName");
	assert_null(dn);
}

static void assert_dn(struct ldb_message *msg)
{
	struct ldb_message_element *dn;

	dn = ldb_msg_find_element(msg, "distinguishedName");
	assert_non_null(dn);

	assert_int_equal(dn->num_values, 1);
	assert_string_equal(dn->values[0].data, "dc=test");
}

struct msg_filter_test_ctx {
	struct ldb_message *msg;
	struct ldb_mdb_util_test_ctx *test_ctx;
};

static int setup_msg_filter_attrs(void **state)
{
	struct msg_filter_test_ctx *msg_test_ctx;

	msg_test_ctx = talloc_zero(NULL, struct msg_filter_test_ctx);
	assert_non_null(msg_test_ctx);

	msg_test_ctx->test_ctx = ldb_mdb_util_test_ctx_new(msg_test_ctx);
	assert_non_null(msg_test_ctx->test_ctx);

	msg_test_ctx->msg = prep_filter_msg(msg_test_ctx,
			msg_test_ctx->test_ctx->ldb);
	assert_non_null(msg_test_ctx->msg);
	assert_both_cn(msg_test_ctx->msg);

	*state = msg_test_ctx;
	return 0;
}

static int teardown_msg_filter_attrs(void **state)
{
	struct msg_filter_test_ctx *msg_filter_test_ctx = \
			talloc_get_type_abort(*state,
						struct msg_filter_test_ctx);

	talloc_free(msg_filter_test_ctx);
	return 0;
}

static void test_msg_filter_attrs_null(void **state)
{
	struct msg_filter_test_ctx *msg_filter_test_ctx = \
			talloc_get_type_abort(*state,
						struct msg_filter_test_ctx);

	struct ldb_message *msg;

	msg = ldb_msg_filter_attrs(msg_filter_test_ctx->msg, NULL);
	assert_non_null(msg);
	assert_both_cn(msg);
	assert_both_uid(msg);
	assert_dn(msg);
}

static void test_msg_filter_attrs_all(void **state)
{
	struct msg_filter_test_ctx *msg_filter_test_ctx = \
			talloc_get_type_abort(*state,
						struct msg_filter_test_ctx);

	struct ldb_message *msg;
	const char *attr_all[] = { "*", NULL };

	msg = ldb_msg_filter_attrs(msg_filter_test_ctx->msg, attr_all);
	assert_non_null(msg);
	assert_both_cn(msg);
	assert_both_uid(msg);
	assert_dn(msg);
	talloc_free(msg);
}

static void test_msg_filter_attrs_cn(void **state)
{
	struct msg_filter_test_ctx *msg_filter_test_ctx = \
			talloc_get_type_abort(*state,
						struct msg_filter_test_ctx);

	struct ldb_message *msg;
	const char *attr_cn[] = { "cn", NULL };

	msg = ldb_msg_filter_attrs(msg_filter_test_ctx->msg, attr_cn);
	assert_non_null(msg);
	assert_both_cn(msg);
	assert_no_uid(msg);
	assert_no_dn(msg);
	talloc_free(msg);
}

static void test_msg_filter_attrs_cn_dn(void **state)
{
	struct msg_filter_test_ctx *msg_filter_test_ctx = \
			talloc_get_type_abort(*state,
						struct msg_filter_test_ctx);

	struct ldb_message *msg;
	const char *attr_cn_dn[] = { "cn", "distinguishedName", NULL };

	msg = ldb_msg_filter_attrs(msg_filter_test_ctx->msg, attr_cn_dn);
	assert_non_null(msg);
	assert_both_cn(msg);
	assert_no_uid(msg);
	assert_dn(msg);
	talloc_free(msg);
}

static void test_msg_filter_attrs_nomatch(void **state)
{
	struct msg_filter_test_ctx *msg_filter_test_ctx = \
			talloc_get_type_abort(*state,
						struct msg_filter_test_ctx);

	struct ldb_message *msg;
	const char *attrs_nomatch[] = { "gecos", NULL };

	msg = ldb_msg_filter_attrs(msg_filter_test_ctx->msg, attrs_nomatch);
	assert_non_null(msg);
	assert_no_cn(msg);
	assert_no_uid(msg);
	assert_no_dn(msg);
	talloc_free(msg);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_ldb_mdb_dn_to_key,
				ldb_mdb_util_test_setup,
				ldb_mdb_util_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_mdb_msg_to_value,
				ldb_mdb_util_test_setup,
				ldb_mdb_util_test_teardown),
		cmocka_unit_test(test_el_single_valued),
		cmocka_unit_test(test_el_dupval_index),
		cmocka_unit_test(test_add_element),
		cmocka_unit_test(test_del_element),
		cmocka_unit_test(test_extend_element),
		cmocka_unit_test(test_find_element),
		cmocka_unit_test_setup_teardown(test_del_element_value,
						ldb_mdb_util_test_setup,
						ldb_mdb_util_test_teardown),
		cmocka_unit_test(test_filter_duplicates),
		cmocka_unit_test(test_el_shallow_copy),
		cmocka_unit_test_setup_teardown(test_msg_filter_attrs_null,
						setup_msg_filter_attrs,
						teardown_msg_filter_attrs),
		cmocka_unit_test_setup_teardown(test_msg_filter_attrs_all,
						setup_msg_filter_attrs,
						teardown_msg_filter_attrs),
		cmocka_unit_test_setup_teardown(test_msg_filter_attrs_cn,
						setup_msg_filter_attrs,
						teardown_msg_filter_attrs),
		cmocka_unit_test_setup_teardown(test_msg_filter_attrs_cn_dn,
						setup_msg_filter_attrs,
						teardown_msg_filter_attrs),
		cmocka_unit_test_setup_teardown(test_msg_filter_attrs_nomatch,
						setup_msg_filter_attrs,
						teardown_msg_filter_attrs),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
