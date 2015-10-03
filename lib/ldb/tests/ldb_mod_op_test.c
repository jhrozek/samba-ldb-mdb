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

#define DEFAULT_BE  "mdb"

#ifndef TEST_BE
#define TEST_BE DEFAULT_BE
#endif /* TEST_BE */

struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;

	const char *dbfile;
	const char *lockfile;   /* lockfile is separate */

	const char *dbpath;
};

static void unlink_old_db(struct ldbtest_ctx *test_ctx)
{
	int ret;

	errno = 0;
	ret = unlink(test_ctx->lockfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}

	errno = 0;
	ret = unlink(test_ctx->dbfile);
	if (ret == -1 && errno != ENOENT) {
		fail();
	}
}

static int ldbtest_noconn_setup(void **state)
{
	struct ldbtest_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct ldbtest_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	test_ctx->dbfile = talloc_strdup(test_ctx, "apitest.ldb");
	assert_non_null(test_ctx->dbfile);

	test_ctx->lockfile = talloc_asprintf(test_ctx, "%s-lock",
					     test_ctx->dbfile);
	assert_non_null(test_ctx->lockfile);

	test_ctx->dbpath = talloc_asprintf(test_ctx,
			TEST_BE"://%s", test_ctx->dbfile);
	assert_non_null(test_ctx->dbpath);

	unlink_old_db(test_ctx);
	*state = test_ctx;
	return 0;
}

static int ldbtest_noconn_teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);

	unlink_old_db(test_ctx);
	talloc_free(test_ctx);
	return 0;
}

static void test_connect(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	int ret;

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);
}

static int ldbtest_setup(void **state)
{
	struct ldbtest_ctx *test_ctx;
	int ret;

	ldbtest_noconn_setup((void **) &test_ctx);

	ret = ldb_connect(test_ctx->ldb, test_ctx->dbpath, 0, NULL);
	assert_int_equal(ret, 0);

	*state = test_ctx;
	return 0;
}

static int ldbtest_teardown(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	ldbtest_noconn_teardown((void **) &test_ctx);
	return 0;
}

static void test_ldb_add(void **state)
{
	int ret;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "dc=test");
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	talloc_free(tmp_ctx);
}

static void test_ldb_search(void **state)
{
	int ret;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *basedn;
	struct ldb_dn *basedn2;
	struct ldb_result *result = NULL;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	basedn = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "dc=test");
	assert_non_null(basedn);

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(result);
	assert_int_equal(result->count, 0);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = basedn;
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val1");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	basedn2 = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "dc=test2");
	assert_non_null(basedn2);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = basedn2;
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_cn_val2");
	assert_int_equal(ret, 0);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, 0);

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	assert_string_equal(ldb_dn_get_linearized(result->msgs[0]->dn),
			    ldb_dn_get_linearized(basedn));

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn2,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, 0);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	assert_string_equal(ldb_dn_get_linearized(result->msgs[0]->dn),
			    ldb_dn_get_linearized(basedn2));

	talloc_free(tmp_ctx);
}

static int base_search_count(struct ldbtest_ctx *test_ctx, const char *entry_dn)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *basedn;
	struct ldb_result *result = NULL;
	int ret;
	int count;

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	basedn = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "%s", entry_dn);
	assert_non_null(basedn);

	ret = ldb_search(test_ctx->ldb, tmp_ctx, &result, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);

	count = result->count;
	talloc_free(tmp_ctx);
	return count;
}

static void assert_dn_exists(struct ldbtest_ctx *test_ctx,
			     const char *entry_dn)
{
	int count;

	count = base_search_count(test_ctx, entry_dn);
	assert_int_equal(count, 1);
}

static void assert_dn_doesnt_exist(struct ldbtest_ctx *test_ctx,
				   const char *entry_dn)
{
	int count;

	count = base_search_count(test_ctx, entry_dn);
	assert_int_equal(count, 0);
}

static void test_ldb_del(void **state)
{
	int ret;
	struct ldb_message *msg;
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							struct ldbtest_ctx);
	TALLOC_CTX *tmp_ctx;
	const char *basedn = "dc=ldb_del_test";

	tmp_ctx = talloc_new(test_ctx);
	assert_non_null(tmp_ctx);

	assert_dn_doesnt_exist(test_ctx, basedn);

	msg = ldb_msg_new(tmp_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(tmp_ctx, test_ctx->ldb, "%s", basedn);
	assert_non_null(msg->dn);

	ret = ldb_msg_add_string(msg, "cn", "test_del_cn_val");
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_add(test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_dn_exists(test_ctx, basedn);

	ret = ldb_delete(test_ctx->ldb, msg->dn);
	assert_int_equal(ret, LDB_SUCCESS);

	assert_dn_doesnt_exist(test_ctx, basedn);

	talloc_free(tmp_ctx);
}

static void test_ldb_del_noexist(void **state)
{
	struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
							     struct ldbtest_ctx);
	struct ldb_dn *basedn;
	int ret;

	basedn = ldb_dn_new(test_ctx, test_ctx->ldb, "dc=nosuchplace");
	assert_non_null(basedn);

	ret = ldb_delete(test_ctx->ldb, basedn);
	assert_int_equal(ret, LDB_ERR_NO_SUCH_OBJECT);
}

static void add_keyval(struct ldbtest_ctx *test_ctx,
		       const char *key,
		       const char *val)
{
    int ret;
    struct ldb_message *msg;

    msg = ldb_msg_new(test_ctx);
    assert_non_null(msg);

    msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "%s=%s", key, val);
    assert_non_null(msg->dn);

    ret = ldb_msg_add_string(msg, key, val);
    assert_int_equal(ret, 0);

    ret = ldb_add(test_ctx->ldb, msg);
    assert_int_equal(ret, 0);

    talloc_free(msg);
}

static struct ldb_result *get_keyval(struct ldbtest_ctx *test_ctx,
				     const char *key,
				     const char *val)
{
    int ret;
    struct ldb_result *result;
    struct ldb_dn *basedn;

    basedn = ldb_dn_new_fmt(test_ctx, test_ctx->ldb, "%s=%s", key, val);
    assert_non_null(basedn);

    ret = ldb_search(test_ctx->ldb, test_ctx, &result, basedn,
                     LDB_SCOPE_BASE, NULL, NULL);
    assert_int_equal(ret, 0);

    return result;
}

static void test_transactions(void **state)
{
    int ret;
    struct ldbtest_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct ldbtest_ctx);
    struct ldb_result *res;

    /* start lev-0 transaction */
    ret = ldb_transaction_start(test_ctx->ldb);
    assert_int_equal(ret, 0);

    add_keyval(test_ctx, "vegetable", "carrot");

    /* commit lev-0 transaction */
    ret = ldb_transaction_commit(test_ctx->ldb);
    assert_int_equal(ret, 0);

    /* start another lev-1 nested transaction */
    ret = ldb_transaction_start(test_ctx->ldb);
    assert_int_equal(ret, 0);

    add_keyval(test_ctx, "fruit", "apple");

    /* abort lev-1 nested transaction */
    ret = ldb_transaction_cancel(test_ctx->ldb);
    assert_int_equal(ret, 0);

    res = get_keyval(test_ctx, "vegetable", "carrot");
    assert_non_null(res);
    assert_int_equal(res->count, 1);

    res = get_keyval(test_ctx, "fruit", "apple");
    assert_non_null(res);
    assert_int_equal(res->count, 0);
}

struct ldb_mod_test_ctx {
	struct ldbtest_ctx *ldb_test_ctx;
	const char *entry_dn;
};

struct keyval {
	const char *key;
	const char *val;
};

static struct ldb_message *build_mod_msg(TALLOC_CTX *mem_ctx,
					 struct ldbtest_ctx *test_ctx,
					 const char *dn,
					 int modify_flags,
					 struct keyval *kvs)
{
	struct ldb_message *msg;
	int ret;
	int i;

	msg = ldb_msg_new(mem_ctx);
	assert_non_null(msg);

	msg->dn = ldb_dn_new_fmt(msg, test_ctx->ldb, "%s", dn);
	assert_non_null(msg->dn);

	for (i = 0; kvs[i].key != NULL; i++) {
		if (modify_flags) {
			ret = ldb_msg_add_empty(msg, kvs[i].key,
						modify_flags, NULL);
			assert_int_equal(ret, 0);
		}

		if (kvs[i].val) {
			ret = ldb_msg_add_string(msg, kvs[i].key, kvs[i].val);
			assert_int_equal(ret, LDB_SUCCESS);
		}
	}

	return msg;
}

static void mod_test_add_data(struct ldb_mod_test_ctx *mod_test_ctx,
			      struct keyval *kvs)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_message *msg;
	struct ldb_result *result = NULL;
	struct ldbtest_ctx *ldb_test_ctx;
	int ret;

	ldb_test_ctx = mod_test_ctx->ldb_test_ctx;

	tmp_ctx = talloc_new(mod_test_ctx);
	assert_non_null(tmp_ctx);

	msg = build_mod_msg(tmp_ctx, ldb_test_ctx,
			    mod_test_ctx->entry_dn, 0, kvs);
	assert_non_null(msg);

	ret = ldb_add(ldb_test_ctx->ldb, msg);
	assert_int_equal(ret, LDB_SUCCESS);

	ret = ldb_search(ldb_test_ctx->ldb, tmp_ctx, &result, msg->dn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 1);
	assert_string_equal(ldb_dn_get_linearized(result->msgs[0]->dn),
			    ldb_dn_get_linearized(msg->dn));

	talloc_free(tmp_ctx);
}

static void mod_test_remove_data(struct ldb_mod_test_ctx *mod_test_ctx)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *basedn;
	struct ldb_result *result = NULL;
	int ret;
	struct ldbtest_ctx *ldb_test_ctx;

	ldb_test_ctx = mod_test_ctx->ldb_test_ctx;

	tmp_ctx = talloc_new(mod_test_ctx);
	assert_non_null(tmp_ctx);

	basedn = ldb_dn_new_fmt(tmp_ctx, ldb_test_ctx->ldb,
				"%s", mod_test_ctx->entry_dn);
	assert_non_null(basedn);

	ret = ldb_delete(ldb_test_ctx->ldb, basedn);
	assert_true(ret == LDB_SUCCESS || ret == LDB_ERR_NO_SUCH_OBJECT);

	ret = ldb_search(ldb_test_ctx->ldb, tmp_ctx, &result, basedn,
			LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(result);
	assert_int_equal(result->count, 0);

	talloc_free(tmp_ctx);
}

static struct ldb_result *run_mod_test(struct ldb_mod_test_ctx *mod_test_ctx,
				       int modify_flags,
				       struct keyval *kvs)
{
	TALLOC_CTX *tmp_ctx;
	struct ldb_result *res;
	struct ldb_message *mod_msg;
	struct ldb_dn *basedn;
	struct ldbtest_ctx *ldb_test_ctx;
	int ret;

	ldb_test_ctx = mod_test_ctx->ldb_test_ctx;

	tmp_ctx = talloc_new(mod_test_ctx);
	assert_non_null(tmp_ctx);

	mod_msg = build_mod_msg(tmp_ctx, ldb_test_ctx, mod_test_ctx->entry_dn,
				modify_flags, kvs);
	assert_non_null(mod_msg);

	ret = ldb_modify(ldb_test_ctx->ldb, mod_msg);
	assert_int_equal(ret, LDB_SUCCESS);

	basedn = ldb_dn_new_fmt(tmp_ctx, ldb_test_ctx->ldb,
			"%s", mod_test_ctx->entry_dn);
	assert_non_null(basedn);

	ret = ldb_search(ldb_test_ctx->ldb, mod_test_ctx, &res, basedn,
			 LDB_SCOPE_BASE, NULL, NULL);
	assert_int_equal(ret, LDB_SUCCESS);
	assert_non_null(res);
	assert_int_equal(res->count, 1);
	assert_string_equal(ldb_dn_get_linearized(res->msgs[0]->dn),
			    ldb_dn_get_linearized(mod_msg->dn));

	talloc_free(tmp_ctx);
	return res;
}

static int ldb_modify_test_setup(void **state)
{
	struct ldbtest_ctx *ldb_test_ctx;
	struct ldb_mod_test_ctx *mod_test_ctx;
	struct keyval kvs[] = {
		{ "cn", "test_mod_cn" },
		{ NULL, NULL },
	};

	ldbtest_setup((void **) &ldb_test_ctx);

	mod_test_ctx = talloc(ldb_test_ctx, struct ldb_mod_test_ctx);
	assert_non_null(mod_test_ctx);

	mod_test_ctx->entry_dn = "dc=mod_test_entry";
	mod_test_ctx->ldb_test_ctx = ldb_test_ctx;

	mod_test_remove_data(mod_test_ctx);
	mod_test_add_data(mod_test_ctx, kvs);
	*state = mod_test_ctx;
	return 0;
}

static int ldb_modify_test_teardown(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
				talloc_get_type_abort(*state,
						      struct ldb_mod_test_ctx);
	struct ldbtest_ctx *ldb_test_ctx;

	ldb_test_ctx = mod_test_ctx->ldb_test_ctx;

	mod_test_remove_data(mod_test_ctx);
	talloc_free(mod_test_ctx);

	ldbtest_teardown((void **) &ldb_test_ctx);
	return 0;
}

static void test_ldb_modify_add_key(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
				talloc_get_type_abort(*state,
						      struct ldb_mod_test_ctx);
	struct keyval mod_kvs[] = {
		{ "name", "test_mod_name" },
		{ NULL, NULL },
	};
	struct ldb_result *res;
	struct ldb_message_element *el;

	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_ADD, mod_kvs);
	assert_non_null(res);

	/* Check cn is intact and name was added */
	assert_int_equal(res->count, 1);
	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, "test_mod_cn");

	el = ldb_msg_find_element(res->msgs[0], "name");
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, "test_mod_name");
}

static void test_ldb_modify_extend_key(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct keyval mod_kvs[] = {
		{ "cn", "test_mod_cn2" },
		{ NULL, NULL },
	};
	struct ldb_result *res;
	struct ldb_message_element *el;

	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_ADD, mod_kvs);
	assert_non_null(res);

	/* Check cn was extended with another value */
	assert_int_equal(res->count, 1);
	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_non_null(el);
	assert_int_equal(el->num_values, 2);
	assert_string_equal(el->values[0].data, "test_mod_cn");
	assert_string_equal(el->values[1].data, "test_mod_cn2");
}

static void test_ldb_modify_add_key_noval(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct ldb_message *mod_msg;
	struct ldbtest_ctx *ldb_test_ctx;
	struct ldb_message_element *el;
	int ret;

	ldb_test_ctx = mod_test_ctx->ldb_test_ctx;

	mod_msg = ldb_msg_new(mod_test_ctx);
	assert_non_null(mod_msg);

	mod_msg->dn = ldb_dn_new_fmt(mod_msg, ldb_test_ctx->ldb,
			"%s", mod_test_ctx->entry_dn);
	assert_non_null(mod_msg->dn);

	el = talloc_zero(mod_msg, struct ldb_message_element);
	el->flags = LDB_FLAG_MOD_ADD;
	assert_non_null(el);
	el->name = talloc_strdup(el, "cn");
	assert_non_null(el->name);

	mod_msg->elements = el;
	mod_msg->num_elements = 1;

	ret = ldb_modify(ldb_test_ctx->ldb, mod_msg);
	assert_int_equal(ret, LDB_ERR_CONSTRAINT_VIOLATION);
}

static void test_ldb_modify_replace_key(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	const char *new_cn = "new_cn";
	struct keyval mod_kvs[] = {
		{ "cn", new_cn },
		{ NULL, NULL },
	};
	struct ldb_result *res;
	struct ldb_message_element *el;

	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_REPLACE, mod_kvs);
	assert_non_null(res);

	/* Check cn was replaced */
	assert_int_equal(res->count, 1);
	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, new_cn);
}

static void test_ldb_modify_replace_noexist_key(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct keyval mod_kvs[] = {
		{ "name", "name_val" },
		{ NULL, NULL },
	};
	struct ldb_result *res;
	struct ldb_message_element *el;

	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_REPLACE, mod_kvs);
	assert_non_null(res);

	/* Check cn is intact and name was added */
	assert_int_equal(res->count, 1);
	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, "test_mod_cn");

	el = ldb_msg_find_element(res->msgs[0], mod_kvs[0].key);
	assert_non_null(el);
	assert_int_equal(el->num_values, 1);
	assert_string_equal(el->values[0].data, mod_kvs[0].val);
}

static void test_ldb_modify_replace_zero_vals(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct ldb_message_element *el;
	struct ldb_result *res;
	struct keyval kvs[] = {
		{ "cn", NULL },
		{ NULL, NULL },
	};

	/* cn must be gone */
	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_REPLACE, kvs);
	assert_non_null(res);
	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_null(el);
}

static void test_ldb_modify_replace_noexist_key_zero_vals(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct ldb_message_element *el;
	struct ldb_result *res;
	struct keyval kvs[] = {
		{ "noexist_key", NULL },
		{ NULL, NULL },
	};

	/* cn must be gone */
	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_REPLACE, kvs);
	assert_non_null(res);

	/* cn should be intact */
	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_non_null(el);
}

static void test_ldb_modify_del_key(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct ldb_message_element *el;
	struct ldb_result *res;
	struct keyval kvs[] = {
		{ "cn", NULL },
		{ NULL, NULL },
	};

	/* cn must be gone */
	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_DELETE, kvs);
	assert_non_null(res);

	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_null(el);
}

static void test_ldb_modify_del_keyval(void **state)
{
	struct ldb_mod_test_ctx *mod_test_ctx = \
			talloc_get_type_abort(*state,
					      struct ldb_mod_test_ctx);
	struct ldb_message_element *el;
	struct ldb_result *res;
	struct keyval kvs[] = {
		{ "cn", "test_mod_cn" },
		{ NULL, NULL },
	};

	/* cn must be gone */
	res = run_mod_test(mod_test_ctx, LDB_FLAG_MOD_DELETE, kvs);
	assert_non_null(res);

	el = ldb_msg_find_element(res->msgs[0], "cn");
	assert_null(el);
}

struct search_test_ctx {
	struct ldbtest_ctx *ldb_test_ctx;
	struct ldb_message *msg;
};

# if 0
static void ldb_search_test_setup(void **state)
{
	struct ldbtest_ctx *ldb_test_ctx;
	struct search_test_ctx *search_test_ctx;

	ldbtest_setup((void **) &ldb_test_ctx);

	search_test_ctx = talloc(ldb_test_ctx, struct search_test_ctx);
	assert_non_null(search_test_ctx);

	*state = search_test_ctx;
}

static void ldb_search_test_teardown(void **state)
{
	struct search_test_ctx *search_test_ctx = talloc_get_type_abort(*state,
			struct search_test_ctx);
	struct ldbtest_ctx *ldb_test_ctx;

	ldb_test_ctx = search_test_ctx->ldb_test_ctx;

	ldbtest_teardown((void **) &ldb_test_ctx);
}

static void ldb_search_test_attr_all(void **state)
{
}
#endif

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_connect,
						ldbtest_noconn_setup,
						ldbtest_noconn_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_add,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_search,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_del,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_del_noexist,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_transactions,
						ldbtest_setup,
						ldbtest_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_add_key,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_extend_key,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_add_key_noval,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_replace_key,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_replace_noexist_key,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_replace_zero_vals,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_replace_noexist_key_zero_vals,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_del_key,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
		cmocka_unit_test_setup_teardown(test_ldb_modify_del_keyval,
						ldb_modify_test_setup,
						ldb_modify_test_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
