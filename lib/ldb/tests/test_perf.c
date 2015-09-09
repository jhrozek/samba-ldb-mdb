#include <ldb.h>
#include <talloc.h>

#ifndef LDB_BE
#error "Define LDB_BE"
#endif

int main(int argc, const char *argv[])
{
    int ret;
    unsigned int i;
    unsigned int ii;
    struct ldb_context *ldb;
    struct ldb_message *msg;
    struct ldb_dn *dn;
    struct ldb_result *res;
    const char *attrs[] = { "cn", NULL };
    const unsigned default_num_records = 1000;
    unsigned num_records = 1000;
    const char *val;
    char *uri;

    if (argc < 2) {
        num_records = default_num_records;
    } else {
        num_records = atoi(argv[1]);
    }

    ldb = ldb_init(NULL, NULL);
    if (ldb == NULL) {
        return 1;
    }

    uri = talloc_asprintf(ldb, "%s://perfdb", LDB_BE);
    if (uri == NULL) {
        return 1;
    }

    ret = ldb_connect(ldb, uri, 0, NULL);
    if (ret != LDB_SUCCESS) {
        fprintf(stderr, "ldb_connect failed\n");
        return 1;
    }

    printf("Adding %d records\n", num_records);
    for (i = 0; i < num_records; i++) {
        msg = ldb_msg_new(ldb);
        if (msg == NULL) {
            fprintf(stderr, "ldb_msg_new failed\n");
            continue;
        }

        dn = ldb_dn_new_fmt(msg, ldb, "dc=test%d", i);
        if (dn == NULL) {
            fprintf(stderr, "ldb_dn_new failed\n");
            talloc_free(msg);
            continue;
        }
        msg->dn = dn;

        for (ii = 0; ii < i+1; ii++) {
            val = talloc_asprintf(msg, "foo%d", ii);
            if (val == NULL) {
                fprintf(stderr, "talloc_asprintf failed\n");
                talloc_free(msg);
                continue;
            }

            ret = ldb_msg_add_string(msg, "cn", val);
            if (ret != LDB_SUCCESS) {
                fprintf(stderr, "ldb_msg_add_string failed\n");
                talloc_free(msg);
                continue;
            }
        }

        ret = ldb_transaction_start(ldb);
        if (ret != LDB_SUCCESS) return 1;

        ret = ldb_add(ldb, msg);
        if (ret != LDB_SUCCESS) {
            fprintf(stderr, "ldb_add failed\n");
            talloc_free(msg);
            continue;
        }

        ret = ldb_transaction_commit(ldb);
        if (ret != LDB_SUCCESS) return 1;

        talloc_free(msg);
    }
    printf("Added %d records\n", num_records);

    printf("Searching %d records\n", num_records);
    for (i = 0; i < num_records; i++) {
        dn = ldb_dn_new_fmt(ldb, ldb, "dc=test%d", i);
        if (dn == NULL) {
            fprintf(stderr, "ldb_dn_new failed\n");
            talloc_free(msg);
            continue;
        }

        ret = ldb_search(ldb, ldb, &res, dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            fprintf(stderr, "ldb_search failed\n");
            return 1;
        }

        if (res->count != 1) {
            fprintf(stderr, "No match!\n");
            return 1;
        }
    }
    printf("Searched %d records\n", num_records);

    printf("Deleting %d records\n", num_records);
    for (i = 0; i < num_records; i++) {
        dn = ldb_dn_new_fmt(ldb, ldb, "dc=test%d", i);
        if (dn == NULL) {
            fprintf(stderr, "ldb_dn_new failed\n");
            return 1;
        }

        ret = ldb_transaction_start(ldb);
        if (ret != LDB_SUCCESS) return 1;

        ret = ldb_delete(ldb, dn);
        if (ret != LDB_SUCCESS) {
            fprintf(stderr, "ldb_delete failed\n");
            return 1;
        }

        ret = ldb_transaction_commit(ldb);
        if (ret != LDB_SUCCESS) return 1;

        talloc_free(dn);
    }
    printf("Deleted %d records\n", num_records);

    return 0;
}
