/*
   Helper functions for LDB back ends built over key-value

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
#include <string.h>

#include "ldb_private.h"
#include "ldb_tev_wrap.h"

struct ldb_tv_module {
	struct ldb_module *ldb_mod;
	struct ldb_module_ops *mod_ops;

	const char *name;
	const struct ldb_tv_ops *ops;
	const char * const *supp_ctrls;
	void *kv_mod_data;
};

struct ldb_tv_req {
	struct ldb_tv_module *kv_mod;
	struct ldb_request *req;

	struct tevent_timer *timeout_event;
	bool handled;
};

static const char *ldb_tv_req_unsup_ctrl(struct ldb_tv_module *kv_mod,
					 struct ldb_request *req)
{
	unsigned i;
	unsigned ii;

	if (req->controls == NULL) {
		return NULL;
	}

	/* This is O(n**2) but normally the controls list is empty or has a
	 * single element..
	 */
	for (i = 0; req->controls[i]; i++) {
		if (req->controls[i]->critical) {
			if (kv_mod->supp_ctrls == NULL) {
				/* No ctrl supported? Just break */
				return req->controls[i]->oid;
			}

			for (ii = 0; kv_mod->supp_ctrls[ii]; ii++) {
				if (strcmp(kv_mod->supp_ctrls[ii],
					   req->controls[i]->oid) == 0) {
					/* We know this support */
					break;
				}
			}

			if (kv_mod->supp_ctrls[ii] == NULL) {
				return req->controls[i]->oid;
			}
		}
	}

	return NULL;
}

/*
 * Finishes a request with status code error. If request was already finished,
 * calling this function has no effect
 */
static void ldb_tv_request_finish(struct ldb_tv_req *lkr, int error)
{
	struct ldb_context *ldb;
	struct ldb_request *req;
	struct ldb_reply *reply;

	ldb = ldb_module_get_ctx(lkr->kv_mod->ldb_mod);
	req = lkr->req;

	/* if this request was already handled, just return */
	if (lkr->handled == true) {
		return;
	}

	/* FIXME - tdb be contains this check. Is it possible for a request
	 * to acquire status elsewhere than with finish? If yes, we need to
	 * keep this code
	 */
	if (ldb_request_get_status(req) != LDB_SUCCESS) {
		return;
	}

	reply = talloc_zero(req, struct ldb_reply);
	if (reply == NULL) {
		ldb_oom(ldb);
		req->callback(req, NULL);
		return;
	}

	reply->type = LDB_REPLY_DONE;
	reply->error = error;

	req->callback(req, reply);
}

static void ldb_tv_timeout(struct tevent_context *ev,
			   struct tevent_timer *te,
			   struct timeval t,
			   void *pvt)
{
	struct ldb_tv_req *lkr;

	lkr = talloc_get_type(pvt, struct ldb_tv_req);
	if (lkr == NULL) {
		/* Nothing much we can do, just don't crash */
		return;
	}

	ldb_tv_request_finish(lkr, LDB_ERR_TIME_LIMIT_EXCEEDED);
	talloc_free(lkr);
}

static void ldb_tv_callback(struct tevent_context *ev,
			    struct tevent_immediate *im,
			    void *pvt)
{
	struct ldb_tv_req *lkr;
	const struct ldb_tv_ops *kv_ops;
	struct ldb_tv_module *kv_mod;
	int ret;

	lkr = talloc_get_type(pvt, struct ldb_tv_req);
	if (lkr == NULL || lkr->kv_mod == NULL) {
		/* Nothing much we can do, just don't crash */
		return;
	}

	kv_mod = lkr->kv_mod;
	kv_ops = lkr->kv_mod->ops;
	if (kv_ops == NULL) {
		/* Module not initialized? */
		return;
	}

	switch (lkr->req->operation) {
	case LDB_ADD:
		ret = kv_ops->add(kv_mod, lkr->req, &(lkr->req->op.add));
		break;
	case LDB_SEARCH:
		ret = kv_ops->search(kv_mod, lkr->req, &(lkr->req->op.search));
		break;
	case LDB_DELETE:
		ret = kv_ops->del(kv_mod, lkr->req, &(lkr->req->op.del));
		break;
	case LDB_MODIFY:
		ret = kv_ops->modify(kv_mod, lkr->req, &(lkr->req->op.mod));
		break;
	case LDB_RENAME:
		ret = kv_ops->rename(kv_mod, lkr->req, &(lkr->req->op.rename));
		break;
	case LDB_EXTENDED:
		ret = kv_ops->extended(kv_mod, lkr->req, &(lkr->req->op.extended));
		break;
	default:
		ret = EINVAL;
		break;
	}
	ldb_tv_request_finish(lkr, ret);
	talloc_free(lkr);
}

static int ldb_tv_handle_request(struct ldb_module *ldb_mod,
				 struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct tevent_context *ev;
	struct ldb_tv_req *lkr;
	struct ldb_tv_module *kv_mod;
	struct tevent_immediate *imm;
	struct timeval tv;
	const char *unsup_ctrl;

	ldb = ldb_module_get_ctx(ldb_mod);
	ev = ldb_get_event_context(ldb);
	kv_mod = ldb_module_get_private(ldb_mod);
	if (ldb == NULL || ev == NULL || kv_mod == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	unsup_ctrl = ldb_tv_req_unsup_ctrl(kv_mod, req);
	if (unsup_ctrl != NULL) {
		ldb_asprintf_errstring(ldb, "Unsupported critical extension %s",
				       unsup_ctrl);
		return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}

	if (req->starttime == 0 || req->timeout == 0) {
		ldb_set_errstring(ldb, "Invalid timeout settings");
		return LDB_ERR_TIME_LIMIT_EXCEEDED;
	}

	lkr = talloc_zero(req, struct ldb_tv_req);
	if (lkr == NULL) {
		return ldb_oom(ldb);
	}
	lkr->kv_mod = kv_mod;
	lkr->req = req;

	imm = tevent_create_immediate(lkr);
	if (imm == NULL) {
		talloc_free(lkr);
		return ldb_oom(ldb);
	}
	tevent_schedule_immediate(imm, ev, ldb_tv_callback, lkr);

	tv.tv_sec = req->starttime + req->timeout;
	tv.tv_usec = 0;
	lkr->timeout_event = tevent_add_timer(ev, lkr, tv, ldb_tv_timeout, lkr);
	if (lkr->timeout_event == NULL) {
		talloc_free(lkr);
		return ldb_oom(ldb);
	}

	return LDB_SUCCESS;
}

static int ldb_tv_start_trans(struct ldb_module *module)
{
	struct ldb_tv_module *kv_mod;

	kv_mod = ldb_module_get_private(module);
	if (kv_mod == NULL) {
		return EINVAL;
	}

	return kv_mod->ops->start_transaction(kv_mod);
}

static int ldb_tv_end_trans(struct ldb_module *module)
{
	struct ldb_tv_module *kv_mod;

	kv_mod = ldb_module_get_private(module);
	if (kv_mod == NULL) {
		return EINVAL;
	}

	return kv_mod->ops->end_transaction(kv_mod);
}

static int ldb_tv_prepare_commit(struct ldb_module *module)
{
	struct ldb_tv_module *kv_mod;

	kv_mod = ldb_module_get_private(module);
	if (kv_mod == NULL) {
		return EINVAL;
	}

	return kv_mod->ops->prepare_transaction(kv_mod);
}

static int ldb_tv_del_trans(struct ldb_module *module)
{
	struct ldb_tv_module *kv_mod;

	kv_mod = ldb_module_get_private(module);
	if (kv_mod == NULL) {
		return EINVAL;
	}

	return kv_mod->ops->del_transaction(kv_mod);
}

static struct ldb_module_ops kv_ops = {
	.search            = ldb_tv_handle_request,
	.add               = ldb_tv_handle_request,
	.del               = ldb_tv_handle_request,
	.modify            = ldb_tv_handle_request,
	.rename            = ldb_tv_handle_request,

	/* FIXME Is there actually a reason to treat the transactions
	 * differently rather than reusing ldb_tv_handle_request()? */
	.start_transaction = ldb_tv_start_trans,
	.end_transaction   = ldb_tv_end_trans,
	.prepare_commit    = ldb_tv_prepare_commit,
	.del_transaction   = ldb_tv_del_trans,
};

int ldb_tv_register(TALLOC_CTX *mem_ctx,
			      struct ldb_context *ldb,
			      const char *name,
			      const char *supp_ctrls[],
			      const struct ldb_tv_ops *ops,
			      void *kv_mod_data,
			      struct ldb_tv_module **_kv_mod)
{
	struct ldb_tv_module *kv_mod;

	kv_mod = talloc_zero(mem_ctx, struct ldb_tv_module);
	if (kv_mod == NULL) {
		return ldb_oom(ldb);
	}

	kv_mod->mod_ops = &kv_ops;
	kv_mod->name = name;
	kv_mod->mod_ops->name = name;
	kv_mod->supp_ctrls = supp_ctrls;

	kv_mod->ldb_mod = ldb_module_new(ldb,
					 ldb,
					 kv_mod->name,
					 kv_mod->mod_ops);
	if (kv_mod->ldb_mod == NULL) {
		talloc_free(kv_mod);
		return ldb_oom(ldb);
	}
	ldb_module_set_private(kv_mod->ldb_mod, kv_mod);
	talloc_steal(kv_mod->ldb_mod, kv_mod);

	kv_mod->ops = ops;
	kv_mod->kv_mod_data = kv_mod_data;
	*_kv_mod = kv_mod;
	return LDB_SUCCESS;
}

struct ldb_module *ldb_tv_get_ldb_module(struct ldb_tv_module *kv_mod)
{
	return kv_mod->ldb_mod;
}

/* FIXME - make type-safe with talloc? */
void *ldb_tv_get_mod_data(struct ldb_tv_module *kv_mod)
{
	return kv_mod->kv_mod_data;
}

struct ldb_context *ldb_tv_get_ldb_ctx(struct ldb_tv_module *kv_mod)
{
	struct ldb_module *ldb_mod;

	ldb_mod = ldb_tv_get_ldb_module(kv_mod);
	return ldb_mod->ldb;
}
