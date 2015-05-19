/*
   Common functionality for message modification

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

#include "ldb_msg_mod.h"
#include "ldb_private.h"

#define DISTINGUISHED_NAME "distinguishedName"

bool el_single_valued(const struct ldb_schema_attribute *a,
			  struct ldb_message_element *el)
{
	if (!a) {
		return false;
	}

	if (el != NULL) {
		if (el->flags & LDB_FLAG_INTERNAL_FORCE_SINGLE_VALUE_CHECK) {
			/* override from a ldb module, for example
			 * used for the description field, which is
			 * marked multi-valued in the schema but which
			 * should not actually accept multiple
			 * values */
			return true;
		}
		if (el->flags & LDB_FLAG_INTERNAL_DISABLE_SINGLE_VALUE_CHECK) {
			/* override from a ldb module, for example used for
			 * deleted linked attribute entries */
			return false;
		}
	}

	if (a->flags & LDB_ATTR_FLAG_SINGLE_VALUE) {
		return true;
	}
	return false;
}

long el_dupval_index(struct ldb_message_element *el)
{
	size_t j;

	for (j=0; j<el->num_values; j++) {
		if (ldb_msg_find_val(el, &el->values[j]) != &el->values[j]) {
			return j;
		}
	}

	return -1;
}

int add_element(struct ldb_message *msg,
		struct ldb_message_element *el)
{
#if 0
	/* FIXME - we should just use ldb_msg_add() here and also in tdb */
	return ldb_msg_add(msg, el, el->flags);
#endif

	struct ldb_message_element *new_el;
	unsigned int i;

	if (el->num_values == 0) {
		/* nothing to do here - we don't add empty elements */
		return 0;
	}

	new_el = talloc_realloc(msg, msg->elements,
				struct ldb_message_element,
				msg->num_elements+1);
	if (new_el == NULL) {
		return ENOMEM;
	}

	msg->elements = new_el;

	new_el = &msg->elements[msg->num_elements];

	new_el->name = el->name;
	new_el->flags = el->flags;
	new_el->values = talloc_array(msg->elements,
				      struct ldb_val,
				      el->num_values);
	if (new_el->values == NULL) {
		return ENOMEM;
	}

	for (i=0;i<el->num_values;i++) {
		new_el->values[i] = el->values[i];
	}
	new_el->num_values = el->num_values;

	msg->num_elements++;
	return 0;
}

/* The element must be guaranteed to be in the message! */
int del_element(struct ldb_message *msg,
		struct ldb_message_element *el)
{
#if 0
	return ldb_msg_remove_element(struct ldb_message *msg, struct ldb_message_element *el)
#endif

	unsigned int i;

	if (el == NULL) {
		return LDB_ERR_OTHER;
	}

	i = el - msg->elements;
	talloc_free(el->values);

	if (msg->num_elements > (i+1)) {
		memmove(el, el+1, sizeof(*el) * (msg->num_elements - (i+1)));
	}
	msg->num_elements--;

	msg->elements = talloc_realloc(msg, msg->elements,
				       struct ldb_message_element,
				       msg->num_elements);
	/* Not checking the retval on purpose so that we can remove the last
	 * attribute */
	return LDB_SUCCESS;
}

static bool matches_by_schema(struct ldb_context *ldb,
			      const char *name,
			      const struct ldb_val *val,
			      const struct ldb_val *del_val)
{
	bool matched;
	const struct ldb_schema_attribute *sch_attr;
	int ret;

	sch_attr = ldb_schema_attribute_by_name(ldb, name);
	if (sch_attr->syntax->operator_fn) {
		ret = sch_attr->syntax->operator_fn(ldb, LDB_OP_EQUALITY,
						    sch_attr, val, del_val,
						    &matched);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	} else {
		ret = sch_attr->syntax->comparison_fn(ldb, ldb, val, del_val);
		matched = (ret == 0);
	}

	return matched;
}

static int del_matched_value(struct ldb_message *msg,
			     struct ldb_message_element *el,
			     unsigned int idx)
{
	if (el->num_values == 1) {
		return del_element(msg, el);
	}

	if (idx < el->num_values - 1) {
		memmove(&el->values[idx],
			&el->values[idx+1],
			sizeof(el->values[idx]) * (el->num_values-(idx + 1)));
	}

	el->num_values--;
	return LDB_SUCCESS;
}

int del_element_value(struct ldb_context *ldb,
		      struct ldb_message *msg,
		      const char *name,
		      const struct ldb_val *del_val)
{
	int idx;
	struct ldb_message_element *el;
	unsigned int i;
	bool match;

	idx = find_element_by_name(msg, name);
	if (idx == -1) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	el = &(msg->elements[idx]);
	for (i = 0; i < el->num_values; i++) {
		match = matches_by_schema(ldb, el->name,
					  &el->values[i], del_val);
		if (match == false) {
			continue;
		}

		return del_matched_value(msg, el, i);
	}

	return LDB_ERR_NO_SUCH_ATTRIBUTE;
}

/* Extend values of element orig which belongs to ldb_message msg
 * with values of element add_el.
 *
 * Returns LDB_SUCCESS on success, an error code otherwise.
 */
int extend_element(struct ldb_message *msg,
		   struct ldb_message_element *orig,
		   struct ldb_message_element *add_el)
{
	struct ldb_val *vals;
	size_t j;

	vals = talloc_realloc(msg->elements, orig->values, struct ldb_val,
			      orig->num_values + add_el->num_values);
	if (vals == NULL) {
		return ENOMEM;
	}

	for (j=0; j < add_el->num_values; j++) {
		vals[orig->num_values + j] =
			ldb_val_dup(vals, &add_el->values[j]);
	}

	orig->values = vals;
	orig->num_values += add_el->num_values;
	return LDB_SUCCESS;
}

/* Return index at which  contains element named name. If msg does not
 * contain element called name, return -1
 */
int find_element_by_name(struct ldb_message *msg,
		         const char *name)
{
	unsigned int i;

	for (i=0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(msg->elements[i].name, name) == 0) {
			return i;
		}
	}

	return -1;
}

/* Return index at which msg contains el. If msg does not
 * contain el, return -1
 */
int find_element(struct ldb_message *msg,
		 struct ldb_message_element *el)
{
	return find_element_by_name(msg, el->name);
}

/* Checks if needle is present in haystack. If yes and permissive is set to
 * true, then the duplicates are filtered out. If permissive is set to false,
 * an error is returned
 */
int filter_duplicates(struct ldb_message_element *haystack,
		      struct ldb_message_element *needle,
		      bool permissive)
{
	unsigned i, j;
	struct ldb_val *val;

	for (i = 0; i < needle->num_values; i++) {
		val = ldb_msg_find_val(haystack, &(needle->values[i]));
		if (val == NULL) {
			continue;
		}

		if (permissive == false) {
			return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
		}

		needle->num_values--;
		for (j = i; j < needle->num_values; j++) {
			needle->values[j] = needle->values[j + 1];
		}
		i--; /* rewind */
	}

	return LDB_SUCCESS;
}

struct ldb_message_element *
el_shallow_copy(TALLOC_CTX *mem_ctx,
		const struct ldb_message_element *el)
{
	struct ldb_message_element *copy = NULL;
	unsigned i;

	copy = talloc(mem_ctx, struct ldb_message_element);
	if (copy == NULL) {
		return NULL;
	}

	copy->flags = el->flags;
	copy->name = el->name;
	copy->num_values = el->num_values;

	copy->values = talloc_array(copy, struct ldb_val, copy->num_values);
	if (copy->values == NULL) {
		talloc_free(copy);
		return NULL;
	}

	for (i = 0; i < el->num_values; i++) {
		copy->values[i] = el->values[i];
	}

	return copy;
}

static int mod_el_extend(struct ldb_context *ldb,
			 struct ldb_message *db_msg,
			 const struct ldb_schema_attribute *sch_attr,
			 struct ldb_message_element *el,
			 int db_idx)
{
	struct ldb_message_element *db_el;
	int ret;
	long dup_idx;

	db_el = &(db_msg->elements[db_idx]);

	/* We cannot add another value on a existing one
	   if the attribute is single-valued */
	if (el_single_valued(sch_attr, el)) {
		ldb_asprintf_errstring(ldb,
				       "SINGLE-VALUE attribute %s on %s "
				       "specified more than once",
				       el->name,
				       ldb_dn_get_linearized(db_msg->dn));
		return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
	}

	ret = filter_duplicates(db_el, el, false);
	if (ret != LDB_SUCCESS) {
		return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
	}

	dup_idx = el_dupval_index(el);
	if (dup_idx != -1) {
		ldb_asprintf_errstring(ldb,
				       "attribute '%s': value %ld on '%s' "
				       "provided more than once",
				       el->name, dup_idx,
				       ldb_dn_get_linearized(db_msg->dn));
		return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
	}

	/* Add the element el to db_msg */
	ret = extend_element(db_msg, db_el, el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int mod_el_add(struct ldb_context *ldb,
		      struct ldb_message *db_msg,
		      struct ldb_message_element *el)
{
	int idx;
	const struct ldb_schema_attribute *sch_attr;

	if (el->num_values == 0) {
		ldb_asprintf_errstring(ldb,
				       "attribute %s on %s "
				       "specified with zero values",
				       el->name,
				       ldb_dn_get_linearized(db_msg->dn));
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	sch_attr = ldb_schema_attribute_by_name(ldb, el->name);
	if (el->num_values > 1 && el_single_valued(sch_attr, el)) {
		ldb_asprintf_errstring(ldb,
				       "SINGLE-VALUE attribute %s on %s "
				       "specified more than once",
				       el->name,
				       ldb_dn_get_linearized(db_msg->dn));
		return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
	}

	idx = find_element(db_msg, el);
	if (idx == -1) {
		/* Element didn't exist, add it */
		return add_element(db_msg, el);
	} else {
		return mod_el_extend(ldb, db_msg, sch_attr, el, idx);
	}
}

static int mod_el_rep(struct ldb_context *ldb,
		struct ldb_message *db_msg,
		struct ldb_message_element *el)
{
	bool strict_equal;
	long idx;
	struct ldb_message_element *db_el;
	const struct ldb_schema_attribute *sch_attr;
	int ret;

	sch_attr = ldb_schema_attribute_by_name(ldb, el->name);

	if (el->num_values > 1 && el_single_valued(sch_attr, el)) {
		ldb_asprintf_errstring(ldb,
				       "SINGLE-VALUE attribute %s on %s "
				       "specified more than once",
				       el->name,
				       ldb_dn_get_linearized(db_msg->dn));
		return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
	}

	idx = el_dupval_index(el);
	if (idx != -1) {
		ldb_asprintf_errstring(ldb,
				       "attribute '%s': value %ld on '%s' "
				       "provided more than once",
				       el->name, idx,
				       ldb_dn_get_linearized(db_msg->dn));
		return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
	}

	idx = find_element(db_msg, el);
	if (idx > -1) {
		db_el = &(db_msg->elements[idx]);

		/* we consider two elements to be equal only if the order
		 * matches. This allows dbcheck to fix the ordering on
		 * attributes where order matters, such as objectClass
		 */
		strict_equal = ldb_msg_element_equal_ordered(el, db_el);
		if (strict_equal) {
			return LDB_SUCCESS;
		}

		/* Delete the attribute if it exists in the DB */
		ret = del_element(db_msg, db_el);
		if (ret != 0) {
			return ret;
		}
	}

	ret = add_element(db_msg, el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static inline int handle_notfound(struct ldb_context *ldb,
				  struct ldb_dn *dn,
				  const char *name,
				  const int err,
				  const bool permissive)
{
	int ret;
	const char *strdn = NULL;

	ret = err;

	if (permissive == false) {
		strdn = ldb_dn_get_linearized(dn);
		ldb_asprintf_errstring(ldb,
				       "attribute '%s': no such attribute "
				       "for delete on '%s'",
				       name, strdn);
	} else {
		ret = LDB_SUCCESS;
	}

	talloc_free(discard_const(strdn));
	return ret;
}

static int mod_el_del(struct ldb_context *ldb,
		      struct ldb_message *db_msg,
		      struct ldb_message_element *el)
{
	int ret;
	bool permissive = false;
	size_t i;

	if (el->num_values == 0) {
		/* Delete whole element */
		ret = del_element(db_msg, el);
		if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
			ret = handle_notfound(ldb, db_msg->dn, el->name,
					      ret, permissive);
		}

		return ret;
	}

	for (i=0; i < el->num_values; i++) {
		ret = del_element_value(ldb, db_msg, el->name, &el->values[i]);
		if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
			ret = handle_notfound(ldb, db_msg->dn,
					      el->name, ret, permissive);
		}
		return ret;
	}

	return LDB_SUCCESS;
}

/* Iterates through elements of mod_msg provided by the user and updates
 * db_msg accordingly.
 *
 * Returns LDB_SUCCESS on success, an error code otherwise.
 */
int ldb_msg_modify(struct ldb_context *ldb,
		   const struct ldb_message *mod_msg,
		   struct ldb_message *db_msg)
{
	struct ldb_message_element *el;
	int ret;
	size_t i;

	for (i=0; i < mod_msg->num_elements; i++) {
		el = &mod_msg->elements[i];

		switch (el->flags & LDB_FLAG_MOD_MASK) {
			case LDB_FLAG_MOD_ADD:
				ret = mod_el_add(ldb, db_msg, el);
				break;
			case LDB_FLAG_MOD_REPLACE:
				ret = mod_el_rep(ldb, db_msg, el);
				break;
			case LDB_FLAG_MOD_DELETE:
				ret = mod_el_del(ldb, db_msg, el);
				break;
			default:
				ldb_asprintf_errstring(ldb,
						"attribute '%s': invalid modify "
						"flags on '%s': 0x%x",
						el->name,
						ldb_dn_get_linearized(mod_msg->dn),
						el->flags & LDB_FLAG_MOD_MASK);
				ret = LDB_ERR_PROTOCOL_ERROR;
				break;
		}
	}

	return ret;
}

static struct ldb_message *msg_add_dn(struct ldb_message *msg)
{
	int ret;

	ret = ldb_msg_add_linearized_dn(msg, DISTINGUISHED_NAME, msg->dn);
	if (ret != LDB_SUCCESS) {
		return NULL;
	}

	return msg;
}

static bool attrs_has_dn(const char * const *attrs)
{
	unsigned int i;

	for (i = 0; attrs[i]; i++) {
		if (ldb_attr_cmp(attrs[i], DISTINGUISHED_NAME) == 0) {
			return true;
		}
	}

	return false;
}

static bool attrs_keep_all(const char * const *attrs)
{
	unsigned int i;

	if (attrs == NULL) {
		return true;
	}

	for (i = 0; attrs[i]; i++) {
		if (ldb_attr_cmp(attrs[i], "*") == 0) {
			return true;
		}
	}

	return false;
}

static bool include_attr(const char * const *haystack, const char *needle)
{
	unsigned int i;

	for (i = 0; haystack[i]; i++) {
		if (ldb_attr_cmp(needle, haystack[i]) == 0) {
			return true;
		}
	}

	return false;
}

static struct ldb_message *filter_elements(struct ldb_message *msg,
		const char * const *attrs)
{
	struct ldb_message_element *new_el;
	unsigned int num_elements;
	unsigned int i;
	bool found_attr;

	new_el = talloc_array(msg, struct ldb_message_element, msg->num_elements);
	if (new_el == NULL) {
		return NULL;
	}

	num_elements = 0;
	for (i = 0; i < msg->num_elements; i++) {
		/* We could use the standard ldb_msg_remove_attr() but this is
		 * faster, see samba commit eaabb595
		 */
		found_attr = include_attr(attrs, msg->elements[i].name);
		if (found_attr == true) {
			new_el[num_elements] = msg->elements[i];
			talloc_steal(new_el, new_el[num_elements].name);
			talloc_steal(new_el, new_el[num_elements].values);
			num_elements++;
		}
	}

	talloc_free(msg->elements);
	/* FIXME - is num_elements correct here? Test when no attributes match */
	msg->elements = talloc_realloc(msg, new_el,
				       struct ldb_message_element,
				       num_elements);
	if (msg->elements == NULL && num_elements > 0) {
		return NULL;
	}
	msg->num_elements = num_elements;

	return msg;
}

struct ldb_message *ldb_msg_filter_attrs(struct ldb_message *msg,
				         const char * const *attrs)
{
	bool keep_all;
	bool include_dn;

	keep_all = attrs_keep_all(attrs);
	if (keep_all == true) {
		return msg_add_dn(msg);
	}

	include_dn = attrs_has_dn(attrs);
	if (include_dn) {
		msg = msg_add_dn(msg);
		if (msg == NULL) {
			return NULL;
		}
	}

	return filter_elements(msg, attrs);
}
