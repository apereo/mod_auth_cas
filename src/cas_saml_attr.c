/*
 *
 * Copyright 2011 the mod_auth_cas team.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * mod_auth_cas.c
 * Apache CAS Authentication Module
 * Version 1.0.10
 *
 * Contact: cas-user@apereo.org
 *
 */

#include <assert.h>

#include "apr_strings.h"

#include "cas_saml_attr.h"

/* Track the state necessary to incrementally build a list of
 * attributes.
 */
struct cas_attr_builder
{
    /* The pool to use for allocating cells in the attribute
     * structure.
     */
    apr_pool_t *pool;

    /* The slot in which to put a new attribute.
     *
     * Invariants outside of builder functions:
     *
     *  * next_attr is never NULL
     *  * (*next_attr) is always NULL (it's the terminator of the list)
     */
    cas_saml_attr **next_attr;

    /* The slot in which to put new values of the current attribute
     *
     * Invariants:
     *
     *  * If there is at least one attribute in the list, then next_val
     *    is not NULL.
     *  * If the list is empty, then next_val is NULL.
     *  * If next_val is not NULL, then (*next_val) is NULL.
     */
    cas_saml_attr_val **next_val;

    /* The attribute name that was last passed to cas_attr_builder_add
     *
     * Invariants:
     *
     *  * If the list is not empty, this value is not NULL.
     *  * This value points to a string that compares as equal to the
     *    last attribute in the list of attributes.
     */
    const char *last_attr;
};

/* Create a new attribute builder, building a linked list whose head
 * will be stored in *result when the builder is done.
 *
 * During the use of the builder, *result will point to a valid,
 * NULL-terminated, linked list of attributes containing the
 * attributes in the order that they were added to the builder.
 */
cas_attr_builder *cas_attr_builder_new(apr_pool_t *pool,
                                       cas_saml_attr **result)
{
    cas_attr_builder *builder = apr_palloc(pool, sizeof(cas_attr_builder));
    builder->pool = pool;
    builder->next_attr = result;
    builder->next_val = NULL;
    builder->last_attr = NULL;

    /* Set the result to be an empty list for now */
    *result = NULL;

    return builder;
}

/* Add an (attribute, value) pair to the list of attributes that we
 * are building.
 *
 * The attribute is added to the end of the list of attributes. If the
 * attribute name is exactly the same as the most recently added
 * attribute, then the value is added to that attribute's list of
 * values. If the attribute name is not the same, then a new list of
 * attributes is created.
 */
void cas_attr_builder_add(cas_attr_builder *builder,
                          const char *const name,
                          const char *const value) {
    cas_saml_attr_val *new_val;
    cas_saml_attr *new_attr = NULL;

    /* check to see if we are adding to the list of values for an
     * existing attribute, or if we are creating a new attribute */
    const int is_new_attribute =
        (builder->last_attr == NULL) ||
        ((name != builder->last_attr)
         && (strcmp(name, builder->last_attr) != 0));

    /* Create a new attribute cell. */
    if (is_new_attribute) {
        new_attr = apr_palloc(builder->pool, sizeof(cas_saml_attr));
        new_attr->next = NULL;
        new_attr->values = NULL;
        new_attr->attr = apr_pstrdup(builder->pool, name);
    } else {
        /* if this attribute name is not new, then there must be a
         * slot to add new values already. */
        assert(builder->next_val);
    }

    /* Add a cell to the values list of the current attribute, and
     * remember its next pointer for subsequent calls. */
    new_val = apr_palloc(builder->pool, sizeof(cas_saml_attr_val));
    new_val->next = NULL;
    new_val->value = apr_pstrdup(builder->pool, value);

    /* Update the fields of the builder. */

    /* Do this before updating the value pointer, because if this is a
     * new attribute, then the value pointer gets modified. */
    if (new_attr != NULL) {
        *(builder->next_attr) = new_attr;
        builder->next_attr = &(new_attr->next);
        builder->next_val = &(new_attr->values);
    }

    *(builder->next_val) = new_val;
    builder->next_val = &(new_val->next);

    /* Remember the exact pointer to the attribute name so that the
     * next time this function is called, we can efficiently test to
     * see if the attribute has the same name.
     */
    builder->last_attr = name;
}

/* Make a new (deep) copy of a set of cas_saml_attrs. The attribute
 * names and values are copied as well. It is safe to call this
 * function with an empty list of attributes (NULL).
 */
cas_saml_attr *cas_saml_attr_pdup(apr_pool_t *pool, cas_saml_attr *attrs)
{
    cas_saml_attr *result;
    cas_attr_builder *builder = cas_attr_builder_new(pool, &result);
    cas_saml_attr_cat(builder, attrs);
    return result;
}

/* Add all of the attributes from the list of attributes to the
 * builder */
void cas_saml_attr_cat(cas_attr_builder *builder, cas_saml_attr *attrs)
{
    cas_saml_attr_val *vals;
    for (; attrs != NULL; attrs = attrs->next) {
        for (vals = attrs->values; vals != NULL; vals = vals->next) {
            cas_attr_builder_add(builder, attrs->attr, vals->value);
        }
    }
}
