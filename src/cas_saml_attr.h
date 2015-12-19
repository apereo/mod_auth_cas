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

#include "apr_general.h"

#ifndef CAS_SAML_ATTR_H
#define CAS_SAML_ATTR_H

typedef struct cas_saml_attr_val {
    char *value;
    struct cas_saml_attr_val *next;
} cas_saml_attr_val;

typedef struct cas_saml_attr {
    char *attr;
    cas_saml_attr_val *values;
    struct cas_saml_attr *next;
} cas_saml_attr;

/* Building sets of attributes
 *
 * Attribute lists created with a builder have the following properties:
 *
 *  * No two adjacent cells in the list of attributes will have equal
 *    attribute names.
 *
 *  * The order of (attribute, value) pairs in the resulting linked
 *    list will be the same as the order they were added using this
 *    function.
 *
 *  * Every attribute in the list will have at least one value.
 */
typedef struct cas_attr_builder cas_attr_builder;
cas_attr_builder *cas_attr_builder_new(apr_pool_t *p, cas_saml_attr **result);
void cas_attr_builder_add(cas_attr_builder *builder, const char *const name,
                          const char *const value);
void cas_saml_attr_cat(cas_attr_builder *builder, cas_saml_attr *attrs);

cas_saml_attr *cas_saml_attr_pdup(apr_pool_t *pool, cas_saml_attr *attrs);

#endif /* def CAS_SAML_ATTR_H */
