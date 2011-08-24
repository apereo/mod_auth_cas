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
void cas_attr_builder_add(cas_attr_builder *builder, const char *const name, const char *const value);
void cas_saml_attr_cat(cas_attr_builder *builder, cas_saml_attr *attrs);

cas_saml_attr *cas_saml_attr_pdup(apr_pool_t *pool, cas_saml_attr *attrs);

#endif /* def CAS_SAML_ATTR_H */
