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

#include <check.h>
#include <stdio.h>

#include <apr.h>

#include "../src/cas_saml_attr.h"

TCase *cas_saml_attr_tcase(void);

static apr_pool_t *pool;

/* XXX: This is duplicated from cas_saml_attr.c
 *
 * It's an opaque structure by design, but the tests need to see
 * inside of it to check the invariants.
 */
struct cas_attr_builder
{
    apr_pool_t *pool;
    cas_saml_attr **next_attr;
    cas_saml_attr_val **next_val;
    const char *last_attr;
};

/* Compare two lists of attributes. The lists are equal if they have
 * exactly the same structure (including ordering, etc.). It is a deep
 * value comparison (i.e. object identity is not required).
 */
static int cas_saml_attr_cmp(cas_saml_attr *a, cas_saml_attr *b) {
    cas_saml_attr_val *va;
    cas_saml_attr_val *vb;

    /* Walk both lists together until we hit the end of one of
     * them. */
    for ( ; a && b; a = a->next, b = b->next) {
        /* If the attribute names are not equal, that is our
           ordering. */
        const int v = strcmp(a->attr, b->attr);
        if (v) {
            return v;
        }

        /* Walk both value lists for this attribute together in the
         * same way */
        for (va = a->values, vb = b->values;
             va && vb;
             va = va->next, vb = vb->next) {
            const int cv = strcmp(va->value, vb->value);
            if (cv) {
                return cv;
            }
        }
        if (va) return 1;
        if (vb) return -1;
    }
    /* If we are not at the end of both lists, the shorter (NULL) one
     * is less */
    if (a) return 1;
    if (b) return -1;

    /* We've examined both structures completely and found no
     * differences */
    return 0;
}

/* This function should always succeed when passed a builder and a
 * pointer to the cas_saml_attr list that its building.
 */
static void cas_attr_builder_check_invariants(cas_attr_builder *builder,
                                              cas_saml_attr **result) {
    cas_saml_attr *attrs = *result;
    cas_saml_attr_val *vals;
    if (attrs) {
        /* All attributes have at least one value */
        for (; attrs->next != NULL; attrs = attrs->next) {
            fail_unless(attrs->values != NULL);
        }
        fail_unless(attrs->values != NULL);

        /* attrs is now the last cell in the list */
        fail_unless(attrs->next == NULL);

        /* The next_attr pointer references the spot where the null
         * terminator currently lives */
        fail_unless(builder->next_attr == &(attrs->next));

        /* last_attr is a string that compares equal to the name of
         * the last attribute in the list */
        fail_unless(strcmp(attrs->attr, builder->last_attr) == 0);

        if (attrs->values) {
            for (vals = attrs->values; vals->next != NULL; vals = vals->next);

            /* The next_val pointer points to the end of the values
             * list for the last attribute */
            fail_unless(builder->next_val == &(vals->next));
        }
    } else {
        /* When no attributes have been defined, there is no
         * next_val or last_attr*/
        fail_unless(builder->next_val == NULL);
        fail_unless(builder->last_attr == NULL);

        /* When no attributes have been defined, result is where
         * next_attr goes. */
        fail_unless(builder->next_attr == result);
    }
}

static int cas_saml_attr_len(cas_saml_attr *attrs) {
    int l = 0;
    for ( ; attrs; attrs = attrs->next) {
        l += 1;
    }
    return l;
}

START_TEST(cas_attr_builder_test) {
    const char *foo = "foo";
    struct test_data {
        const char *const k;
        const char *const v;
        const int len;
    } test_data_list[] = {
        {"foo", "bar", 1},
        {"foo", "bar", 1},
        {"foo", "baz", 1},
        {"quux", "blitz", 2},
        {"foo", "bar", 3},
        {foo, "1", 3},
        {foo, "2", 3},
        {NULL, NULL, 0} /* NULL terminator */
    };
    struct test_data *d;

    int i = 0;
    cas_saml_attr *attrs;
    cas_attr_builder *builder = cas_attr_builder_new(pool, &attrs);
    fail_unless(cas_saml_attr_len(attrs) == 0);

    while (1) {
        cas_attr_builder_check_invariants(builder, &attrs);

        d = &test_data_list[i];
        if (d->v == NULL) break;

        cas_attr_builder_add(builder, d->k, d->v);
        fail_unless(cas_saml_attr_len(attrs) == d->len);
        i++;
    }
}
END_TEST

START_TEST(cas_attr_cmp_test) {
    cas_saml_attr *attrs1, *attrs2;
    cas_attr_builder *builder1 = cas_attr_builder_new(pool, &attrs1);
    cas_attr_builder *builder2 = cas_attr_builder_new(pool, &attrs2);

    /* Newly created, empty attribute lists compare equal. */
    fail_unless(cas_saml_attr_cmp(attrs1, attrs2) == 0);

    /* Adding equal pairs to each lists still compares equal. */
    cas_attr_builder_add(builder1, "foo", "bar");
    cas_attr_builder_add(builder2, "foo", "bar");
    fail_unless(cas_saml_attr_cmp(attrs1, attrs2) == 0);

    /* An explicitly empty (NULL) list compares less than a list that
       we have added a value to. */
    fail_unless(cas_saml_attr_cmp(NULL, attrs2) < 0);

    /* A duplicated list behaves the same as the original list. */
    fail_unless(cas_saml_attr_cmp(cas_saml_attr_pdup(pool, attrs1),
                                  attrs2) == 0);
}
END_TEST

static void cas_saml_attr_setup(void) {
  apr_pool_create(&pool, NULL);
}

static void cas_saml_attr_teardown(void) {
  apr_pool_destroy(pool);
}

TCase *cas_saml_attr_tcase(void) {
  TCase *tc_builder = tcase_create("cas_saml_attr_builder");
  tcase_add_checked_fixture(tc_builder,
                            cas_saml_attr_setup,
                            cas_saml_attr_teardown);
  tcase_add_test(tc_builder, cas_attr_builder_test);
  tcase_add_test(tc_builder, cas_attr_cmp_test);
  return tc_builder;
}
