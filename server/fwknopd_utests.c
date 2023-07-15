/**
 * \file server/fwknopd_utests.c
 *
 * \brief CUnit tests for the server
 */

#include "CUnit/Basic.h"

#include "fwknopd_common.h"
#include "access.h"

/**
 * Register test suites from FKO files.
 *
 * The module should fetch functions according to used modules. All of them follow the same
 * naming convention.
 */
static void register_test_suites(void)
{
    register_ts_access();
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main()
{
    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* Register test suites from fko files */
    register_test_suites();

    /* Run all tests using the CUnit Basic interface */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
