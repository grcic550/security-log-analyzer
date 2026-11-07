#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "detector.h"

static void test_is_suspicious(void) {

    assert(is_suspicious(0, 3) == false);
    assert(is_suspicious(2, 3) == false);
    assert(is_suspicious(3, 3) == true);
    assert(is_suspicious(10, 3) == true);
    assert(is_suspicious(3, 0) == false);
}

int main(void) {

    test_is_suspicious();

    printf("\nAll test passed!");

    return 0;
}