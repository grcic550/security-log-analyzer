#include "cli_utils.h"

#include <assert.h>
#include <stdio.h>

static void test_positive_size(void){

    size_t result = 3;

    assert(parse_positive_size("10", &result));
    assert(result == 10);

    assert(!parse_positive_size("abc", &result));
    assert(result == 10);

    assert(!parse_positive_size("34abc", &result));
    assert(result == 10);

    assert(!parse_positive_size("-5", &result));
    assert(result == 10);
    
    assert(!parse_positive_size("   -5", &result));
    assert(result == 10);

    assert(!parse_positive_size("999999999999999999999999999", &result));
    assert(result == 10);

    assert(!parse_positive_size("", &result));
    assert(result == 10);

    assert(!parse_positive_size("0", &result));
    assert(result == 10);

    assert(!parse_positive_size(NULL, &result));
    assert(result == 10);

    assert(!parse_positive_size("10", NULL));
    assert(result == 10);
}

static void test_positive_double(void){

    double result = 60.0;

    assert(parse_positive_double("60.0", &result));
    assert(result == 60.0);

    assert(!parse_positive_double("abc", &result));
    assert(result == 60.0);

    assert(!parse_positive_double("34abc", &result));
    assert(result == 60.0);

    assert(!parse_positive_double("-5", &result));
    assert(result == 60.0);
    
    assert(!parse_positive_double("   -5", &result));
    assert(result == 60.0);

    assert(!parse_positive_double("nan", &result));
    assert(result == 60.0);

    assert(!parse_positive_double("inf", &result));
    assert(result == 60.0);

    assert(!parse_positive_double("", &result));
    assert(result == 60.0);

    assert(parse_positive_double("0.5", &result));
    assert(result == 0.5);

    assert(!parse_positive_double("0", &result));
    assert(result == 0.5);

    assert(!parse_positive_double("nan", &result));
    assert(result == 0.5);
}

int main(void){

    test_positive_size();
    test_positive_double();

    printf("\nAll CLI tests pass!!\n");
    return 0;
}