#include "unity.h"
#include "compositor.h"

void
setUp(void)
{
}

void
tearDown(void)
{
}

int
main(void)
{
    UNITY_BEGIN();

    compositor_run();
    
    compositor_stop();

    return UNITY_END();
}

// vim: ts=4 sw=4 sts=4 et
