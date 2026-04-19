#include "util.h"
#include <getopt.h>
#include <stdlib.h>

static const struct option OPTIONS[] = {
    {"config", required_argument, 0, 'c'},
    {"log", required_argument, 0, 'l'},
    {NULL, 0, 0, 0}
};

int
main(int argc, char **argv)
{
    int c;
    int idx;

    while ((c = getopt_long(argc, argv, "", OPTIONS, &idx)) != -1)
    {
        switch (c)
        {
        case 'c':
            break;
        case 'l':
            break;
        default:
            
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
