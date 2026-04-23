#include <getopt.h>
#include <stdlib.h>
#include <string.h>

static const struct option OPTIONS[] = {{NULL, 0, 0, 0}};

int
main(int argc, char **argv)
{
    int c;
    int idx;

    while ((c = getopt_long(argc, argv, "", OPTIONS, &idx)) != -1)
    {
        switch (c)
        {
        default:
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
