#include <stdio.h>
#include <stdlib.h>

typedef void (*Handler)(void);    /* A pointer to a handler function */

/* The functions */
void func3 (void) { printf( "3\n" ); }
void func2 (void) { printf( "2\n" ); }
void func1 (void) { printf( "1\n" ); }
void func0 (void) { printf( "0\n" ); }

Handler jump_table[4] = {func0, func1, func2, func3};

int main (int argc, char **argv) {
    int value;

    for(int i = 0; i < 4; i++) {
        /* Call appropriate function (func0 thru func3) */
        jump_table[i]();
    }

    value = ((atoi(argv[1]) % 4) + 4) % 4;
    jump_table[value]();

    return 0;
}
