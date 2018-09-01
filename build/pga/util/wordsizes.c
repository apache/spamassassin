
#define WL 32
#define FAKE_MPI

#include <stdio.h>
#include "../include/pgapack.h"

/*
 *  Compile with: cc -o wordsizes wordsizes.c
 *
 *  Any size WL can be used -- it will not affect the sizes below.
 *
 *  FAKE_MPI will also not affect the sizes of the structures below,
 *  but will simplify the compilation.  
 *
 *  If PGAContext * is 8 bytes, then you have a "64-bit" machine.  Be
 *  sure to use integer*8 for the PGAContext variable, and integer*4
 *  (usually just integer) for everything else.
 *
 */
void main(void) {
    printf("Sizes of various datatypes in bytes.\n\n");
    printf("sizeof(PGAContext *):      %2d\n", sizeof(PGAContext *));
    printf("sizeof(PGABinary):         %2d\n", sizeof(PGABinary));
    printf("sizeof(PGAReal):           %2d\n", sizeof(PGAReal));
    printf("sizeof(PGAInteger):        %2d\n", sizeof(PGAInteger));
    printf("sizeof(PGACharacter):      %2d\n", sizeof(PGACharacter));

    printf("sizeof(int):               %2d\n", sizeof(int));
    printf("sizeof(long int):          %2d\n", sizeof(long int));

    printf("sizeof(double):            %2d\n", sizeof(double));
    printf("sizeof(char):              %2d\n", sizeof(char));
}
