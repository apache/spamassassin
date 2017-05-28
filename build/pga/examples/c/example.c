#include <pgapack.h>

double evaluate (PGAContext *ctx, int p, int pop);
int myMutation  (PGAContext *, int, int, double);

int main( int argc, char **argv )
{
     PGAContext *ctx; 
     int i, lower[10], upper[10];

     for (i=0; i<10; i++) {
	 lower[i] = 1;
	 upper[i] = 10;
     }
     ctx = PGACreate (&argc, argv, PGA_DATATYPE_INTEGER, 10, PGA_MAXIMIZE);
     PGASetUserFunction (ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);
     PGASetIntegerInitRange(ctx, lower, upper);
     PGASetUp              (ctx);
     PGARun                (ctx, evaluate);
     PGADestroy            (ctx);
     return(0);
}
int myMutation(PGAContext *ctx, int p, int pop, double pm)
{
    int stringlen, i, k, count = 0;
    stringlen = PGAGetStringLength(ctx);
    for (i = 0; i < stringlen; i++)
    if (PGARandomFlip(ctx, pm)) {
        k = PGARandomInterval(ctx, 1, stringlen);
        PGASetIntegerAllele(ctx, p, pop, i, k);
        count++;
    }
    return ((double) count);
}
double evaluate(PGAContext *ctx, int p, int pop)
{
     int stringlen, i, sum = 0;
     stringlen = PGAGetStringLength(ctx);
     for (i = 0; i < stringlen; i++)
         sum += PGAGetIntegerAllele(ctx, p, pop, i);
     return ((double)sum);
}
