/*
 *  This is a test program for PGAPack.  The objective is to maximize each
 *  allele.  The evaluation function sums all allele values.
 */
#include <pgapack.h>

double evaluate(PGAContext *, int, int);
int    myMutation(PGAContext *, int, int, double);
int    GetIntegerParameter(char *query);


int main(int argc, char **argv) {
     PGAContext *ctx;
     int         len, maxiter;

     MPI_Init(&argc, &argv);

     len     = GetIntegerParameter("String length?\n");
     maxiter = GetIntegerParameter("How many iterations?\n");

     ctx = PGACreate(&argc, argv, PGA_DATATYPE_INTEGER, len, PGA_MAXIMIZE);

     PGASetRandomSeed(ctx, 1);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);
     PGASetIntegerInitPermute(ctx, 1, len);

     PGASetMaxGAIterValue(ctx, maxiter);
     PGASetNumReplaceValue(ctx, 90);
     PGASetMutationAndCrossoverFlag(ctx, PGA_TRUE);
     PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE);

     PGASetUp(ctx);

     PGARun(ctx, evaluate);
     PGADestroy(ctx);

     MPI_Finalize();

     return(0);
}


int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         stringlen, i, v, count;

    stringlen = PGAGetStringLength(ctx);
    count     = 0;

    for (i=stringlen-1; i>=0; i--) {
	if (PGARandomFlip(ctx, mr)) {
	    v = PGARandomInterval(ctx, 1, stringlen);
            PGASetIntegerAllele(ctx, p, pop, i, v);
	    count++;
	}
    }
    return((double)count);
}



double evaluate(PGAContext *ctx, int p, int pop) {
     int  stringlen, i, sum;

     stringlen = PGAGetStringLength(ctx);
     sum       = 0;
     
     for (i=stringlen-1; i>=0; i--)
	  sum += PGAGetIntegerAllele(ctx, p, pop, i);

     return((double)sum);
}



/*  Get an integer parameter from the user.  Since this is
 *  typically a parallel program, we must only do I/O on the
 *  "master" process -- process 0.  Once we read the parameter,
 *  we broadcast it to all the other processes, then every 
 *  process returns the correct value.
 */
int GetIntegerParameter(char *query) {
    int  rank, tmp;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if (rank == 0) {
        printf(query);
        scanf("%d", &tmp);
    }
    MPI_Bcast(&tmp, 1, MPI_INT, 0, MPI_COMM_WORLD);
    return(tmp);
}



