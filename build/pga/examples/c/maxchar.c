/*
 *  This is a test program for PGAPack.  The objective is to maximize the
 *  number of 'z's in a chromosome.
 */

#include <pgapack.h>

double NumberOfZs(PGAContext *, int, int);
int    myMutation(PGAContext *, int, int, double);
int    GetIntegerParameter(char *query);

/*******************************************************************
*                   user main program                              *
*******************************************************************/
int main( int argc, char **argv )
{
     PGAContext *ctx;
     int         len, maxiter;


     MPI_Init(&argc, &argv);

     len = GetIntegerParameter("String length?\n");
     maxiter = GetIntegerParameter("How many iterations?\n");

     ctx = PGACreate(&argc, argv, PGA_DATATYPE_CHARACTER, len, PGA_MAXIMIZE);

     PGASetRandomSeed(ctx, 1);
     PGASetMaxGAIterValue(ctx, maxiter);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);

     PGASetUp(ctx);
     PGARun(ctx, NumberOfZs);
     PGADestroy(ctx);

     MPI_Finalize();

     return(0);
}


/*******************************************************************
*               user defined evaluation function                   *
*   ctx - contex variable                                          *
*   p   - chromosome index in population                           *
*   pop - which population to refer to                             *
*******************************************************************/
double NumberOfZs(PGAContext *ctx, int p, int pop) {
     int i, nzs;
     int stringlen;

     stringlen = PGAGetStringLength(ctx);
     
     nzs = 0;
     for ( i=0; i<stringlen; i++ )
	  if (PGAGetCharacterAllele(ctx, p, pop, i) == 'z')
	       nzs++;
     
     return((double) nzs);
}


/*  Custom mutation function.  Searches for an unset bit, 
 *  then sets it.  Returns the number of bits that are changed.
 */
int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         i, count;
    char        c;

    count = 0;
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--) {
	if (PGARandomFlip(ctx, mr)) {
	    c = PGAGetCharacterAllele(ctx, p, pop, i);
	    if (c != 'z') {
		PGASetCharacterAllele(ctx, p, pop, i, c+1);
		count++;
	    }
	}
    }
    return(count);
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


