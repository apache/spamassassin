/*  Miscelaneous test functions.
 *
 *  Rather than deal with parallel I/O, we just list the tests here:
 *     1.  Griewank
 *     2.  Rastrigin
 *     3.  Schwefel
 *
 */
#include <pgapack.h>

#ifndef M_PI
#define M_PI 3.14159265354
#endif

double griewank(PGAContext *, int, int);
double rastrigin(PGAContext *, int, int);
double schwefel(PGAContext *, int, int);
void   printResultInterpretation(PGAContext *, int);
int    GetIntegerParameter(char *query);

int    NumCoords[3]  = { 10, 20, 10 };
double Lower[3]      = { -512.0, -5.12, -512.0 };
double Upper[3]      = { 511.0, 5.11, 511.0 };

/*******************************************************************
 *                   user main program                              *
 *******************************************************************/
void main( int argc, char **argv ) {
    PGAContext *ctx;     /* the context variable */
    int testnum;         /* the DeJong test to run */
    int maxiter;         /* the maximum number of iterations */
    double l[20], u[20]; /* for initializing lu ranges */
    int i;

    MPI_Init(&argc, &argv); 

    testnum = GetIntegerParameter("Which test? (1-Griewank, 2-Rastrigin, 3-Schwefel)\n") - 1;
    maxiter = GetIntegerParameter("How many iterations?\n");

    for (i=0; i<20; i++) {
	l[i] = Lower[testnum];
	u[i] = Upper[testnum];
    }


    ctx = PGACreate(&argc, argv, PGA_DATATYPE_REAL, 
		    NumCoords[testnum], PGA_MINIMIZE);
    
    PGASetRandomSeed(ctx, 1);

    PGASetRealInitRange(ctx, l, u);
    PGASetMaxGAIterValue(ctx, maxiter);
    
    PGASetUp(ctx);

    if (testnum == 0)    PGARun(ctx, griewank);
    if (testnum == 1)    PGARun(ctx, rastrigin);
    if (testnum == 2)    PGARun(ctx, schwefel);

    PGADestroy(ctx);
    
    MPI_Finalize();
}


double griewank(PGAContext *ctx, int p, int pop) {
    int i, len;
    double term, sum, product;

    sum = 0;
    product = 1;
    len = PGAGetStringLength(ctx);
    for (i = 0; i < len; i++) {
        term = PGAGetRealAllele(ctx, p, pop, i);
        sum = sum + term * term / 4000.0;
        product = product * cos(term / sqrt(((double)i + 1)));
    }

    return (1 + sum - product);
}


double rastrigin(PGAContext *ctx, int p, int pop)
{
    int i, len;
    double term, sum;

    sum = 0;
    len = PGAGetStringLength(ctx);
    for (i = 0; i < len; i++) {
        term = PGAGetRealAllele(ctx, p, pop, i);
        sum = sum + term * term - 10 * cos(2 * M_PI * term);
    }
    return (len * 10 + sum);
}


double schwefel(PGAContext *ctx, int p, int pop) {
    int i, len;
    double term, sum;

    sum = 0;
    len = PGAGetStringLength(ctx);
    for (i = 0; i < len; i++) {
        term = PGAGetRealAllele(ctx, p, pop, i);
        sum = sum - term * sin(sqrt(fabs(term)));
    }
    return (sum);
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



