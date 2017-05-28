/*  The DeJong test suite.
 *
 */
#include <pgapack.h>

double dejong1(PGAContext *, int, int);
double dejong2(PGAContext *, int, int);
double dejong3(PGAContext *, int, int);
double dejong4(PGAContext *, int, int);
double dejong5(PGAContext *, int, int);
void   printResultInterpretation(PGAContext *, int);
int    GetIntegerParameter(char *query);

int    gray_on;

int    BinLen[5]     = { 10, 12, 10, 8, 17 };
int    NumCoords[5]  = { 3, 2, 5, 30, 2 };
double Lower[5]      = { -5.12, -2.048, -5.12, -1.28, -65.536 };
double Upper[5]      = { 5.11, 2.047, 5.11, 1.27, 65.535 };

/*******************************************************************
 *                   user main program                              *
 *******************************************************************/
void main( int argc, char **argv ) {
    PGAContext *ctx;    /* the context variable */
    int testnum;        /* the DeJong test to run */
    int maxiter;        /* the maximum number of iterations */

    MPI_Init(&argc, &argv); 

    testnum = GetIntegerParameter("Which test? (1 - 5)\n") - 1;
    gray_on = GetIntegerParameter("Gray-coded? (0 = no)\n");
    maxiter = GetIntegerParameter("How many iterations?\n");

    ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 
		    BinLen[testnum]*NumCoords[testnum], PGA_MINIMIZE);
    
    PGASetMaxGAIterValue(ctx, maxiter);
    PGASetRandomSeed(ctx, 1);
    
    PGASetUp(ctx);

    if (testnum == 0)    PGARun(ctx, dejong1);
    if (testnum == 1)    PGARun(ctx, dejong2);
    if (testnum == 2)    PGARun(ctx, dejong3);
    if (testnum == 3)    PGARun(ctx, dejong4);
    if (testnum == 4)    PGARun(ctx, dejong5);

    printResultInterpretation(ctx, testnum);

    PGADestroy(ctx);
    
    MPI_Finalize();
}


double GetTerm(PGAContext *ctx, int p, int pop, int t, int problem) {
    double    x;
    int       len;
    double    l, u;

    len = BinLen[problem];
    l   = Lower[problem];
    u   = Upper[problem];

    if (gray_on) 
	x = PGAGetRealFromGrayCode(ctx, p, pop, t*len, (t+1)*len-1, l, u);
    else
	x = PGAGetRealFromBinary(ctx, p, pop, t*len, (t+1)*len-1, l, u);
    return(x);
}


double dejong1(PGAContext *ctx, int p, int pop) {
    int i;
    double term, sum = 0;
    
    for(i = 0; i < NumCoords[0]; i++) {
	term = GetTerm(ctx, p, pop, i, 0);
	sum += (term * term);
    }
    
    return (sum);
}


double dejong2(PGAContext *ctx, int p, int pop) {
    double x1, x2, p1, p2;
    
    x1 = GetTerm(ctx, p, pop, 0, 1);
    x2 = GetTerm(ctx, p, pop, 1, 1);

    p1 = x1 * x1 - x2;
    p2 = 1 - x1;
    
    return (100 * p1 * p1 + p2 * p2);
}

double dejong3(PGAContext *ctx, int p, int pop) {
    int i;
    double sum = 0;
    
    for(i = 0; i < NumCoords[2]; i++)
	sum += floor(GetTerm(ctx, p, pop, i, 2));

    return (sum);
}

double dejong4(PGAContext *ctx, int p, int pop) {
    int i;
    double term, sum = 0;
    
    for(i = 0; i < NumCoords[3]; i++) {
	term = GetTerm(ctx, p, pop, i, 3);
	sum += ((i + 1) * term * term * term * term);
    }
    
    return (sum + PGARandomGaussian(ctx, 0, 1));
}

double dejong5(PGAContext *ctx, int p, int pop) {
    int    a[2][25];
    int    i, j;
    double sum_over_i = 0, sum_over_j = 0;

    for (i=0; i<5; i++) {
        a[0][5*i]   = -32;
        a[1][i]     = -32;

        a[0][5*i+1] = -16;
        a[1][i+5]   = -16;

        a[0][5*i+2] = 0;
        a[1][i+10]  = 0;

        a[0][5*i+3] = 16;
        a[1][i+15]  = 16;

        a[0][5*i+4] = 32;
        a[1][i+20]  = 32;
    }

    for (j = 0; j < 25; j++) {
	sum_over_i =
	    pow(GetTerm(ctx, p, pop, 0, 4) - a[0][j], 6) +
	    pow(GetTerm(ctx, p, pop, 1, 4) - a[1][j], 6);
	sum_over_j += (1.0 / (j + sum_over_i));
    }
    
    return (1.0 / (0.002 + sum_over_j));
}


void printResultInterpretation(PGAContext *ctx, int problem) {
    int      best, i;
    double   value;

    if (PGAGetRank(ctx, MPI_COMM_WORLD) == 0) {
	best = PGAGetBestIndex(ctx, PGA_OLDPOP);
	
	printf("The real interpretation:\n");
	for (i = 0; i < NumCoords[problem]; i++) {
	    value = GetTerm(ctx, best, PGA_OLDPOP, i, problem);
	    
	    switch ( i % 5 ) {
	    case 0:
		printf ("#%4d: [%11.7g]", i, value);
		break;
	    case 1:
	    case 2:
	    case 3:
		printf (", [%11.7g]", value);
		break;
	    case 4:
		printf (", [%11.7g]", value);
		if (i+1 < NumCoords[problem])
		    printf ("\n");
		break;
	    }
	}
	printf("\n");
    }
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
