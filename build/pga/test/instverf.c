/*  Example program that shows how to run more than one GA in one
 *  executable, _AND_ verifies the accuracy of installation.
 *
 *  We will run five distinct GA's, each using a different datatype, and,
 *  thus, a different evaluation function.  The correct output of these GA's
 *  is in instverf.data, which we read and compare after all GA's are done.
 *
 *  The correct solution for #4 and #5 is somewhere around 4.49339389176 for
 *  the genes, and an evaluation value of around -6.951476096.
 *
 *  Author:  Brian P. Walenz
 */
#include <pgapack.h>


double maxbit(PGAContext *, int, int);
double ordering(PGAContext *, int, int);
double name(PGAContext *, int, int);
double function(PGAContext *, int, int);
double functionb(PGAContext *, int, int);

/*  The user defined functions.
 *
 *  O_* --> for the Ordering problem (integer), problem 2
 *  N_* --> for the Name problem (character), problem 3
 *  R_* --> for the real problem, problem 4
 *  Rb_* -> for the real problem using the binary datatype, problem 5
 */
void EOG(PGAContext *);
int  O_Mutate(PGAContext *, int, int, double);
void O_Crossover(PGAContext *, int, int, int, int, int, int);
int  N_Mutate(PGAContext *, int, int, double);
int  N_StopCond(PGAContext *);
void R_Init(PGAContext *, int, int);
void Rb_Init(PGAContext *, int, int);
void Rb_PrintString(PGAContext *, FILE *, int, int);

char      String[65] = 
          "THEQUICKBROWNFOXJUMPESOVERTHELAZYDOGWHILETHEOLDGOOSELOOKSPUZZLED";
double    Results[5][1001];
int       ResultsIndex;

/*  How often to print, and the size (in bits) of each number in a binary
 *  string (used by problem 5)
 */
#define   PRINTFREQ  100
#define   RBS        24

void main(int argc, char **argv) {
    PGAContext     *ctx;
    int             i, rank;
    FILE           *ResultsFile;
    double          R[5];
    int             E[5];


    /*  Even though we aren't doing I/O, we MUST initialize MPI ourselves.
     *  If we don't, the first call to PGADestroy will finalize MPI, and
     *  the MPI standard does not allow any MPI calls after that (even
     *  if it is MPI_Init())!
     */
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    
    /*  All examples use a common custom end of generation function to 
     *  stuff the best of generation evaluation into an array.
     */


    /*  Our first example is the ever-popular maxbit.  As usual, it is
     *  very simple, not even setting PGAPack options!  Plus, we use a
     *  very odd string length, 999, which is not divisible by 16, 32 or
     *  64!  What an excellent test!
     */
    ResultsIndex = 0;
    ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 999, PGA_MAXIMIZE);
    PGASetRandomSeed(ctx, 42);
    PGASetPrintFrequencyValue(ctx, PRINTFREQ);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,  (void *)EOG);
    PGASetUp(ctx);
    PGARun(ctx, maxbit);
    PGADestroy(ctx);

    /*  Second on the menu is a delicious integer ordering function.
     *  This uses custom mutation and crossover, but permutation
     *  initialization.  The objective is to order all alleles in the
     *  integer datatype in an increasing fashion.
     */
    ResultsIndex = 1;
    ctx = PGACreate(&argc, argv, PGA_DATATYPE_INTEGER, 64, PGA_MAXIMIZE);
    PGASetRandomSeed(ctx, 42);
    PGASetPrintFrequencyValue(ctx, PRINTFREQ);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,  (void *)O_Mutate);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER, (void *)O_Crossover);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,  (void *)EOG);
    PGASetIntegerInitPermute(ctx, 0, 63);
    PGASetUp(ctx);
    PGARun(ctx, ordering);
    PGADestroy(ctx);


    /*  Third, and least interesting, is the character maximizer.
     *  Much like name, it uses custom mutation and stopping conditions.
     */
    ResultsIndex = 2;
    ctx = PGACreate(&argc, argv, PGA_DATATYPE_CHARACTER, 64, PGA_MAXIMIZE);
    PGASetRandomSeed(ctx, 42); 
    PGASetPrintFrequencyValue(ctx, PRINTFREQ);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,  (void *)N_Mutate);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_STOPCOND,  (void *)N_StopCond);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,  (void *)EOG);
    PGASetCharacterInitType(ctx, PGA_CINIT_UPPER);
    PGASetUp(ctx);
    PGARun(ctx, name);
    PGADestroy(ctx);


    /*  And, finally, the last of the day.  A simple real-valued function
     *  optimizer.  Uses custom init string.
     */
    ResultsIndex = 3;
    ctx = PGACreate(&argc, argv, PGA_DATATYPE_REAL, 32, PGA_MINIMIZE);
    PGASetRandomSeed(ctx, 42); 
    PGASetMutationType(ctx, PGA_MUTATION_CONSTANT);
    PGASetMutationRealValue(ctx, .1); 
    PGASetPrintFrequencyValue(ctx, PRINTFREQ);
    PGASetMutationProb(ctx, 0.1);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING,  (void *)R_Init);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,    (void *)EOG);
    PGASetUp(ctx);
    PGARun(ctx, function);
    PGADestroy(ctx);


    /*  Encore, encore!  Fine.  We will now perform the last number
     *  using the binary datatype and PGAGetRealFromBinary alternating
     *  with PGAGetRealFromGrayCode.
     */
    ResultsIndex = 4;
    ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 32*RBS, PGA_MINIMIZE);
    PGASetRandomSeed(ctx, 42); 
    PGASetPrintFrequencyValue(ctx, PRINTFREQ);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING,  (void *)Rb_Init);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING, (void *)Rb_PrintString);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,    (void *)EOG);
    PGASetUp(ctx);
    PGARun(ctx, functionb);
    PGADestroy(ctx);


    /*  Compare the Results with the correct values
     *  stored in "./test/data/Results.data"
     */
    if (rank == 0) {
	ResultsFile = fopen("instverf.data", "r");
	if (ResultsFile) {
	    E[0] = E[1] = E[2] = E[3] = E[4] = 0;
	    
	    for (i=1; i<1001; i++) {
#if 0
		/*  This is used to generate the results file... */
		printf("%12.6f %12.6f %12.6f %12.6f %12.6f\n",
		       Results[0][i], Results[1][i], Results[2][i],
		       Results[3][i], Results[4][i]);
#endif
		fscanf(ResultsFile, "%lf %lf %lf %lf %lf",
		       R, R+1, R+2, R+3, R+4);
		if (fabs(R[0] - Results[0][i]) > 0.001)   E[0]++;
		if (fabs(R[1] - Results[1][i]) > 0.001)   E[1]++;
		if (fabs(R[2] - Results[2][i]) > 0.001)   E[2]++;
		if (fabs(R[3] - Results[3][i]) > 0.001)   E[3]++;
		if (fabs(R[4] - Results[4][i]) > 0.001)   E[4]++;
	    }
	    fclose(ResultsFile);
	    for (i=0; i<5; i++) {
		if (E[i])
		    printf("Test %d had %d errors.\n", i, E[i]);
		else
		    printf("Test %d was successful.\n", i);
	    }
	} else {
	    fprintf(stderr, "Couldn't open \"instverf.data\".\n");
	}
    }

    MPI_Finalize();
}


/******************************************************************************
 *
 *  The fitness functions
 *
 *****************************************************************************/
double maxbit(PGAContext *ctx, int p, int pop) {
    int i, result;

    result = 0;
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--) 
	if (PGAGetBinaryAllele(ctx, p, pop, i) == 1)
	    result = result + 1;

    return((double)result);
}


/*  Award points if two alleles are increasing (i.e., gene = .., 1, 2, ..)
 *  and if any allele is in the correct spot (i.e., gene = 1, 2, 3, 4, ...)
 */
double ordering(PGAContext *ctx, int p, int pop) {
    int i, n, o, len, result;

    len = PGAGetStringLength(ctx);

    result = 0;
    o = PGAGetIntegerAllele(ctx, p, pop, 0);
    if (o == 0)
	result = 2;
    for (i=1; i<len; i++) {
	n = PGAGetIntegerAllele(ctx, p, pop, i);
	if (o == n-1)
	    result = result + 1;
	if (n = i)
	    result = result + 2;
	o = n;
    }

    return((double)result);
}

double name(PGAContext *ctx, int p, int pop) {
    int  i, result;

    result = 0;
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--)
	if (PGAGetCharacterAllele(ctx, p, pop, i) == String[i])
	    result = result + 1;

    return((double)result);
}


double function(PGAContext *ctx, int p, int pop) {
    int    i;
    double x, result;

    result = 0;
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--) {
	x = PGAGetRealAllele(ctx, p, pop, i);
	result = result + sin(x) / x;
    }

    return(result);
}


double functionb(PGAContext *ctx, int p, int pop) {
    int    i;
    double x, result;

    result = 0;
    i = PGAGetStringLength(ctx)/RBS - 1;

    for ( ; i>=0; i--) {
	if (i % 2) {
	    x = PGAGetRealFromBinary
		(ctx, p, pop, i*RBS, (i+1)*RBS-1, 0.0, 6.28318530718);
	} else {
	    x = PGAGetRealFromGrayCode
		(ctx, p, pop, i*RBS, (i+1)*RBS-1, 0.0, 6.28318530718);
	}
	result = result + sin(x) / x;
    }
    return(result);
}



/**********************************************************************/
void EOG(PGAContext *ctx) {
    int     best, iter;
    double  besteval;

    iter = PGAGetGAIterValue(ctx);
    best = PGAGetBestIndex(ctx, PGA_NEWPOP);
    besteval = PGAGetEvaluation(ctx, best, PGA_NEWPOP);

    Results[ResultsIndex][iter] = besteval;
}



/**********************************************************************/
int O_Mutate(PGAContext *ctx, int p, int pop, double mr) {
    int i, a, b, len;
 
    len = PGAGetStringLength(ctx);
    
    a = PGARandomInterval(ctx, 0, len-1);
    b = PGARandomInterval(ctx, 0, len-1);

    i = PGAGetIntegerAllele(ctx, p, pop, a);
    PGASetIntegerAllele(ctx, p, pop, a,
			PGAGetIntegerAllele(ctx, p, pop, b));
    PGASetIntegerAllele(ctx, p, pop, b, i);
    return(1);
}

/*  Crossover:  Ripped from tsp.c  */
void O_Crossover(PGAContext *ctx, int A, int B, int ppop,
		 int C, int D, int cpop) {
    int     co1, co2, i, len, a, b;
    int     inA[64], inB[64];

    len = PGAGetStringLength(ctx);

    /*  Select random crossover points from [1, len-1].  */
    co1 = PGARandomInterval(ctx, 1, len-1);
    while (co1 == (co2 = PGARandomInterval(ctx, 1, len-1))) ;
    if (co1 > co2) {
        i = co1;
        co1 = co2;
        co2 = i;
    }

    /*  Copy a->c and b->d up to the first crossover point. */
    for (i=0; i<co1; i++) {
        a = PGAGetIntegerAllele(ctx, A, ppop, i);
        b = PGAGetIntegerAllele(ctx, B, ppop, i);
        PGASetIntegerAllele(ctx, C, cpop, i, a);
        PGASetIntegerAllele(ctx, D, cpop, i, b);
    }
    
    /*  Copy a->c and b->d from the second co point to the end of the
     *  string.  (Yes, we're ignoring the middle for now.)
     */
    for (i=co2; i<len; i++) {
        a = PGAGetIntegerAllele(ctx, A, ppop, i);
        b = PGAGetIntegerAllele(ctx, B, ppop, i);
        PGASetIntegerAllele(ctx, C, cpop, i, a);
        PGASetIntegerAllele(ctx, D, cpop, i, b);
    }
    
    /*  Now, copy a->d and b->c in the middle (co1 <--> co2).  We must
     *  be careful to not use any cities twice, thus, we must check
     *  the rest of the string to see if the allele is used.  If it is,
     *  change the allele to that of the corresponding one in the other
     *  string, and check again.  For efficiency, we build a couple of
     *  tables, AtoB and BtoA.
     */
    for (i=0; i<len; i++) {
        a = PGAGetIntegerAllele(ctx, A, ppop, i);
        b = PGAGetIntegerAllele(ctx, B, ppop, i);
        inA[a] = i;
        inB[b] = i;
    }
    
    for (i=co1; i<co2; i++) {
        /*  While what we picked is outside the crossover region
         *  in the other string, keep cross-referencing.
         */
	b = PGAGetIntegerAllele(ctx, B, ppop, i);
        while ((inA[b]<co1) || (inA[b]>=co2)) 
	    b = PGAGetIntegerAllele(ctx, B, ppop, inA[b]);

        a = PGAGetIntegerAllele(ctx, A, ppop, i);
        while ((inB[a]<co1) || (inB[a]>=co2)) 
	    a = PGAGetIntegerAllele(ctx, A, ppop, inB[a]);

        PGASetIntegerAllele(ctx, C, cpop, i, b);
        PGASetIntegerAllele(ctx, D, cpop, i, a);
    }
}



/**********************************************************************/
int N_Mutate(PGAContext *ctx, int p, int pop, double mr) {
    int i, count;

    count = 0;
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--) {
	if ((PGAGetCharacterAllele(ctx, p, pop, i) != String[i]) &&
	    (PGARandomFlip(ctx, mr) == PGA_TRUE)) {
	    PGASetCharacterAllele(ctx, p, pop, i, String[i]);
	    count += 1;
	}
    }
    return(count);
}

int N_StopCond(PGAContext *ctx) {
    int     done, len;
    double  e;

    done = 0;
    len  = PGAGetStringLength(ctx);
    e    = PGAGetEvaluation(ctx, PGAGetBestIndex(ctx, PGA_OLDPOP), PGA_OLDPOP);

    if (PGACheckStoppingConditions(ctx) || (len == e))
	done = 1;

    return(done);
}


/**********************************************************************/
void R_Init(PGAContext *ctx, int p, int pop) {
    int     i;
    double  r;
    
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--) {
	r = 6.28318530718 * PGARandom01(ctx, 0) - 3.14159265354;
      	r = 6.28318530718 * exp(r) / (exp(r) + exp(-r));

	PGASetRealAllele(ctx, p, pop, i, r);
    }
}

void Rb_Init(PGAContext *ctx, int p, int pop) {
    int     i;
    double  r;
    
    i = PGAGetStringLength(ctx) / RBS - 1;

    for ( ; i>=0; i--) {
	r = 6.28318530718 * PGARandom01(ctx, 0) - 3.14159265354;
      	r = 6.28318530718 * exp(r) / (exp(r) + exp(-r));

	if (i % 2) {
	    PGAEncodeRealAsBinary
		(ctx, p, pop, i*RBS, (i+1)*RBS-1, 0.0, 6.28318530718, r);
	} else {
	    PGAEncodeRealAsGrayCode
		(ctx, p, pop, i*RBS, (i+1)*RBS-1, 0.0, 6.28318530718, r);
	}
    }
}

void Rb_PrintString(PGAContext *ctx, FILE *file, int p, int pop) {
    int     i, j, len;
    double  r;

    len = PGAGetStringLength(ctx) / RBS - 1;

    for(i=j=0; i<len; i++, j++) {
	if (i % 2) {
	    r = PGAGetRealFromBinary
		(ctx, p, pop, i*RBS, (i+1)*RBS-1, 0.0, 6.28318530718);
	} else {
	    r = PGAGetRealFromGrayCode
		(ctx, p, pop, i*RBS, (i+1)*RBS-1, 0.0, 6.28318530718);
	}
	fprintf(file, "  %10.6f", r);
	if (j==5) {
	    fprintf(file, "\n");
	    j = -1;
	}
    }
}

