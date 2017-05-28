/*  PGAPack test program.
 *
 *  The objective is to evolve a string of characters to match a string
 *  supplied by the user.  We will stop evolving when either we run out
 *  of iterations (500), or when the best string has the same evaluation
 *  value for 100 generations.
 *
 *  One problem with this implementation is that ' ' is not in
 *  PGA_DATATYPE_CHAR if we limit it using PGA_CINIT_MIXED, PGA_CINIT_LOWER,
 *  or PGA_CINIT_UPPER.  To fix this, we must define our own interval, and
 *  thus, our own mutation, initialization operators.
 *
 *  A user function is also used to check the "done" condition; we are 
 *  done if we've done more than 1000 iterations, or the evolved string
 *  is correct.
 *
 *  Created 28 Sep 95, Brian P. Walenz.  Thanks to Dan Ashlock for the idea.
 */

#include "pgapack.h"

void   N_InitString(PGAContext *ctx, int p, int pop);
int    N_Mutation(PGAContext *ctx, int p, int pop, double mr);
int    N_StopCond(PGAContext *ctx);
double EvalName(PGAContext *ctx, int p, int pop);
void   GetStringParameter(char *query, char *string);

/*  Global, because we use it in EvalName.  */
char   Name[42];

void main(int argc, char **argv) {
    PGAContext *ctx;

    MPI_Init(&argc, &argv);

    /*  Rather than deal with standard io and strings, we'll just set
     *  this explicitly.
     */
    strcpy(Name,"Levine, Hallstrom, Noelle, Walenz");

    ctx = PGACreate(&argc, argv, PGA_DATATYPE_CHARACTER, strlen(Name),
		    PGA_MAXIMIZE);
    
    PGASetRandomSeed(ctx, 1);
    
    PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING, (void *)N_InitString);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,   (void *)N_Mutation);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_STOPCOND,   (void *)N_StopCond);

    PGASetPopSize(ctx, 100);
    PGASetNumReplaceValue(ctx, 75);
    PGASetPopReplaceType(ctx, PGA_POPREPL_BEST);
    
    PGASetCrossoverProb(ctx, 0.0);
    PGASetMutationOrCrossoverFlag(ctx, PGA_TRUE);
    PGASetMaxGAIterValue(ctx, 100);
    
    PGASetUp(ctx);
    PGARun(ctx, EvalName);
    PGADestroy(ctx);

    MPI_Finalize();
}


/*  Function to randomly initialize a PGA_DATATYPE_CHARACTER string using
 *  all printable ASCII characters for the range.
 */
void N_InitString(PGAContext *ctx, int p, int pop) {
    int               i;
    
    for(i=0; i<PGAGetStringLength(ctx); i++)
	PGASetCharacterAllele(ctx, p, pop, i, 
			      PGARandomInterval(ctx, 32, 126));
}


/*  Function to muatate a PGA_DATATYPE_CHARACTER string.  This is done
 *  by simply picking allele locations, and replacing whatever was there
 *  with a new value.  Again, legal values are all printable ASCII characters.
 */
int N_Mutation(PGAContext *ctx, int p, int pop, double mr) {
    int               i, count=0;
    
    for(i=0; i<PGAGetStringLength(ctx); i++)
	if (PGARandomFlip(ctx, mr)) {
	    PGASetCharacterAllele(ctx, p, pop, i,
				  PGARandomInterval(ctx, 32, 126));
            count++;
	}
    return(count);
}


int N_StopCond(PGAContext *ctx) {
    int   done, best;

    done = PGACheckStoppingConditions(ctx);

    best = PGAGetBestIndex(ctx, PGA_OLDPOP);
    if ((done == PGA_FALSE) && 
	(PGAGetEvaluation(ctx, best, PGA_OLDPOP) ==
	 PGAGetStringLength(ctx)))
	done = PGA_TRUE;

    return(done);
}

    
/*  Evaluate the string.  A highly fit string will have many of
 *  the characters matching Name.
 */
double EvalName(PGAContext *ctx, int p, int pop) {
    int     i, count;
    
    count = 0;
    for (i=PGAGetStringLength(ctx)-1; i>=0; i--) {
	if (PGAGetCharacterAllele(ctx, p, pop, i) == Name[i])
	    count++;
    }
    
    return((double)count);
}

