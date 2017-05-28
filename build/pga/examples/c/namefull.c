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
 *
 *  Be warned that duplicate checking will sometimes go into an infinite
 *  loop.
 */

#include "pgapack.h"

void   N_InitString (PGAContext *, int, int);
int    N_Mutation   (PGAContext *, int, int, double);
int    N_StopCond   (PGAContext *);
void   N_Crossover  (PGAContext *ctx, int, int, int, int, int, int);
int    N_Duplicate  (PGAContext *, int, int, int, int);
void   N_PrintString(PGAContext *, FILE *, int, int);
void   N_EndOfGen   (PGAContext *);
double EvalName     (PGAContext *, int, int);
void   GetStringParameter(char *, char *);

/*  Global, because we use it in EvalName.  */
char   Name[70];

void main(int argc, char **argv) {
    PGAContext *ctx;

    MPI_Init(&argc, &argv);

    /*  Rather than deal with standard io and strings, we'll just set
     *  this explicitly.
     */
    strcpy(Name, "David M. Levine, Philip L. Hallstrom, David M. Noelle, "
                 "Brian P. Walenz");

    ctx = PGACreate(&argc, argv, PGA_DATATYPE_CHARACTER, strlen(Name),
		    PGA_MAXIMIZE);
    
    PGASetRandomSeed(ctx, 42);
    
    PGASetUserFunction(ctx, PGA_USERFUNCTION_INITSTRING, (void *)N_InitString);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION,   (void *)N_Mutation);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER,  (void *)N_Crossover);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_DUPLICATE,  (void *)N_Duplicate);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_STOPCOND,   (void *)N_StopCond);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING,(void *)N_PrintString);
    PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN,   (void *)N_EndOfGen);

    /*  We don't want to report anything.  */
    PGASetPrintFrequencyValue(ctx, 10000);
    PGASetPopSize(ctx, 100);
    PGASetNumReplaceValue(ctx, 90);
    PGASetPopReplaceType(ctx, PGA_POPREPL_BEST);
    PGASetNoDuplicatesFlag(ctx, PGA_TRUE);
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
    
    for(i=PGAGetStringLength(ctx)-1; i>=0; i--)
	PGASetCharacterAllele(ctx, p, pop, i, 
			      PGARandomInterval(ctx, 32, 126));
}



/*  Function to crossover two name strings.  Quite an interesting
 *  crossover, too.  Works like a normal uniform crossover, except
 *  that, if one of the strings matches the correct value, we set
 *  BOTH children to the correct value 50% of the time.
 */
void N_Crossover(PGAContext *ctx, int p1, int p2, int pop1, int c1, 
		 int c2, int pop2) {
    int           i, length;
    char          a, b;
	    
    length = PGAGetStringLength(ctx);

    for (i=0; i<length; i++) {
	a = PGAGetCharacterAllele(ctx, p1, pop1, i);
	b = PGAGetCharacterAllele(ctx, p2, pop1, i);
	if ((a == Name[i]) || (b == Name[i]))
	    a = b = Name[i];

	if (PGARandomFlip(ctx, 0.5) == PGA_TRUE) {
            PGASetCharacterAllele(ctx, c1, pop2, i, a);
            PGASetCharacterAllele(ctx, c2, pop2, i, b);
	} else {
            PGASetCharacterAllele(ctx, c1, pop2, i, b);
            PGASetCharacterAllele(ctx, c2, pop2, i, a);
        }
    }
}



/*  Function to compare two strings.  Strings are "equalivalent"
 *  if they match Name at the same alleles (and, thus, disagree at the
 *  same alleles).  We don't care what the disagreement is, just that
 *  it is there.
 *
 *  NOTE that because it is possible to get stuck in an infinite
 *  loop while doing duplicate checking on this string (assuming that
 *  the mutation operator is always beneficial), we ALWAYS return PGA_FALSE.
 *  The code is left as an example (and for testing).
 */
int N_Duplicate(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    int          i, match;
    char         a, b, c;
    
    match = PGA_TRUE;

    for (i=PGAGetStringLength(ctx)-1; match && i>=0; i--) {
	a = PGAGetCharacterAllele(ctx, p1, pop1, i);
	b = PGAGetCharacterAllele(ctx, p2, pop2, i);
	c = Name[i];
	if (((a == c) && (b != c)) || ((a != c) && (b == c))) 
	    match = PGA_FALSE;
    }

    return(match);
}


/*  Function to muatate a PGA_DATATYPE_CHARACTER string.  This is done
 *  by simply picking allele locations and replacing whatever was there.
 *  Again, legal values are all printable ASCII characters.
 */
int N_Mutation(PGAContext *ctx, int p, int pop, double mr) {
    int               i, count;

    count = 0;
    for(i=PGAGetStringLength(ctx)-1; i>=0; i--)
	if (PGAGetCharacterAllele(ctx, p, pop, i) != Name[i]) {
	    if (PGARandomFlip(ctx, mr) == PGA_TRUE) {
		PGASetCharacterAllele(ctx, p, pop, i,
				      PGARandomInterval(ctx, 32, 126));
		count++;
	    }
	}
    return(count);
}


/*  Function to print a string.  Since fortran does NOT support
 *  C file handles, we just print normally.  If we we're in C,
 *  we would print to the file "file".
 */
void N_PrintString(PGAContext *ctx, FILE *file, int p, int pop) {
    int          i;
    char         string[71];

    for (i=PGAGetStringLength(ctx)-1; i>=0; i--)
	string[i] = PGAGetCharacterAllele(ctx, p, pop, i);
    string[70] = 0;

    fprintf(file," :%s:\n", string);
}


/*  Function to check "doneness" of the GA.  We check the iteration
 *  count (by calling PGACheckStoppingConditions), then check if we have found
 *  the string yet.
 */
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



/*  After each generation, this routine is called.  What is done here,
 *  is to print the best string in our own format, then check if the
 *  best string is close to the correct value.  If it is, duplicate
 *  checking is tunred off.  This is critical, as the mutation operator
 *  will not degrade a string, so when the strings get near the correct
 *  solution, they all become duplicates, but none can be changed!
 *
 *  Other applications have done such things as send the best string 
 *  to another process to be visualized.  For here, we just call our
 *  print string function to print the best string.
 */
void N_EndOfGen(PGAContext *ctx) {
    int best;

    best = PGAGetBestIndex(ctx, PGA_NEWPOP);
    N_PrintString(ctx, stdout, best, PGA_NEWPOP);

    if (PGAGetEvaluation(ctx, best, PGA_NEWPOP) >=
	PGAGetStringLength(ctx)-10) 
	PGASetNoDuplicatesFlag(ctx, PGA_FALSE);
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

