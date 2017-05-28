/*
COPYRIGHT

The following is a notice of limited availability of the code, and disclaimer
which must be included in the prologue of the code and in all source listings
of the code.

(C) COPYRIGHT 2008 University of Chicago

Permission is hereby granted to use, reproduce, prepare derivative works, and
to redistribute to others. This software was authored by:

D. Levine
Mathematics and Computer Science Division 
Argonne National Laboratory Group

with programming assistance of participants in Argonne National 
Laboratory's SERS program.

GOVERNMENT LICENSE

Portions of this material resulted from work developed under a
U.S. Government Contract and are subject to the following license: the
Government is granted for itself and others acting on its behalf a paid-up,
nonexclusive, irrevocable worldwide license in this computer software to
reproduce, prepare derivative works, and perform publicly and display
publicly.

DISCLAIMER

This computer code material was prepared, in part, as an account of work
sponsored by an agency of the United States Government. Neither the United
States, nor the University of Chicago, nor any of their employees, makes any
warranty express or implied, or assumes any legal liability or responsibility
for the accuracy, completeness, or usefulness of any information, apparatus,
product, or process disclosed, or represents that its use would not infringe
privately owned rights.
*/

/*****************************************************************************
*     FILE: integer.c: This file contains the routines specific to the integer
*                      data structure
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
   PGASetIntegerAllele - sets the value of a (integer) allele.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in
      i   - allele index
      val - integer value to set the allele to

   Outputs:

   Example:
      Set the value of the ith allele of string p in population PGA_NEWPOP
      to 64.

      PGAContext *ctx;
      int p, i;
      :
      PGASetIntegerAllele (ctx, p, PGA_NEWPOP, i, 64)

****************************************************************************U*/
void PGASetIntegerAllele (PGAContext *ctx, int p, int pop, int i, int value)
{
    PGAIndividual *ind;
    PGAInteger     *chrom;

    PGADebugEntered("PGASetIntegerAllele");
    PGACheckDataType("PGASetIntegerAllele", PGA_DATATYPE_INTEGER);

    ind = PGAGetIndividual ( ctx, p, pop );
    chrom = (PGAInteger *)ind->chrom;
    chrom[i] = value;

    PGADebugExited("PGASetIntegerAllele");
}

/*U****************************************************************************
   PGAGetIntegerAllele - Returns the value of allele i of member p in
   population pop.  Assumes the data type is PGA_DATATYPE_INTEGER.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in
      i   - allele index

   Outputs:

   Example:
      Returns the value of the ith integer allele of string p
      in population PGA_NEWPOP.

      PGAContext *ctx;
      int p, i, k;
      :
      k =  PGAGetIntegerAllele ( ctx, p, PGA_NEWPOP, i )

****************************************************************************U*/
int PGAGetIntegerAllele (PGAContext *ctx, int p, int pop, int i)
{
    PGAIndividual *ind;
    PGAInteger     *chrom;

    PGADebugEntered("PGAGetIntegerAllele");

    PGACheckDataType("PGAGetIntegerAllele", PGA_DATATYPE_INTEGER);

    ind = PGAGetIndividual ( ctx, p, pop );
    chrom = (PGAInteger *)ind->chrom;

    PGADebugExited("PGAGetIntegerAllele");

    return( (int) chrom[i] );
}

/*U****************************************************************************
  PGASetIntegerInitPermute - sets a flag to tell the initialization routines
  to set each integer-valued gene to a random permutation of the values given
  by an upper and lower bound.  The length of the interval must be the same
  as the string length.  This is the default strategy for initializing
  integer-valued strings. The default interval is [0,L-1] where L is the
  string length.  No string initialization is done by this call.

  Category: Initialization

  Inputs:
     ctx - context variable
     min - the lower bound of numbers used in the permutation
     max - the upper bound of numbers used in the permutation

  Outputs:

  Example:
      Set the initialization routines to set each gene to a random and
      unique value from the interval $[500,599]$.

      PGAContext *ctx;
      :
      PGASetIntegerInitPermute(ctx, 500, 599)}

****************************************************************************U*/
void PGASetIntegerInitPermute ( PGAContext *ctx, int min, int max)
{
     int i, range;

    PGADebugEntered("PGASetIntegerInitPermute");
    PGAFailIfSetUp("PGASetIntegerInitPermute");
    PGACheckDataType("PGASetIntegerInitPermute", PGA_DATATYPE_INTEGER);

     range = max - min + 1;
     if (max <= min)
          PGAError(ctx, "PGASetIntegerInitPermute: max does not exceed min:",
                   PGA_FATAL, PGA_INT, (void *) &max);
     else if (range != ctx->ga.StringLen) {
          PGAError(ctx, "PGASetIntegerInitPermute: range of:",
                   PGA_FATAL, PGA_INT, (void *) &range);
          PGAError(ctx, "PGASetIntegerInitPermute: does not equal "
                   "string length:", PGA_FATAL, PGA_INT,
                    (void *) &(ctx->ga.StringLen));
     }
     else
     {
          ctx->init.IntegerType = PGA_IINIT_PERMUTE;
          for (i = 0; i < ctx->ga.StringLen; i++)
          {
               ctx->init.IntegerMin[i] = min;
               ctx->init.IntegerMax[i] = max;
          }
     }

    PGADebugExited("PGASetIntegerInitPermute");
}

/*U****************************************************************************
  PGASetIntegerInitRange - sets a flag to tell the initialization routines to
  set each integer-valued gene to a value chosen randomly from the interval
  given by an upper and lower bound.  No string initialization is done by
  this call.

  Category: Initialization

  Inputs:
     ctx - context variable
     min - array of lower bounds that define the interval the gene is
           initialized from
     max - array of upper bounds that define the interval the gene is
           initialized from

  Outputs:

  Example:
      Set the initialization routines to select a value for gene i
      uniformly randomly from the interval [0,i].  Assumes all strings
      are of the same length.

      PGAContext *ctx;
      int *low, *high, stringlen, i;
      :
      stringlen = PGAGetStringLength(ctx);
      low  = (int *) malloc(stringlen*sizeof(int));
      high = (int *) malloc(stringlen*sizeof(int));
      for(i=0;i<stringlen;i++) {
          low[i]  = 0;
          high[i] = i
      }
      PGASetIntegerInitRange(ctx, low, high);

****************************************************************************U*/
void PGASetIntegerInitRange (PGAContext *ctx, int *min, int *max)
{
     int i;

     PGADebugEntered("PGASetIntegerInitRange");
     PGAFailIfSetUp("PGASetIntegerInitRange");
     PGACheckDataType("PGASetIntegerInitRange", PGA_DATATYPE_INTEGER);

     for (i = 0; i < ctx->ga.StringLen; i++)
     {
        if (max[i] < min[i])
            PGAError(ctx, "PGASetIntegerInitRange: Lower bound exceeds upper "
                    "bound for allele #", PGA_FATAL, PGA_INT, (void *) &i);
        else {
            ctx->init.IntegerMin[i] = min[i];
            ctx->init.IntegerMax[i] = max[i];
        }
     }
     ctx->init.IntegerType = PGA_IINIT_RANGE;

     PGADebugExited("PGASetIntegerInitRange");
}

/*U***************************************************************************
  PGAGetIntegerInitType - returns the type of scheme used to randomly
  initialize strings of data type PGA_DATATYPE_INTEGER.

   Category: Initialization

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the scheme used to initialize integer strings

   Example:
      PGAContext *ctx;
      int inittype;
      :
      inittype = PGAGetIntegerInitType(ctx);
      switch (inittype) {
      case PGA_IINIT_PERMUTE:
          printf("Data Type = PGA_IINIT_PERMUTE\n");
          break;
      case PGA_IINIT_RANGE:
          printf("Data Type = PGA_IINIT_RANGE\n");
          break;
      }

***************************************************************************U*/
int PGAGetIntegerInitType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetIntegerInitType");
    PGAFailIfNotSetUp("PGAGetIntegerInitType");
    PGACheckDataType("PGAGetIntegerInitType", PGA_DATATYPE_INTEGER);

    PGADebugExited("PGAGetIntegerInitType");

    return(ctx->init.IntegerType);
}

/*U***************************************************************************
   PGAGetMinIntegerInitValue - returns the minimum of the range of integers
   used to randomly initialize integer strings.

   Category: Initialization

   Inputs:
      ctx - context variable

   Outputs:
      The minimum of the range of integers used to randomly initialize
      integer strings

   Example:
      PGAContext *ctx;
      int min;
      :
      min = PGAGetMinIntegerInitValue(ctx);

***************************************************************************U*/
int PGAGetMinIntegerInitValue (PGAContext *ctx, int i)
{
    PGADebugEntered("PGAGetMinIntegerInitValue");
    PGAFailIfNotSetUp("PGAGetMinIntegerInitValue");
    PGACheckDataType("PGASetIntegerAllele", PGA_DATATYPE_INTEGER);

    if (i < 0 || i >= ctx->ga.StringLen)
         PGAError(ctx, "PGAGetMinIntegerInitValue: Index out of range:",
                  PGA_FATAL, PGA_INT, (int *) &i);

    PGADebugExited("PGAGetMinIntegerInitValue");

    return(ctx->init.IntegerMin[i]);
}

/*U***************************************************************************
   PGAGetMaxIntegerInitValue - returns the maximum of the range of integers
   used to randomly initialize integer strings.

   Category: Initialization

   Inputs:
      ctx - context variable

   Outputs:
      The maximum of the range of integers used to randomly initialize
      integer strings.

   Example:
      PGAContext *ctx;
      int max;
      :
      max = PGAGetMaxIntegerInitValue(ctx);

***************************************************************************U*/
int PGAGetMaxIntegerInitValue (PGAContext *ctx, int i)
{
    PGADebugEntered("PGAGetMaxIntegerInitValue");
    PGAFailIfNotSetUp("PGAGetMaxIntegerInitValue");
    PGACheckDataType("PGAGetMaxIntegerInitValue", PGA_DATATYPE_INTEGER);

    if (i < 0 || i >= ctx->ga.StringLen)
         PGAError(ctx, "PGAGetMaxIntegerInitValue: Index out of range:",
                  PGA_FATAL, PGA_INT, (int *) &i);

    PGADebugExited("PGAGetMaxIntegerInitValue");

    return(ctx->init.IntegerMax[i]);
}


/*I****************************************************************************
   PGAIntegerCreateString - Allocate memory for a string of type PGAInteger,
   and initializes or clears the string according to initflag.

   Inputs:
      ctx      - context variable
      p        - string index
      pop      - symbolic constant of the population string p is in
      initflag - A true/false flag used in conjunction with ctx->ga.RandomInit
                 to initialize the string either randomly or set to zero

   Outputs:
      new      - a pointer set to the address of the allocated memory

   Example:
      Allocates and clears memory and assigns the address of the allocated
      memory to the string field (ind->chrom) of the individual.

      PGAContext *ctx;
      PGAIndividual *ind;
      :
      PGAIntegerCreateString( ctx, ind, PGA_FALSE );

****************************************************************************I*/
void PGAIntegerCreateString (PGAContext *ctx, int p, int pop, int InitFlag)
{
    int i, fp;
    PGAInteger *c;
    PGAIndividual *new = PGAGetIndividual(ctx, p, pop);

    PGADebugEntered("PGAIntegerCreateString");

    new->chrom = (void *)malloc(ctx->ga.StringLen * sizeof(PGAInteger));
    if (new->chrom == NULL)
	PGAError(ctx, "PGAIntegerCreateString: No room to allocate "
		 "new->chrom", PGA_FATAL, PGA_VOID, NULL);
    c = (PGAInteger *)new->chrom;
    if (InitFlag)
	if (ctx->fops.InitString) {
	    fp = ((p == PGA_TEMP1) || (p == PGA_TEMP2)) ? p : p+1;
	    (*ctx->fops.InitString)(&ctx, &fp, &pop);
	} else {
	    (*ctx->cops.InitString)(ctx, p, pop);
	}
    else
	for (i=0; i<ctx->ga.StringLen; i++)
	    c[i] = 0;
    
    PGADebugExited("PGAIntegerCreateString");
}

/*I****************************************************************************
   PGAIntegerMutation - randomly mutates an integer-valued gene with a
   specified probability. This routine is called from PGAMutation and must
   cast the void string pointer it is passed as the second argument.

   Inputs:
      ctx      - context variable
      p        - string index
      pop      - symbolic constant of the population string p is in
      mr       - probability of mutating an integer-valued gene

   Outputs:
      Returns the number of mutations

   Example:

****************************************************************************I*/
int PGAIntegerMutation( PGAContext *ctx, int p, int pop, double mr )
{
     PGAInteger *c;
     int i, j, temp;
     int count = 0;

     PGADebugEntered("PGAIntegerMutation");

     c = (PGAInteger *)PGAGetIndividual(ctx, p, pop)->chrom;
     for(i=0; i<ctx->ga.StringLen; i++) {

         /* randomly choose an allele   */
         if ( PGARandomFlip(ctx, mr) ) {

             /* apply appropriate mutation operator */
             switch (ctx->ga.MutationType) {
             case PGA_MUTATION_CONSTANT:
                 /* add or subtract from allele */             
                 if ( PGARandomFlip(ctx, .5) )
                      c[i] += ctx->ga.MutateIntegerValue;
                 else
                      c[i] -= ctx->ga.MutateIntegerValue;
                 break;
             case PGA_MUTATION_PERMUTE:
                 /* could check for j == i if we were noble */
	         /* edd: 16 Jun 2007  applying patch from Debian bug
                    report #333381 correcting an 'off-by-one' here
		    bu reducing StringLen by 1 */
                 j = PGARandomInterval(ctx, 0, ctx->ga.StringLen - 1);
                 temp = c[i];                 
                 c[i] = c[j];
                 c[j] = temp;                 
                 break;
             case PGA_MUTATION_RANGE:
                 c[i] = PGARandomInterval(ctx, ctx->init.IntegerMin[i],
                                               ctx->init.IntegerMax[i]);
                 break;
             default:
                  PGAError(ctx, "PGAIntegerMutation: Invalid value of "
                           "ga.MutationType:", PGA_FATAL, PGA_INT,
                           (void *) &(ctx->ga.MutationType));
                  break;
             }

             /* reset to min/max if bounded flag true and outside range */
             if( ctx->ga.MutateBoundedFlag == PGA_TRUE ) {
                 if( c[i] < ctx->init.IntegerMin[i])
                     c[i] = ctx->init.IntegerMin[i];
                 if( c[i] > ctx->init.IntegerMax[i])
                     c[i] = ctx->init.IntegerMax[i];
             }

             count++;
         }
     }
     PGADebugExited("PGAIntegerMutation");
     return(count);
}

/*I****************************************************************************
   PGAIntegerOneptCrossover - performs one-point crossover on two parent
   strings producing two children via side-effect

   Inputs:
      ctx  - context variable
      p1   - the first parent string
      p2   - the second parent string
      pop1 - symbolic constant of the population containing string p1 and p2
      c1   - the first child string
      c2   - the second child string
      pop2 - symbolic constant of the population to contain string c1 and c2

   Outputs:

   Example:
      Performs crossover on the two parent strings m and d, producing
      children s and b.

      PGAContext *ctx;
      int m, d, s, b;
      :
      PGAIntegerOneptCrossover(ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP);

****************************************************************************I*/
void PGAIntegerOneptCrossover(PGAContext *ctx, int p1, int p2, int pop1,
                              int c1, int c2, int pop2)
{
     PGAInteger *parent1 = (PGAInteger *)PGAGetIndividual(ctx, p1,
                                                          pop1)->chrom;
     PGAInteger *parent2 = (PGAInteger *)PGAGetIndividual(ctx, p2,
                                                          pop1)->chrom;
     PGAInteger *child1  = (PGAInteger *)PGAGetIndividual(ctx, c1,
                                                          pop2)->chrom;
     PGAInteger *child2  = (PGAInteger *)PGAGetIndividual(ctx, c2,
                                                          pop2)->chrom;
     int i, xsite;

    PGADebugEntered("PGAIntegerOneptCrossover");

    xsite = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);

    for(i=0;i<xsite;i++) {
        child1[i] = parent1[i];
        child2[i] = parent2[i];
    }

    for(i=xsite;i<ctx->ga.StringLen;i++) {
        child1[i] = parent2[i];
        child2[i] = parent1[i];
    }

    PGADebugExited("PGAIntegerOneptCrossover");
}


/*I****************************************************************************
   PGAIntegerTwoptCrossover - performs two-point crossover on two parent
   strings producing two children via side-effect

   Inputs:
      ctx  - context variable
      p1   - the first parent string
      p2   - the second parent string
      pop1 - symbolic constant of the population containing string p1 and p2
      c1   - the first child string
      c2   - the second child string
      pop2 - symbolic constant of the population to contain string c1 and c2

   Outputs:

   Example:
      Performs crossover on the two parent strings m and d, producing
      children s and b.

      PGAContext *ctx;
      int m, d, s, b;
      :
      PGAIntegerTwoptCrossover(ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP);

****************************************************************************I*/
void PGAIntegerTwoptCrossover( PGAContext *ctx, int p1, int p2, int pop1,
                              int c1, int c2, int pop2)
{
     PGAInteger *parent1 = (PGAInteger *)PGAGetIndividual(ctx, p1,
                                                          pop1)->chrom;
     PGAInteger *parent2 = (PGAInteger *)PGAGetIndividual(ctx, p2,
                                                          pop1)->chrom;
     PGAInteger *child1  = (PGAInteger *)PGAGetIndividual(ctx, c1,
                                                          pop2)->chrom;
     PGAInteger *child2  = (PGAInteger *)PGAGetIndividual(ctx, c2,
                                                          pop2)->chrom;
     int i, temp, xsite1, xsite2;

    PGADebugEntered("PGAIntegerTwoptCrossover");

    /* pick two cross sites such that xsite2 > xsite1 */
    xsite1 = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);
    xsite2 = xsite1;
    while ( xsite2 == xsite1 )
        xsite2 = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);
    if ( xsite1 > xsite2 ) {
        temp   = xsite1;
        xsite1 = xsite2;
        xsite2 = temp;
    }

    for(i=0;i<xsite1;i++) {
        child1[i] = parent1[i];
        child2[i] = parent2[i];
    }

    for(i=xsite1;i<xsite2;i++) {
        child1[i] = parent2[i];
        child2[i] = parent1[i];
    }

    for(i=xsite2;i<ctx->ga.StringLen;i++) {
        child1[i] = parent1[i];
        child2[i] = parent2[i];
    }

    PGADebugExited("PGAIntegerTwoptCrossover");
}


/*I****************************************************************************
   PGAIntegerUniformCrossover - performs uniform crossover on two parent
   strings producing two children via side-effect

   Inputs:
      ctx  - context variable
      p1   - the first parent string
      p2   - the second parent string
      pop1 - symbolic constant of the population containing string p1 and p2
      c1   - the first child string
      c2   - the second child string
      pop2 - symbolic constant of the population to contain string c1 and c2

   Outputs:

   Example:
      Performs crossover on the two parent strings m and d, producing
      children s and b.

      PGAContext *ctx;
      int m, d, s, b;
      :
      PGAIntegerUniformCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP);

****************************************************************************I*/
void PGAIntegerUniformCrossover(PGAContext *ctx, int p1, int p2, int pop1,
                                int c1, int c2, int pop2)
{
     PGAInteger *parent1 = (PGAInteger *)PGAGetIndividual(ctx, p1,
                                                          pop1)->chrom;
     PGAInteger *parent2 = (PGAInteger *)PGAGetIndividual(ctx, p2,
                                                          pop1)->chrom;
     PGAInteger *child1  = (PGAInteger *)PGAGetIndividual(ctx, c1,
                                                          pop2)->chrom;
     PGAInteger *child2  = (PGAInteger *)PGAGetIndividual(ctx, c2,
                                                          pop2)->chrom;
     int i;

    PGADebugEntered("PGAIntegerUniformCrossover");

    for(i=0;i<ctx->ga.StringLen;i++) {
        if ( parent1[i] == parent2[i] ) {
            child1[i] = parent1[i];
            child2[i] = parent2[i];
        }
        else {
            if(PGARandomFlip(ctx, ctx->ga.UniformCrossProb)) {
                child1[i] = parent1[i];
                child2[i] = parent2[i];
            }
            else {
                child1[i] = parent2[i];
                child2[i] = parent1[i];
            }
        }
    }

    PGADebugExited("PGAIntegerUniformCrossover");
}

/*I****************************************************************************
   PGAIntegerPrintString - writes an integer-valued string to a file.

   Inputs:
      ctx - context variable
      fp  - file pointer to file to write the string to
      p   - index of the string to write out
      pop - symbolic constant of the population string p is in

   Outputs:

   Example:
      Write member p in population PGA_NEWPOP to stdout.

      PGAContext *ctx;
      int  p;
      :
      PGAIntegerPrintString(ctx, stdout, p, PGA_NEWPOP);

****************************************************************************I*/
void PGAIntegerPrintString ( PGAContext *ctx, FILE *fp, int p, int pop)
{
    PGAInteger *c = (PGAInteger *)PGAGetIndividual(ctx, p, pop)->chrom;
    int i;

    PGADebugEntered("PGAIntegerPrintString");

    for(i = 0; i < ctx->ga.StringLen; i++)
    {
        switch ( i % 6 )
        {
        case 0:
            fprintf ( fp, "#%5d: [%8ld]",i,c[i]);
            break;
        case 1:
        case 2:
        case 3:
        case 4:
            fprintf ( fp, ", [%8ld]",c[i]);
            break;
        case 5:
            fprintf ( fp, ", [%8ld]",c[i]);
            if (i+1 < ctx->ga.StringLen)
                fprintf ( fp, "\n");
            break;
        }
    }
    fprintf ( fp, "\n" );

    PGADebugExited("PGAIntegerPrintString");
}

/*I****************************************************************************
   PGAIntegerCopyString - Copy one integer-valued string to another.

   Inputs:
      ctx - context variable
      p1   - string to copy
      pop1 - symbolic constant of population containing string p1
      p2   - string to copy p1 to
      pop2 - symbolic constant of population containing string p2

   Outputs:

   Example:

****************************************************************************I*/
void PGAIntegerCopyString (PGAContext *ctx, int p1, int pop1, int p2, int pop2)
{
    PGAInteger *source = (PGAInteger *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    PGAInteger *dest   = (PGAInteger *)PGAGetIndividual(ctx, p2, pop2)->chrom;
    int i;

    PGADebugEntered("PGAIntegerCopyString");

    for (i = 0; i < ctx->ga.StringLen; i++)
        dest[i] = source[i];

    PGADebugExited("PGAIntegerCopyString");
}

/*I****************************************************************************
   PGAIntegerDuplicate - Returns true if string a is a duplicate of
   string b, else returns false.

   Inputs:
      ctx - context variable
      p1   - string index of the first string to compare
      pop1 - symbolic constant of the population string p1 is in
      p2   - string index of the second string to compare
      pop2 - symbolic constant of the population string p2 is in

   Outputs:
      Returns true/false if strings are duplicates

   Example:

****************************************************************************I*/
int PGAIntegerDuplicate( PGAContext *ctx, int p1, int pop1, int p2, int pop2)
{
     PGAInteger *a = (PGAInteger *)PGAGetIndividual(ctx, p1, pop1)->chrom;
     PGAInteger *b = (PGAInteger *)PGAGetIndividual(ctx, p2, pop2)->chrom;
     int i;

    PGADebugEntered("PGAIntegerDuplicate");

     i = ctx->ga.StringLen-1;
     if (a[0] == b[0])
       for(; (i>0) && (a[i] == b[i]); i--);

    PGADebugExited("PGAIntegerDuplicate");

     return((i==0) ? PGA_TRUE : PGA_FALSE);
}

/*I****************************************************************************
   PGAIntegerInitString - randomly initialize a string of type PGAInteger

   Inputs:
      ctx - context variable
      p   - index of string to randomly initialize
      pop - symbolic constant of the population string p is in

   Outputs:

   Example:

****************************************************************************I*/
void PGAIntegerInitString(PGAContext *ctx, int p, int pop)
{
     int *list;
     int len, i, j;
     PGAInteger *c = (PGAInteger *)PGAGetIndividual(ctx, p, pop)->chrom;

     PGADebugEntered("PGAIntegerInitString");

     len = ctx->ga.StringLen;

     switch (ctx->init.IntegerType)
     {
     case PGA_IINIT_PERMUTE:
          list = (int *)malloc(sizeof(int) * len);
          if (list == NULL)
               PGAError(ctx, "PGAIntegerInitString: No room to allocate list",
                        PGA_FATAL, PGA_VOID, NULL);
          j = ctx->init.IntegerMin[0];
          for (i = 0; i < len; i++)
               list[i] = j++;
          for (i = 0; i < len; i++)
          {
               j = PGARandomInterval ( ctx, 0, len - i - 1 );
               c[i] = list[j];
               list[j] = list[len - i - 1];
          }
          free(list);
          break;
     case PGA_IINIT_RANGE:
          for (i = 0; i < len; i++)
               c[i] = PGARandomInterval(ctx, ctx->init.IntegerMin[i],
                                        ctx->init.IntegerMax[i]);
          break;
     }

     PGADebugExited("PGAIntegerInitString");
}

/*I****************************************************************************
  PGAIntegerBuildDatatype - Build an MPI datatype for a string of type
  PGA_DATATYPE_INTEGER.

  Inputs:
      ctx - context variable
      p   - index of string to randomly initialize
      pop - symbolic constant of the population string p is in

  Outputs:

  Example:

****************************************************************************I*/
MPI_Datatype PGAIntegerBuildDatatype(PGAContext *ctx, int p, int pop)
{

     int            counts[4];      /* Number of elements in each
                                       block (array of integer) */
     MPI_Aint       displs[4];      /* byte displacement of each
                                       block (array of integer) */
     MPI_Datatype   types[4];       /* type of elements in each block (array
                                       of handles to datatype objects) */
     MPI_Datatype   individualtype; /* new datatype (handle) */
     PGAIndividual *traveller;      /* address of individual in question */

    PGADebugEntered("PGAIntegerBuildDatatype");

     traveller = PGAGetIndividual(ctx, p, pop);
     MPI_Address(&traveller->evalfunc, &displs[0]);
     counts[0] = 1;
     types[0]  = MPI_DOUBLE;

     MPI_Address(&traveller->fitness, &displs[1]);
     counts[1] = 1;
     types[1]  = MPI_DOUBLE;

     MPI_Address(&traveller->evaluptodate, &displs[2]);
     counts[2] = 1;
     types[2]  = MPI_INT;

     MPI_Address(traveller->chrom, &displs[3]);
     counts[3] = ctx->ga.StringLen;
     types[3]  = MPI_LONG;

     MPI_Type_struct(4, counts, displs, types, &individualtype);
     MPI_Type_commit(&individualtype);

    PGADebugExited("PGAIntegerBuildDatatype");

     return (individualtype);
}
