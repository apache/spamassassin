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
*     File: binary.c: This file contains routines specific to the binary
*                     datatype.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
   PGASetBinaryAllele - sets a binary allele to the specified value.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in
      i   - allele index
      val - binary value (either 1 or 0) to set the allele to

   Outputs:
      The allele is changed by side-effect.

   Example:
      Copies the alleles from member p in PGA_OLDPOP to member q PGA_NEWPOP.
      Assumes strings are of the same length.

      PGAContext *ctx;
      int p, q, i;
      :
      for (i=PGAGetStringLength(ctx)-1; i>=0; i--)
          PGASetBinaryAllele(ctx, q, PGA_NEWPOP, i,
                             PGAGetBinaryAllele(ctx, p, PGA_OLDPOP, i))

****************************************************************************U*/
void PGASetBinaryAllele ( PGAContext *ctx, int p, int pop, int i, int val )
{
    int windex;        /* index of the computer word allele i is in      */
    int bix;           /* bit position in word chrom[windex] of allele i */
    PGAIndividual *ind;
    PGABinary *chrom;

    PGADebugEntered("PGASetBinaryAllele");
    PGACheckDataType("PGAGetBinaryAllele", PGA_DATATYPE_BINARY);

    INDEX( windex,bix,i,WL );
    ind = PGAGetIndividual ( ctx, p, pop );
    chrom = (PGABinary *)ind->chrom;
    if ( val == 0 )
        UNSET( bix, chrom[windex] );
    else
        SET( bix, chrom[windex] );

    PGADebugExited("PGASetBinaryAllele");
}

/*U****************************************************************************
   PGAGetBinaryAllele - returns the value of a (binary) allele in a
   PGA_DATATYPE_BINARY string

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in
      i   - allele index

   Outputs:
      The value of the ith allele of string p in population pop.

   Example:
      Copies the alleles from member p in PGA_OLDPOP to member q PGA_NEWPOP.
      Assumes the strings are of the same length.

      PGAContext *ctx;
      int p, q, i;
      :
      for (i=PGAGetStringLength(ctx)-1; i>=0; i--)
          PGASetBinaryAllele(ctx, q, PGA_NEWPOP, i,
                             PGAGetBinaryAllele(ctx, p, PGA_OLDPOP, i))

****************************************************************************U*/
int PGAGetBinaryAllele ( PGAContext *ctx, int p, int pop, int i )
{

    int windex;        /* index of the computer word allele i is in      */
    int bix;           /* bit position in word chrom[windex] of allele i */
    PGAIndividual *ind;
    PGABinary *chrom;

    PGADebugEntered("PGAGetBinaryAllele");
    PGACheckDataType("PGAGetBinaryAllele", PGA_DATATYPE_BINARY);

    INDEX( windex,bix,i,WL );
    ind = PGAGetIndividual ( ctx, p, pop );
    chrom = (PGABinary *)ind->chrom;

    PGADebugExited("PGAGetBinaryAllele");
    return( BIT(bix, chrom[windex]) != 0 );
}

/*U****************************************************************************
   PGASetBinaryInitProb - specify the probability of initializing an allele to
   "1" when creating a PGA_DATATYPE_BINARY string.  The default value is 0.5.

   Category: Initialization

   Inputs:
      ctx - context variable
      p   - the binary initialization probability

   Outputs:
      None

   Example:
      Set approximately 1 percent of all binary alleles to "1" when randomly
      initializing the population.

      PGAContext *ctx;
      :
      PGASetBinaryInitProb(ctx, 0.01);

****************************************************************************U*/
void PGASetBinaryInitProb ( PGAContext *ctx, double probability )
{
    PGADebugEntered("PGASetBinaryInitProb");
    PGAFailIfSetUp("PGASetBinaryInitProb");
    PGACheckDataType("PGASetBinaryInitProb", PGA_DATATYPE_BINARY);

     if ( (probability <= 1.0) && (probability >= 0.0) )
          ctx->init.BinaryProbability = probability;
     else
          PGAError( ctx, "PGASetBinaryInitProb: Invalid value of probability:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &probability );

    PGADebugExited("PGASetBinaryInitProb");
}

/*U***************************************************************************
   PGAGetBinaryInitProb - Returns the probability that an allele will be
   randomly initialized to "1" in a PGA_DATATYPE_BINARY string.

   Category: Initialization

   Inputs:
      ctx - context variable

   Outputs:
      The probability that a bit will be randomly initialized to one

   Example:
      PGAContext *ctx;
      double prob;
      :
      prob = PGAGetBinaryInitProb(ctx);

***************************************************************************U*/
double PGAGetBinaryInitProb (PGAContext *ctx)
{
    PGADebugEntered("PGAGetBinaryInitProb");
    PGAFailIfNotSetUp("PGAGetBinaryInitProb");
    PGACheckDataType("PGAGetBinaryInitProb", PGA_DATATYPE_BINARY);

    PGADebugExited("PGAGetBinaryInitProb");
    return(ctx->init.BinaryProbability);
}


/*I****************************************************************************
   PGABinaryCreateString - Allocate a PGA_DATATYPE_BINARY string for member
   p of population pop.  If initflag is PGA_TRUE, randomly initialize all
   alleles, otherwise clear all alleles.

   Inputs:
      ctx      - context variable
      p        - string index
      pop      - symbolic constant of the population string p is in
      initflag - a flag, if set, randomly initialize, else clear alleles

   Outputs:
      Member p in population pop is allocated and initialized.

   Example:
      Allocates and clears alleles for all strings in PGA_NEWPOP

      PGAContext *ctx;
      int p;
      :
      for (p=PGAGetPopSize(ctx)-1; p>=0; p--)
          PGABinaryCreateString( ctx, p, PGA_NEWPOP, PGA_FALSE );

****************************************************************************I*/
void PGABinaryCreateString(PGAContext *ctx, int p, int pop, int initflag)
{
    int i, fp;
    PGABinary *s;
    PGAIndividual *new = PGAGetIndividual(ctx, p, pop);
    
    PGADebugEntered("PGABinaryCreateString");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR, "PGABinaryCreateString",
		  "initflag = ", PGA_INT, (void *) &initflag );
    
    new->chrom = (void *)malloc(ctx->ga.tw * sizeof(PGABinary));
    if (new->chrom == NULL)
	PGAError(ctx, "PGABinaryCreateString: No room to allocate "
		 "new->chrom", PGA_FATAL, PGA_VOID, NULL);
    
    s = (PGABinary *)new->chrom;
    if (initflag)
	if (ctx->fops.InitString) {
	    fp = ((p == PGA_TEMP1) || (p == PGA_TEMP2)) ? p : p+1;
            (*ctx->fops.InitString)(&ctx, &fp, &pop);
	} else {
	    (*ctx->cops.InitString)(ctx, p, pop);
	}
    else
	for ( i=0; i<ctx->ga.tw; i++ )
	    s[i] = 0;
    
    PGADebugExited("PGABinaryCreateString");
}

/*I****************************************************************************
   PGABinaryMutation - randomly mutates a bit with a specified probability.
   This routine is called from PGAMutation.

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant for the population string p is in
      mr  - probability of mutating (toggling) a bit

   Outputs:
      Returns the number of mutations

   Example:
      Mutates string p in population PGA_NEWPOP with a probability of 0.001
      for each bit.

      PGAContext *ctx;
      int p;
      :
      PGABinaryMutation( ctx, p, PGA_NEWPOP, .001 );

****************************************************************************I*/
int PGABinaryMutation( PGAContext *ctx, int p, int pop, double mr )
{
     int i,wi;
     int count = 0;
     PGABinary *c;

     PGADebugEntered("PGABinaryMutation");

     c = (PGABinary *)PGAGetIndividual(ctx, p, pop)->chrom;
     for(wi=0; wi<ctx->ga.fw; wi++)
          for(i=0; i<WL; ++i)
               if ( PGARandomFlip(ctx, mr) )
               {
                    TOGGLE(i,c[wi]);
                    count++;
               }

     /* clean up the partial word if eb > 0 */
     if (ctx->ga.eb > 0 )
          for(i=0;i<ctx->ga.eb;++i)
               if ( PGARandomFlip(ctx, mr) )
               {
                    TOGGLE(i,c[ctx->ga.fw]);
                    count++;
               }

    PGADebugExited("PGABinaryMutation");
    return(count);

}

/*I****************************************************************************
   PGABinaryOneptCrossover - performs one-point crossover on two parent strings
   to create two children via side-effect

   Inputs:
      ctx  - context variable
      p1   - the first parent string
      p2   - the second parent string
      pop1 - symbolic constant of the population containing p1 and p2
      c1   - the first child string
      c2   - the second child string
      pop2 - symbolic constant of the population containing c1 and c2

   Outputs:
      None.

   Example:
      Performs crossover on the two parent strings m and d, producing
      children s and b.

      PGAContext *ctx;
      int m, d, s, b;
      :
      PGABinaryOneptCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP );

****************************************************************************I*/
void PGABinaryOneptCrossover(PGAContext *ctx, int p1, int p2, int pop1, int c1,
                             int c2, int pop2)
{
    PGABinary *parent1 = (PGABinary *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    PGABinary *parent2 = (PGABinary *)PGAGetIndividual(ctx, p2, pop1)->chrom;
    PGABinary *child1  = (PGABinary *)PGAGetIndividual(ctx, c1, pop2)->chrom;
    PGABinary *child2  = (PGABinary *)PGAGetIndividual(ctx, c2, pop2)->chrom;

    /*
      If the bits are numbered from 0 as follows:

      b   b   b   b   b   b   b   b          b  b
      0   1   2   3   4   5   6   7         30 31

      Then if the cross site is bit 5 (which is the sixth bit by our
      numbering scheme) we would get

      o   o   o   o   o   n   n   n          n  n
      0   1   2   3   4   5   6   7         30 31

      where o indicates the original bit and n is a new bit from the crossover
      operator.
    */

    PGABinary mask;
    int windex;   /* index of the word the crossover bit position is in */
    int bix;      /* bit position to perform crossover (mod WL)         */
    int i;
    int xsite;

    PGADebugEntered("PGABinaryOneptCrossover");

    xsite = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);

    INDEX(windex,bix,xsite,WL);

    for(i=0;i<windex;i++) {
        child1[i] = parent1[i];
        child2[i] = parent2[i];
    }

    mask = ~0;
    mask = mask >> bix;

    child1[windex] = (~mask & parent1[windex])|(mask & parent2[windex]);
    child2[windex] = (~mask & parent2[windex])|(mask & parent1[windex]);

    for(i=windex+1;i<ctx->ga.tw;i++) {
        child1[i] = parent2[i];
        child2[i] = parent1[i];
    }

    PGADebugExited("PGABinaryOneptCrossover");
}


/*I****************************************************************************
   PGABinaryTwoptCrossover - performs two-point crossover on two parent strings
   producing two children via side-effect

   Inputs:
      ctx  - context variable
      p1   - the first parent string
      p2   - the second parent string
      pop1 - symbolic constant of the population containing string p1 and p2
      c1   - the first child string
      c2   - the second child string
      pop2 - symbolic constant of the population to contain string c1 and c2

   Outputs:
      None.

   Example:
      Performs crossover on the two parent strings m and d, producing
      children s and b.

      PGAContext *ctx;
      int m, d, s, b;
      :
      PGABinaryTwoptCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP );

****************************************************************************I*/
void PGABinaryTwoptCrossover(PGAContext *ctx, int p1, int p2, int pop1, int c1,
                             int c2, int pop2)
{
    PGABinary *parent1 = (PGABinary *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    PGABinary *parent2 = (PGABinary *)PGAGetIndividual(ctx, p2, pop1)->chrom;
    PGABinary *child1  = (PGABinary *)PGAGetIndividual(ctx, c1, pop2)->chrom;
    PGABinary *child2  = (PGABinary *)PGAGetIndividual(ctx, c2, pop2)->chrom;

    PGABinary mask, mask1, mask2;
    int windex1, windex2;
    int bix1, bix2;
    int i;
    int xsite1, xsite2;
    int temp;

    PGADebugEntered("PGABinaryTwoptCrossover");

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

    INDEX(windex1,bix1,xsite1,WL);
    INDEX(windex2,bix2,xsite2,WL);

    if ( windex1 == windex2 ) {     /* both cross sites in the same word */

        for(i=0;i<windex1;i++) {
            child1[i] = parent1[i];
            child2[i] = parent2[i];
        }

        mask1 = ~0;
        if (bix1 == 0)
             mask1 = 0;
        else
             mask1 = mask1 << (WL-bix1);
        mask2 = ~0;
        mask2 = mask2 >> bix2;
        mask  = mask1 | mask2;

        child1[windex1] = (mask & parent1[windex1])|(~mask & parent2[windex1]);
        child2[windex1] = (mask & parent2[windex1])|(~mask & parent1[windex1]);

        for(i=windex1+1;i<ctx->ga.tw;i++) {
            child1[i] = parent1[i];
            child2[i] = parent2[i];
        }
    }
    else {                          /* cross sites in different words */

        for(i=0;i<windex1;i++) {
            child1[i] = parent1[i];
            child2[i] = parent2[i];
        }

        mask = ~0;
        mask = mask >> bix1;

        child1[windex1] = (~mask & parent1[windex1])|(mask & parent2[windex1]);
        child2[windex1] = (~mask & parent2[windex1])|(mask & parent1[windex1]);

        for(i=windex1+1; i<windex2; i++) {
            child1[i] = parent2[i];
            child2[i] = parent1[i];
        }

        mask = ~0;
        mask = mask >> bix2;

        child1[windex2] = (mask & parent1[windex2])|(~mask & parent2[windex2]);
        child2[windex2] = (mask & parent2[windex2])|(~mask & parent1[windex2]);

        for(i=windex2+1; i<ctx->ga.tw; i++) {
            child1[i] = parent1[i];
            child2[i] = parent2[i];
        }
    }

    PGADebugExited("PGABinaryTwoptCrossover");
}


/*I****************************************************************************
   PGABinaryUniformCrossover - performs uniform crossover on two parent strings
   producing two children via side-effect

   Inputs:
      ctx  - context variable
      p1   - the first parent string
      p2   - the second parent string
      pop1 - symbolic constant of the population containing string p1 and p2
      c1   - the first child string
      c2   - the second child string
      pop2 - symbolic constant of the population to contain string c1 and c2

   Outputs:
      None.

   Example:
      Performs crossover on the two parent strings m and d, producing
      children s and b.

      PGAContext *ctx;
      int m, d, s, b;
      :
      PGABinaryUniformCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP );

****************************************************************************I*/
void PGABinaryUniformCrossover(PGAContext *ctx, int p1, int p2, int pop1,
                               int c1, int c2, int pop2)
{
     PGABinary *parent1 = (PGABinary *)PGAGetIndividual(ctx, p1, pop1)->chrom;
     PGABinary *parent2 = (PGABinary *)PGAGetIndividual(ctx, p2, pop1)->chrom;
     PGABinary *child1  = (PGABinary *)PGAGetIndividual(ctx, c1, pop2)->chrom;
     PGABinary *child2  = (PGABinary *)PGAGetIndividual(ctx, c2, pop2)->chrom;
     PGABinary mask;
     int j,wi;

    PGADebugEntered("PGABinaryUniformCrossover");

    for(wi=0;wi<ctx->ga.tw;wi++) {
        if ( parent1[wi] == parent2[wi] ) {
            child1[wi] = parent1[wi];
            child2[wi] = parent2[wi];
        }
        else {
            mask = 0;
            for (j=0;j<WL;j++)
                if(PGARandomFlip(ctx, ctx->ga.UniformCrossProb))
                    SET(j,mask);
            child1[wi] = (mask & parent1[wi])|(~mask & parent2[wi]);
            child2[wi] = (mask & parent2[wi])|(~mask & parent1[wi]);
        }
    }

    PGADebugExited("PGABinaryUniformCrossover");
}

/*I****************************************************************************
   PGABinaryPrintString - writes a bit string to a file.

   Inputs:
      ctx - context variable
      fp  - file pointer to file to write bit string to
      p   - index of the string to write out
      pop - symbolic constant of the population string p is in

   Outputs:
      None.

   Example:
      Write string s to stdout.

      PGAContext *ctx;
      int s;
      :
      PGABinaryPrintString( ctx, stdout, s, PGA_NEWPOP );

****************************************************************************I*/
void PGABinaryPrintString( PGAContext *ctx, FILE *fp, int p, int pop )
{
     PGABinary *c = (PGABinary *)PGAGetIndividual(ctx, p, pop)->chrom;
     int i;

     PGADebugEntered("PGABinaryPrintString");

     for( i=0; i<ctx->ga.fw; i++ ) {
          fprintf(fp,"[ ");
          PGABinaryPrint( ctx, fp, (c+i), WL );
          fprintf(fp," ]\n");
     }
     if ( ctx->ga.eb > 0 ) {
          fprintf(fp,"[ ");
          PGABinaryPrint( ctx, fp, (c+ctx->ga.fw), ctx->ga.eb );
          fprintf(fp," ]");
     }

     PGADebugExited("PGABinaryPrintString");
}

/*I****************************************************************************
   PGABinaryCopyString - Copy one bit string to another

   Inputs:
      ctx  - context variable
      p1   - string to copy
      pop1 - symbolic constant of population containing string p1
      p2   - string to copy p1 to
      pop2 - symbolic constant of population containing string p2

   Outputs:
      None.

   Example:
      Copy bit string x to y (both are implicitly assumed to have the same
      length).

      PGAContext *ctx;
      int x, y
      :
      PGABinaryCopyString ( ctx, x, PGA_OLDPOP, y, PGA_NEWPOP );

****************************************************************************I*/
void PGABinaryCopyString (PGAContext *ctx, int p1, int pop1, int p2, int pop2)
{
    PGABinary *source = (PGABinary *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    PGABinary *dest   = (PGABinary *)PGAGetIndividual(ctx, p2, pop2)->chrom;
    int i;

    PGADebugEntered("PGABinaryCopyString");

    for (i = ctx->ga.tw-1; i>=0; i--)
        dest[i] = source[i];

    PGADebugExited("PGABinaryCopyString");
}

/*I****************************************************************************
   PGABinaryDuplicate - Returns true if bit string a is a duplicate of bit
   string b, else returns false.

   Inputs:
      ctx  - context variable
      p1   - string index of the first string to compare
      pop1 - symbolic constant of the population string p1 is in
      p2   - string index of the second string to compare
      pop2 - symbolic constant of the population string p2 is in

   Outputs:
      Returns true/false if strings are duplicates

   Example:
      Compare bit string x with y and print a message if they are the same.

      PGAContext *ctx;
      int x, y;
      :
      if ( PGABinaryDuplicate( ctx, x, PGA_NEWPOP, y, PGA_NEWPOP ) )
          printf("strings are duplicates\n");

****************************************************************************I*/
int PGABinaryDuplicate( PGAContext *ctx, int p1, int pop1, int p2, int pop2)
{
     PGABinary *a = (PGABinary *)PGAGetIndividual(ctx, p1, pop1)->chrom;
     PGABinary *b = (PGABinary *)PGAGetIndividual(ctx, p2, pop2)->chrom;
     int wi;

     PGADebugEntered("PGABinaryDuplicate");

     wi = ctx->ga.tw-1;
     if (a[0] == b[0])
         for (; (wi>0) && (a[wi] == b[wi]); wi--);

     PGADebugExited("PGABinaryDuplicate");

     return((wi==0) ? PGA_TRUE : PGA_FALSE);
}

/*I****************************************************************************
   PGABinaryInitString - randomly initialize a string of type PGABinary

   Inputs:
      ctx - context variable
      p   - index of string to randomly initialize
      pop - symbolic constant of the population string p is in

   Outputs:

   Example:
      PGAContext *ctx;
      int p;
      :
      PGABinaryInitString ( ctx, p, PGA_NEWPOP );

****************************************************************************I*/
void PGABinaryInitString(PGAContext *ctx, int p, int pop)
{
     PGABinary *c = (PGABinary *)PGAGetIndividual(ctx, p, pop)->chrom;
     int i;
     int windex;        /* index of the computer word allele i is in      */
     int bix;           /* binary position in word chrom[windex] of allele i */

     PGADebugEntered("PGABinaryInitString");

     for (i = 0; i < ctx->ga.tw; i++)
          c[i] = 0;
     for (i = 0; i < ctx->ga.StringLen; i++)
     {
          INDEX(windex,bix,i,WL);
          if ( PGARandomFlip(ctx, ctx->init.BinaryProbability) )
               SET  ( bix, c[windex] );
     }

     PGADebugExited("PGABinaryInitString");
}


/*I****************************************************************************
  PGABinaryBuildDatatype - Build an MPI_Datatype for a binary string
  datatype.

  Inputs:
      ctx  - context variable
      p    - index of the string to build a datatype from
      pop  - symbolic constant of the population string p is in

  Outputs:
      MPI_Datatype.

  Example:
      Called only by MPI routines.  Not for user consumption.

****************************************************************************I*/
MPI_Datatype PGABinaryBuildDatatype(PGAContext *ctx, int p, int pop)
{

     int            counts[4];      /* Number of elements in each
                                       block (array of integer) */
     MPI_Aint       displs[4];      /* byte displacement of each
                                       block (array of integer) */
     MPI_Datatype   types[4];       /* type of elements in each block (array
                                       of handles to datatype objects) */
     MPI_Datatype   individualtype; /* new datatype (handle) */
     PGAIndividual *traveller;      /* address of individual in question */

     PGADebugEntered("PGABinaryBuildDatatype");

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
     counts[3] = ctx->ga.tw;
     types[3]  = MPI_UNSIGNED_LONG;

     MPI_Type_struct(4, counts, displs, types, &individualtype);
     MPI_Type_commit(&individualtype);

     PGADebugExited("PGABinaryBuildDatatype");

     return (individualtype);
}


/*I****************************************************************************
   PGABinaryHammingDistance - Returns the Hamming distance between two strings

   Inputs:
      ctx - context variable
      s1  - the first string to compare
      s2  - the second string to compare

   Outputs:
      The Hamming distance between two strings

   Example:
      Returns the Hamming distance between bit strings x and y.

      PGAContext *ctx;
      PGABinary *x, *y;
      int d;
      :
      d = PGABinaryHammingDistance( ctx, x, y );

****************************************************************************I*/
int PGABinaryHammingDistance ( PGAContext *ctx, PGABinary *s1, PGABinary *s2 )
{
    int        j, wi, distance;
    PGABinary  t1, t2, mask;

    PGADebugEntered("PGABinaryHammingDistance");

    distance = 0;
    for(wi=0; wi<ctx->ga.tw; wi++)  /* step through each word in the string */
        if ( s1[wi] != s2[wi] ) {   /* if equal, no bits are different      */
            /*fprintf(stdout,"s1[wi] = %x, s2[wi] = %x\n",s1[wi],s2[wi]);*/
            mask = 1;
            for(j=0;j<WL;++j) {     /* not equal, compare all bits          */
                /* Build bit mask in position j. Mask bit from each         */
                /* string into t1 and t2 and test if bits are the same      */
                t1 = s1[wi] & mask;
                t2 = s2[wi] & mask;
                /*fprintf(stdout,"mask = %u, t1 = %u, t2 = %u, j = %d, wi = %d\n",mask,t1,t2,j,wi);*/
                if ( t1 != t2 )
                    distance++;
                mask <<= 1;          /* shift mask 1 position */
            }
        }

    PGADebugExited("PGABinaryHammingDistance");

    return(distance);
}

/*I****************************************************************************
   PGABinaryPrint - writes a bit string to a file.  Puts the binary
   representation of the bit string pointed to by chrom into a character
   string and writes that out. Assumes the maximum length of string to
   print is WL, and that all bits are in the same word.

   Inputs:
      ctx   - context variable
      fp    - file to write the bit string to
      chrom - pointer to the bit string to write
      nb    - number of bits to write out

   Outputs:

   Example:
      Internal function.  Use PGABinaryPrintString to print a binary string.

****************************************************************************I*/
void PGABinaryPrint( PGAContext *ctx, FILE *fp, PGABinary *chrom, int nb )
{
     char *s, string[WL+1];
     PGABinary mask;
     int i;

     PGADebugEntered("PGABinaryPrint");

     mask = ((PGABinary)1)<<(WL-1);
     s = string;
     for(i=0; i<nb; mask>>=1,i++)              /* mask each bit and set the  */
          *s++ = (mask&(*chrom)?'1':'0');      /* appropriate character      */
     *s=0;                                     /* string terminator          */
     fprintf(fp, "%s", string);                /* print out character string */

     PGADebugExited("PGABinaryPrint");
}


