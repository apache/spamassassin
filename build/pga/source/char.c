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
 *     FILE: char.c: This file contains the routines specific to the
 *                    character datatype.
 *
 *     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
 *              Brian P. Walenz
 *****************************************************************************/

#include <pgapack.h>

/*U****************************************************************************
   PGASetCharacterAllele - sets the value of an allele in a
   PGA_DATATYPE_CHARACTER string.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in
      i   - allele index
      val - character value to set the allele to

   Outputs:
      The allele is changed by side-effect.

   Example:
      Copies the alleles from member p in PGA_OLDPOP to member q in PGA_NEWPOP.
      Assumes the strings are of the same length.
      
      PGAContext *ctx;
      int p, q, i;
      :
      for (i=PGAGetStringLength(ctx)-1; i>=0; i--)
          PGASetCharacterAllele(ctx, q, PGA_NEWPOP, i,
                                PGAGetCharacterAllele(ctx, p, PGA_OLDPOP, i))

****************************************************************************U*/
void PGASetCharacterAllele (PGAContext *ctx, int p, int pop, int i, char value)
{
    PGAIndividual *ind;

    PGADebugEntered("PGASetCharacterAllele");
    PGACheckDataType("PGASetCharacterAllele", PGA_DATATYPE_CHARACTER);
 
    ind = PGAGetIndividual ( ctx, p, pop );
    ((PGACharacter *)ind->chrom)[i] = value;
    
    PGADebugExited("PGASetCharacterAllele");
}

/*U****************************************************************************
   PGAGetCharacterAllele: returns the value of character allele in a
   PGA_DATATYPE_CHARACTER string

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in
      i   - allele index

   Outputs:
      The value of allele i in string p.

   Example:
      Copies the alleles from member p in PGA_OLDPOP to member q in PGA_NEWPOP.
      Assumes the strings are of the same length.

      PGAContext *ctx;
      int p, q, i;
      :
      for (i=PGAGetStringLength(ctx, p, PGA_NEWPOP)-1; i>=0; i--)
          PGASetCharacterAllele(ctx, q, PGA_NEWPOP, i,
                                PGAGetCharacterAllele(ctx, p, PGA_OLDPOP, i))

****************************************************************************U*/
char PGAGetCharacterAllele (PGAContext *ctx, int p, int pop, int i)
{
     PGAIndividual *ind;

    PGADebugEntered("PGAGetCharacterAllele");
     PGACheckDataType("PGAGetCharacterAllele", PGA_DATATYPE_CHARACTER);

     ind = PGAGetIndividual ( ctx, p, pop );

    PGADebugExited("PGAGetCharacterAllele");

     return (((PGACharacter *)ind->chrom)[i]);
}


/*U****************************************************************************
  PGASetCharacterInitType - sets a flag to specify whether the character
  strings will be exclusively lowercase, exclusively uppercase, or a mixure
  of both cases.  Legal flags are PGA_CINIT_UPPER, PGA_CINIT_LOWER, and
  PGA_CINIT_MIXED.  Default is PGA_CINIT_LOWER.

  Category: Initialization

  Inputs:
     ctx   - context variable
     value - symbolic constant specifying which case

  Outputs:

  Example:
     Set program to generate exclusively uppercase letters

     PGAContext *ctx;
     :
     PGASetCharacterInitType(ctx, PGA_CINIT_UPPER);

****************************************************************************U*/
void PGASetCharacterInitType(PGAContext *ctx, int value)
{
    PGADebugEntered("PGASetCharacterInitType");
     PGACheckDataType("PGASetCharacterInitType", PGA_DATATYPE_CHARACTER);

     switch (value)
     {
     case PGA_CINIT_UPPER:
     case PGA_CINIT_LOWER:
     case PGA_CINIT_MIXED:
          ctx->init.CharacterType = value;
          break;
     default:
          PGAError(ctx, "PGASetCharacterInitType: Invalid case type:",
                   PGA_FATAL, PGA_INT, (void *)&value);
          break;
     }

    PGADebugExited("PGASetCharacterInitType");
}

/*I****************************************************************************
   PGACharacterCreateString - Allocate memory for a string of type PGACharacter

   Inputs:
      ctx      - context variable
      p        - string index
      pop      - symbolic constant of the population string p is in
      initflag - A true/false flag used in conjunction with ctx->ga.RandomInit
                 to initialize the string either randomly or set to zero

   Outputs:
      Member p in population pop is allocated and initialized.

   Example:
      Allocates memory and assigns the address of the allocated memory to
      the string field (ind->chrom) of the individual.  Additionally, the
      string is initialized to zero.

      PGAContext *ctx;
      int p;
      :
      PGACharacterCreateString( ctx, p, PGA_NEWPOP, PGA_FALSE );

****************************************************************************I*/
void PGACharacterCreateString (PGAContext *ctx, int p, int pop, int InitFlag)
{
    int i, fp;
    PGACharacter *c;
    PGAIndividual *new = PGAGetIndividual(ctx, p, pop);
    
    PGADebugEntered("PGACharacterCreateString");
    
    new->chrom = (void *)malloc(ctx->ga.StringLen * sizeof(PGACharacter));
    if (new->chrom == NULL)
	PGAError(ctx, "PGACharacterCreateString: No room to allocate "
		 "new->chrom", PGA_FATAL, PGA_VOID, NULL);
    c = (PGACharacter *)new->chrom;
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
    
    PGADebugExited("PGACharacterCreateString");
}

/*I****************************************************************************
   PGACharacterMutation - randomly mutates a character-valued gene with a
   specified probability. This routine is called from PGAMutation.

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population string p is in
      mr  - probability of mutating an character-valued gene

   Outputs:
      Returns the number of mutations

   Example:
      PGAContext *ctx;
      int p;
      int NumMutations;
      :
      NumMutations = PGACharacterMutation(ctx, p, PGA_NEWPOP, 0.01);
****************************************************************************I*/
int PGACharacterMutation( PGAContext *ctx, int p, int pop, double mr )
{
     PGACharacter *c;
     int i, j;
     int count = 0;

    PGADebugEntered("PGACharacterMutation");

     c = (PGACharacter *)PGAGetIndividual(ctx, p, pop)->chrom;
     for(i=0; i<ctx->ga.StringLen; i++)
          if ( PGARandomFlip(ctx, mr) )       /* randomly choose an allele   */
          {
               switch (ctx->init.CharacterType)
               {
               case PGA_CINIT_LOWER:
                    c[i] = PGARandomInterval(ctx, 'a', 'z');
                    break;
               case PGA_CINIT_UPPER:
                    c[i] = PGARandomInterval(ctx, 'A', 'Z');
                    break;
               case PGA_CINIT_MIXED:
                    j = PGARandomInterval(ctx, 0, 51);
                    if (j < 26)
                         c[i] = 'A' + j;
                    else
                         c[i] = 'a' + j - 26;
                    break;
               }
               count++;
          }

    PGADebugExited("PGACharacterMutation");

     return (count);
}

/*I****************************************************************************
   PGACharacterOneptCrossover - performs one-point crossover on two parent
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
      PGACharacterOneptCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP );

****************************************************************************I*/
void PGACharacterOneptCrossover(PGAContext *ctx, int p1, int p2, int pop1,
                                int c1, int c2, int pop2)
{
     PGACharacter *parent1, *parent2, *child1, *child2;
     int i, xsite;

    PGADebugEntered("PGACharacterOneptCrossover");

     parent1 = (PGACharacter *)PGAGetIndividual(ctx, p1, pop1)->chrom;
     parent2 = (PGACharacter *)PGAGetIndividual(ctx, p2, pop1)->chrom;
     child1  = (PGACharacter *)PGAGetIndividual(ctx, c1, pop2)->chrom;
     child2  = (PGACharacter *)PGAGetIndividual(ctx, c2, pop2)->chrom;
     xsite = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);

     for(i=0;i<xsite;i++)
     {
          child1[i] = parent1[i];
          child2[i] = parent2[i];
     }

     for(i=xsite;i<ctx->ga.StringLen;i++)
     {
          child1[i] = parent2[i];
          child2[i] = parent1[i];
     }

    PGADebugExited("PGACharacterOneptCrossover");
}

/*I****************************************************************************
   PGACharacterTwoptCrossover - performs two-point crossover on two parent
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
      PGACharacterTwoptCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP );

****************************************************************************I*/
void PGACharacterTwoptCrossover( PGAContext *ctx, int p1, int p2, int pop1,
                              int c1, int c2, int pop2)
{
     PGACharacter *parent1, *parent2, *child1, *child2;
     int i, temp, xsite1, xsite2;

    PGADebugEntered("PGACharacterTwoptCrossover");

     parent1 = (PGACharacter *)PGAGetIndividual(ctx, p1, pop1)->chrom;
     parent2 = (PGACharacter *)PGAGetIndividual(ctx, p2, pop1)->chrom;
     child1  = (PGACharacter *)PGAGetIndividual(ctx, c1, pop2)->chrom;
     child2  = (PGACharacter *)PGAGetIndividual(ctx, c2, pop2)->chrom;
     /* pick two cross sites such that xsite2 > xsite1 */
     xsite1 = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);
     xsite2 = xsite1;
     while ( xsite2 == xsite1 )
          xsite2 = PGARandomInterval(ctx, 1,ctx->ga.StringLen-1);
     if ( xsite1 > xsite2 )
     {
          temp   = xsite1;
          xsite1 = xsite2;
          xsite2 = temp;
     }

     for(i=0;i<xsite1;i++)
     {
          child1[i] = parent1[i];
          child2[i] = parent2[i];
     }

     for(i=xsite1;i<xsite2;i++)
     {
          child1[i] = parent2[i];
          child2[i] = parent1[i];
     }

     for(i=xsite2;i<ctx->ga.StringLen;i++)
     {
          child1[i] = parent1[i];
          child2[i] = parent2[i];
     }

    PGADebugExited("PGACharacterTwoptCrossover");
}


/*I****************************************************************************
   PGACharacterUniformCrossover - performs uniform crossover on two parent
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
      PGACharacterUniformCrossover( ctx, m, d, PGA_OLDPOP, s, b, PGA_NEWPOP );

****************************************************************************I*/
void PGACharacterUniformCrossover(PGAContext *ctx, int p1, int p2, int pop1,
                                int c1, int c2, int pop2)
{
     PGACharacter *parent1, *parent2, *child1, *child2;
     int i;

    PGADebugEntered("PGACharacterUniformCrossover");

     parent1 = (PGACharacter *)PGAGetIndividual(ctx, p1, pop1)->chrom;
     parent2 = (PGACharacter *)PGAGetIndividual(ctx, p2, pop1)->chrom;
     child1  = (PGACharacter *)PGAGetIndividual(ctx, c1, pop2)->chrom;
     child2  = (PGACharacter *)PGAGetIndividual(ctx, c2, pop2)->chrom;

     for(i=0;i<ctx->ga.StringLen;i++)
          if ( parent1[i] == parent2[i] )
          {
               child1[i] = parent1[i];
               child2[i] = parent2[i];
          }
          else if (PGARandomFlip(ctx, ctx->ga.UniformCrossProb))
          {
               child1[i] = parent1[i];
               child2[i] = parent2[i];
          }
          else
          {
               child1[i] = parent2[i];
               child2[i] = parent1[i];
          }

    PGADebugExited("PGACharacterUniformCrossover");
}

/*I****************************************************************************
   PGACharacterPrintString - writes a character-valued string to a file.

   Inputs:
      ctx - context variable
      fp  - file pointer to file to write the string to
      p   - index of the string to write out
      pop - symbolic constant of the population string p is in

   Outputs:

   Example:
      Write string s to stdout.

      PGAContext *ctx;
      int p;
      :
      PGACharacterPrintString( ctx, stdout, p, PGA_NEWPOP );

****************************************************************************I*/
void PGACharacterPrintString ( PGAContext *ctx, FILE *fp, int p, int pop)
{
    PGACharacter *c;
    int           i, pos, len;

    PGADebugEntered("PGACharacterPrintString");

    c = (PGACharacter *)PGAGetIndividual(ctx, p, pop)->chrom;
    len = PGAGetStringLength(ctx);

    pos = 0;
    while (len > 0) {
      fprintf(fp, "#%5d: [", pos);
      for (i=0; i<50 && len>0; i++,len--,c++)
	fputc(*c, fp);
      pos+=50;
      fprintf(fp, "]\n");
    }
    fprintf(fp, "\n");
    
    PGADebugExited("PGACharacterPrintString");
}

/*I****************************************************************************
   PGACharacterCopyString - Copy one character-valued string to another
   Assumes the strings are of the same length.

   Inputs:
      ctx - context variable
      p1   - string to copy
      pop1 - symbolic constant of population containing string p1
      p2   - string to copy p1 to
      pop2 - symbolic constant of population containing string p2

   Outputs:

   Example:
      Copy character string x to y (both are implicitly assumed to be the same
      length)

      PGAContext *ctx;
      int x, y;
      :
      PGACharacterCopyString ( ctx, x, PGA_OLDPOP, y, PGA_NEWPOP );

****************************************************************************I*/
void PGACharacterCopyString (PGAContext *ctx, int p1, int pop1, int p2,
                             int pop2)
{
     void *source, *dest;
     int len;

    PGADebugEntered("PGACharacterCopyString");

     source = PGAGetIndividual(ctx, p1, pop1)->chrom;
     dest   = PGAGetIndividual(ctx, p2, pop2)->chrom;
     len    = PGAGetStringLength(ctx);
     memcpy(dest, source, len * sizeof(PGACharacter));

    PGADebugExited("PGACharacterCopyString");
}

/*I****************************************************************************
   PGACharacterDuplicate - Returns true if string p1 in pop1 is a dublicate
   of string p2 in pop2, else returns false.
   Assumes the strings are the same length.

   Inputs:
      ctx - context variable
      p1   - string index of the first string to compare
      pop1 - symbolic constant of the population string p1 is in
      p2   - string index of the second string to compare
      pop2 - symbolic constant of the population string p2 is in

   Outputs:
      Returns true if strings are duplicates.

   Example:
      Compare string x with y to see if they are duplicates

      PGAContext *ctx;
      int x, y;
      :
      if ( PGACharacterDuplicate( ctx, x, PGA_NEWPOP, y, PGA_NEWPOP ) )
          printf("strings are duplicates\n");

****************************************************************************I*/
int PGACharacterDuplicate( PGAContext *ctx, int p1, int pop1, int p2, int pop2)
{
     void *a, *b;
     int len;

    PGADebugEntered("PGACharacterDuplicate");

     a = PGAGetIndividual(ctx, p1, pop1)->chrom;
     b = PGAGetIndividual(ctx, p2, pop2)->chrom;
     len = PGAGetStringLength(ctx);

    PGADebugExited("PGACharacterDuplicate");

     return (!memcmp(a, b, len * sizeof(PGACharacter)));
}

/*I****************************************************************************
   PGACharacterInitString - randomly initialize a string of type PGACharacter

   Inputs:
      ctx   - context variable
      p   - index of string to randomly initialize
      pop - symbolic constant of the population string p is in

   Outputs:

   Example:
      PGAContext *ctx;
      int p;
      :
      PGACharacterInitString ( ctx, p, PGA_NEWPOP );

****************************************************************************I*/
void PGACharacterInitString(PGAContext *ctx, int p, int pop)
{
     int len, i, j;
     PGACharacter *c;

    PGADebugEntered("PGACharacterInitString");

     len = ctx->ga.StringLen;
     c = (PGACharacter *)PGAGetIndividual(ctx, p, pop)->chrom;
     switch (ctx->init.CharacterType)
     {
     case PGA_CINIT_LOWER:
          for (i = 0; i < len; i++)
               c[i] = PGARandomInterval(ctx, 'a', 'z');
          break;
     case PGA_CINIT_UPPER:
          for (i = 0; i < len; i++)
               c[i] = PGARandomInterval(ctx, 'A', 'Z');
          break;
     case PGA_CINIT_MIXED:
          for (i = 0; i < len; i++)
          {
               j = PGARandomInterval(ctx, 0, 51);
               if (j < 26)
                    c[i] = 'A' + j;
               else
                    c[i] = 'a' + j - 26;
          }
          break;
     }
    PGADebugExited("PGACharacterInitString");
}

/*I****************************************************************************
  PGACharacterBuildDatatype - Build an MPI_Datatype for a character string.

  Inputs:
      ctx  - context variable
      p    - index of the string to build a datatype from
      pop  - symbolic constant of the population string p is in

  Outputs:
      MPI_Datatype

  Example:
      Called only by MPI routines.  Not for user consumption.

****************************************************************************I*/
MPI_Datatype PGACharacterBuildDatatype(PGAContext *ctx, int p, int pop)
{

     int            counts[4];      /* Number of elements in each
                                       block (array of integer) */
     MPI_Aint       displs[4];      /* byte displacement of each
                                       block (array of integer) */
     MPI_Datatype   types[4];       /* type of elements in each block (array
                                       of handles to datatype objects) */
     MPI_Datatype   individualtype; /* new datatype (handle) */
     PGAIndividual *traveller;      /* address of individual in question */

    PGADebugEntered("PGACharacterBuildDatatype");

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
     types[3]  = MPI_CHAR;

     MPI_Type_struct(4, counts, displs, types, &individualtype);
     MPI_Type_commit(&individualtype);

    PGADebugExited("PGACharacterBuildDatatype");

     return (individualtype);
}
