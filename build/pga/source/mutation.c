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
*     File: mutation.c: This file contains the data structure neutral mutation
*                       routines
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGAMutate - This routine performs mutation on a string.  The type of mutation
  depends on the data type.  Refer to the user guide for data-specific
  examples.

  Category: Operators

  Inputs:
      ctx  - context variable
      p   - index of string to mutate
      pop - symbolic constant of the population containing p

  Output:
      The number of mutations performed.  Member p in population pop is
      mutated by side-effect.

  Example:
      Mutate the best string in the population, until 10 or more mutations
      have occured.

      PGAContext *ctx;
      int p, count = 0;
      :
      p = PGAGetBestIndex(ctx, PGA_NEWPOP);
      while (count < 10) {
          count += PGAMutate(ctx, p, PGA_NEWPOP);
      }

****************************************************************************U*/
int PGAMutate(PGAContext *ctx, int p, int pop)
{
    double mr;
    int count;
    int fp;
    PGADebugEntered("PGAMutate");
    
    mr    = ctx->ga.MutationProb;
    if (ctx->fops.Mutation) {
	fp = ((p == PGA_TEMP1) || (p == PGA_TEMP2)) ? p : p+1;
        count = (*ctx->fops.Mutation)(&ctx, &fp, &pop, &mr);
    } else {
	count = (*ctx->cops.Mutation)( ctx, p, pop, mr );
    }
    
    if ( count > 0 )
	PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_FALSE);
    
    PGADebugExited("PGAMutate");
    
    return(count);
}

/*U****************************************************************************
   PGASetMutationType - set type of mutation to use. Only effects integer-
   and real-valued strings.  Binary-valued strings are always complemented.
   In character-valued strings, one alphabetic character is replaced with
   another chosen uniformly randomly.  The alphabetic characters will be lower,
   upper, or mixed case depending on how the strings were initialized.

   Valid choices are PGA_MUTATION_CONSTANT (Real/Integer), PGA_MUTATION_RANGE
   (Real/Integer), PGA_MUTATION_UNIFORM (Real), PGA_MUTATION_GAUSSIAN (Real),
   and PGA_MUTATION_PERMUTE (Integer).  The default for integer-valued strings
   conforms to how the strings were initialized.  The default for real-valued
   strings is PGA_MUTATION_GAUSSIAN.  See the user guide for more details.

   Category: Operators

   Inputs:
      ctx           - context variable
      mutation_type - symbolic constant to specify the mutation type

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMutationType(ctx, PGA_MUTATION_UNIFORM);

****************************************************************************U*/
void PGASetMutationType( PGAContext *ctx, int mutation_type)
{
    PGADebugEntered("PGASetMutationType");

     switch (mutation_type)
     {
     case PGA_MUTATION_CONSTANT:
     case PGA_MUTATION_RANGE:
     case PGA_MUTATION_UNIFORM:
     case PGA_MUTATION_GAUSSIAN:
     case PGA_MUTATION_PERMUTE:
          ctx->ga.MutationType = mutation_type;
          break;
     default:
          PGAError ( ctx,
                    "PGASetMutationType: Invalid value of mutation_type:",
                    PGA_FATAL, PGA_INT, (void *) &mutation_type);
          break;
     }

    PGADebugExited("PGASetMutationType");
}

/*U***************************************************************************
   PGAGetMutationType - Returns the type of mutation used

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the type of mutation specified

   Example:
      PGAContext *ctx;
      int mutatetype;
      :
      mutatetype = PGAGetMutationType(ctx);
      switch (mutatetype) {
      case PGA_MUTATION_CONSTANT:
          printf("Mutation Type = PGA_MUTATION_CONSTANT\n");
          break;
      case PGA_MUTATION_RANGE:
          printf("Mutation Type = PGA_MUTATION_RANGE\n");
          break;
      case PGA_MUTATION_UNIFORM:
          printf("Mutation Type = PGA_MUTATION_UNIFORM\n");
          break;
      case PGA_MUTATION_GAUSSIAN:
          printf("Mutation Type = PGA_MUTATION_GAUSSIAN\n");
          break;
      case PGA_MUTATION_PERMUTE:
          printf("Mutation Type = PGA_MUTATION_PERMUTE\n");
          break;
      }

***************************************************************************U*/
int PGAGetMutationType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMutationType");
    PGAFailIfNotSetUp("PGAGetMutationType");
    PGADebugExited("PGAGetMutationType");
    return(ctx->ga.MutationType);
}

/*U****************************************************************************
   PGASetMutationRealValue - Set multiplier to mutate PGA_DATATYPE_REAL
   strings with.  The use of this value depends on the type of mutation
   being used.  The default value is 0.1.  See the user guide for more details.

   Category: Operators

   Inputs:
      ctx - context variable
      val - the mutation value to use for Real mutation

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMutationRealValue(ctx,50.0);

****************************************************************************U*/
void PGASetMutationRealValue( PGAContext *ctx, double val)
{
    PGADebugEntered("PGASetMutationRealValue");

    if (val < 0.0)
        PGAError ( ctx,
                  "PGASetMutationRealValue: Invalid value of val:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &val);
    else
        ctx->ga.MutateRealValue = val;

    PGADebugExited("PGASetMutationRealValue");
}

/*U***************************************************************************
   PGAGetMutationRealValue - Returns the value of the multiplier used to
   mutate PGA_DATATYPE_REAL strings with.

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      The value of the multiplier used to mutate PGA_DATATYPE_REAL strings with

   Example:
      PGAContext *ctx;
      double val;
      :
      val = PGAGetMutationRealValue(ctx);

***************************************************************************U*/
double PGAGetMutationRealValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMutationRealValue");
    PGAFailIfNotSetUp("PGAGetMutationRealValue");

    PGADebugExited("PGAGetMutationRealValue");

    return(ctx->ga.MutateRealValue);
}

/*U****************************************************************************
   PGASetMutationIntegerValue - Set multiplier to mutate PGA_DATATYPE_INTEGER
   strings with.  The use of this value depends on the type of mutation
   being used.  The default value is 1.  See the user guide for more details.

   Category: Operators

   Inputs:
      ctx - context variable
      val - the mutation value to use for Integer mutation

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMutationIntegerValue(ctx, 5);

****************************************************************************U*/
void PGASetMutationIntegerValue( PGAContext *ctx, int val)
{
    PGADebugEntered("PGASetMutationIntegerValue");

    if (val < 0.0)
        PGAError ( ctx,
                  "PGASetMutationIntegerValue: Invalid value of val:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &val);
    else
        ctx->ga.MutateIntegerValue = val;

    PGADebugExited("PGASetMutationIntegerValue");
}


/*U***************************************************************************
  PGAGetMutationIntegerValue - Returns the value of the multiplier
  used to mutate PGA_DATATYPE_INTEGER strings with.

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      The value of the multiplier used to mutate PGA_DATATYPE_INTEGER
      strings with

   Example:
      PGAContext *ctx;
      int ival;
      :
      ival = PGAGetMutationIntegerValue(ctx);

***************************************************************************U*/
int PGAGetMutationIntegerValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMutationIntegerValue");
    PGAFailIfNotSetUp("PGAGetMutationIntegerValue");

    PGADebugExited("PGAGetMutationIntegerValue");

    return(ctx->ga.MutateIntegerValue);
}

/*U****************************************************************************
   PGASetMutationBoundedFlag - If this flag is set to PGA_TRUE, then for
   Integer and Real strings whenever a gene is mutated, if it underflows
   (overflows) the lower (upper)bound it is reset to the lower (upper) bound.
   In this way all allele values remain within the range the integer strings
   were initialized on.  If this flag is PGA_FALSE (the default), the alleles
   may take any values.

   Category: Operators

   Inputs:
      ctx  - context variable
      flag - either PGA_TRUE or PGA_FALSE

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMutationBoundedFlag(ctx, PGA_TRUE);

****************************************************************************U*/
void PGASetMutationBoundedFlag(PGAContext *ctx, int val)
{
    PGADebugEntered("PGASetMutationBoundedFlag");

    switch (val)
    {
    case PGA_TRUE:
    case PGA_FALSE:
         ctx->ga.MutateBoundedFlag = val;
         break;
    default:
         PGAError(ctx, "PGASetMutationBoundedFlag: Invalid value:",
                  PGA_FATAL, PGA_INT, (void *) &val);
         break;
    }

    PGADebugExited("PGASetMutationBoundedFlag");
}


/*U****************************************************************************
   PGAGetMutationBoundedFlag - returns PGA_TRUE or PGA_FALSE to indicate
   whether mutated integer strings remain in the range specified when
   initialized with PGASetIntegerInitRange.

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      PGA_TRUE if restricted to the given range, otherwise PGA_FALSE.

   Example:
      PGAContext *ctx;
      int val;
      :
      val = PGAGetMutationBoundedFlag(ctx);

****************************************************************************U*/
int PGAGetMutationBoundedFlag(PGAContext *ctx)
{
    PGADebugEntered  ("PGAGetMutationBoundedFlag");
    PGAFailIfNotSetUp("PGAGetMutationBoundedFlag");
    PGADebugExited   ("PGAGetMutationBoundedFlag");
    return (ctx->ga.MutateBoundedFlag);
}



/*U****************************************************************************
   PGASetMutationProb - Specifies the probability that a given allele will
   be mutated.  If this is called without calling PGASetMutationType(), the
   default mutation type is PGA_MUTATION_FIXED.  The default probability is
   the reciprocal of the string length.

   Category: Operators

   Inputs:
      ctx - context variable
      p   - the mutation probability

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMutationProb(ctx,0.001);

****************************************************************************U*/
void PGASetMutationProb(PGAContext *ctx, double mutation_prob)
{
    PGADebugEntered("PGASetMutationProb");

    if ((mutation_prob < 0.0) || (mutation_prob > 1.0))
        PGAError ( ctx,
                  "PGASetMutationProb: Invalid value of mutation_prob:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &mutation_prob);
    else
        ctx->ga.MutationProb = mutation_prob;

    PGADebugExited("PGASetMutationProb");
}

/*U***************************************************************************
   PGAGetMutationProb - Returns the probability of mutation.

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      The mutation probability

   Example:
      PGAContext *ctx;
      double pm;
      :
      pm = PGAGetMutateProb(ctx);

***************************************************************************U*/
double PGAGetMutationProb (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMutationProb");
    PGAFailIfNotSetUp("PGAGetMutationProb");
    PGADebugExited("PGAGetMutationProb");
    return(ctx->ga.MutationProb);
}
