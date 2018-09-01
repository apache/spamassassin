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
*     FILE: pop.c: This file contains systme routines that act on entire
*                  populations.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
   PGASortPop - Creates an (internal) array of indices according to one of
   three criteria.  If PGA_POPREPL_BEST is used (the default) the array is
   sorted from most fit to least fit.  If PGA_POPREPL_RANDOM_REP is
   used the indices in the array are selected randomly with replacement.
   If PGA_POPREPL_RANDOM_NOREP is used the indices in the array are selected
   randomly without replacement.  The function PGASetPopReplaceType() is used
   to specify which strategy is used.  The indices of the sorted population
   members may then be accessed from the internal array via
   PGAGetSortedPopIndex().  This routine is typically used during population
   replacement.

   Category: Generation

   Inputs:
       ctx      - context variable
       popindex - symbolic constant of the population from which to create
                  the srted array.

   Output:
      An inteneral array of indices sorted according to one of three
      criteria is created.

   Example:
      Copy the five best strings from the old population into the new
      population.  The rest of the new population will be created by
      recombination, and is not shown.

      PGAContext *ctx;
      int i,j;
      :
      PGASetPopReplaceType(ctx,PGA_POPREPL_BEST)
      :
      PGASortPop(ctx, PGA_OLDPOP);
      for ( i=0; i < 5; i++) {
          j = PGAGetSortedPopIndex(ctx, i);
      PGACopyIndividual (ctx, j, PGA_OLDPOP, i, PGA_NEWPOP);
      :

****************************************************************************U*/
void PGASortPop ( PGAContext *ctx, int pop )
{
    int i,j;
    PGADebugEntered("PGASortPop");
    switch (ctx->ga.PopReplace) {
    case PGA_POPREPL_BEST:
            switch ( pop ) {
            case PGA_OLDPOP:
                for (i = 0 ; i < ctx->ga.PopSize ; i++ ) {
                    ctx->ga.sorted[i] = i;
                    ctx->scratch.dblscratch[i] = ctx->ga.oldpop[i].fitness;
                };
                break;
            case PGA_NEWPOP:
                for (i = 0 ; i < ctx->ga.PopSize ; i++ ) {
                    ctx->ga.sorted[i] = i;
                    ctx->scratch.dblscratch[i] = ctx->ga.newpop[i].fitness;
                };
                break;
            default:
                PGAError( ctx,
                         "PGASort: Invalid value of pop:",
                         PGA_FATAL,
                         PGA_INT,
                         (void *) &pop );
                break;
            };
            PGADblHeapSort ( ctx, ctx->scratch.dblscratch, ctx->ga.sorted,
                            ctx->ga.PopSize );
            break;
    case PGA_POPREPL_RANDOM_REP:
        if ((pop != PGA_OLDPOP) && (pop != PGA_NEWPOP))
            PGAError( ctx,
                     "PGASort: Invalid value of pop:",
                      PGA_FATAL,
                      PGA_INT,
                      (void *) &pop );
        for (i = 0; i < ctx->ga.PopSize; i++) {
            ctx->scratch.intscratch[i] = i;
        };
        for (i = 0; i < ctx->ga.PopSize; i++) {
            j = PGARandomInterval ( ctx, 0, ctx->ga.PopSize-1 );
            ctx->ga.sorted[i] = ctx->scratch.intscratch[j];
        };
        break;
    case PGA_POPREPL_RANDOM_NOREP:
        if ((pop != PGA_OLDPOP) && (pop != PGA_NEWPOP))
            PGAError( ctx,
                     "PGASort: Invalid value of pop:",
                      PGA_FATAL,
                      PGA_INT,
                      (void *) &pop );
        for (i = 0; i < ctx->ga.PopSize; i++) {
            ctx->scratch.intscratch[i] = i;
        };
        for (i = 0; i < ctx->ga.PopSize; i++) {
            j = PGARandomInterval ( ctx, 0, ctx->ga.PopSize-i-1 );
            ctx->ga.sorted[i] = ctx->scratch.intscratch[j];
            ctx->scratch.intscratch[j] =
                ctx->scratch.intscratch[ctx->ga.PopSize-i-1];
        };
        break;
    }
    PGADebugExited("PGASortPop");
}


/*U***************************************************************************
   PGAGetPopSize - Returns the population size

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The population size

   Example:
      PGAContext *ctx;
      int popsize;
      :
      popsize = PGAGetPopSize(ctx);

***************************************************************************U*/
int PGAGetPopSize (PGAContext *ctx)
{
    PGADebugEntered("PGAGetPopSize");
    PGAFailIfNotSetUp("PGAGetPopSize");

    PGADebugExited("PGAGetPopSize");

    return(ctx->ga.PopSize);
}

/*U***************************************************************************
   PGAGetNumReplaceValue - Returns the maximum number of strings to replace
   each generation.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The maximum number number of strings to replace each generation

   Example:
      PGAContext *ctx;
      int numreplace;
      :
      numreplace = PGAGetNumReplaceValue(ctx);

***************************************************************************U*/
int PGAGetNumReplaceValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetNumReplaceValue");
    PGAFailIfNotSetUp("PGAGetNumReplaceValue");

    PGADebugExited("PGAGetNumReplaceValue");

    return(ctx->ga.NumReplace);
}

/*U***************************************************************************
   PGAGetPopReplaceType - returns the symbolic constant used to determine
   which strings to copy from the old population to the new population.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The symbolic constant of the replacement strategy.

   Example:
      PGAContext *ctx;
      int popreplace;
      :
      popreplace = PGAGetPopReplaceType(ctx);
      switch (popreplace) {
      case PGA_POPREPL_BEST:
          printf("Replacement Strategy = PGA_POPREPL_BEST\n");
          break;
      case PGA_POPREPL_RANDOM_REP:
          printf("Replacement Strategy = PGA_POPREPL_RANDOM_REP\n");
          break;
      case PGA_POPREPL_RANDOM_NOREP:
          printf("Replacement Strategy = PGA_POPREPL_RANDOM_NOREP\n");
          break;
      }

****************************************************************************U*/
int PGAGetPopReplaceType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetPopReplaceType");
    PGAFailIfNotSetUp("PGAGetPopRelaceType");

    PGADebugExited("PGAGetPopReplaceType");

    return(ctx->ga.PopReplace);
}


/*U****************************************************************************
   PGAGetSortedPopIndex - returns a population string index from the array
   created by PGASortPop().

   Category: Generation

   Inputs:
       ctx      - context variable
       n        - specified which index element is to be returned.

   Output:
       A population string index from the array created by PGASortPop

   Example:
      Copy the five best strings from the old population into the new
      population.  The rest of the new population will be created by
      recombination, and is not shown.

      PGAContext *ctx;
      int i,j;
      :
      PGASetPopReplaceType(ctx,PGA_POPREPL_BEST)
      PGASortPop(ctx, PGA_OLDPOP);
      for ( i=0; i < 5; i++) {
          j = PGAGetSortedPopIndex(ctx, i);
      PGACopyIndividual (ctx, j, PGA_OLDPOP, i, PGA_NEWPOP);
      :

****************************************************************************U*/
int PGAGetSortedPopIndex ( PGAContext *ctx, int n )
{
     int temp;

    PGADebugEntered("PGAGetSortedPopIndex");
     if (n >= 0 && n < ctx->ga.PopSize )
          temp = ctx->ga.sorted[n];
     else
          PGAError( ctx, "PGAGetSorted: Invalid value of n:",
                   PGA_FATAL, PGA_INT, (void *) &n );

    PGADebugExited("PGAGetSortedPopIndex");

     return (temp);
}

/*U****************************************************************************
   PGASetPopSize - Specifies the size of the genetic algorithm population.
   The default population size is 100.

   Category: Generation

   Inputs:
      ctx     - context variable
      popsize - the genetic algorithm population size to use

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetPopSize(ctx, 200);

****************************************************************************U*/
void PGASetPopSize (PGAContext *ctx, int popsize)
{

    PGADebugEntered("PGASetPopSize");
    PGAFailIfSetUp("PGASetPopSize");

    if (popsize < 1 || popsize % 2)
        PGAError( ctx, "PGASetPopSize: Invalid value of popsize:",
                  PGA_FATAL, PGA_INT, (void *) &popsize );
    else
        ctx->ga.PopSize = popsize;

    PGADebugExited("PGASetPopSize");
}



/*U****************************************************************************
   PGASetNumReplaceValue - specifies the number of new strings to create each
   generation.  The default is ten percent of the population size

   Category: Generation

   Inputs:
      ctx         - context variable
      pop_replace - the genetic algorithm population size to use

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetNumReplaceValue(ctx, 35);

****************************************************************************U*/
void PGASetNumReplaceValue( PGAContext *ctx, int pop_replace)
{
    PGADebugEntered("PGASetNumReplaceValue");

    if (pop_replace < 0)
      PGAError( ctx,
               "PGASetNumReplaceValue: Invalid value of pop_replace:",
                PGA_FATAL, PGA_INT, (void *) &pop_replace );
    else
        ctx->ga.NumReplace = pop_replace;

    PGADebugExited("PGASetNumReplaceValue");
}




/*U****************************************************************************
   PGASetPopReplaceType - Choose method of sorting strings to copy from old
   population to new population.  Valid choices are PGA_POPREPL_BEST,
   PGA_POPREPL_RANDOM_NOREP, or PGA_POPREPL_RANDOM_REP for copying the best
   strings, or  random string, with or without replacement, respectively,
   from the old population into the new population. The default is
   PGA_POPREPL_BEST.

   Category: Generation

   Inputs:
      ctx         - context variable
      pop_replace - symbolic constant to specify the population replacement
                    strategy

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetPopReplaceType(ctx, PGA_POPREPL_RANDOM_NOREP);

****************************************************************************U*/
void PGASetPopReplaceType( PGAContext *ctx, int pop_replace)
{
    PGADebugEntered("PGASetPopReplaceType");

    switch (pop_replace) {
    case PGA_POPREPL_BEST:
    case PGA_POPREPL_RANDOM_NOREP:
    case PGA_POPREPL_RANDOM_REP:
        ctx->ga.PopReplace = pop_replace;
        break;
    default:
        PGAError ( ctx,
                  "PGASetPopReplaceType: Invalid value of pop_replace:",
                   PGA_FATAL, PGA_INT, (void *) &pop_replace);
        break;
    }

    PGADebugExited("PGASetPopReplaceType");
}
