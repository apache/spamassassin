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
*     FILE: select.c: This file contains the routines that have to do with
*                     selection
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGASelect - performs genetic algorithm selection using either the default
  selection scheme or that specified with PGASetSelectType().  Valid selection
  methods are proportional, stochastic universal, tournament, or probabilistic
  tournament selection, PGA_SELECT_PROPORTIONAL, PGA_SELECT_SUS, 
  PGA_SELECT_TOURNAMENT, and PGA_SELECT_PTOURNAMENT, respectively.  This 
  function updates an internal array with the indices of members of popix 
  selected for recombination.  These indices may be accessed with 
  PGASelectNextIndex()

  Category: Operators

  Inputs:
    ctx   - context variable
    popix - symbolic constant of population to select from

  Outputs:
    An array used by PGASelectNextIndex() is created which contains the
    population indices of the selected individuals.

  Example:
    PGAContext *ctx,
    :
    PGASelect(ctx, PGA_OLDPOP);

****************************************************************************U*/
void PGASelect( PGAContext *ctx, int popix )
{
    int i;                   /* not to intefere with dummy argument        */
    int j;                   /* random number                              */
    int temp;                /* for shuffling selected indices US          */
    PGAIndividual *pop;      /* pointer to appropriate population          */

    PGADebugEntered("PGASelect");

    pop = PGAGetIndividual(ctx, 0, popix);

    switch (ctx->ga.SelectType) {

    case PGA_SELECT_PROPORTIONAL:  /* proportional selection             */
        for (i=0; i<ctx->ga.PopSize; i++)
            ctx->ga.selected[i] = PGASelectProportional( ctx, pop );
        break;
    case PGA_SELECT_SUS:           /* stochastic universal selection     */
        PGASelectSUS( ctx, pop );
        break;
    case PGA_SELECT_TOURNAMENT:    /* tournament selection               */
        for (i=0; i<ctx->ga.PopSize; i++)
            ctx->ga.selected[i] = PGASelectTournament( ctx, pop );
        break;
    case PGA_SELECT_PTOURNAMENT:   /* probabilistic tournament selection */
        for (i=0; i<ctx->ga.PopSize; i++)
            ctx->ga.selected[i] = PGASelectPTournament( ctx, pop );
        break;
    default:
        PGAError( ctx,
                 "PGASelect: Invalid value of SelectType:",
                  PGA_FATAL,
                  PGA_INT,
                  (void *) &(ctx->ga.SelectType) );
        break;
    }

    /* randomize selected string locations */
    for (i=0; i<ctx->ga.PopSize; i++) {
        j          = PGARandomInterval(ctx, 0,ctx->ga.PopSize-1);
        temp       = ctx->ga.selected[j];
        ctx->ga.selected[j] = ctx->ga.selected[i];
        ctx->ga.selected[i] = temp;
    }

    PGADebugExited("PGASelect");
}

/*U****************************************************************************
  PGASelectNextIndex - returns the index of next individual in
  internal array that contains the indices determined by PGASelect

  Category: Operators

  Inputs:
    ctx   - context variable

  Outputs:
    A population index for the next selected creature.

  Example:
    PGAContext *ctx;
    int l;
    :
    l = PGASelectNextIndex(ctx, PGA_OLDPOP);

****************************************************************************U*/
int PGASelectNextIndex ( PGAContext *ctx )
{
    PGADebugEntered("PGASelectNextIndex");

    if (ctx->ga.SelectIndex < ctx->ga.PopSize) {
	PGADebugExited("PGASelectNextIndex");
        return(ctx->ga.selected[ctx->ga.SelectIndex++]);
    }

    /*  Oops.  We never found the index.  Fatal error.  (return is here
     *  so that compilers will be quiet.)
     */
    PGAError( ctx, "PGASelectNextIndex: SelectIndex >= ctx->ga.PopSize",
             PGA_FATAL, PGA_INT, (void *) &ctx->ga.SelectIndex );
    return(0);
}

/*U****************************************************************************
   PGASetSelectType - specify the type of selection to use. Valid choices
   are PGA_SELECT_PROPORTIONAL, PGA_SELECT_SUS, PGA_SELECT_TOURNAMENT, and
   PGA_SELECT_PTOURNAMENT for proportional, stochastic universal selection,
   tournament, and probabilistic tournament selection, respectively.  The
   default is PGA_SELECT_TOURNAMENT.

   Category: Operators

   Inputs:
      ctx         - context variable
      select_type - symbolic constant to specify selection type

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetSelectType(ctx, PGA_SELECT_SUS);

****************************************************************************U*/
void PGASetSelectType( PGAContext *ctx, int select_type)
{

    PGADebugEntered("PGASetSelectType");

    switch (select_type) {
        case PGA_SELECT_PROPORTIONAL:
        case PGA_SELECT_SUS:
        case PGA_SELECT_TOURNAMENT:
        case PGA_SELECT_PTOURNAMENT:
            ctx->ga.SelectType = select_type;
            break;
        default:
            PGAError ( ctx, "PGASetSelectType: Invalid value of select_type:",
                      PGA_FATAL, PGA_INT, (void *) &select_type);
        break;
    }

    PGADebugExited("PGASetSelectType");
}

/*U***************************************************************************
   PGAGetSelectType - Returns the type of selection selected

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the type of selection specified

   Example:
      PGAContext *ctx;
      int selecttype;
      :
      selecttype = PGAGetSelectType(ctx);
      switch (selecttype) {
      case PGA_SELECT_PROPORTIONAL:
          printf("Selection Type = PGA_SELECT_PROPORTIONAL\n");
          break;
      case PGA_SELECT_SUS:
          printf("Selection Type = PGA_SELECT_SUS\n");
          break;
      case PGA_SELECT_TOURNAMENT:
          printf("Selection Type = PGA_SELECT_TOURNAMENT\n");
          break;
      case PGA_SELECT_PTOURNAMENT:
          printf("Selection Type = PGA_SELECT_PTOURNAMENT\n");
          break;
      }

***************************************************************************U*/
int PGAGetSelectType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetSelectType");
    PGAFailIfNotSetUp("PGAGetSelectType");

    PGADebugExited("PGAGetSelectType");

    return(ctx->ga.SelectType);
}


/*U****************************************************************************
   PGASetPTournamentProb - Specifies the probability that the string that wins
   a binary tournament will be selected.  This function will have no effect
   unless PGA_SELECT_PTOURNAMENT was specified as the type of selection to
   use with PGASetSelectType.  The default value is 0.6.

   Category: Operators

   Inputs:
      ctx - context variable
      p   - the probability of selecting the better string

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetPTournamentProb(ctx,0.8);

****************************************************************************U*/
void PGASetPTournamentProb(PGAContext *ctx, double ptournament_prob)
{
    PGADebugEntered("PGASetPTournamentProb");

    ctx->ga.PTournamentProb = ptournament_prob;

    PGADebugExited("PGASetPTournamentProb");
}

/*U***************************************************************************
   PGAGetPTournamentProb - returns the probability of selecting the best
   string in a probabilistic binary tournament

   Category: Operators

   Inputs:
      ctx - context variable

   Outputs:
      The probabilistic binary tournament selection probability

   Example:
      PGAContext *ctx;
      double pt;
      :
      pt = PGAGetPTournamentProb(ctx);

***************************************************************************U*/
double PGAGetPTournamentProb(PGAContext *ctx)
{
    PGADebugEntered("PGAGetPTournamentProb");
    PGAFailIfNotSetUp("PGAGetPTournamentProb");

    PGADebugExited("PGAGetPTournamentProb");

     return ctx->ga.PTournamentProb;
}


/*I****************************************************************************
  PGASelectProportional - selects a parent for the next generation using a
  linear search through a (fitness) weighted ``roulette wheel''.  The
  probability of selection is given by p_i = f_i/sum(i)f_i
  Ref: D. Goldberg, Genetic Algorithms, pg.

  Inputs:
    ctx   - context variable
    popix - symbolic constant of population to select from

  Outputs:
    index of the selected string

  Example:
    PGAContext *ctx,
    int l;
    :
    l = PGASelectProportional(ctx, PGA_OLDPOP);

****************************************************************************I*/
int PGASelectProportional(PGAContext *ctx, PGAIndividual *pop)
{
    double sum, sumfitness, r;
    int i;

    PGADebugEntered("PGASelectProportional");

    sumfitness = 0.0;
    for (i=0; i<ctx->ga.PopSize; i++)
        sumfitness += (pop+i)->fitness;

    i = 0;
    sum = (pop+i)->fitness;

    r = sumfitness * PGARandom01(ctx, 0);
    while(r > sum || i==ctx->ga.PopSize) {
        i++;
        sum += (pop+i)->fitness;
    }

    PGADebugExited("PGASelectProportional");

    return(i);
}

/*I****************************************************************************
  PGASelectSUS - A select routine using stochastic universal sampling
  Ref:    J. Baker, Reducing Bias and Inefficiency in the Selection Algorithm.
  Second GA conference, pp 14-21 (page 16)

  Inputs:
    ctx   - context variable
    popix - symbolic constant of population to select from

  Outputs:
    the array ga.selected[] created via side effect.  I.e., this routine
    creates the entire selected population with one call

  Example:
    PGAContext *ctx,
    :
    PGASelectSUS(ctx, PGA_OLDPOP);

****************************************************************************I*/
void PGASelectSUS( PGAContext *ctx, PGAIndividual *pop )
{
    int i;
    int k;                          /* index to fill samples array    */
    double davg;                    /* population average fitness     */
    double sum;                     /* running sum of expected values */
    double r;                       /* random number                  */

    PGADebugEntered("PGASelectSUS");

    /* fill the expected value array */
    davg = 0.0;
    for(i=0;i<ctx->ga.PopSize;i++)
        davg += (pop+i)->fitness;
    davg /=  (double) ctx->ga.PopSize;
    for(i=0;i<ctx->ga.PopSize;i++)
        ctx->scratch.dblscratch[i] = (pop+i)->fitness / davg;

    /* select ctx->ga.PopSize as follows */
    sum = 0;
    k   = 0;
    r   = PGARandom01(ctx, 0);
    for(i=0;i<ctx->ga.PopSize;i++)
        for( sum+=ctx->scratch.dblscratch[i]; sum>r; r++ )
            ctx->ga.selected[k++] = i;

    PGADebugExited("PGASelectSUS");
}


/*I****************************************************************************
  PGASelectTournament - chooses two strings randomly and returns the one with
  higher fitness
  Ref:    D. Goldberg, Genetic Algorithms, pg. 121

  Inputs:
    ctx   - context variable
    popix - symbolic constant of population to select from

  Outputs:
    index of the selected string

  Example:
    PGAContext *ctx,
    int l;
    :
    l = PGASelectTournament(ctx, PGA_OLDPOP);

****************************************************************************I*/
int PGASelectTournament( PGAContext *ctx, PGAIndividual *pop )
{
    int m1, m2;

    PGADebugEntered("PGASelectTournament");

    m1 = PGARandomInterval(ctx, 0, ctx->ga.PopSize-1);
    m2 = PGARandomInterval(ctx, 0, ctx->ga.PopSize-1);

    PGADebugExited("PGASelectTournament");

    return( ((pop+m1)->fitness > (pop+m2)->fitness) ? m1 : m2);
}

/*I****************************************************************************
  PGASelectPTournament - chooses two strings randomly and returns the one with
  higher fitness with a specified probability
  Ref:    D. Goldberg, Genetic Algorithms, pg. 121

  Inputs:
    ctx   - context variable
    popix - symbolic constant of population to select from

  Outputs:
    index of the selected string

  Example:
    PGAContext *ctx,
    int l;
    :
    l = PGASelectPTournament(ctx, PGA_OLDPOP);

****************************************************************************I*/
int PGASelectPTournament( PGAContext *ctx, PGAIndividual *pop )
{
    int m1, m2;
    int RetVal;

    PGADebugEntered("PGASelectPTournament");

    m1 = PGARandomInterval(ctx, 0, ctx->ga.PopSize-1);
    m2 = PGARandomInterval(ctx, 0, ctx->ga.PopSize-1);

    if ( (pop+m1)->fitness > (pop+m2)->fitness )
        if ( (double) PGARandom01(ctx, 0) < ctx->ga.PTournamentProb )
            RetVal = m1;
        else
            RetVal = m2;
    else
        if ( (double) PGARandom01(ctx, 0) < ctx->ga.PTournamentProb )
            RetVal = m2;
        else
            RetVal = m1;

    PGADebugExited("PGASelectPTournament");
    return(RetVal);
}


