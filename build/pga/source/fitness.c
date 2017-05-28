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
*     FILE: fitness.c: This file contains the routines that have to do with
*                      fitness calculations.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGAFitness - Maps the user's evaluation function value to a fitness value.
  First, the user's evaluation function value is translated to all positive
  values if any are negative.  Next, this positive sequence is translated to
  a maximization problem if the user's optimization direction was minimization.
  This positive sequence is then mapped to a fitness value using linear
  ranking, linear normalization fitness, or the identity (i.e., the evaluation
  function value).  This routine is usually used after PGAEvaluate is called.

  Category: Fitness & Evaluation

  Inputs:
    ctx  - context variable
    pop  - symbolic constant of the population to calculate fitness for

  Outputs:
     Calculates the fitness for each string in the population via side effect

  Example:
     Calculate the fitness of all strings in population PGA_NEWPOP after
     calling PGAEvaluate to calculate the strings evaluation value.

     double energy(PGAContext *ctx, int p, int pop);
     PGAContext *ctx;
     :
     PGAEvaluate(ctx, PGA_NEWPOP, energy);
     PGAFitness (ctx, PGA_NEWPOP);

****************************************************************************U*/
void PGAFitness ( PGAContext *ctx, int popindex )
{
    int i;
    double mineval;
    PGAIndividual *pop;

    PGADebugEntered("PGAFitness");

    /* set pointer to appropriate population */

    switch (popindex) {
    case PGA_OLDPOP:
        pop = ctx->ga.oldpop;
        break;
    case PGA_NEWPOP:
        pop = ctx->ga.newpop;
        break;
    default:
        PGAError( ctx, "PGAFitness: Invalid value of popindex:",
                  PGA_FATAL, PGA_INT, (void *) &popindex );
        break;
    }

    /* make sure all evaluation function values are up-to-date */

    for( i=0; i<ctx->ga.PopSize; i++ ) {
        /*printf("i = %d, evaluptodate = %d\n",i,(pop+i)->evaluptodate);*/
        if ( (pop+i)->evaluptodate != PGA_TRUE )
            PGAError( ctx, "PGAFitness: evaluptodate not PGA_TRUE for:",
                      PGA_FATAL, PGA_INT, (void *) &i );
    }

    /* put raw fitness into fitness field */

    for( i=0; i<ctx->ga.PopSize; i++ )
        (pop+i)->fitness = (pop+i)->evalfunc;

    /* translate to all positive sequence (if necessary) */

    mineval = ctx->sys.PGAMaxDouble;
    for( i=0; i<ctx->ga.PopSize; i++ )
        if ( (pop+i)->fitness < mineval )
            mineval =(pop+i)->fitness;
    if ( mineval < 0.0 ) {
        mineval = (-1.01) * mineval;
        for( i=0; i<ctx->ga.PopSize; i++ )
           (pop+i)->fitness  = (pop+i)->fitness + mineval;
    }

    /* translate to maximization problem  (if necessary) */

    if ( ctx->ga.optdir == PGA_MINIMIZE ) {
        switch (ctx->ga.FitnessMinType) {
        case PGA_FITNESSMIN_RECIPROCAL:
            PGAFitnessMinReciprocal( ctx, pop );
            break;
        case PGA_FITNESSMIN_CMAX:
            PGAFitnessMinCmax      ( ctx, pop );
            break;
        default:
            PGAError( ctx,
                     "PGAFitness: Invalid FitnessMinType:",
                      PGA_FATAL,
                      PGA_INT,
                      (void *) &(ctx->ga.FitnessMinType) );
            break;
        }
    }

    /* last step in fitness calculation */

    switch (ctx->ga.FitnessType) {
    case PGA_FITNESS_RAW:
        break;
    case PGA_FITNESS_NORMAL:
        PGAFitnessLinearNormal    ( ctx, pop );
        break;
    case PGA_FITNESS_RANKING:
        PGAFitnessLinearRank   ( ctx, pop );
        break;
    default:
        PGAError( ctx,
                 "PGAFitness: Invalid FitnessType:",
                  PGA_FATAL,
                  PGA_INT,
                  (void *) &(ctx->ga.FitnessType) );
        break;
    }

    PGADebugExited("PGAFitness");
}


/*U****************************************************************************
  PGARank - returns the rank of a string in a population.  This is a value
  between 1,...,N (the population size).  The most fit string has rank 1,
  the least fit string has rank N.

  Category: Fitness & Evaluation

  Inputs:
    ctx   - context variable
    p     - the index of the string whose rank is desired
    order - an array containing a unique rank for each string
    n     - the size of the array order

  Outputs:
    The rank of string p

  Example:
    Determine the rank of string p.

    PGAContext *ctx;
    int i, popsize, rank, *order;
    double *fitness;

    popsize = PGAGetPopsize(ctx);
    order   = (int *)   malloc(sizeof(int)    * popsize);
    fitness = (double *)malloc(sizeof(double) * popsize);

    for(i=0;i<popsize; i++) {
        fitness[i] = PGAGetFitness(ctx, p, PGA_OLDPOP);
        order[i]   = i;
    }

    PGADblHeapSort(ctx, fitness, order, popsize);
    rank = PGARank(ctx, p, order, popsize)

****************************************************************************U*/
int PGARank( PGAContext *ctx, int p, int *order, int n )
{
    int i;

    PGADebugEntered("PGARank");

    /*  If the user gives us PGA_TEMP1 or PGA_TEMP2 (or, gasp, some random
     *  number that is not in the population), fail.
     */
    if ((p<0) || (p > PGAGetPopSize(ctx)))
        PGAError(ctx, "PGARank: Not a valid population member, p = ",
                 PGA_FATAL, PGA_INT, (void *)&p);

    /*  Search through all the orderings until we find the one that
     *  matches the given string.  Return the index number.  If we do not
     *  find one, something is _very_ bad; terminate with a fatal error.
     */
    for(i=0; i<n; i++)
        if (order[i] == p) {
	    PGADebugExited("PGARank");
	    return(i+1);
        }

    /*  Ideally, we should print out the order array, but, well, ideally,
     *  we should never get here anyway...Also, to make some compilers
     *  shut up, return(0) is here, even though PGAError doesn't return.
     */
    PGAError( ctx, "PGARank: Bottom of loop in rank, p = ", PGA_FATAL,
             PGA_INT, (void *) &p );
    return(0);
}

/*U***************************************************************************
   PGAGetFitness - returns the fitness value for a string

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in

   Outputs:
      The fitness value for string p in population pop

   Example:
      PGAContext *ctx;
      int p;
      double fit;
      :
      fit = PGAGetFitness(ctx, p, PGA_NEWPOP);

***************************************************************************U*/
double PGAGetFitness ( PGAContext *ctx, int p, int pop )
{
    PGAIndividual *ind;

    PGADebugEntered("PGAGetFitness");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAGetFitness", "p = ",
                   PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAGetFitness", "pop = ",
                   PGA_INT, (void *) &pop );

    ind = PGAGetIndividual ( ctx, p, pop );

    PGADebugExited("PGAGetFitness");

    return(ind->evalfunc);
}

/*U***************************************************************************
   PGAGetFitnessType - Returns the type of fitness transformation used.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the type of fitness transformation used

   Example:
      PGAContext *ctx;
      int fittype;
      :
      fittype = PGAGetFitnessType(ctx);
      switch (fittype) {
      case PGA_FITNESS_RAW:
          printf("Fitness Type = PGA_FITNESS_RAW\n");
          break;
      case PGA_FITNESS_NORMAL:
          printf("Fitness Type = PGA_FITNESS_NORMAL\n");
          break;
      case PGA_FITNESS_RANKING:
          printf("Fitness Type = PGA_FITNESS_RANKING\n");
          break;
      }

***************************************************************************U*/
int PGAGetFitnessType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetFitnessType");
    PGAFailIfNotSetUp("PGAGetFitnessType");

    PGADebugExited("PGAGetFitnessType");

    return(ctx->ga.FitnessType);
}

/*U***************************************************************************
   PGAGetFitnessMinType - Returns the type of fitness transformation used
   for minimization problems.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the type of fitness transformation used
      for minimization problems

   Example:
      PGAContext *ctx;
      int fitmintype;
      :
      fitmintype = PGAGetFitnessMinType(ctx);
      switch (fitmintype) {
      case PGA_FITNESSMIN_RECIPROCAL:
          printf("Fitness Minimization Type = PGA_FITNESSMIN_RECIPROCAL\n");
          break;
      case PGA_FITNESSMIN_CMAX:
          printf("Fitness Minimization Type = PGA_FITNESSMIN_CMAX\n");
          break;
      }

***************************************************************************U*/
int PGAGetFitnessMinType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetFitnessMinType");
    PGAFailIfNotSetUp("PGAGetFitnessType");

    PGADebugExited("PGAGetFitnessMinType");

    return(ctx->ga.FitnessMinType);
}

/*U***************************************************************************
   PGAGetMaxFitnessRank - returns the maximum value used in rank-based
   fitness.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable

   Outputs:
      The value of MAX used in rank-based fitness

   Example:
      PGAContext *ctx;
      double max;
      :
      max = PGAGetMaxFitnessRank(ctx);

***************************************************************************U*/
double PGAGetMaxFitnessRank (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMaxFitnessRank");
    PGAFailIfNotSetUp("PGAGetFitnessType");

    PGADebugExited("PGAGetMaxFitnessRank");

    return(ctx->ga.FitnessRankMax);
}

/*U****************************************************************************
   PGASetFitnessType - Set the type of fitness algorithm to use. Valid choices
   are PGA_FITNESS_RAW, PGA_FITNESS_NORMAL, or PGA_FITNESS_RANKING for
   raw fitness (the evaluation function value), linear normalization, or
   linear ranking, respectively.  The default is PGA_FITNESS_RAW.

   Category: Fitness & Evaluation

   Inputs:
      ctx          - context variable
      fitness_type - symbolic constant to specify fitness type

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetFitnessType(ctx, PGA_FITNESS_RANKING);

****************************************************************************U*/
void PGASetFitnessType( PGAContext *ctx, int fitness_type)
{

    PGADebugEntered("PGASetFitnessType");

    switch (fitness_type) {
        case PGA_FITNESS_RAW:
        case PGA_FITNESS_NORMAL:
        case PGA_FITNESS_RANKING:
            ctx->ga.FitnessType = fitness_type;
            break;
        default:
            PGAError(ctx, "PGASetFitnessType: Invalid value of fitness_type:",
                     PGA_FATAL, PGA_INT, (void *) &fitness_type);
            break;
    }

    PGADebugExited("PGASetFitnessType");
}

/*U****************************************************************************
   PGASetFitnessMinType - sets the type of algorithm used if a minimization
   problem is specified to determine how values are remapped for maximization.
   Valid choices are PGA_FITNESSMIN_RECIPROCAL and PGA_FITNESSMIN_CMAX to do
   the mapping using the reciprocal of the evaluation function, or by
   subtracting the worst evaluation function value from each evaluation
   function value, respectively.  The default is PGA_FITNESSMIN_CMAX

   Category: Fitness & Evaluation

   Inputs:
      ctx          - context variable
      fitness_type - symbolic constant to specify fitness minimization type

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetFitnessMinType(ctx, PGA_FITNESSMIN_CMAX);

****************************************************************************U*/
void PGASetFitnessMinType( PGAContext *ctx, int fitness_type)
{

    PGADebugEntered("PGASetFitnessMinType");

    switch (fitness_type) {
        case PGA_FITNESSMIN_RECIPROCAL:
        case PGA_FITNESSMIN_CMAX:
            ctx->ga.FitnessMinType = fitness_type;
            break;
        default:
            PGAError ( ctx,
                      "PGASetFitnessMinType: Invalid value of fitness_type:",
                       PGA_FATAL, PGA_INT, (void *) &fitness_type);
        break;
    }

    PGADebugExited("PGASetFitnessMinType");
}

/*U****************************************************************************
   PGASetMaxFitnessRank - The value of the parameter Max when using linear
   ranking for fitness determination. The default value is 1.2.  The value
   must be from the interval [1.0, 2.0].  The fitness type must have been set
   to PGA_FITNESS_RANKING with PGASetFitnessType for this function call
   to have any effect.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      max - the value of the parameter Max when using linear ranking

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMaxFitnessRank(ctx, 1.1);

****************************************************************************U*/
void PGASetMaxFitnessRank( PGAContext *ctx, double fitness_rank_max)
{
    PGADebugEntered("PGASetMaxFitnessRank");

    if ((fitness_rank_max < 1.0) || (fitness_rank_max > 2.0))
        PGAError ( ctx,
                  "PGASetMaxFitnessRank: Invalid value of fitness_rank_max:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &fitness_rank_max);
    else
        ctx->ga.FitnessRankMax = fitness_rank_max;

    PGADebugExited("PGASetMaxFitnessRank");
}



/*I****************************************************************************
  PGAFitnessLinearNormal - Calculates fitness using a ranking method and
  linear' ordering.  The fitness function is of the form
  u(x) = K - ( rank * sigma ) with the constant K equal to the mean of the
  evaluation functions, and the decrement sigma equal to the standard
  deviation of the same.
  Ref:    L. Davis, Handbook of Genetic Algorithms, pg. 33

  Inputs:
    ctx  - context variable
    pop  - population pointer to calculate fitness for

  Outputs:
     Calculates the fitness for each string in the population via side effect

  Example:

****************************************************************************I*/
void PGAFitnessLinearNormal ( PGAContext *ctx, PGAIndividual *pop )
{

    int i;
    double K, sigma, mean;

    PGADebugEntered("PGAFitnessLinearNormal");

    /* fill arrays for sorting */

    for(i=0;i<ctx->ga.PopSize;i++) {
        ctx->scratch.dblscratch[i] = (pop+i)->fitness;
        ctx->scratch.intscratch[i] =                i;
    }

    /* calculate parameters for linear normalization */

    mean  = PGAMean   ( ctx, ctx->scratch.dblscratch, ctx->ga.PopSize  );
    sigma = PGAStddev ( ctx, ctx->scratch.dblscratch, ctx->ga.PopSize, mean );
    if (sigma == 0)
         sigma = 1;
    K = sigma * (double) ctx->ga.PopSize;
    PGADblHeapSort ( ctx, ctx->scratch.dblscratch,
                  ctx->scratch.intscratch,
                  ctx->ga.PopSize);

    for( i=0; i<ctx->ga.PopSize; i++ )
        (pop+i)->fitness = K - ( sigma *
            (double) PGARank(ctx,i,ctx->scratch.intscratch,ctx->ga.PopSize) );

    PGADebugExited("PGAFitnessLinearNormal");
}

/*I****************************************************************************
  PGAFitnessLinearRank - Calculates fitness using linear ranking. The fitness
  function is of the form 1/N * ( max - (max-min) * ( (i-1)/(N-1) ) ) where
  min = 2-max and 1 <= max <= 2.
  Ref:    J. Baker: Adaptive selection methods for GAs
  Ref:    J. Baker: Extended selection mechanism in GAs
  Ref:    J. Grefenstte: A critical look at implicit parallelism
  Ref:    D. Whitley's linear() function on pp. 121 of ICGA

  Inputs:
    ctx  - context variable
    pop  - population pointer to calculate fitness for

  Outputs:
     Calculates the fitness for each string in the population via side effect

  Example:

****************************************************************************I*/
void PGAFitnessLinearRank ( PGAContext *ctx, PGAIndividual *pop )
{
    double max, min, popsize, rpopsize;
    int i;

    PGADebugEntered("PGAFitnessLinearRank");

    max      = ctx->ga.FitnessRankMax;
    min      = 2. - max;
    popsize  = (double) ctx->ga.PopSize;
    rpopsize = 1.0/popsize;

    for(i=0;i<ctx->ga.PopSize;i++) {
        ctx->scratch.dblscratch[i] = (pop+i)->fitness;
        ctx->scratch.intscratch[i] =                i;
    }

    PGADblHeapSort ( ctx, ctx->scratch.dblscratch,
                  ctx->scratch.intscratch,
                  ctx->ga.PopSize);

    for(i=0;i<ctx->ga.PopSize;i++) {
        (pop+i)->fitness = rpopsize * ( max -
        ( (max - min) *
        ( ( (double) PGARank(ctx,i,ctx->scratch.intscratch,ctx->ga.PopSize)
             - 1. ) / ( popsize - 1. ) ) ) );

    }

    PGADebugExited("PGAFitnessLinearRank");
}


/*I****************************************************************************
  PGAFitnessMinReciprocal - Calculates fitness in the case of a minimization
  problem using the reciprocal of the evaluation function. This is a power law
  u(x) = ( a f(x) + b )^k with a=1, b=0, k=-1

  Inputs:
    ctx  - context variable
    pop  - population pointer to calculate fitness for

  Outputs:
     Calculates the fitness for each string in the population via side effect

  Example:

****************************************************************************I*/
void PGAFitnessMinReciprocal ( PGAContext *ctx, PGAIndividual *pop )
{
    int i;

    PGADebugEntered("PGAFitnessMinReciprocal");

    for( i=0; i<ctx->ga.PopSize; i++ ) {
        if ( (pop+i)->fitness != 0. )
            (pop+i)->fitness = 1. / (pop+i)->fitness;
        else
            PGAError( ctx,
                     "PGAFitnessReciprocal: Value 0.0 for fitness member:",
                      PGA_FATAL,
                      PGA_INT,
                     (void *) &i );
    }

    PGADebugExited("PGAFitnessMinReciprocal");
}


/*I****************************************************************************
  PGAFitnessMinCmax - Calculates fitness in the case of a minimization
  problem by subtracting the worst evaluation function value from each
  evaluation function.  This is a dynamic linear fitness function
  u(x) = a f(x) + b(t) with a=-1, b(t) = 1.1 * max f(x)

  Inputs:
    ctx  - context variable
    pop  - population pointer to calculate fitness for

  Outputs:
     Calculates the fitness for each string in the population via side effect

  Example:

****************************************************************************I*/
void PGAFitnessMinCmax ( PGAContext *ctx, PGAIndividual *pop )
{
    int i;
    double cmax;

    PGADebugEntered("PGAFitnessMinCmax");

    cmax = 0.;

    for(i=0; i<ctx->ga.PopSize; i++)
        if ( (pop+i)->evalfunc > cmax )
            cmax = (pop+i)->evalfunc;

    cmax *= ctx->ga.FitnessCmaxValue; /* so worst string has nonzero fitness */

    for(i=0;i<ctx->ga.PopSize;i++)
        (pop+i)->fitness = cmax - (pop+i)->evalfunc;

    PGADebugExited("PGAFitnessMinCmax");
}


/*U****************************************************************************
   PGASetFitnessCmaxValue - The value of the multiplier used by
   PGAFitnessMinCmax so that the worst string has a nonzero fitness.
   The default value is 1.01.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      val - the value of the multiplier

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetFitnessCmaxValue(ctx, 1.2);

****************************************************************************U*/
void PGASetFitnessCmaxValue( PGAContext *ctx, double val)
{
    PGADebugEntered("PGASetFitnessCmaxValue");
    ctx->ga.FitnessCmaxValue = val;
    PGADebugExited("PGASetFitnessCmaxValue");
}



/*U***************************************************************************
   PGAGetFitnessCmaxValue - returns the value of the multiplier used by
   PGAFitnessMinCmax.

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable

   Outputs:
      The value of Cmax used in

   Example:
      PGAContext *ctx;
      double cmax;
      :
      cmax = PGAGetFitnessCmaxValue(ctx);

***************************************************************************U*/
double PGAGetFitnessCmaxValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetFitnessCmaxValue");
    PGAFailIfNotSetUp("PGAGetFitnessType");
    PGADebugExited("PGAGetFitnessCmaxValue");
    return(ctx->ga.FitnessCmaxValue);
}

