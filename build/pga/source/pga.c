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
*     FILE: pga.c: This file contains all the routines that are data structure
*                  neutral
*
*     Authors: David M. Levine, Philip L. Hallstrom, and David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGARun - Highest level routine to execute the genetic algorithm.  It
  is called after PGACreate and PGASetup have been called.

  Category: Generation

  Inputs:
    ctx      - context variable
    evaluate - a pointer to the user's evaluation function, which must
               have the calling sequence shown in the example.

  Outputs:
    none

  Example:
    PGAContext *ctx,
    double f(PGAContext *ctx, int p, int pop);
    :
    ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
    PGASetUp(ctx);
    PGARun(ctx, f);
    PGADestroy(ctx);

****************************************************************************U*/
void PGARun(PGAContext *ctx, double (*evaluate)(PGAContext *c, int p, int pop))
{
     MPI_Comm comm;                  /* value of default communicator */
     int nprocs;                     /* number of processes in above  */
     int npops;                      /* number of populations         */
     int ndemes;                     /* number of demes               */
     

     PGADebugEntered("PGARun");
     PGAFailIfNotSetUp("PGARun");

     comm   = PGAGetCommunicator(ctx);
     nprocs = PGAGetNumProcs    (ctx, comm);
     npops  = PGAGetNumIslands  (ctx);
     ndemes = PGAGetNumDemes    (ctx);

     /**********************************************************************/
     /*              Global model, one island, one deme                    */
     /**********************************************************************/
     if     ( (npops == 1) && (ndemes == 1) ) {

	 PGARunGM(ctx, evaluate, comm);
     }
     
     /**********************************************************************/
     /*              Island model, > one island, one deme                  */
     /**********************************************************************/
     else if( (npops > 1) && (ndemes == 1) ) {
         if ( nprocs == 1 )
             PGAError (ctx, "PGARun: island model with one process",
                       PGA_FATAL, PGA_VOID, (void *) &nprocs);
         if ( nprocs != npops) {
             PGAError (ctx, "PGARun: island model no. processes != no. pops",
                       PGA_FATAL, PGA_VOID, (void *) &nprocs);
         }
         PGARunIM(ctx,evaluate,comm);
     }
             
     /**********************************************************************/
     /*              Neighborhood model, one island, > one deme            */
     /**********************************************************************/
     else if( (npops == 1) && (ndemes > 1) ) {
         if ( nprocs == 1 )
             PGAError (ctx, "PGARun: neighborhood model with one process",
                       PGA_FATAL, PGA_VOID, (void *) &nprocs);
         if ( nprocs != ndemes)
             PGAError (ctx, "PGARun: neighborhood model no. processes "
                       "!= no. demes", PGA_FATAL, PGA_VOID, (void *) &nprocs);
         PGARunNM(ctx,evaluate,comm);
     }
             
     /**********************************************************************/
     /*              Mixed model, > one island, > one deme                 */
     /**********************************************************************/
     else if( (npops > 1) && (ndemes > 1) ) {
         PGAError (ctx, "PGARun: Cannot execute mixed models",
                   PGA_FATAL, PGA_VOID, (void *) &nprocs);
     }

     /**********************************************************************/
     /*                        E R R O R                                   */
     /**********************************************************************/
     else {
         PGAError (ctx, "PGARun: Invalid combination of numislands,"
                   "ndemes, and nprocs.",
                   PGA_FATAL, PGA_VOID, (void *) &nprocs);
     }

     /**********************************************************************/
     /*                         E X I T                                    */
     /**********************************************************************/
     PGADebugExited("PGARun");
     return;
 }


/*U****************************************************************************
  PGARunMutationAndCrossover - Performs crossover and mutation from one
  population to create the next.  Assumes PGASelect has been called.

  Category: Generation

  Inputs:
    ctx - context variable
    oldpop - symbolic constant of old population
    newpop - symbolic constant of new population

  Outputs:
    newpop is modified by side-effect.

  Example:
     PGAContext *ctx,
    :
    PGARunMutationAndCrossover(ctx, PGA_OLDPOP, PGA_NEWPOP);

****************************************************************************U*/
void PGARunMutationAndCrossover (PGAContext *ctx, int oldpop, int newpop)
{
    int i, j, n, m1, m2;
    int popsize, numreplace;
    double pc;

    PGADebugEntered("PGARunMutationAndCrossover");

    popsize = PGAGetPopSize(ctx);
    numreplace = PGAGetNumReplaceValue(ctx);
    /*** first, copy n best strings (sorted by fitness) to new pop ***/
    PGASortPop( ctx, oldpop );
    n = popsize - numreplace;
    for ( i=0; i < n; i++ ) {
        j = PGAGetSortedPopIndex( ctx, i );
        PGACopyIndividual ( ctx, j, oldpop, i, newpop );
    }
    pc = PGAGetCrossoverProb(ctx);
    /*** reproduce to create the rest of the new population ***/
    while ( n < popsize) {
        m1 = PGASelectNextIndex( ctx );
        m2 = PGASelectNextIndex( ctx );
        if ( PGARandomFlip(ctx, pc) ) {
             PGACrossover ( ctx, m1, m2, oldpop, PGA_TEMP1,
                            PGA_TEMP2, newpop);

              /*** mutate and copy first string to new population ***/
              PGAMutate ( ctx, PGA_TEMP1, newpop);
              while (PGADuplicate( ctx, PGA_TEMP1, newpop, newpop, n))
                   PGAChange ( ctx, PGA_TEMP1, newpop );
              PGACopyIndividual ( ctx, PGA_TEMP1, newpop, n, newpop);
              n++;

              if ( n < popsize ) {
              /*** mutate and copy second string to new population ***/
              PGAMutate ( ctx, PGA_TEMP2, newpop);
              while ( PGADuplicate( ctx, PGA_TEMP2, newpop, newpop, n))
                   PGAChange ( ctx, PGA_TEMP2, newpop );
              PGACopyIndividual ( ctx, PGA_TEMP2, newpop, n, newpop);
              n++;
              }
         }
         else {
            PGACopyIndividual ( ctx, m1, oldpop, n, newpop );
            n++;
            if ( n < ctx->ga.PopSize ) {
                PGACopyIndividual ( ctx, m2, oldpop, n, newpop );
                n++;
            }
       }
    }

    PGADebugExited("PGARunMutationAndCrossover");
}


/*U****************************************************************************
  PGARunMutationOrCrossover - Performs crossover or mutation (but not both)
  from one populationto create the next.  Assumes PGASelect has been called.

  Category: Generation

  Inputs:
    ctx - context variable
    oldpop - symbolic constant of old population
    newpop - symbolic constant of new population

  Outputs:
    newpop is modified by side-effect.

  Example:
    PGAContext *ctx,
    :
    PGARunMutationOrCrossover(ctx, PGA_OLDPOP, PGA_NEWPOP);

****************************************************************************U*/
void PGARunMutationOrCrossover ( PGAContext *ctx, int oldpop, int newpop )
{
    int i, j, n, m1, m2;
    int popsize, numreplace;
    double pc;

    PGADebugEntered("PGARunMutationOrCrossover");

    popsize = PGAGetPopSize(ctx);
    numreplace = PGAGetNumReplaceValue(ctx);
    /*** first, copy n best strings (sorted by fitness) to new pop ***/
    PGASortPop( ctx, oldpop );
    n = popsize - numreplace;
    for ( i=0; i < n; i++ ) {
        j = PGAGetSortedPopIndex( ctx, i );
        PGACopyIndividual ( ctx, j, oldpop, i, newpop );
    }
    pc = PGAGetCrossoverProb(ctx);
    /*** reproduce to create the rest of the new population ***/
    while ( n < popsize ) {
        m1 = PGASelectNextIndex( ctx );
        m2 = PGASelectNextIndex( ctx );
        if ( PGARandomFlip(ctx, pc) ) {
            PGACrossover ( ctx, m1, m2, oldpop, PGA_TEMP1,
                                        PGA_TEMP2, newpop);

            /*** copy first string to new population ***/
            while (PGADuplicate(ctx, PGA_TEMP1, newpop,  newpop, n))
                PGAChange ( ctx, PGA_TEMP1, newpop );
            PGACopyIndividual ( ctx, PGA_TEMP1, newpop, n, newpop);
            n++;

            if ( n < popsize )
            {
                 /*** copy second string to new population ***/
                 while (PGADuplicate(ctx, PGA_TEMP2, newpop,  newpop, n))
                      PGAChange ( ctx, PGA_TEMP2, newpop );
                 PGACopyIndividual ( ctx, PGA_TEMP2, newpop, n, newpop);
                 n++;
            }
        }
        else
        {
             PGACopyIndividual(ctx, m1, oldpop, PGA_TEMP1, newpop);
             PGAMutate ( ctx, PGA_TEMP1, newpop );
             while (PGADuplicate(ctx, PGA_TEMP1, newpop, newpop, n ))
                  PGAChange ( ctx, PGA_TEMP1, newpop );
             PGACopyIndividual ( ctx, PGA_TEMP1, newpop, n, newpop);
             n++;

             if ( n < popsize ) {
                  PGACopyIndividual(ctx, m2, oldpop, PGA_TEMP2, newpop);
                  PGAMutate ( ctx, PGA_TEMP2, newpop );
                  while (PGADuplicate(ctx, PGA_TEMP2, newpop, newpop, n ))
                       PGAChange ( ctx, PGA_TEMP2, newpop );
                  PGACopyIndividual ( ctx, PGA_TEMP2, newpop, n, newpop);
                  n++;
             }
        }
    }

    PGADebugExited("PGARunMutationOrCrossover");
}


/*U****************************************************************************
  PGAUpdateGeneration - updates internal data structures for the next
  genetic algorithm iteration, and checks if the termination conditions, both
  user and PGAPack, have been met.  This routine must be called by both
  master and slave processes at the end of each GA generation.

  Category: Generation

  Inputs:
     ctx  - context variable
     comm - an MPI communicator

  Outputs:
     PGA_TRUE if the genetic algorithm has terminated, otherwise PGA_FALSE.

  Example:
    PGAContext *ctx;
    :
    PGAUpdateGeneration(ctx, MPI_COMM_WORLD);

****************************************************************************U*/
void PGAUpdateGeneration(PGAContext *ctx, MPI_Comm comm)
{
    PGAIndividual *temp;
    int i, rank;

    PGADebugEntered("PGAUpdateGeneration");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAUpdateGeneration",
                  "ga.iter = ", PGA_INT, (void *) &(ctx->ga.iter) );

    rank = PGAGetRank(ctx, comm);

    ctx->ga.iter++;

    if (rank == 0) {
	if (ctx->rep.PrintOptions & PGA_REPORT_AVERAGE)
	    PGAUpdateAverage(ctx, PGA_NEWPOP);

	if (ctx->rep.PrintOptions & PGA_REPORT_ONLINE)
	    PGAUpdateOnline(ctx, PGA_NEWPOP);

	if (ctx->rep.PrintOptions & PGA_REPORT_OFFLINE)
	    PGAUpdateOffline(ctx, PGA_NEWPOP);

	if ((ctx->ga.StoppingRule & PGA_STOP_NOCHANGE) || ctx->ga.restart) {
	    i = PGAGetBestIndex(ctx, PGA_NEWPOP);
	    if (ctx->rep.Best == PGAGetEvaluation(ctx, i, PGA_NEWPOP))
		ctx->ga.ItersOfSame++;
	    else {
		ctx->rep.Best = PGAGetEvaluation(ctx, i, PGA_NEWPOP);
		ctx->ga.ItersOfSame = 1;
	    }
	}

	if (ctx->ga.StoppingRule & PGA_STOP_TOOSIMILAR)
	    ctx->ga.PercentSame = PGAComputeSimilarity(ctx, ctx->ga.newpop);

	/*  Clear this twice in case the user EOG calls PGASelect.  */
	ctx->ga.SelectIndex = 0;

	if (ctx->fops.EndOfGen)
	    (*ctx->fops.EndOfGen)(&ctx);
	if (ctx->cops.EndOfGen)
	    (*ctx->cops.EndOfGen)(ctx);

	ctx->ga.SelectIndex = 0;
	temp           = ctx->ga.oldpop;
	ctx->ga.oldpop = ctx->ga.newpop;
	ctx->ga.newpop = temp;
    }

    PGADebugExited("PGAUpdateGeneration");
}


/*U***************************************************************************
   PGAGetDataType - Returns the data type used by the given context.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the data type.

   Example:
      PGAContext *ctx;
      int datatype;
      :
      datatype = PGAGetDataType(ctx);
      switch (datatype) {
      case PGA_DATATYPE_BINARY:
          printf("Data Type = PGA_DATATYPE_BINARY\n");
          break;
      case PGA_DATATYPE_CHARACTER:
          printf("Data Type = PGA_DATATYPE_CHARACTER\n");
          break;
      case PGA_DATATYPE_INTEGER:
          printf("Data Type = PGA_DATATYPE_INTEGER\n");
          break;
      case PGA_DATATYPE_REAL:
          printf("Data Type = PGA_DATATYPE_REAL\n");
          break;
      case PGA_DATATYPE_USER:
          printf("Data Type = PGA_DATATYPE_USER\n");
          break;
      }

***************************************************************************U*/
int PGAGetDataType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetDataType");

    PGADebugExited("PGAGetDataType");

    return(ctx->ga.datatype);
}

/*U***************************************************************************
   PGAGetOptDirFlag - Returns a symbolic constant that represents the
   direction of optimization

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      Returns the integer corresponding to the symbolic constant
      used to specify the  direction of optimization

   Example:
      PGAContext *ctx;
      int optdir;
      :
      optdir = PGAGetOptDirFlag(ctx);
      switch (optdir) {
      case PGA_MAXIMIZE:
          printf("Optimization direction = PGA_MAXIMIZE\n");
          break;
      case PGA_MINIMIZE:
          printf("Optimization direction = PGA_MINIMIZE\n");
          break;
      }

***************************************************************************U*/
int PGAGetOptDirFlag (PGAContext *ctx)
{
    PGADebugEntered("PGAGetOptDirFlag");

    PGADebugExited("PGAGetOptDirFlag");

    return(ctx->ga.optdir);
}

/*U***************************************************************************
   PGAGetStringLength - Returns the string length

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The string length

   Example:
      PGAContext *ctx;
      int stringlen;
      :
      stringlen = PGAGetStringLength(ctx);

***************************************************************************U*/
int PGAGetStringLength (PGAContext *ctx)
{
    PGADebugEntered("PGAGetStringLength");

    PGADebugExited("PGAGetStringLength");

    return(ctx->ga.StringLen);
}

/*I***************************************************************************
   PGAGetVariableStringLength - Returns the length of a variable length
   string.

   Category: Generation

   Inputs:
      ctx - context variable
      p   - index into the population
      pop - symbolic constant for the population

   Outputs:
      The string length

   Example:
      PGAContext *ctx;
      int stringlen;
      :
      stringlen = PGAGetVariableStringLength(ctx, 0, PGA_NEWPOP);

***************************************************************************I*/
int PGAGetVariableStringLength (PGAContext *ctx, int p, int pop)
{
    PGADebugEntered("PGAGetVariableStringLength");

    PGADebugExited("PGAGetVariableStringLength");

    PGAError(ctx, "PGAGetVariableStringLength:  Variable length strings not "
	     "currently supported.", PGA_FATAL, PGA_VOID, NULL);
#if 0
    ind = PGAGetIndividual(ctx, p, pop);
    return(ind->StringLength);
#endif
    /*  Make the compilers be quiet.  */
    return(0);
}

/*U***************************************************************************
  PGAGetGAIterValue - returns the number of the current genetic
  algorithm generation

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The genetic algorithm generation number

   Example:
      PGAContext *ctx;
      int g;
      :
      g = PGAGetGAIterValue(ctx);

***************************************************************************U*/
int PGAGetGAIterValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetGAIterValue");
    PGAFailIfNotSetUp("PGAGetGAIterValue");

    PGADebugExited("PGAGetGAIterValue");

    return(ctx->ga.iter);
}

/*U****************************************************************************
  PGASetMutationOrCrossoverFlag - A boolean flag to indicate if recombination
  uses exactly one of crossover or mutation on selected strings.

   Category: Generation

   Inputs:
      ctx  - context variable
      flag - PGA_TRUE (default) or PGA_FALSE

   Outputs:
      None

   Example:
      Set the genetic algorithm to use mutation only when crossover is
      not used.

      PGAContext *ctx;
      :
      PGASetMutationOrCrossoverFlag(ctx,PGA_FALSE);

****************************************************************************U*/
void PGASetMutationOrCrossoverFlag( PGAContext *ctx, int flag)
{
    PGADebugEntered("PGASetMutationOrCrossoverFlag");

     switch (flag)
     {
     case PGA_TRUE:
     case PGA_FALSE:
          ctx->ga.MutateOnlyNoCross = flag;
          break;
     default:
          PGAError (ctx, "PGASetMutationOrCrossoverFlag: Invalid value of "
                    "flag:", PGA_FATAL, PGA_INT, (void *) &flag);
          break;
     }

    PGADebugExited("PGASetMutationOrCrossoverFlag");
}

/*U****************************************************************************
  PGASetMutationAndCrossoverFlag - A boolean flag to indicate if
  recombination uses both crossover and mutation on selected strings

   Category: Generation

   Inputs:
      ctx  - context variable
      flag - PGA_TRUE (default) or PGA_FALSE

   Outputs:
      None

   Example:
      Set the genetic algorithm to use both crossover and mutation when
      reproducing strings.

      PGAContext *ctx;
      :
      PGASetMutationAndCrossoverFlag(ctx,PGA_FALSE);

****************************************************************************U*/
void PGASetMutationAndCrossoverFlag( PGAContext *ctx, int flag)
{
    PGADebugEntered("PGASetMutationAndCrossoverFlag");

     switch (flag)
     {
     case PGA_TRUE:
     case PGA_FALSE:
          ctx->ga.MutateOnlyNoCross = !flag;
          break;
     default:
          PGAError (ctx, "PGASetMutationAndCrossoverFlag: Invalid value of "
                    "flag:", PGA_FATAL, PGA_INT, (void *) &flag);
          break;
     }

    PGADebugExited("PGASetMutationAndCrossoverFlag");
}
/*U***************************************************************************
   PGAGetMutationOrCrossoverFlag - Returns true if mutation only occurs when
   crossover does not.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      Returns PGA_TRUE if mutation only occurs when crossover does not,
      otherwise, returns PGA_FALSE.

   Example:
      PGAContext *ctx;
      int mutatetype;
      :
      mutatetype = PGAGetMutationOrCrossoverFlag(ctx);
      switch (mutatetype) {
      case PGA_TRUE:
          printf("Only mutating strings not undergoing crossover\n");
          break;
      case PGA_FALSE:
          printf("Mutating strings only after crossover\n");
          break;
      }

***************************************************************************U*/
int PGAGetMutationOrCrossoverFlag (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMutationOrCrossoverFlag");
    PGAFailIfNotSetUp("PGAGetMutationOrCrossoverFlag");

    PGADebugExited("PGAGetMutationOrCrossoverFlag");

    return(ctx->ga.MutateOnlyNoCross);
}

/*U***************************************************************************
   PGAGetMutationAndCrossoverFlag - Returns true if mutation occurs only
   when crossover does.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      Returns PGA_TRUE if mutation is applied to crossed-over strings.
      Otherwise, returns PGA_FALSE

   Example:
      PGAContext *ctx;
      int mutatetype;
      :
      mutatetype = PGAGetMutationAndCrossoverFlag(ctx);
      switch (mutatetype) {
      case PGA_TRUE:
          printf("Mutating strings only after crossover\n");
          break;
      case PGA_FALSE:
          printf("Only mutating strings not undergoing crossover\n");
          break;
      }

***************************************************************************U*/
int PGAGetMutationAndCrossoverFlag (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMutationAndCrossoverFlag");
    PGAFailIfNotSetUp("PGAGetMutationAndCrossoverFlag");

    PGADebugExited("PGAGetMutationAndCrossoverFlag");

    return(!ctx->ga.MutateOnlyNoCross);
}

