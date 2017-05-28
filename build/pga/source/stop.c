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
*     FILE: stop.c: This file contains routines related to the stopping
*                   conditions for the GA.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGADone - Returns PGA_TRUE if the stopping conditions have been met,
  otherwise returns false.  Calls exactly one of the user defined C or
  fortran or system (PGACheckStoppingConditions) stopping condition functions.

  Category: Generation

  Inputs:
     ctx  - context variable
     comm - an MPI communicator

  Outputs:
     returns PGA_TRUE if at least one of the termination conditions has been
     met.  Otherwise, returns PGA_FALSE

  Example:
    PGAContext *ctx;
    :
    PGADone(ctx, comm);

****************************************************************************U*/
int PGADone(PGAContext *ctx, MPI_Comm comm)
{
    int rank, size, done;

    PGADebugEntered("PGADone");

    rank = PGAGetRank(ctx, comm);
    size = PGAGetNumProcs(ctx, comm);

    if (rank == 0) {
	if (ctx->fops.StopCond)
	    done = (*ctx->fops.StopCond)(&ctx);
	else if (ctx->cops.StopCond)
	    done = (*ctx->cops.StopCond)(ctx);
	else
	    done = PGACheckStoppingConditions(ctx);
    }

    if (size > 1)
	MPI_Bcast(&done, 1, MPI_INT, 0, comm);

    PGADebugExited("PGADone");

    return(done);
}

/*U****************************************************************************
  PGACheckStoppingConditions - returns boolean to indicate if the PGAPack
  termination conditions -- PGA_STOP_MAXITER, PGA_STOP_TOOSIMILAR, 
  PGA_STOP_NOCHANGE -- have been met.

  Category: Generation

  Inputs:
     ctx  - context variable

  Outputs:
     returns PGA_TRUE if at least one of the termination conditions has been
     met.  Otherwise, returns PGA_FALSE

  Example:
    PGAContext *ctx;
    :
    PGACheckStoppingConditions(ctx);

****************************************************************************U*/
int PGACheckStoppingConditions( PGAContext *ctx)
{
    int done = PGA_FALSE;

    PGADebugEntered("PGACheckStoppingConditions");

    if (((ctx->ga.StoppingRule & PGA_STOP_MAXITER) == PGA_STOP_MAXITER) &&
	(ctx->ga.iter > ctx->ga.MaxIter))
	done |= PGA_TRUE;
    
    if (((ctx->ga.StoppingRule & PGA_STOP_NOCHANGE) == PGA_STOP_NOCHANGE) &&
	(ctx->ga.ItersOfSame >= ctx->ga.MaxNoChange))
	done |= PGA_TRUE;
	
    if (((ctx->ga.StoppingRule & PGA_STOP_TOOSIMILAR) == PGA_STOP_TOOSIMILAR) &&
	(ctx->ga.PercentSame >= ctx->ga.MaxSimilarity))
	done |= PGA_TRUE;

    PGADebugExited("PGACheckStoppingConditions");
    return(done);
}

/*U****************************************************************************
   PGASetStoppingRuleType - specify a stopping criterion.  If called more than
   once the different stopping criterion are ORed together.  Valid choices
   are PGA_STOP_MAXITER, PGA_STOP_TOOSIMILAR, or PGA_STOP_NOCHANGE to
   specify iteration limit reached, population too similar, or no change in
   the best solution found in a given number of iterations, respectively.
   The default is to stop when a maximum iteration limit is reached (by
   default, 1000 iterations).

   Category: Generation

   Inputs:
      ctx      - context variable
      stoprule - symbolic constant to specify stopping rule

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetStoppingRuleType(ctx, PGA_STOP_TOOSIMILAR);

****************************************************************************U*/
void PGASetStoppingRuleType (PGAContext *ctx, int stoprule)
{

    PGADebugEntered("PGASetStoppingRuleType");
    PGAFailIfSetUp("PGASetStoppingRuleType");

    switch (stoprule) {
	case PGA_STOP_MAXITER  :
        case PGA_STOP_NOCHANGE :
	case PGA_STOP_TOOSIMILAR :
	    ctx->ga.StoppingRule |= stoprule;
	    break;
	default:
	    PGAError( ctx,
		     "PGASetStoppingRuleType: Invalid value of stoprule:",
		     PGA_FATAL, PGA_INT, (void *) &stoprule );
    }

    PGADebugExited("PGASetStoppingRuleType");
}

/*U***************************************************************************
   PGAGetStoppingRuleType - Returns a symbolic constant that defines the
   termination criteria.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      Returns an integer which is an ORed mask of the symbolic constants
      used to specify the stopping rule(s).

   Example:
      PGAContext *ctx;
      int stop;
      :
      stop = PGAGetStoppingRuleType(ctx);
      if (stop & PGA_STOP_MAXITER)
          printf("Stopping Rule = PGA_STOP_MAXITER\n");
      if (stop & PGA_STOP_NOCHANGE)
          printf("Stopping Rule = PGA_STOP_NOCHANGE\n");
      if (stop & PGA_STOP_TOOSIMILAR)
          printf("Stopping Rule = PGA_STOP_TOOSIMILAR\n");

***************************************************************************U*/
int PGAGetStoppingRuleType (PGAContext *ctx)
{
    PGADebugEntered("PGAGetStoppingRuleType");
    PGAFailIfNotSetUp("PGAGetStoppingRuleType");

    PGADebugExited("PGAGetStoppingRuleType");

    return(ctx->ga.StoppingRule);
}

/*U****************************************************************************
   PGASetMaxGAIterValue - specify the maximum number of iterations for the
   stopping rule PGA_STOP_MAXITER (which, by itself, is the default stopping
   rule and is always in effect).  The default value is 1000 iterations.

   Category: Generation

   Inputs:
      ctx     - context variable
      maxiter - the maximum number of GA iterations to run before stopping

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMaxGAIterValue(ctx,5000);

****************************************************************************U*/
void PGASetMaxGAIterValue(PGAContext *ctx, int maxiter)
{

    PGADebugEntered("PGASetMaxGAIterValue");
    PGAFailIfSetUp("PGASetMaxGAIterValue");

    if (maxiter < 1)
	PGAError( ctx, "PGASetMaxGAIterValue: Invalid value of maxiter:",
		 PGA_FATAL, PGA_INT, (void *) &maxiter );
    else
	ctx->ga.MaxIter = maxiter;
    
    PGADebugExited("PGASetMaxGAIterValue");
}

/*U***************************************************************************
   PGAGetMaxGAIterValue - Returns the maximum number of iterations to run

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The maximum number of iterations to run

   Example:
      PGAContext *ctx;
      int maxiter;
      :
      maxiter = PGAGetMaxGAIterValue(ctx);

***************************************************************************U*/
int PGAGetMaxGAIterValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMaxGAIterValue");
    PGAFailIfNotSetUp("PGAGetMaxGAIterValue");

    PGADebugExited("PGAGetMaxGAIterValue");

    return(ctx->ga.MaxIter);
}

/*U****************************************************************************
   PGASetMaxNoChangeValue - specifiy maximum number of iterations of no change
   in the evaluation function value of the best string before stopping.  The
   default value is 50.  The stopping rule PGA_STOP_NOCHANGE must have been
   set by PGASetStoppingRuleType for this function call to have any effect.

   Category: Generation

   Inputs:
      ctx     - context variable
      maxiter - the maximum number of GA iterations allowed with no change
                in the best evaluation function value.

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMaxGAIterValue(ctx,5000);

****************************************************************************U*/
void PGASetMaxNoChangeValue(PGAContext *ctx, int max_no_change)
{
    PGADebugEntered("PGASetMaxNoChangeValue");
    PGAFailIfSetUp("PGASetMaxNoChangeValue");

    if (max_no_change <= 0)
	PGAError(ctx, "PGASetMaxNoChangeValue: max_no_change invalid",
		 PGA_FATAL, PGA_INT, (void *)&max_no_change);
    
    ctx->ga.MaxNoChange = max_no_change;
    
    PGADebugExited("PGASetMaxNoChangeValue");
}

/*U****************************************************************************
   PGASetMaxSimilarityValue - Specifiy the maximum percent of homogeneity of
   the population before stopping.  The similarity measure is the same
   evaluation function value.  The default value is 95 percent.  The stopping
   rule PGA_STOP_TOOSIMILAR must have been set by PGASetStoppingRuleType for
   this function call to have any effect.

   Category: Generation

   Inputs:
      ctx            - context variable
      max_similarity - the maximum percent of the population that can share
                       the same evaluation function value

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetMaxSimilarityValue(ctx,99);

****************************************************************************U*/
void PGASetMaxSimilarityValue(PGAContext *ctx, int max_similarity)
{
    PGADebugEntered("PGASetMaxSimilarityValue");
    PGAFailIfSetUp("PGASetMaxSimilarityValue");

    if ((max_similarity <= 0) || (max_similarity > 100))
        PGAError(ctx, "PGASetMaxSimilarityValue: max_similarity invalid",
                 PGA_FATAL, PGA_INT, (void *) &max_similarity);
    
    ctx->ga.MaxSimilarity = max_similarity;

    PGADebugExited("PGASetMaxSimilarityValue");
}
