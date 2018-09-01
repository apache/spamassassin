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
*     FILE: system.c: This file contains systme routines such as errors and
*                     exits
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

char PGAProgram[100];    /* Holds argv[0] for PGAUsage() call */

/*U****************************************************************************
   PGAError - reports error messages.  Prints out the message supplied, and
   the value of a piece of data.  Terminates if PGA_FATAL.

   Category: System

   Inputs:
      ctx      - context variable
      msg      - the error message to print
      level    - PGA_WARNING or PGA_FATAL to indicate the error's severity
      datatype - the data type of the following argument
      data     - the address of the data to be written out, cast as a void
                 pointer

   Outputs:
      None

   Example:
      PGAContext *ctx;
      int         val;
      :
      PGAError(ctx, "Some Non Fatal Error: val = ", PGA_WARNING, PGA_INT,
               (void *) &val);
      :
      PGAError(ctx, "A Fatal Error!", PGA_FATAL, PGA_VOID, NULL);

****************************************************************************U*/
void PGAError( PGAContext *ctx, char *msg,
               int level, int datatype, void *data )
{

    PGADebugEntered("PGAError");

    switch (datatype) {
      case PGA_INT:
	fprintf(stderr, "%s %d\n", msg, *(int *)    data);
	break;
      case PGA_DOUBLE:
	fprintf(stderr, "%s %f\n", msg, *(double *) data);
	break;
      case PGA_CHAR:
	fprintf(stderr, "%s %s\n", msg,  (char *)   data);
	break;
      case PGA_VOID:
	fprintf(stderr, "%s\n", msg);
	break;
    }
    if ( level == PGA_FATAL ) {
	fprintf(stderr, "PGAError: Fatal\n");
	PGADestroy(ctx);
	exit(-1);
    }
    PGADebugExited("PGAError");
}

/*U****************************************************************************
  PGADestroy - deallocate memory for this instance of PGAPack, if this context
  initialized MPI, finalize MPI as well.

  Category: Generation

  Inputs:
     ctx   - context variable

  Outputs:
     None

  Example:
    PGAContext *ctx;
    :
    PGADestroy(ctx);

****************************************************************************U*/
void PGADestroy (PGAContext *ctx)
{
    int i;

    PGADebugEntered("PGADestroy");

    /*  These are allocated by PGASetUp.  Free then only if PGASetUp
     *  was called.
     */
    if (ctx->sys.SetUpCalled == PGA_TRUE) {
      /*  Free the population...fly little birdies!  You're FREE!!!  */
      for ( i = 0; i < ctx->ga.PopSize + 2; i++ ) {
        free ( ctx->ga.oldpop[i].chrom );
        free ( ctx->ga.newpop[i].chrom );
      }
      free ( ctx->ga.oldpop );
      free ( ctx->ga.newpop );

      /*  Free the scratch space.  */
      free ( ctx->scratch.intscratch );
      free ( ctx->scratch.dblscratch );
      free ( ctx->ga.selected );
      free ( ctx->ga.sorted );
    }

    /*  These are allocated by PGACreate  */
    if (ctx->ga.datatype == PGA_DATATYPE_REAL)
      {
        free ( ctx->init.RealMax );
        free ( ctx->init.RealMin );
      }
    else if (ctx->ga.datatype == PGA_DATATYPE_INTEGER)
      {
        free ( ctx->init.IntegerMax );
        free ( ctx->init.IntegerMin );
      }

    /*  We want to finalize MPI only if it was not started for us (as
     *  fortran would do) AND it is actually running.  It would not be
     *  running if, for example, -pgahelp is specified on the command
     *  line.
     */
    MPI_Initialized(&i);
    if ((ctx->par.MPIAlreadyInit == PGA_FALSE) && i)
      MPI_Finalize();

    /*  We really should perform a PGADebugPrint here, but we can't;
     *  we've already deallocated most of the stuff we need!!
     */
    free ( ctx );
}

/*U***************************************************************************
   PGAGetMaxMachineIntValue - returns the largest integer of the current
   machine

   Category: System

   Inputs:
      ctx - context variable

   Outputs:
      The largest integer of the given machine

   Example:
      PGAContext *ctx;
      int intmax;
      :
      intmax = PGAGetMaxMachineIntValue(ctx);

***************************************************************************U*/
int PGAGetMaxMachineIntValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMaxMachineIntValue");

    PGADebugExited("PGAGetMaxMachineIntValue");

    return(ctx->sys.PGAMaxInt);
}

/*U***************************************************************************
   PGAGetMaxMachineIntValue - returns the smallest integer of the current
   machine

   Category: System

   Inputs:
      ctx - context variable

   Outputs:
      The smallest integer of the given machine

   Example:
      PGAContext *ctx;
      int intmin;
      :
      intmin = PGAGetMinMachineIntValue(ctx);

***************************************************************************U*/
int PGAGetMinMachineIntValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMinMachineIntValue");

    PGADebugExited("PGAGetMinMachineIntValue");

    return(ctx->sys.PGAMinInt);
}

/*U***************************************************************************
   PGAGetMaxMachineDoubleValue - returns the largest double of the current
   machine

   Category: System

   Inputs:
      ctx - context variable

   Outputs:
      The largest double of the given machine

   Example:
      PGAContext *ctx;
      double big;
      :
      big = PGAGetMaxMachineDoubleValue(ctx);

***************************************************************************U*/
double PGAGetMaxMachineDoubleValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMaxMachineDoubleValue");

    PGADebugExited("PGAGetMaxMachineDoubleValue");

    return(ctx->sys.PGAMaxDouble);
}

/*U***************************************************************************
   PGAGetMaxMachineDoubleValue - returns the smallest double of the current
   machine

   Category: System

   Inputs:
      ctx - context variable

   Outputs:
      The smallest double of the given machine

   Example:
      PGAContext *ctx;
      double small;
      :
      small = PGAGetMinMachineDoubleValue(ctx);

***************************************************************************U*/
double PGAGetMinMachineDoubleValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetMinMachineDoubleValue");

    PGADebugExited("PGAGetMinMachineDoubleValue");

    return(ctx->sys.PGAMinDouble);
}


/*U****************************************************************************
   PGAUsage - print list of available parameters and quit

   Inputs:
      ctx - context variable

   Outputs:
     list of available parametersNone

   Example:
      PGAContext ctx;
      :
      PGAUsage(ctx);

****************************************************************************U*/
void PGAUsage( PGAContext *ctx )
{
    /*  Print the usage info out if MPI isn't running (thus, only one process
     *  is probably running), or if we actually are the master.
     */
    if (!ctx->par.MPIAlreadyInit || (PGAGetRank(ctx, MPI_COMM_WORLD) == 0)) {
	PGAPrintVersionNumber( ctx );
	printf("PGAPack usage: %s [pga options]\n", PGAProgram);
	printf("Valid PGAPack options:\n");
	printf("\t-pgahelp          \tget this message\n");
	printf("\t-pgahelp debug    \tlist of debug options\n");
	printf("\t-pgadbg <option>  \tset debug option\n");
	printf("\t-pgadebug <option>\tset debug option\n");
	printf("\t-pgaversion       \tprint current PGAPack version number\n");
	printf("\n");
    }
    PGADestroy(ctx);
    exit(-1);
}

/*U****************************************************************************
   PGAPrintVersionNumber - print PGAPack version number

   Inputs:
      ctx - context variable

   Outputs:
      PGAPack version number

   Example:
      PGAContext ctx;
      :
      PGAPrintVersionNumber(ctx);

****************************************************************************U*/
void PGAPrintVersionNumber( PGAContext *ctx )
{
    if (!ctx->par.MPIAlreadyInit || (PGAGetRank(ctx, MPI_COMM_WORLD) == 0)) {
#ifdef FAKE_MPI
#define PRINT1  "Sequential"
#else
#define PRINT1  "Parallel"
#endif               
        printf("\nPGAPack version 1.0: (%s, %s)\n\n",
	       (OPTIMIZE)                ? "Optimized"  : "Debug",
		PRINT1 );
    }
}

