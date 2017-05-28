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
*     FILE: duplicate.c: This file contains the routines that have to do with
*                        testing for duplicate strings
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGADuplicate - determines if a specified string is a duplicate of one
  already in an existing population

  Category: Generation

  Inputs:
     ctx  - context variable
     p    - string index
     pop1 - symbolic constant of the population containing string p
     pop2 - symbolic constant of the (possibly partial) population containing
            strings to compare string p against
     n    - the number of strings in pop2 to compare string p against
            (indexed 0,...,n-1)

  Outputs:
     Returns PGA_TRUE if PGAGetNoDuplicates() returns PGA_TRUE and
     string p in population pop1 is a duplicate of at least one strings
     0,...,n-1 in population pop2.  Otherwise returns PGA_FALSE

  Example:
     Change any string in PGA_NEWPOP that is an exact copy of a string
     in PGA_OLDPOP.

     PGAContext *ctx;
     int b, n;
     :
     n  = PGAGetPopsize(ctx);
     for (b=0; b<n; b++)
         if (PGADuplicate(ctx, b, PGA_NEWPOP, PGA_OLDPOP, n))
             PGAChange(ctx, b, PGA_NEWPOP);


     Check if the best string in population PGA_OLDPOP is a duplicate of any
     of the strings in the first half of population PGA_NEWPOP.

     PGAContext *ctx;
     int b, n;
     :
     b  = PGAGetBestIndex(ctx, PGA_OLDPOP);
     n  = PGAGetPopsize(ctx) / 2;
     if (PGADuplicate(ctx, b, PGA_OLDPOP, PGA_NEWPOP, n))
         printf("A duplicate!\n");

****************************************************************************U*/
int PGADuplicate(PGAContext *ctx, int p, int pop1, int pop2, int n)
{
    int p2, fp;
    int RetVal = PGA_FALSE;
    
    PGADebugEntered("PGADuplicate");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGADuplicate", "p = ",
		  PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGADuplicate", "pop1 = ",
		  PGA_INT, (void *) &pop1 );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGADuplicate", "pop2 = ",
		  PGA_INT, (void *) &pop2 );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGADuplicate", "n  = ",
		  PGA_INT, (void *) &n );
    
    if (ctx->ga.NoDuplicates == PGA_TRUE) {
	if (ctx->fops.Duplicate) {
	    fp = ((p == PGA_TEMP1) || (p == PGA_TEMP2)) ? p : p+1;
	    for (p2 = 1; p2 <= n; p2++)
		if ((*ctx->fops.Duplicate)(&ctx, &fp, &pop1, &p2, &pop2)) {
		    RetVal = PGA_TRUE;
		    p2 = n+1;
		}
	} else {
	    for (p2 = 0; p2 < n; p2++)
		if ((*ctx->cops.Duplicate)(ctx, p, pop1, p2, pop2)) {
		    RetVal = PGA_TRUE;
		    p2 = n;
		}
	}
    }
    
    PGADebugExited("PGADuplicate");
    
    return(RetVal);
}


/*U****************************************************************************
  PGAChange - Repeatedly apply mutation to a string (with an increasing
  mutation rate) until one or more mutations have occurred.  This routine is
  usually used with PGADuplicate to modify a duplicate string.  It is not
  intended to replace PGAMutation

  Category: Generation

  Inputs:
     ctx  - context variable
     p    - string index
     pop  - symbolic constant of the population containing string p

  Outputs:
     Mutates string p in population pop via side effect.

  Example:
     Change any string in PGA_NEWPOP that is an exact copy of a string
     in PGA_OLDPOP.  To be complete, we should check the population again
     if any changes are made; for simplicity, we don't.

     PGAContext *ctx;
     int b, n;
     :
     n  = PGAGetPopsize(ctx);
     for (b=0; b<n; b++)
         if (PGADuplicate(ctx, b, PGA_NEWPOP, PGA_OLDPOP, n))
             PGAChange(ctx, b, PGA_NEWPOP);

****************************************************************************U*/
void PGAChange( PGAContext *ctx, int p, int pop )
{
    int    changed = PGA_FALSE;
    int    fp, nflips;
    double mr;

    PGADebugEntered("PGAChange");

    mr = ctx->ga.MutationProb;

    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR, "PGAChange", " mr = ",
                   PGA_DOUBLE, (void *) &mr );

    while (( changed == PGA_FALSE ) && (mr <= 1.0)) {
	if (ctx->fops.Mutation) {
	    fp = ((p == PGA_TEMP1) || (p == PGA_TEMP2)) ? p : p+1;
            nflips = (*ctx->fops.Mutation)(&ctx, &fp, &pop, &mr);
	} else {
	    nflips = (*ctx->cops.Mutation)( ctx, p, pop, mr );
	}

        if ( nflips > 0 )
            changed = PGA_TRUE;
        else
            mr = 1.1*mr;
    }

    if (changed == PGA_FALSE) {
	PGAError(ctx, "Could not change string:", PGA_WARNING, PGA_VOID, NULL);
	PGAPrintString(ctx, stderr, p, pop);
    }

    PGADebugExited("PGAChange");
}

/*U****************************************************************************
   PGASetNoDuplicatesFlag - A boolean flag to indicate if duplicate strings are
   allowed in the population. Valid choices are PGA_TRUE and PGA_FALSE.  The
   default is PGA_FALSE -- allow duplicates.

   Category: Generation

   Inputs:
      ctx  - context variable
      flag - PGA_TRUE or PGA_FALSE

   Outputs:
      None

   Example:
      Set the NoDuplicates flag to require that all strings are unique.

      PGAContext *ctx;
      :
      PGASetNoDuplicatesFlag(ctx,PGA_TRUE);

****************************************************************************U*/
void PGASetNoDuplicatesFlag( PGAContext *ctx, int no_dup)
{
    PGADebugEntered("PGASetNoDuplicatesFlag");

    switch (no_dup) {
        case PGA_TRUE:
        case PGA_FALSE:
            ctx->ga.NoDuplicates = no_dup;
            break;
        default:
            PGAError ( ctx, "PGASetNoDuplicatesFlag: Invalid value of no_dup:",
                       PGA_FATAL, PGA_INT, (void *) &no_dup);
            break;
    }

    PGADebugExited("PGASetNoDuplicatesFlag");
}

/*U***************************************************************************
   PGAGetNoDuplicatesFlag - Returns PGA_TRUE if duplicates are not allowed,
   else returns PGA_FALSE.

   Category: Generation

   Inputs:
      ctx - context variable

   Outputs:
      The value of the NoDuplicates flag.

   Example:
      PGAContext *ctx;
      int nodups;
      :
      nodups = PGAGetNoDuplicatesFlag(ctx);
      switch (nodups) {
      case PGA_TRUE:
          printf("Duplicate strings not allowed in population\n");
          break;
      case PGA_FALSE:
          printf("Duplicate strings allowed in population\n");
          break;
      }

***************************************************************************U*/
int PGAGetNoDuplicatesFlag (PGAContext *ctx)
{
    PGADebugEntered("PGAGetNoDuplicatesFlag");

    PGAFailIfNotSetUp("PGAGetNoDuplicatesFlag");

    PGADebugExited("PGAGetNoDuplicatesFlag");

    return(ctx->ga.NoDuplicates);
}
