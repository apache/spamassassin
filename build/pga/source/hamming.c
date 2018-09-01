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
*     FILE: hamming.c: This file contains the routines that have to do with
*                      Hamming distances.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGAHammingDistance - Calculates the mean Hamming distance for a population
  of binary strings.  For all other data types returns a value of 0.0 and
  prints a warning message.

  Category: Utility

  Inputs:
      ctx      - context variable
      popindex - symbolic constant of the population for which the
                 Hamming distance is to be calculated
  Output:
      The mean Hamming distance in the population

  Example:
      PGAContext *ctx;
      double hd;
      :
      hd = PGAHammingDistance(ctx, PGA_NEWPOP);

****************************************************************************U*/
double PGAHammingDistance( PGAContext *ctx, int popindex)
{
    int i, j, hd, count=0;
    double avg_hd = 0.;
    PGAIndividual *pop;      /* pointer to appropriate population          */

    PGADebugEntered("PGAHammingDistance");

    switch (popindex) {
    case PGA_OLDPOP:
        pop = ctx->ga.oldpop;
        break;
    case PGA_NEWPOP:
        pop = ctx->ga.newpop;
        break;
    default:
        PGAError( ctx, "PGAHammingDistance: Invalid value of popindex:",
                  PGA_FATAL, PGA_INT, (void *) &popindex );
        break;
    }

    switch (ctx->ga.datatype) {
    case PGA_DATATYPE_BINARY:
        for(i=0; i<ctx->ga.PopSize-1; ++i)
            for ( j = i+1; j<ctx->ga.PopSize; ++j ) {
                count++;
                hd = PGABinaryHammingDistance( ctx,
                                            (pop+i)->chrom, (pop+j)->chrom );
                avg_hd += (double) hd;
            }
        avg_hd /= (double) count;
        break;
    case PGA_DATATYPE_INTEGER:
        avg_hd = 0.0;
        PGAError( ctx,
        "PGAHammingDistance: No Hamming Distance for PGA_DATATYPE_INTEGER ",
                  PGA_WARNING,
                  PGA_DOUBLE,
                  (void *) &avg_hd );
        break;
    case PGA_DATATYPE_REAL:
        avg_hd = 0;
        PGAError( ctx,
        "PGAHammingDistance: No Hamming Distance for PGA_DATATYPE_REAL ",
                  PGA_WARNING,
                  PGA_DOUBLE,
                  (void *) &avg_hd );
        break;
    case PGA_DATATYPE_CHARACTER:
        avg_hd = 0;
        PGAError( ctx,
        "PGAHammingDistance: No Hamming Distance for PGA_DATATYPE_CHARACTER ",
                  PGA_WARNING,
                  PGA_DOUBLE,
                  (void *) &avg_hd );
        break;
    case PGA_DATATYPE_USER:
        avg_hd = 0;
        PGAError( ctx,
        "PGAHammingDistance: No Hamming Distance for PGA_DATATYPE_USER ",
                  PGA_WARNING,
                  PGA_DOUBLE,
                  (void *) &avg_hd );
        break;
    default:
        PGAError( ctx,
                 "PGAHammingDistance: Invalid value of datatype:",
                  PGA_FATAL,
                  PGA_INT,
                  (void *) &(ctx->ga.datatype) );
        break;
    }

    PGADebugExited("PGAHammingDistance");

    return(avg_hd);
}
