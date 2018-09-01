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
*     FILE: random.c: This file contains routines to generate randomness.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
   PGARandomFlip - flip a biased coin and return PGA_TRUE if the coin is
   a "winner."  Otherwise, return PGA_FALSE.

   Category: Utility

   Inputs:
      ctx - context variable
      p   - biased probability (.5 is a fair coin)

   Outputs:
      PGA_TRUE or PGA_FALSE

   Example:
      To return PGA_TRUE approximately seventy percent of the time, use

      PGAContext *ctx;
      int p;
      :
      PGARandomFlip(ctx, 0.7)

****************************************************************************U*/
int PGARandomFlip ( PGAContext *ctx, double p )
{
    PGADebugEntered("PGARandomFlip");

    PGADebugExited("PGARandomFlip");

    return( (PGARandom01(ctx, 0) < p) ? PGA_TRUE : PGA_FALSE);
}


/*U****************************************************************************
   PGARandomInterval - returns a uniform random number on the specified
   interval

   Category: Utility

   Inputs:
      ctx - context variable
      start - starting (integer) value of the interval
      end   - ending   (integer) value of the interval

   Outputs:
      A uniformly distributed random number in the interval [start, end].

   Example:
      Generate a value uniformly random from the interval [0,99]

      PGAContext *ctx;
      :
      PGARandomInterval(ctx, 0, 99);

****************************************************************************U*/
int PGARandomInterval( PGAContext *ctx, int start, int end)
{
    PGADebugEntered("PGARandomInterval");
    
    PGADebugExited("PGARandomInterval");

    return( (int)floor(PGARandom01(ctx, 0) * (double)(end-start+1) ) + start );
    
/*
   The original call...

   return(ceil( (double)(end-start+1) * PGARandom01(ctx, 0) )+start-1);
*/
}


/*****************************************************************************
*  This is a C language implementation of the universal random number        *
*  generator proposed by G. Marsaglia and A. Zaman and translated from       *
*  F. James' version.                                                        *
*                                                                            *
*  F. James                                                                  *
*  A review of pseudorandom number generators                                *
*  Computer Physics Communication                                            *
*  60 (1990) 329-344                                                         *
*                                                                            *
*  G. Marsaglia, A. Zaman, W. Tseng                                          *
*  Stat Prob. Letter                                                         *
*  9 (1990) 35.                                                              *
*                                                                            *
*  G. Marsaglia, A. Zaman                                                    *
*  FSU-SCRI-87-50                                                            *
*                                                                            *
*  This algorithm is a combination of a lagged Fibonacci and arithmetic      *
*  sequence (F. James) generator with period of 2^144.  It provides 32-bit   *
*  floating point numbers in the range from zero to one.  It is claimed to   *
*  be portable and provides bit-identical results on all machines with at    *
*  least 24-bit mantissas.                                                   *
*                                                                            *
*  PGARandom01 should be initialized with a 32-bit integer seed such that    *
*  0 <= seed <= 900,000,000.  Each of these 900,000,000 values gives rise    *
*  to an independent sequence of ~ 10^30.                                    *
*                                                                            *
*  warning on use of static storage class on thread shared memory machines   *
*****************************************************************************/
/*U****************************************************************************
   PGARandom01 - generates a uniform random number on the interval [0,1)
   If the second argument is 0 it returns the next random number in the
   sequence.  Otherwise, the second argument is used as a new seed for the
   population

   Category: Utility

   Inputs:
      ctx     - context variable
      newseed - either 0 to get the next random number, or nonzero
                to reseed
   Outputs:
      A random number on the interval [0,1)

   Example:
      To get the next random number use

      PGAContext *ctx;
      double r;
      :
      r = PGARandom01(ctx,0);

****************************************************************************U*/
double PGARandom01( PGAContext *ctx, int newseed )
{

    /* initialization variables */
    int ij, kl, i, j, k, l, m, ii, jj;
    float s, t;

    /* random number variables */
    static int seed=1;      /* default seed if none specified */
    static int i96, j96;
    static float u[97], uni, c, cd, cm;


    PGADebugEntered("PGARandom01");

    /* initialization */
/*     printf("i96 = %d\tj96 = %d\n", i96, j96); */

    if ( newseed != 0 ) {

        seed = newseed % 900000000;
        ij   = seed / 30082;
        kl   = seed - 30082 * ij;
        i    = ( (ij/177) % 177 ) + 2;
        j    = (  ij      % 177 ) + 2;
        k    = ( (kl/169) % 178 ) + 1;
        l    = (  kl      % 169 );

        for ( ii=0; ii<97; ii++ ) {

            s = 0.0;
            t = 0.5;

            for ( jj=0; jj<24; jj++ ) {

                m = ( ((i*j) % 179) * k ) % 179;
                i = j;
                j = k;
                k = m;
                l = ( (53*l) + 1 ) % 169;
                if ( ( (l*m) % 64 ) >= 32 )
                    s += t;
                t *= .5;
            }

            u[ii] = s;
        }

        c   = 362436.  /16777216.;
        cd  = 7654321. /16777216.;
        cm  = 16777213./16777216.;
        i96 = 96;
        j96 = 32;
    }

    /* random number generation */
    uni = u[i96] - u[j96];
    if ( uni < 0. ) uni += 1.0;
    u[i96] = uni;
    i96--;
    if ( i96 < 0  ) i96 = 96;
    j96--;
    if ( j96 < 0  ) j96 = 96;
    c   -= cd;
    if ( c   < 0. ) c += cm;
    uni -= c;
    if ( uni < 0. ) uni += 1.0;

    PGADebugExited("PGARandom01");
    return( (double) uni);
}

/*U****************************************************************************
   PGARandomUniform - returns a uniform random number on the interval
   [start,end]

   Category: Utility

   Inputs:
      ctx - context variable
      start - starting (double) value of the interval
      end   - ending   (double) value of the interval

   Outputs:
      A random number on the interval [start,end]

   Example:
      Generate a uniform random number on the interval [-0.5, 1.5]

      PGAContext *ctx;
      double r;
      :
      r = PGARandomUniform(ctx, -0.5, 1.5);

****************************************************************************U*/
double PGARandomUniform( PGAContext *ctx, double start, double end)
{
    double val, r;

    PGADebugEntered("PGARandomUniform");

    r = PGARandom01(ctx, 0);
    val = (end-start) * r + start;

    PGADebugExited("PGARandomUniform");

    return(val);
}


/*U****************************************************************************
   PGARandomGaussian - returns an approximation to a Gaussian random number

   Category: Utility

   Inputs:
       mean  - the mean of the Gaussian distribution
       sigma - the standard deviation of the Gaussian distribution

   Outputs:
      A random number selected from a Gaussian distribution with given
      mean and standard deviation

   Example:
      To generate a Gaussian random number with mean 0.0 and standard
      deviation 1.0 use

      PGAContext *ctx;
      :
      r = PGARandomGaussian(ctx, 0.0, 1.0);

****************************************************************************U*/
double PGARandomGaussian( PGAContext *ctx, double mean, double sigma)
{
    int i;
    double sum = 0.;

    PGADebugEntered("PGARandomGaussian");

    for (i=11;i>=0; i--)
        sum += PGARandom01(ctx, 0);

    PGADebugExited("PGARandomGaussian");

    return ( (sum-6.0) * sigma + mean );
}

/*U***************************************************************************
   PGAGetRandomSeed - returns the integer to seed random numbers with

   Category: Utility

   Inputs:
      ctx - context variable

   Outputs:
      The seed for the random number generator

   Example:
      PGAContext *ctx;
      int seed;
      :
      seed = PGAGetRandomSeed(ctx);

***************************************************************************U*/
int PGAGetRandomSeed(PGAContext *ctx)
{
    PGADebugEntered("PGAGetRandomSeed");

    PGADebugExited("PGAGetRandomSeed");

    return(ctx->init.RandomSeed);
}

/*U****************************************************************************
   PGASetRandomSeed - set a seed for the random number generator.  The
   default is to use a random seed.  Specifying a seed exlicitly allows
   for reproducibility of runs.

   Category: Utility

   Inputs:
      ctx  - context variable
      seed - seed  for the random number generator

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetRandomSeed(ctx,1);

****************************************************************************U*/
void PGASetRandomSeed(PGAContext *ctx, int seed)
{
#define MAX_PROCESSORS 2048

    PGADebugEntered("PGASetRandomSeed");
    PGAFailIfSetUp("PGASetRandomSeed");

    if ((seed < 1) || (seed + MAX_PROCESSORS > 900000000))
	PGAError ( ctx, "PGASetRandomSeed: Invalid value of seed:",
		  PGA_FATAL, PGA_INT, (void *) &seed);
    else
	ctx->init.RandomSeed = seed;
    
    PGADebugExited("PGASetRandomSeed");
}
