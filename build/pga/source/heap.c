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
*      FILE: heap.c: This file contains routines for sorting individuals for
*                     selection
*
*      Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*               Brian P. Walenz
*****************************************************************************/

#include <pgapack.h>

/******************************************************************************
   PGAAdjustHeap - Auxiliary routine called by PGA*HeapSort

   Category: Sorting

   Inputs:
       ctx      - context variable
       a        - array of values to be sorted
       idx      - array of integer indices corresponding to the array
                  a being sorted
       i        - point of combination -- combine the node at a[i] with
                  the two heaps at a[2i+1] and a[2i+2] to form a single
                  heap.  0 <= i <= n-1.
       n        - size of the arrays a and idx
       j        - temporary variable, integer
       item     - temporary variable, type must be same as a
       item_idx - temporary variable, integer

   Output:

   Example:

******************************************************************************/
#define PGAAdjustHeap(ctx, a, idx, i, n, j, item, item_idx) {       \
  item     = a[i];                                                  \
  item_idx = idx[i];                                                \
  j = 2*i+1;      /* let j be the left child */                     \
  while (j < n) {                                                   \
    if (j<n-1 && a[j] > a[j+1])                                     \
       j = j + 1;       /* j is the larger child */                 \
    if (item <= a[j])   /* a position for item has been found */    \
       break;                                                       \
    a[(j-1)/2]   = a[j];    /* move the larger child up a level */  \
    idx[(j-1)/2] = idx[j];                                          \
    j = j*2+1;                                                      \
  }                                                                 \
  a[(j-1)/2]   = item;                                              \
  idx[(j-1)/2] = item_idx;                                          \
}                                                                   \




/*I****************************************************************************
   PGADblHeapSort - Uses a heapsort algorithm to sort from largest to smallest
   element.  An integer array, intialized with the original indices of the
   elements of array a is sorted also so that the original locations are known

   Category: Sorting

   Inputs:
       ctx      - context variable
       a        - array of (double) values to be sorted
       idx      - array of integer indices corresponding to the array
                  a being sorted
       n        - size of the arrays a and idx

   Output:
       The sorted arrays a and idx

   Example:
      The following code sorts the population by fitness

      PGAContext *ctx;
      int i,j,n,idx[LARGE]
      double a[LARGE];
      :
      n = PGAGetPopsize(ctx);
      for(i=0;i<n;i++) {
        a[i]   = PGAGetFitness(ctx,p,PGA_OLDPOP);
        idx[i] = i;
      }
      PGADblHeapSort ( ctx, a, idx, n);

****************************************************************************I*/
void PGADblHeapSort ( PGAContext *ctx, double *a, int *idx, int n )
{
  int i;
  double temp_a;
  int temp_idx;
  int j, item_idx;
  double item;

    PGADebugEntered("PGADblHeapSort");

  /*  Create a heap from our array  */
  for (i=(n-2)/2; i>=0; i--)
    PGAAdjustHeap(ctx, a, idx, i, n, j, item, item_idx);

  for ( i=n-1; i>=1; i--)  /* interchange the new maximum with the   */
  {                        /* element at the end of the tree         */
    temp_a   = a[i];
    temp_idx = idx[i];
    a[i]     = a[0];
    idx[i]   = idx[0];
    a[0]     = temp_a;
    idx[0]     = temp_idx;
    PGAAdjustHeap(ctx, a, idx, 0, i, j, item, item_idx);
  }

    PGADebugExited("PGADblHeapSort");
}




/*I****************************************************************************
   PGAIntHeapSort - Uses a heapsort algorithm to sort from largest to smallest
   element.  An integer array, intialized with the original indices of the
   elements of array a is sorted also so that the original locations are known

   Category: Sorting

   Inputs:
       ctx      - context variable
       a        - array of (int) values to be sorted
       idx      - array of integer indices corresponding to the array
                  a being sorted
       n        - size of the arrays a and idx

   Output:
       The sorted arrays a and idx

   Example:
      The following code sorts the population by fitness

      PGAContext *ctx;
      int i,j,n,idx[LARGE],a[LARGE];
      :
      n = PGAGetPopsize(ctx);
      for(i=0;i<n;i++) {
        a[i]   = (int) PGAGetEvaluation(ctx,p,PGA_OLDPOP);
        idx[i] = i;
      }
      PGAIntHeapSort ( ctx, a, idx, n);

****************************************************************************I*/
void PGAIntHeapSort ( PGAContext *ctx, int *a, int *idx, int n )
{
  int i;                   /* index of for loops                      */
  int temp_a;
  int temp_idx;
  int j, item_idx;
  double item;

    PGADebugEntered("PGAIntHeapSort");

  /*  Create a heap from our elements.  */
  for (i=(n-2)/2; i>=0; i--)
    PGAAdjustHeap(ctx, a, idx, i, n, j, item, item_idx);

  for ( i=n-1; i>=1; i--)  /* interchange the new maximum with the   */
  {                        /* element at the end of the tree         */
    temp_a   = a[i];
    temp_idx = idx[i];
    a[i]     = a[0];
    idx[i]   = idx[0];
    a[0]     = temp_a;
    idx[0]     = temp_idx;
    PGAAdjustHeap(ctx, a, idx, 0, i, j, item, item_idx);
  }

    PGADebugExited("PGAIntHeapSort");
}


