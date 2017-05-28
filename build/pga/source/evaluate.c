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
*     FILE: evaluate.c: This file contains routines specific to the evaluation
*                       of the strings.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
   PGASetEvaluation - Set the evaluation function value for a string to a
   specified value.  Also sets the evaulation up to date flag to PGA_TRUE.

   Category: Fitness & Evaluation

   Inputs:
      ctx  - context variable
      p    - string index
      pop  - symbolic constant of the population string p is in
      val  - the (user) evaluation value to assign to string p

   Outputs:
      Sets the evaluation function value of string p and the EvalUpToDate
      flag (to PGA_TRUE) via side effect

   Example:
      Set the evaluation function value of string p in population PGA_NEWPOP
      to 123.456.

      PGAContext *ctx;
      int p;
      :
      PGASetEvaluation(ctx, p, PGA_NEWPOP, 123.456);

****************************************************************************U*/
void PGASetEvaluation ( PGAContext *ctx, int p, int pop, double val )
{
    PGAIndividual *ind;

    PGADebugEntered("PGASetEvaluation");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGASetEvaluation", "p = ",
                   PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGASetEvaluation", "pop = ",
                   PGA_INT, (void *) &pop );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGASetEvaluation", "val = ",
                   PGA_DOUBLE, (void *) &val );

    ind               = PGAGetIndividual ( ctx, p, pop );
    ind->evalfunc     = val;
    ind->evaluptodate = PGA_TRUE;

    PGADebugExited("PGASetEvaluation");
}

/*U***************************************************************************
   PGAGetEvaluation - returns the evaluation function value for
   string p in population pop

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in

   Outputs:
      The evaluation function value for string p in population pop

   Example:
      PGAContext *ctx;
      int p;
      double eval;
      :
      eval = PGAGetEvaluation(ctx, p, PGA_NEWPOP);

***************************************************************************U*/
double PGAGetEvaluation ( PGAContext *ctx, int p, int pop )
{
    PGAIndividual *ind;

    PGADebugEntered("PGAGetEvaluation");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAGetEvaluation", "p = ",
                   PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAGetEvaluation", "pop = ",
                   PGA_INT, (void *) &pop );

    ind               = PGAGetIndividual ( ctx, p, pop );

#ifndef OPTIMIZE
    if (ind->evaluptodate != PGA_TRUE)
	PGAError(ctx, "Evaluation not up to date.  Returning old evaluation.",
                 PGA_WARNING, PGA_VOID, NULL);
#endif

    PGADebugExited("PGAGetEvaluation");
    return(ind->evalfunc);
}

/*U****************************************************************************
  PGASetEvaluationUpToDateFlag - sets the flag associated with a
  string to PGA_TRUE or PGA_FLASE to indicate whether the evaluate
  function value is out-of-date or not.  Note that this flag is always
  set to PGA_TRUE when PGASetEvaluation is called.

    Category: Fitness & Evaluation

    Inputs:
      ctx  - context variable
      p    - string index
      pop  - symbolic constant of the population string p is in
      status - boolean for whether up-to-date

   Outputs:
      Sets the EvalUpToDate associated with the evaluation function value of
      string p via side effect

   Example:
      Set the evaluation function flag for string p in population PGA_NEWPOP
      to PGA_FALSE (as might happen after, for example, calling a hill-climbing
      routine that modified this string).

      PGAContext *ctx;
      int p;
      :
      PGASetEvaluationUpToDateFlag(ctx, p, PGA_NEWPOP, PGA_FALSE);

****************************************************************************U*/
void PGASetEvaluationUpToDateFlag ( PGAContext *ctx, int p, int pop,
                                   int status )
{
    PGAIndividual *ind;

    PGADebugEntered("PGASetEvaluationUpToDateFlag");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGASetEvaluationUpToDateFlag",
                  "p = ", PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGASetEvaluationUpToDateFlag",
                  "pop = ", PGA_INT, (void *) &pop );

    ind = PGAGetIndividual ( ctx, p, pop );

    switch(status) {
    case PGA_TRUE:
    case PGA_FALSE:
      ind->evaluptodate = status;
      break;
    default:
      PGAError(ctx, "PGASetEvaluationUpToDateFlag: Invalid value of status:",
               PGA_FATAL, PGA_INT, (void *) &status);
      break;
    }

    PGADebugExited("PGASetEvaluationUpToDateFlag");
}

/*U***************************************************************************
  PGAGetEvaluationUpToDateFlag - returns true/false to indicate
  whether the evaluate function value is up to date

   Category: Fitness & Evaluation

   Inputs:
      ctx - context variable
      p   - string index
      pop - symbolic constant of the population the string is in

   Outputs:
      Returns PGA_TRUE if the evaluate function value is up to date.
      Otherwise, returns PGA_FALSE

   Example:
      PGAContext *ctx;
      int uptodate;
      :
      uptodate = PGAGetEvaluationUpToDateFlag(ctx);
      switch (uptodate) {
      case PGA_TRUE:
          printf("Evaluation function value current\n");
          break;
      case PGA_FALSE:
          printf("Evaluation function value out-of-date\n");
          break;
      }

***************************************************************************U*/
int PGAGetEvaluationUpToDateFlag ( PGAContext *ctx, int p, int pop )
{
    PGAIndividual *ind;

    PGADebugEntered("PGAGetEvaluationUpToDateFlag");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAGetEvaluationUpToDateFlag",
                  "p = ", PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAGetEvaluationUpToDateFlag",
                   "p = ", PGA_INT, (void *) &pop );

    ind = PGAGetIndividual ( ctx, p, pop );

    PGADebugExited("PGAGetEvaluationUpToDateFlag");
    return(ind->evaluptodate);
}

/*U****************************************************************************
  PGAGetRealFromBinary - Interpets a binary string as encoding a real value
  and returns the real value it represents.

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in the binary representation
      end   - ending bit position in the binary representation
      lower - lower bound of the interval the real number is defined on
      upper - lower bound of the interval the real number is defined on

  Outputs:
      The real value encoded by the binary string

  Example:
      Decode a real value from the string p in population PGA_NEWPOP.  The
      value to decode lies on the interval [-10,20] and is represented
      using the 20 bits in bit positions 10--29.

      double x;
      :
      x = PGAGetRealFromBinary(ctx, p, PGA_NEWPOP, 10, 29, -10.0, 20.0);

****************************************************************************U*/
double PGAGetRealFromBinary(PGAContext *ctx, int p, int pop, int start,
                            int end, double lower, double upper)
{
     int length, sum;
     double value;

    PGADebugEntered("PGAGetRealFromBinary");
     PGACheckDataType("PGAGetRealFromBinary", PGA_DATATYPE_BINARY);

     length = end - start + 1;

     if (start < 0)
          PGAError(ctx, "PGAGetRealFromBinary: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
	 PGAError(ctx, "PGAGetRealFromBinary: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAGetRealFromBinary: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (lower >= upper)
          PGAError(ctx, "PGAGetRealFromBinary: lower exceeds upper:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &lower);

     sum = PGAGetIntegerFromBinary(ctx, p, pop, start, end);
     value = PGAMapIntegerToReal(ctx, sum, 0,
                                 (length == sizeof(unsigned) * 8 - 1)
                                 ? INT_MAX : (1u << length) - 1, lower, upper);

    PGADebugExited("PGAGetRealFromBinary");

     return(value);
}

/*U****************************************************************************
  PGAGetRealFromGrayCode - interpets a binary reflected Gray code sequence in
  a binary string as encoding a real value and returns the real value it
  represents.

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in the binary representation
      end   - ending bit position in the binary representation
      lower - lower bound of the interval the real number is defined on
      upper - lower bound of the interval the real number is defined on

  Outputs:
      The real value encoded by the binary reflected Gray code sequence

  Example:
      Decode a real value from the string p in population PGA_NEWPOP.  The
      value to decode lies on the interval [-10,20] and is represented
      using the 20 bits in bit positions 10--29.

      double x;
      :
      x = PGAGetRealFromGrayCode(ctx, p, PGA_NEWPOP, 10, 29, -10.0, 20.0);

****************************************************************************U*/
double PGAGetRealFromGrayCode(PGAContext *ctx, int p, int pop, int start,
                                  int end, double lower, double upper)
{
     int length, sum;
     double value;

    PGADebugEntered("PGAGetRealFromGrayCode");
     PGACheckDataType("PGAGetRealFromGrayCode", PGA_DATATYPE_BINARY);

     length = end - start + 1;

     if (start < 0)
          PGAError(ctx, "PGAGetRealFromGrayCode: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAGetRealFromGrayCode: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAGetRealFromGrayCode: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (lower >= upper)
          PGAError(ctx, "PGAGetRealFromGrayCode: lower exceeds upper:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &lower);

     sum = PGAGetIntegerFromGrayCode(ctx, p, pop, start, end);
     value = PGAMapIntegerToReal(ctx, sum, 0,
                                 (length == sizeof(unsigned) * 8 - 1)
                                 ? INT_MAX : (1u << length) - 1, lower, upper);

    PGADebugExited("PGAGetRealFromGrayCode");

     return(value);
}

/*U****************************************************************************
  PGAEncodeRealAsBinary - encodes a real value as a binary string

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in p to encode val in
      end   - ending bit position in p to encode val in
      low   - lower bound of the interval the val is defined on
      high  - lower bound of the interval the val is defined on
      val   - the real number to be represented as a binary string

  Outputs:
      The string is modified by side-effect.

  Example:
      Encode 3.14 from the interval [0,10] in 30 bits in bit positions
      0--29 in string p in population PGA_NEWPOP.

      PGAContext *ctx;
      int p;
      :
      PGAEncodeRealAsBinary(ctx, p, PGA_NEWPOP, 0, 29, 0.0, 10.0, 3.14);

****************************************************************************U*/
void PGAEncodeRealAsBinary(PGAContext *ctx, int p, int pop, int start,
                               int end, double low, double high, double val)
{
     int length, d;

    PGADebugEntered("PGAEncodeRealAsBinary");
     PGACheckDataType("PGAEncodeRealAsBinary", PGA_DATATYPE_BINARY);

     length = end - start + 1;
     if (start < 0)
          PGAError(ctx, "PGAEncodeRealAsBinary: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAEncodeRealAsBinary: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAEncodeRealAsBinary: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (low >= high)
          PGAError(ctx, "PGAEncodeRealAsBinary: low exceeds high:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &low);
     if (val < low || val > high)
          PGAError(ctx, "PGAEncodeRealAsBinary: val outside of bounds:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &val);

     d = PGAMapRealToInteger(ctx, val, low, high, 0,
                             (length == sizeof(unsigned) * 8 - 1)
                             ? INT_MAX : (1u << length) - 1);
     PGAEncodeIntegerAsBinary(ctx, p, pop, start, end, d);

    PGADebugExited("PGAEncodeRealAsBinary");
}

/*U****************************************************************************
  PGAEncodeRealAsGrayCode - encodes a real value as a binary reflected Gray
  code sequence

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in p to encode val in
      end   - ending bit position in p to encode val in
      low   - lower bound of the interval the val is defined on
      high  - lower bound of the interval the val is defined on
      val   - the real number to be represented as a binary string

  Outputs:
      The string is modified by side-effect.

  Example:
      Encode 3.14 from the interval [0,10] in 30 bits in bit positions
      0--29 in string p in population PGA_NEWPOP as a binary reflected Gray
      code sequence.

      PGAContext *ctx;
      int p;
      :
      PGAEncodeRealAsGrayCode(ctx, p, PGA_NEWPOP, 0, 29, 0.0, 10.0, 3.14);

****************************************************************************U*/
void PGAEncodeRealAsGrayCode(PGAContext *ctx, int p, int pop, int start,
                              int end, double low, double high, double val)
{
     int length, d;

    PGADebugEntered("PGAEncodeRealAsGrayCode");
     PGACheckDataType("PGAEncodeRealAsGrayCode", PGA_DATATYPE_BINARY);

     length = end - start + 1;
     if (start < 0)
          PGAError(ctx, "PGAEncodeRealAsGrayCode: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAEncodeRealAsGrayCode: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAEncodeRealAsGrayCode: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (low >= high)
          PGAError(ctx, "PGAEncodeRealAsGrayCode: low exceeds high:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &low);
     if (val < low || val > high)
          PGAError(ctx, "PGAEncodeRealAsGrayCode: val outside of bounds:",
                   PGA_FATAL, PGA_DOUBLE, (void *) &val);

     d = PGAMapRealToInteger(ctx, val, low, high, 0,
                             (length == sizeof(unsigned) * 8 - 1) ? INT_MAX :
                             (1u << length) - 1);
     PGAEncodeIntegerAsGrayCode(ctx, p, pop, start, end, d);

    PGADebugExited("PGAEncodeRealAsGrayCode");
}


/*U****************************************************************************
  PGAGetIntegerFromBinary - interpets a binary string as encoding an integer
  value and returns the integer value it represents.

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in the binary representation
      end   - ending bit position in the binary representation

  Outputs:
      The integer value encoded by the binary string

  Example:
      Get an integer j from bits 10--29 of string p in population PGA_NEWPOP.

      PGAContext *ctx;
      int j, p;
      :
      j = PGAGetIntegerFromBinary(ctx, p, PGA_NEWPOP, 10, 29);

****************************************************************************U*/
int PGAGetIntegerFromBinary(PGAContext *ctx, int p, int pop, int start,
                                 int end)
{
     int length, i, val;
     unsigned power2;

    PGADebugEntered("PGAGetIntegerFromBinary");
     PGACheckDataType("PGAGetIntegerFromBinary", PGA_DATATYPE_BINARY);

     length = end - start + 1;
     if (length > sizeof(int) * 8 - 1)
          PGAError(ctx, "PGAGetIntegerFromBinary: length of bit string "
                   "exceeds sizeof type int:", PGA_FATAL, PGA_INT,
                   (void *) &length);
     if (start < 0)
          PGAError(ctx, "PGAGetIntegerFromBinary: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAGetIntegerFromBinary: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAGetIntegerFromBinary: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);

     val = 0;
     power2 = 1u << (length - 1);
     for (i = start; i <= end; i++)
     {
          if (PGAGetBinaryAllele(ctx, p, pop, i))
               val += power2;
          power2 >>= 1;
     }

    PGADebugExited("PGAGetIntegerFromBinary");

     return(val);
}

/*U****************************************************************************
  PGAGetIntegerFromGrayCode - interpets a binary reflected Gray code sequence
  as encoding an integer value and returns the integer value it represents.

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in the binary representation
      end   - ending bit position in the binary representation

  Outputs:
      The integer value encoded by the binary reflected Gray code sequence

  Example:
      Get an integer j from bits 10--29 of string p in population PGA_NEWPOP.
      The string is encoded in Gray code.

      PGAContext *ctx;
      int j, p;
      :
      j = PGAGetIntegerFromGrayCode(ctx, p, PGA_NEWPOP, 10, 29);

****************************************************************************U*/
int PGAGetIntegerFromGrayCode(PGAContext *ctx, int p, int pop, int start,
                                   int end)
{
     int length, *BitString, i, val;
     unsigned power2;

    PGADebugEntered("PGAGetIntegerFromGrayCode");
     PGACheckDataType("PGAGetIntegerFromGrayCode", PGA_DATATYPE_BINARY);

     length = end - start + 1;
     if (length > sizeof(int) * 8 - 1)
          PGAError(ctx, "PGAGetIntegerFromGrayCode: length of binary string "
                   "exceeds size of type int:", PGA_FATAL, PGA_INT,
                   (void *) &length);
     if (start < 0)
          PGAError(ctx, "PGAGetIntegerFromGrayCode: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAGetIntegerFromGrayCode: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAGetIntegerFromGrayCode: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);

     BitString = (int *) malloc(length * sizeof(int));
     if (!BitString)
          PGAError(ctx, "PGAGetIntegerFromGrayCode: No room for BitString",
                   PGA_FATAL, PGA_VOID, NULL);
     BitString[0] = PGAGetBinaryAllele(ctx, p, pop, start);

     for(i = 1; i < length; i++)
          BitString[i] = BitString[i-1] ^ PGAGetBinaryAllele(ctx, p, pop,
                                                             start + i);
     val = 0;
     power2 = 1u << (length - 1);
     for (i = 0; i < length; i++)
     {
          if (BitString[i])
               val += power2;
          power2 >>= 1;
     }
     free(BitString);

    PGADebugExited("PGAGetIntegerFromGrayCode");
     return(val);
}

/*U****************************************************************************
  PGAEncodeIntegerAsBinary - encodes an integer value as a binary string

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in p to encode val in
      end   - ending bit position in p to encode val in
      val   - the integer value to be represented as a binary string

  Outputs:
      The string is modified by side-effect.

  Example:
      Encode an integer v in 20 bits in bit positions 0--19 in string p
      in population PGA_NEWPOP.

      PGAContext *ctx;
      int v, p;
      :
      PGAEncodeIntegerAsBinary(ctx, p, PGA_NEWPOP, 0, 19, v);

****************************************************************************U*/
void PGAEncodeIntegerAsBinary(PGAContext *ctx, int p, int pop, int start,
                              int end, int val)
{
     int length, i;
     unsigned power2;

    PGADebugEntered("PGAEncodeIntegerAsBinary");
     PGACheckDataType("PGAEncodeIntegerAsBinary", PGA_DATATYPE_BINARY);

     length = end - start + 1;

     if (length > sizeof(int) * 8 - 1)
          PGAError(ctx, "PGAEncodeIntegerAsBinary: length of bit string "
                   "exceeds size of type int:", PGA_FATAL, PGA_INT,
                   (void *) &length);
     if (start < 0)
          PGAError(ctx, "PGAEncodeIntegerAsBinary: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAEncodeIntegerAsBinary: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAEncodeIntegerAsBinary: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if ((val > (1u << length) - 1) && (length != sizeof(int) * 8) - 1)
          PGAError(ctx, "PGAEncodeIntegerAsBinary: Integer too big for string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &val);
     if (val < 0)
          PGAError(ctx, "PGAEncodeIntegerAsBinary: Integer less than zero:",
                   PGA_FATAL, PGA_INT, (void *) & val);

     power2 = 1u << (length - 1);
     for (i = 0; i < length; i++)
     {
          if (val >= power2)
          {
               PGASetBinaryAllele(ctx, p, pop, start + i, 1);
               val -= power2;
          }
          else
               PGASetBinaryAllele(ctx, p, pop, start + i, 0);
          power2 >>= 1;
     }

    PGADebugExited("PGAEncodeIntegerAsBinary");
}

/*U****************************************************************************
  PGAEncodeIntegerAsGrayCode - encodes a real value as a binary reflected
  Gray code sequence

  Category: Fitness & Evaluation

  Inputs:
      ctx   - context variable
      p     - string index
      pop   - symbolic constant of the population the string is in
      start - starting bit position in p to encode val in
      end   - ending bit position in p to encode val in
      val   - the integer value to be represented as a binary reflected
              Gray code sequence

  Outputs:
      The string is modified by side-effect.

  Example:
      Encode an integer v in 20 bits in bit positions  0--19 in string p in
      population PGA_NEWPOP using Gray code.

      PGAContext *ctx;
      int v, p;
      :
      PGAEncodeIntegerAsGrayCode(ctx, p, PGA_NEWPOP, 0, 19, 7);

****************************************************************************U*/
void PGAEncodeIntegerAsGrayCode(PGAContext *ctx, int p, int pop, int start,
                                int end, int val)
{
     int i, *bit, length;
     unsigned power2;

    PGADebugEntered("PGAEncodeIntegerAsGrayCode");
     PGACheckDataType("PGAEncodeIntegerAsGrayCode", PGA_DATATYPE_BINARY);

     length = end - start + 1;

     if (length > sizeof(int) * 8 - 1)
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: length of bit string"
                   "exceeds size of type int:", PGA_FATAL, PGA_INT,
                   (void *) &length);
     if (start < 0)
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: start less than 0:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if (end >= PGAGetStringLength(ctx))
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: end greater than string "
                   "length:", PGA_FATAL, PGA_INT, (void *) &end);
     if (start >= end)
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: start exceeds end:",
                   PGA_FATAL, PGA_INT, (void *) &start);
     if ((val > (1u << length) - 1) && (length != sizeof(int) * 8 - 1))
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: Integer too big for "
                   "string length:", PGA_FATAL, PGA_INT, (void *) &val);
     if (val < 0)
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: Integer less than zero:",
                   PGA_FATAL, PGA_INT, (void *) &val);

     bit = (int *) malloc(length * sizeof(int));
     if (bit == NULL)
          PGAError(ctx, "PGAEncodeIntegerAsGrayCode: No room to allocate bit",
                   PGA_FATAL, PGA_VOID, NULL);
     power2 = 1u << (length - 1);
     for (i = 0; i < length; i++)
     {
          if (val >= power2)
          {
               bit[i] = 1;
               val -= power2;
          }
          else
               bit[i] = 0;
          power2 >>= 1;
     }
     PGASetBinaryAllele(ctx, p, pop, start, bit[0]);
     for(i = 1; i < length; i++)
          PGASetBinaryAllele(ctx, p, pop, start + i, bit[i-1] ^ bit[i]);
     free(bit);

    PGADebugExited("PGAEncodeIntegerAsGrayCode");
}


/*I****************************************************************************
   PGAMapIntegerToReal - Maps the value v defined on [a,b] to r defined on
   [l,u].  In the context of PGAPack [a,b] is the discrete interval
   [0,2^nbits-1] (i.e., the number of bits in a binary string) and [l,u]
   represent the range of possible values of the real number r.

   Inputs:
      ctx      - context variable
      v        - value from original interval (usually the decoded bit string)
      a        - lower bound of integer interval (usually 0)
      b        - upper bound of integer interval (usually 2^nbits-1)
      l        - lower bound of real interval
      u        - upper bound of real interval

   Outputs:
      Scaled value of v defined on [l,u]

   Example:
       Map a five bit (that is, an integer with a range of [0, 31]) integer v
       to a real in the range [0, 3.14].

       PGAContext *ctx;
       double x;
       int v;
       :
       x = PGAMapIntegerToReal(ctx, v, 0, 31, 0.0, 3.14);

****************************************************************************I*/
double PGAMapIntegerToReal (PGAContext *ctx, int v, int a, int b, double l,
                            double u)
{
    PGADebugEntered("PGAMapIntegerToReal");

    PGADebugExited("PGAMapIntegerToReal");

     return((v-a) * (u-l) / (b-a) + l);
}

/*I****************************************************************************
   PGAMapRealToInteger - Maps the value r defined on [l,u] to v defined on
   [a,b].  In the context of PGAPack [a,b] is the discrete interval
   [0,2^nbits-1] (i.e., the number of bits in a binary string) and [l,u]
   represent the range of possible values of the real number r.

   Inputs:
      ctx      - context variable
      r        - real value defined on [l,u]
      l        - lower bound of real interval
      u        - upper bound of real interval
      a        - lower bound of integer interval (usually 0)
      b        - upper bound of integer interval (usually 2^nbits-1)

   Outputs:
      Scaled value of r defined on [a,b]

   Example:
     Map the value r on the interval [0, 3.14] to a five bit integer v.

     PGAContext *ctx;
     double r;
     int v;
     :
     v = PGAMapRealToInteger(ctx, r, 0.0, 3.14, 0, 31);

****************************************************************************I*/
int PGAMapRealToInteger(PGAContext *ctx, double r, double l, double u, int a,
                        int b)
{
    PGADebugEntered("PGAMapRealToInteger");

    PGADebugExited("PGAMapRealToInteger");

     return PGARound(ctx, (b - a) * (r - l) / (u - l) + a);
}


