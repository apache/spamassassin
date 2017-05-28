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
*     FILE: debug.c: This file contains routines for debugging
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
******************************************************************************/

#include "pgapack.h"

/******************************************************************************
 We need two numbering schemes:

   (1) A list of debug levels (numbers) the user types to get certain types
       of prints
   (2) A unique integer debug value for each routine

 The way this works is that the user specified debug level, which we
 arbitrarily restrict to be an integer between 1--100, is mapped to a
 set of actual debug values which are in the range of 101--inf

 Note that the set of debuglevels we define for the user are between 0--100,
 and that all *real* values for a routine (each routine has a debug value
 associated with it) are > 100 and < PGA_DEBUG_NUMFLAGS

  0 Trace all debug prints

  1 Reserved for the user
    :                   :
 10 Reserved for the user
 11 Trace high-level functions
 12 Trace all function entries
 13 Trace all function exits

 20 Trace high-level parallel functions
 21 Trace all parallel functions
 22 Trace all send calls (PGA_DEBUG_SEND)
 23 Trace all receive calls (PGA_DEBUG_RECV)

 30 Trace BINARY    functions
 32 Trace INTEGER   functions
 34 Trace REAL      functions
 36 Trace CHARACTER functions

 40 Trace population creation functions
 42 Trace select functions
 44 Trace mutation functions
 46 Trace crossover functions
 48 Trace function evaluation functions
 50 Trace fitness calculation  functions
 52 Trace duplicate checking functions
 54 Trace restart functions
 56 Trace reporting functions
 58 Trace stopping functions
 60 Trace sorting functions
 62 Trace random number functions
 64 Trace system routines
 66 Trace utility functions

 80 Trace memory allocations
 82 Trace variable print statements
******************************************************************************/

#if OPTIMIZE==0
typedef struct
{
        char    PGAFuncName[36];
        int     PGAFuncNum;
} PGAFuncRec;

int        PGANumFcns;

PGAFuncRec PGAFuncIndex[PGA_DEBUG_MAXPGAPACKFUNCTIONS] =
{
/* Binary Routines 100 - 149 */
        { "PGABinaryCreateString",          100 },
        { "PGABinaryMutation",              101 },
        { "PGABinaryOneptCrossover",        102 },
        { "PGABinaryTwoptCrossover",        103 },
        { "PGABinaryUniformCrossover",      104 },
        { "PGABinaryPrintString",           105 },
        { "PGABinaryCopyString",            106 },
        { "PGABinaryDuplicate",             107 },
        { "PGABinaryInitString",            108 },
        { "PGABinaryBuildDatatype",         109 },
        { "PGASetBinaryAllele",             110 },
        { "PGAGetBinaryAllele",             111 },
        { "PGABinaryHammingDistance",       120 },
        { "PGABinaryPrint",                 121 },
        { "PGAGetBinaryInitProb",           122 },
        { "PGASetBinaryInitProb",           123 },

/* Integer Routines 150 - 199 */
        { "PGAIntegerCreateString",         150 },
        { "PGAIntegerMutation",             151 },
        { "PGAIntegerOneptCrossover",       152 },
        { "PGAIntegerTwoptCrossover",       153 },
        { "PGAIntegerUniformCrossover",     154 },
        { "PGAIntegerPrintString",          155 },
        { "PGAIntegerCopyString",           156 },
        { "PGAIntegerDuplicate",            157 },
        { "PGAIntegerInitString",           158 },
        { "PGAIntegerBuildDatatype",        159 },
        { "PGASetIntegerAllele",            160 },
        { "PGAGetIntegerAllele",            161 },
        { "PGASetIntegerInitPermute",       170 },
        { "PGASetIntegerInitRange",         171 },
        { "PGAGetIntegerInitType",          172 },
        { "PGAGetMinIntegerInitValue",      173 },
        { "PGAGetMaxIntegerInitValue",      174 },

/* Real Routines 200 - 249 */
        { "PGARealCreateString",            200 },
        { "PGARealMutation",                201 },
        { "PGARealOneptCrossover",          202 },
        { "PGARealTwoptCrossover",          203 },
        { "PGARealUniformCrossover",        204 },
        { "PGARealPrintString",             205 },
        { "PGARealCopyString",              206 },
        { "PGARealDuplicate",               207 },
        { "PGARealInitString",              208 },
        { "PGARealBuildDatatype",           209 },
        { "PGASetRealAllele",               210 },
        { "PGAGetRealAllele",               211 },
        { "PGASetRealInitPercent",          220 },
        { "PGASetRealInitRange",            221 },
        { "PGAGetMinRealInitValue",         222 },
        { "PGAGetMaxRealInitValue",         223 },

/* Character Routines 250 - 299 */
        { "PGACharacterCreateString",       250 },
        { "PGACharacterMutation",           251 },
        { "PGACharacterOneptCrossover",     252 },
        { "PGACharacterTwoptCrossover",     253 },
        { "PGACharacterUniformCrossover",   254 },
        { "PGACharacterPrintString",        255 },
        { "PGACharacterCopyString",         256 },
        { "PGACharacterDuplicate",          257 },
        { "PGACharacterInitString",         258 },
        { "PGACharacterBuildDatatype",      259 },
        { "PGASetCharacterAllele",          260 },
        { "PGAGetCharacterAllele",          261 },
        { "PGASetCharacterInitType",        270 },

/* Operators Routines 300 - 499 */
        /* create.c */
        { "PGACreate",                      300 },
        { "PGASetUp",                       301 },
        { "PGACreatePop",                   302 },
        { "PGACreateIndividual",            303 },
        { "PGAGetRandomInitFlag",           304 },
        { "PGASetRandomInitFlag",           305 },

        /* cross.c */
        { "PGACrossover",                   310 },
        { "PGAGetCrossoverType",            311 },
        { "PGAGetCrossoverProb",            312 },
        { "PGAGetUniformCrossoverProb",     313 },
        { "PGASetCrossoverType",            314 },
        { "PGASetCrossoverProb",            315 },
        { "PGASetUniformCrossoverProb",     316 },

        /* pop.c */
        { "PGASortPop",                     320 },
        { "PGAGetPopSize",                  321 },
        { "PGAGetNumReplaceValue",          322 },
        { "PGAGetPopReplaceType",           323 },
        { "PGAGetSortedPopIndex",           324 },
        { "PGASetPopSize",                  325 },
        { "PGASetNumReplaceValue",          326 },
        { "PGASetPopReplaceType",           327 },

        /* mutation.c */
        { "PGAMutate",                      330 },
        { "PGAGetMutationType",             331 },
        { "PGAGetMutationRealValue",        332 },
        { "PGAGetMutationIntegerValue",     333 },
        { "PGAGetMutationProb",             334 },
        { "PGASetMutationType",             335 },
        { "PGASetMutationRealValue",        336 },
        { "PGASetMutationIntegerValue",     337 },
        { "PGASetMutationProb",             338 },
        { "PGASetMutationBoundedFlag",      400 },  /* 400--499 */
        { "PGAGetMutationBoundedFlag",      401 },  /* 400--499 */

        /* duplcate.c */
        { "PGADuplicate",                   340 },
        { "PGAChange",                      341 },
        { "PGASetNoDuplicatesFlag",         342 },
        { "PGAGetNoDuplicatesFlag",         343 },

        /* pga.c */
        { "PGARunMutationAndCrossover",     350 },
        { "PGARunMutationOrCrossover",      351 },
        { "PGAUpdateGeneration",            352 },
        { "PGAGetDataType",                 353 },
        { "PGAGetOptDirFlag",               354 },
        { "PGAGetStringLength",             355 },
        { "PGAGetGAIterValue",              356 },
        { "PGAGetMutationOrCrossoverFlag",  357 },
        { "PGAGetMutationAndCrossoverFlag", 358 },
        { "PGASetMutationOrCrossoverFlag",  359 },
        { "PGASetMutationAndCrossoverFlag", 360 },
        { "PGARun",                         361 },

        /* restart.c */
        { "PGARestart",                     370 },
        { "PGAGetRestartFlag",              371 },
        { "PGAGetRestartFrequencyValue",    372 },
        { "PGAGetRestartAlleleChangeProb",  373 },
        { "PGASetRestartFlag",              374 },
        { "PGASetRestartFrequencyValue",    375 },
        { "PGASetRestartAlleleChangeProb",  376 },

        /* select.c */
        { "PGASelect",                      380 },
        { "PGASelectProportional",          381 },
        { "PGASelectSUS",                   382 },
        { "PGASelectTournament",            383 },
        { "PGASelectPTournament",           384 },
        { "PGASelectNextIndex",             385 },
        { "PGAGetSelectType",               386 },
        { "PGAGetPTournamentProb",          387 },
        { "PGASetSelectType",               388 },
        { "PGASetPTournamentProb",          389 },

        /* stop.c */
        { "PGAGetStoppingRuleType",         390 },
        { "PGASetStoppingRuleType",         391 },
        { "PGAGetMaxGAIterValue",           392 },
        { "PGASetMaxGAIterValue",           393 },
        { "PGACheckStoppingConditions",     394 },
        { "PGASetMaxNoChangeValue",         395 },
        { "PGASetMaxSimilarityValue",       396 },
	{ "PGADone",                        397 },

/* Fitness and Evaluation Routines 500 - 599 */
        /* evaluate.c */
        { "PGAGetRealFromBinary",           500 },
        { "PGAGetRealFromGrayCode",         501 },
        { "PGAEncodeRealAsBinary",          502 },
        { "PGAEncodeRealAsGrayCode",        503 },
        { "PGAMapIntegerToReal",            504 },
        { "PGAMapRealToInteger",            505 },
        { "PGAEncodeIntegerAsBinary",       506 },
        { "PGAEncodeIntegerAsGrayCode",     507 },
        { "PGAGetIntegerFromBinary",        508 },
        { "PGAGetIntegerFromGrayCode",      509 },
        { "PGAEvaluate",                    510 },
	{ "PGAEvaluateSeq",                 515 },
	{ "PGAEvaluateCoop",                516 },
	{ "PGAEvaluateSlave",               517 },
        { "PGASetEvaluation",               511 },
        { "PGASetEvaluationUpToDateFlag",   512 },
        { "PGAGetEvaluation",               513 },
        { "PGAGetEvaluationUpToDateFlag",   514 },

        /* fitness.c */
        { "PGAFitness",                     520 },
        { "PGAFitnessLinearNormal",         521 },
        { "PGAFitnessLinearRank",           522 },
        { "PGAFitnessMinReciprocal",        523 },
        { "PGAFitnessMinCmax",              524 },
        { "PGARank",                        525 },
        { "PGAGetFitness",                  526 },
        { "PGAGetFitnessType",              527 },
        { "PGAGetFitnessMinType",           528 },
        { "PGAGetMaxFitnessRank",           529 },
        { "PGASetFitnessType",              530 },
        { "PGASetFitnessMinType",           531 },
        { "PGASetMaxFitnessRank",           532 },
        { "PGASetFitnessCmaxValue",         533 },
        { "PGAGetFitnessCmaxValue",         534 },

/* Parallel Routines 600 - 699 */
        { "PGABuildDatatype",               600 },
        { "PGASendIndividual",              601 },
        { "PGAReceiveIndividual",           602 },
        { "PGASendReceiveIndividual",       603 },
        { "PGAEvaluateMS",                  605 },
        { "PGAGetRank",                     607 },
        { "PGAGetNumProcs",                 608 },
        { "PGASetCommunicator",             609 },
        { "PGAGetCommunicator",             610 },
        { "PGASetNumIslands",               611 },
        { "PGAGetNumIslands",               612 },
        { "PGASetNumDemes",                 613 },
        { "PGAGetNumDemes",                 614 },
        { "PGARunGM",                       615 },
        { "PGARunIM",                       616 },
        { "PGARunNM",                       617 },

/* System and Utility 700 - 799 */
        /* system.c */
        { "PGAError",                       700 },
        { "PGAUsage",                       702 },
        { "PGAPrintVersionNumber",          703 },
        { "PGAGetMaxMachineIntValue",       704 },
        { "PGAGetMinMachineIntValue",       705 },
        { "PGAGetMaxMachineDoubleValue",    706 },
        { "PGAGetMinMachineDoubleValue",    707 },
        { "PGADestroy",                     708 },

        /* utility.c */
        { "PGAMean",                        710 },
        { "PGAStddev",                      711 },
        { "PGACopyIndividual",              712 },
        { "PGARound",                       713 },
        { "PGACheckSum",                    714 },
        { "PGAGetWorstIndex",               715 },
        { "PGAGetBestIndex",                716 },
        { "PGAGetIndividual",               717 },
        { "PGAUpdateAverage",               718 },
        { "PGAUpdateOnline",                719 },
        { "PGAUpdateOffline",               720 },
        { "PGAComputeSimilarity",           721 },

        /* cmdline.c */
        { "PGAReadCmdLine",                 730 },
        { "PGAParseDebugArg",               731 },
        { "PGAStripArgs",                   732 },

        /* debug.c */
        { "PGADebugPrint",                  740 },
        { "PGAGetDebugFlag",                741 },
        { "PGAPrintDebugOptions",           743 },
        { "PGASetDebugLevel",               744 },

        /* random.c */
        { "PGARandomFlip",                  750 },
        { "PGARandomInterval",              751 },
        { "PGARandom01",                    752 },
        { "PGARandomUniform",               753 },
        { "PGARandomGaussian",              754 },
        { "PGAGetRandomSeed",               755 },
        { "PGASetRandomSeed",               756 },

/* Miscellaneous Routines 800 - 899 */
        /* hamming.c */
        { "PGAHammingDistance",             800 },

        /* heap.c */
        { "PGADblHeapSort",                 810 },
        { "PGADblHeapify",                  811 },
        { "PGADblAdjustHeap",               812 },
        { "PGAIntHeapSort",                 813 },
        { "PGAIntHeapify",                  814 },
        { "PGAIntAdjustHeap",               815 },

        /* report.c */
        { "PGAPrintPopulation",             820 },
        { "PGAPrintIndividual",             821 },
        { "PGAPrintReport",                 822 },
        { "PGAPrintContextVariable",        823 },
        { "PGAPrintString",                 824 },
        { "PGAGetPrintFrequencyValue",      825 },
        { "PGASetPrintFrequencyValue",      826 },
        { "PGASetPrintOptions",             827 },

        /* user.c */
        { "PGASetUserFunction",             830 }
};


/*I****************************************************************************
   PGASortDebugIndex - Sort the index of function names alphabetically.

   Inputs:

   Output:

   Example:

****************************************************************************I*/
void PGASortFuncNameIndex(PGAContext *ctx)
{

    /*  See how many functions are in the index */
    for (PGANumFcns=0; PGAFuncIndex[PGANumFcns].PGAFuncName[0]; PGANumFcns++) ;

    qsort(PGAFuncIndex, PGANumFcns, sizeof(PGAFuncRec),
	  (int (*) (const void *, const void *)) &strcmp);
}


/*U****************************************************************************
  PGADebugPrint - Write debugging information

  Category: Debugging

  Inputs:
     ctx       - context variable
     level     - a symbolic constant that maps to the type of print requested
                 (e.g., an entry or exit print).  Valid values are
                 PGA_DEBUG_ENTERED, PGA_DEBUG_EXIT, PGA_DEBUG_MALLOC,
                 PGA_DEBUG_PRINTVAR, PGA_DEBUG_SEND, and PGA_DEBUG_RECV.
     funcname  - the name of the function that called this routine
     msg       - message to print
     datatype  - a symbolic constant that maps to the data type of the
                 parameter data.  Valid choices are PGA_INT, PGA_DOUBLE,
                 PGA_CHAR and PGA_VOID (no data).
     data      - a pointer, whose contents will be interpreted based upon the
                 datatype parameter (or NULL, if PGA_VOID).

  Outputs:
     The debugging information is printed to stderr.

  Example:
     If the debugging level includes printing variables (level 82), print the
     value of the integer variable num as a debugging tool in the routine
     Add2Nums

     PGAContext *ctx;
     int num;
     :
     PGADebugPrint(ctx, PGA_DEBUG_PRINTVAR, "Add2Nums", "num = ", PGA_INT,
                   (void *) &num);

****************************************************************************U*/
void PGADebugPrint( PGAContext *ctx, int level, char *funcname,
                   char *msg, int datatype, void *data )
{
     int rank;

     /*  Added check if level > 10 so that PGAGetDebugFlag is only called
      *  if it is _not_ a user debug level.
      */

     if (ctx->debug.PGADebugFlags[0]     ||
         ctx->debug.PGADebugFlags[level] ||
         ((level > 10) && PGAGetDebugFlag (ctx, funcname)))
     {
          MPI_Comm_rank(MPI_COMM_WORLD, &rank);
          switch (datatype)
          {
          case PGA_VOID:
               fprintf(stdout, "%4d: %-32s: %s\n", rank, funcname, msg);
               break;
          case PGA_INT:
               switch (*(int *) data)
               {
               case PGA_TEMP1:
                    fprintf(stdout, "%4d: %-32s: %s PGA_TEMP1\n", rank,
                            funcname, msg);
                    break;
               case PGA_TEMP2:
                    fprintf(stdout, "%4d: %-32s: %s PGA_TEMP2\n", rank,
                            funcname, msg);
                    break;
               case PGA_OLDPOP:
                    fprintf(stdout, "%4d: %-32s: %s PGA_OLDPOP\n", rank,
                            funcname, msg);
                    break;
               case PGA_NEWPOP:
                    fprintf(stdout, "%4d: %-32s: %s PGA_NEWPOP\n", rank,
                            funcname, msg);
                    break;
               default:
                    fprintf(stdout, "%4d: %-32s: %s %d\n", rank, funcname, msg,
                            *(int *) data);
                    break;
               }
               break;
          case PGA_DOUBLE:
               fprintf(stdout, "%4d: %-32s: %s %e\n", rank,
                       funcname, msg, *(double *) data);
               break;
          case PGA_CHAR:
               fprintf(stdout, "%4d: %-32s: %s %s\n", rank,
                       funcname, msg,  (char *) data);
               break;
          default:
               fprintf(stderr, "PGADebugPrint: Invalid value of datatype: %d",
                       datatype);
               exit(-1);
               break;
          }
     }
}

/*U****************************************************************************
   PGASetDebugLevel - Turn on a debug level.  Only valid if PGAPack
   was compiled to include debugging calls.  See the user guide for details.

   Category: Debugging

   Inputs:
      ctx   - context variable
      level - the debug level to set to PGA_TRUE.

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetDebugLevel(ctx, 70)

****************************************************************************U*/
void PGASetDebugLevel(PGAContext *ctx, int level)
{
    if ((level < 11) || (level > 100)) {
        ctx->debug.PGADebugFlags[level] = PGA_TRUE;
    } else {
        /*  Call the appropriate routine to clear the set of levels.  */
        switch (level) {
        case 11:  PGASetDebugFlag11(ctx, PGA_TRUE); break;
        case 20:  PGASetDebugFlag20(ctx, PGA_TRUE); break;
        case 21:  PGASetDebugFlag21(ctx, PGA_TRUE); break;
        case 30:  PGASetDebugFlag30(ctx, PGA_TRUE); break;
        case 32:  PGASetDebugFlag32(ctx, PGA_TRUE); break;
        case 34:  PGASetDebugFlag34(ctx, PGA_TRUE); break;
        case 36:  PGASetDebugFlag36(ctx, PGA_TRUE); break;
        case 40:  PGASetDebugFlag40(ctx, PGA_TRUE); break;
        case 42:  PGASetDebugFlag42(ctx, PGA_TRUE); break;
        case 44:  PGASetDebugFlag44(ctx, PGA_TRUE); break;
        case 46:  PGASetDebugFlag46(ctx, PGA_TRUE); break;
        case 48:  PGASetDebugFlag48(ctx, PGA_TRUE); break;
        case 50:  PGASetDebugFlag50(ctx, PGA_TRUE); break;
        case 52:  PGASetDebugFlag52(ctx, PGA_TRUE); break;
        case 54:  PGASetDebugFlag54(ctx, PGA_TRUE); break;
        case 56:  PGASetDebugFlag56(ctx, PGA_TRUE); break;
        case 58:  PGASetDebugFlag58(ctx, PGA_TRUE); break;
        case 60:  PGASetDebugFlag60(ctx, PGA_TRUE); break;
        case 62:  PGASetDebugFlag62(ctx, PGA_TRUE); break;
        case 64:  PGASetDebugFlag64(ctx, PGA_TRUE); break;
        case 66:  PGASetDebugFlag66(ctx, PGA_TRUE); break;
        }
    }
}

/*U****************************************************************************
   PGAClearDebugLevel - Turn off a debul level.  Only valid if PGAPack
   was compiled to include debugging calls.  See the user guide for details.

   Category: Debugging

   Inputs:
      ctx   - context variable
      level - the debug level to set to PGA_FALSE.

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGAClearDebugLevel(ctx, 70)

****************************************************************************U*/
void PGAClearDebugLevel(PGAContext *ctx, int level)
{
    if ((level < 11) || (level > 100)) {
        ctx->debug.PGADebugFlags[level] = PGA_FALSE;
    } else {
        /*  Call the appropriate routine to clear the set of levels.  */
        switch (level) {
        case 11:  PGASetDebugFlag11(ctx, PGA_FALSE); break;
        case 20:  PGASetDebugFlag20(ctx, PGA_FALSE); break;
        case 21:  PGASetDebugFlag21(ctx, PGA_FALSE); break;
        case 30:  PGASetDebugFlag30(ctx, PGA_FALSE); break;
        case 32:  PGASetDebugFlag32(ctx, PGA_FALSE); break;
        case 34:  PGASetDebugFlag34(ctx, PGA_FALSE); break;
        case 36:  PGASetDebugFlag36(ctx, PGA_FALSE); break;
        case 40:  PGASetDebugFlag40(ctx, PGA_FALSE); break;
        case 42:  PGASetDebugFlag42(ctx, PGA_FALSE); break;
        case 44:  PGASetDebugFlag44(ctx, PGA_FALSE); break;
        case 46:  PGASetDebugFlag46(ctx, PGA_FALSE); break;
        case 48:  PGASetDebugFlag48(ctx, PGA_FALSE); break;
        case 50:  PGASetDebugFlag50(ctx, PGA_FALSE); break;
        case 52:  PGASetDebugFlag52(ctx, PGA_FALSE); break;
        case 54:  PGASetDebugFlag54(ctx, PGA_FALSE); break;
        case 56:  PGASetDebugFlag56(ctx, PGA_FALSE); break;
        case 58:  PGASetDebugFlag58(ctx, PGA_FALSE); break;
        case 60:  PGASetDebugFlag60(ctx, PGA_FALSE); break;
        case 62:  PGASetDebugFlag62(ctx, PGA_FALSE); break;
        case 64:  PGASetDebugFlag64(ctx, PGA_FALSE); break;
        case 66:  PGASetDebugFlag66(ctx, PGA_FALSE); break;
        }
    }
}

/*U****************************************************************************
   PGASetDebugLevelByName - Turn on debugging of the named function.

   Category: Debugging

   Inputs:
       ctx        - context variable
       funcname   - name of the function to turn on debugging output

   Outputs:

   Example:
       PGAContext *ctx;
       :
       PGASetDebugLevelByName(ctx, "PGAGetBinaryAllele");

****************************************************************************U*/
void PGASetDebugLevelByName(PGAContext *ctx, char *funcname)
{
    int  level;

    level = PGAGetDebugLevelOfName(ctx, funcname);
    ctx->debug.PGADebugFlags[level] = PGA_TRUE;
}

/*U****************************************************************************
   PGAClearDebugLevelByName - Turn off debugging of the named function.

   Category: Debugging

   Inputs:
       ctx        - context variable
       funcname   - name of the function to turn on debugging output

   Outputs:

   Example:
       PGAContext *ctx;
       :
       PGAClearDebugLevelByName(ctx, "PGAGetBinaryAllele");

****************************************************************************U*/
void PGAClearDebugLevelByName(PGAContext *ctx, char *funcname)
{
    int  level;

    level = PGAGetDebugLevelOfName(ctx, funcname);
    ctx->debug.PGADebugFlags[level] = PGA_FALSE;
}


/*I****************************************************************************
   PGAGetDebugLevelOfName - returns the debug level of the named function
   Internally, it performs a binary search on the run-time sorted list of
   fucntions in PGAFuncIndex.

   Inputs:
       ctx       - context variable
       funcname  - the name of the function

   Outputs:
       The debug level value of the function.  That is, PGAFuncNum associated
       with funcname in PGAFuncIndex.

   Example:


****************************************************************************I*/
int PGAGetDebugLevelOfName(PGAContext *ctx, char *funcname)
{
    int     l, h;
    int     m, missing;

    /*  Binary Search  */
    l = 0;
    h = PGANumFcns-1;
    while (l <= h) {
	m = (l+h)/2 + (l+h)%2;  /*  Actually, floor((l+h)/2)  */
	missing = strcmp(funcname, PGAFuncIndex[m].PGAFuncName);

        if (missing == 0) {
            break;
        } else {
            if (missing < 0) {
                h = m - 1;
            } else {
                l = m + 1;
            }
        }
    }

    if (missing) {
	fprintf(stderr, "PGAGetDebugFlag: Function missing from "
		"PGAFuncIndex: '%s'\n", funcname);
	PGADestroy(ctx);
	exit(-1);
    } 

    return(PGAFuncIndex[m].PGAFuncNum);
}

/*I****************************************************************************
  PGAGetDebugFlag - checks whether the flag to do a debug print in routine
  funcname has been set.  Returns PGA_TRUE if so, otherwise PGA_FALSE.
  If the name is not in the function name database, an error message is
  printed and the program terminates.

  Inputs:
     ctx      - context variable
     funcname - name of the function in question

  Outputs:

  Example:
     PGAContext *ctx;
     int IsItSet;

     IsItSet = PGAGetDebugFlag(ctx, "PGAGetDebugFlags");

****************************************************************************I*/
int PGAGetDebugFlag(PGAContext *ctx, char *funcname)
{
     int level;

     level = PGAGetDebugLevelOfName(ctx, funcname);
     return ctx->debug.PGADebugFlags[level];
}


/*I****************************************************************************
   PGASetDebugFlag11 - Set the debug flags for all functions at debug level 11

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag11(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[300] = Flag; /*PGACreate*/
   ctx->debug.PGADebugFlags[301] = Flag; /*PGASetUp*/
   ctx->debug.PGADebugFlags[304] = Flag; /*PGAGetRandomInitFlag*/
   ctx->debug.PGADebugFlags[305] = Flag; /*PGASetRandomInitFlag*/

   ctx->debug.PGADebugFlags[310] = Flag; /*PGACrossover*/
   ctx->debug.PGADebugFlags[311] = Flag; /*PGAGetCrossoverType*/
   ctx->debug.PGADebugFlags[312] = Flag; /*PGAGetCrossoverProb*/
   ctx->debug.PGADebugFlags[313] = Flag; /*PGAGetUniformCrossoverProb*/
   ctx->debug.PGADebugFlags[314] = Flag; /*PGASetCrossoverType*/
   ctx->debug.PGADebugFlags[315] = Flag; /*PGASetCrossoverProb*/
   ctx->debug.PGADebugFlags[316] = Flag; /*PGASetUniformCrossoverProb*/

   ctx->debug.PGADebugFlags[320] = Flag; /*PGASort*/
   ctx->debug.PGADebugFlags[321] = Flag; /*PGAGetPopSize*/
   ctx->debug.PGADebugFlags[322] = Flag; /*PGAGetNumReplaceValue*/
   ctx->debug.PGADebugFlags[323] = Flag; /*PGAGetPopReplaceType*/
   ctx->debug.PGADebugFlags[325] = Flag; /*PGASetPopSize*/
   ctx->debug.PGADebugFlags[326] = Flag; /*PGASetNumReplaceValue*/
   ctx->debug.PGADebugFlags[327] = Flag; /*PGASetPopReplaceType*/

   ctx->debug.PGADebugFlags[330] = Flag; /*PGAMutate*/
   ctx->debug.PGADebugFlags[331] = Flag; /*PGAGetMutationType*/
   ctx->debug.PGADebugFlags[332] = Flag; /*PGAGetMutationRealValue*/
   ctx->debug.PGADebugFlags[333] = Flag; /*PGAGetMutationIntegerValue*/
   ctx->debug.PGADebugFlags[334] = Flag; /*PGAGetMutationProb*/
   ctx->debug.PGADebugFlags[335] = Flag; /*PGASetMutationType*/
   ctx->debug.PGADebugFlags[336] = Flag; /*PGASetMutationRealValue*/
   ctx->debug.PGADebugFlags[337] = Flag; /*PGASetMutationIntegerValue*/
   ctx->debug.PGADebugFlags[338] = Flag; /*PGASetMutationProb*/
   ctx->debug.PGADebugFlags[400] = Flag; /*PGASetMutationBoundedFlag*/
   ctx->debug.PGADebugFlags[401] = Flag; /*PGAGetMutationBoundedFlag*/

   ctx->debug.PGADebugFlags[340] = Flag; /*PGADuplicate*/
   ctx->debug.PGADebugFlags[341] = Flag; /*PGAChange*/
   ctx->debug.PGADebugFlags[342] = Flag; /*PGASetNoDuplicatesFlag*/
   ctx->debug.PGADebugFlags[343] = Flag; /*PGAGetNoDuplicatesFlag*/

   ctx->debug.PGADebugFlags[350] = Flag; /*PGARunMutationAndCrossover*/
   ctx->debug.PGADebugFlags[351] = Flag; /*PGARunMutationOrCrossover*/
   ctx->debug.PGADebugFlags[352] = Flag; /*PGAUpdateGeneration*/
   ctx->debug.PGADebugFlags[353] = Flag; /*PGAGetDataType*/
   ctx->debug.PGADebugFlags[354] = Flag; /*PGAGetOptDirFlag*/
   ctx->debug.PGADebugFlags[355] = Flag; /*PGAGetStringLength*/
   ctx->debug.PGADebugFlags[356] = Flag; /*PGAGetGAIterValue*/
   ctx->debug.PGADebugFlags[357] = Flag; /*PGAGetMutationOrCrossoverFlag*/
   ctx->debug.PGADebugFlags[358] = Flag; /*PGAGetMutationAndCrossoverFlag*/
   ctx->debug.PGADebugFlags[359] = Flag; /*PGASetMutationOrCrossoverFlag*/
   ctx->debug.PGADebugFlags[360] = Flag; /*PGASetMutationAndCrossoverFlag*/
   ctx->debug.PGADebugFlags[361] = Flag; /*PGARun*/

   ctx->debug.PGADebugFlags[370] = Flag; /*PGARestart*/
   ctx->debug.PGADebugFlags[371] = Flag; /*PGAGetRestartFlag*/
   ctx->debug.PGADebugFlags[372] = Flag; /*PGAGetRestartFrequencyValue*/
   ctx->debug.PGADebugFlags[373] = Flag; /*PGAGetRestartAlleleChangeProb*/
   ctx->debug.PGADebugFlags[374] = Flag; /*PGASetRestartFlag*/
   ctx->debug.PGADebugFlags[375] = Flag; /*PGASetRestartFrequencyValue*/
   ctx->debug.PGADebugFlags[376] = Flag; /*PGASetRestartAlleleChangeProb*/

   ctx->debug.PGADebugFlags[380] = Flag; /*PGASelect*/
   ctx->debug.PGADebugFlags[386] = Flag; /*PGAGetSelectType*/
   ctx->debug.PGADebugFlags[387] = Flag; /*PGAGetPTournamentProb*/
   ctx->debug.PGADebugFlags[388] = Flag; /*PGASetSelectType*/
   ctx->debug.PGADebugFlags[389] = Flag; /*PGASetPTournamentProb*/

   ctx->debug.PGADebugFlags[390] = Flag; /*PGAGetStoppingRuleType*/
   ctx->debug.PGADebugFlags[391] = Flag; /*PGASetStoppingRuleType*/
   ctx->debug.PGADebugFlags[392] = Flag; /*PGAGetMaxGAIterValue*/
   ctx->debug.PGADebugFlags[393] = Flag; /*PGASetMaxGAIterValue*/
   ctx->debug.PGADebugFlags[394] = Flag; /*PGACheckStoppingConditions*/
   ctx->debug.PGADebugFlags[395] = Flag; /*PGASetMaxNoChangeValue*/
   ctx->debug.PGADebugFlags[396] = Flag; /*PGASetMaxSimilarityValue*/
   ctx->debug.PGADebugFlags[397] = Flag; /*PGADone*/

   ctx->debug.PGADebugFlags[510] = Flag; /*PGAEvaluate*/

   ctx->debug.PGADebugFlags[520] = Flag; /*PGAFitness*/
   ctx->debug.PGADebugFlags[527] = Flag; /*PGAGetFitnessType*/
   ctx->debug.PGADebugFlags[528] = Flag; /*PGAGetFitnessMinType*/
   ctx->debug.PGADebugFlags[529] = Flag; /*PGAGetMaxFitnessRank*/
   ctx->debug.PGADebugFlags[530] = Flag; /*PGASetFitnessType*/
   ctx->debug.PGADebugFlags[531] = Flag; /*PGASetFitnessMinType*/
   ctx->debug.PGADebugFlags[532] = Flag; /*PGASetMaxFitnessRank*/
   ctx->debug.PGADebugFlags[533] = Flag; /*PGASetFitnessCmaxValue*/
   ctx->debug.PGADebugFlags[534] = Flag; /*PGAGetFitnessCmaxValue*/

   ctx->debug.PGADebugFlags[604] = Flag; /*PGARunMS*/
   ctx->debug.PGADebugFlags[605] = Flag; /*PGAEvaluateMS*/
   ctx->debug.PGADebugFlags[606] = Flag; /*PGAEvaluateDoneMS*/
   ctx->debug.PGADebugFlags[607] = Flag; /*PGAGetRank*/
   ctx->debug.PGADebugFlags[608] = Flag; /*PGAGetNumProcs*/
   ctx->debug.PGADebugFlags[609] = Flag; /*PGASetCommunicator*/
   ctx->debug.PGADebugFlags[610] = Flag; /*PGAGetCommunicator*/
   ctx->debug.PGADebugFlags[611] = Flag; /*PGASetNumIslands*/
   ctx->debug.PGADebugFlags[612] = Flag; /*PGAGetNumIslands*/
   ctx->debug.PGADebugFlags[613] = Flag; /*PGASetNumDemes*/
   ctx->debug.PGADebugFlags[614] = Flag; /*PGAGetNumDemes*/
   ctx->debug.PGADebugFlags[615] = Flag; /*PGARunSeq*/
   ctx->debug.PGADebugFlags[616] = Flag; /*PGARunIM*/
   ctx->debug.PGADebugFlags[617] = Flag; /*PGARunNM*/

   ctx->debug.PGADebugFlags[700] = Flag; /*PGAError*/
   ctx->debug.PGADebugFlags[702] = Flag; /*PGAUsage*/
   ctx->debug.PGADebugFlags[703] = Flag; /*PGAPrintVersionNumber*/
   ctx->debug.PGADebugFlags[704] = Flag; /*PGAGetMaxMachineIntValue*/
   ctx->debug.PGADebugFlags[705] = Flag; /*PGAGetMinMachineIntValue*/
   ctx->debug.PGADebugFlags[706] = Flag; /*PGAGetMaxMachineRealValue*/
   ctx->debug.PGADebugFlags[707] = Flag; /*PGAGetMinMachineRealValue*/
   ctx->debug.PGADebugFlags[708] = Flag; /*PGADestroy*/

   ctx->debug.PGADebugFlags[741] = Flag; /*PGAGetDebugFlag*/
   ctx->debug.PGADebugFlags[742] = Flag; /*PGASetDebugFlag*/
   ctx->debug.PGADebugFlags[743] = Flag; /*PGAPrintDebugOptions*/

   ctx->debug.PGADebugFlags[800] = Flag; /*PGAHammingDistance*/

   ctx->debug.PGADebugFlags[820] = Flag; /*PGAPrintPopulation*/
   ctx->debug.PGADebugFlags[822] = Flag; /*PGAPrintReport*/
   ctx->debug.PGADebugFlags[823] = Flag; /*PGAContextVariable*/
   ctx->debug.PGADebugFlags[825] = Flag; /*PGAGetPrintFrequencyValue*/
   ctx->debug.PGADebugFlags[826] = Flag; /*PGASetPrintFrequencyValue*/
   ctx->debug.PGADebugFlags[827] = Flag; /*PGASetPrintOptions*/

   ctx->debug.PGADebugFlags[830] = Flag; /*PGASetUserFunction*/
}

/*I****************************************************************************
   PGASetDebugFlag20 - Set the debug flags for all functions at debug level 20

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag20(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[604] = Flag; /*PGARunMS*/
   ctx->debug.PGADebugFlags[605] = Flag; /*PGAEvaluateMS*/
   ctx->debug.PGADebugFlags[606] = Flag; /*PGAEvaluateDoneMS*/
   ctx->debug.PGADebugFlags[607] = Flag; /*PGAGetRank*/
   ctx->debug.PGADebugFlags[608] = Flag; /*PGAGetNumProcs*/
   ctx->debug.PGADebugFlags[609] = Flag; /*PGASetCommunicator*/
   ctx->debug.PGADebugFlags[610] = Flag; /*PGAGetCommunicator*/
   ctx->debug.PGADebugFlags[611] = Flag; /*PGASetNumIslands*/
   ctx->debug.PGADebugFlags[612] = Flag; /*PGAGetNumIslands*/
   ctx->debug.PGADebugFlags[613] = Flag; /*PGASetNumDemes*/
   ctx->debug.PGADebugFlags[614] = Flag; /*PGAGetNumDemes*/
   ctx->debug.PGADebugFlags[616] = Flag; /*PGARunIM*/
   ctx->debug.PGADebugFlags[617] = Flag; /*PGARunNM*/
}

/*I****************************************************************************
   PGASetDebugFlag21 - Set the debug flags for all functions at debug level 21

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag21(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[600] = Flag; /*PGABuildDataType*/
   ctx->debug.PGADebugFlags[601] = Flag; /*PGASendIndividual*/
   ctx->debug.PGADebugFlags[602] = Flag; /*PGAReceiveIndividual*/
   ctx->debug.PGADebugFlags[603] = Flag; /*PGASendReceiveIndividual*/
   ctx->debug.PGADebugFlags[604] = Flag; /*PGARunMS*/
   ctx->debug.PGADebugFlags[605] = Flag; /*PGAEvaluateMS*/
   ctx->debug.PGADebugFlags[606] = Flag; /*PGAEvaluateDoneMS*/
   ctx->debug.PGADebugFlags[607] = Flag; /*PGAGetRank*/
   ctx->debug.PGADebugFlags[608] = Flag; /*PGAGetNumProcs*/
   ctx->debug.PGADebugFlags[609] = Flag; /*PGASetCommunicator*/
   ctx->debug.PGADebugFlags[610] = Flag; /*PGAGetCommunicator*/
   ctx->debug.PGADebugFlags[611] = Flag; /*PGASetNumIslands*/
   ctx->debug.PGADebugFlags[612] = Flag; /*PGAGetNumIslands*/
   ctx->debug.PGADebugFlags[613] = Flag; /*PGASetNumDemes*/
   ctx->debug.PGADebugFlags[614] = Flag; /*PGAGetNumDemes*/
   ctx->debug.PGADebugFlags[616] = Flag; /*PGARunIM*/
   ctx->debug.PGADebugFlags[617] = Flag; /*PGARunNM*/
   ctx->debug.PGADebugFlags[714] = Flag; /*PGACheckSum*/
}

/*I****************************************************************************
   PGASetDebugFlag30 - Set the debug flags for all functions at debug level 30

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag30(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[100] = Flag; /*PGABinaryCreateString*/
   ctx->debug.PGADebugFlags[101] = Flag; /*PGABinaryMutation*/
   ctx->debug.PGADebugFlags[102] = Flag; /*PGABinaryOneptCrossover*/
   ctx->debug.PGADebugFlags[103] = Flag; /*PGABinaryTwoptCrossover*/
   ctx->debug.PGADebugFlags[104] = Flag; /*PGABinaryUniformCrossover*/
   ctx->debug.PGADebugFlags[105] = Flag; /*PGABinaryPrintString*/
   ctx->debug.PGADebugFlags[106] = Flag; /*PGABinaryCopyString*/
   ctx->debug.PGADebugFlags[107] = Flag; /*PGABinaryDuplicate*/
   ctx->debug.PGADebugFlags[108] = Flag; /*PGABinaryInitString*/
   ctx->debug.PGADebugFlags[109] = Flag; /*PGABinaryBuildDatatype*/
   ctx->debug.PGADebugFlags[110] = Flag; /*PGASetBinaryAllele*/
   ctx->debug.PGADebugFlags[111] = Flag; /*PGAGetBinaryAllele*/
   ctx->debug.PGADebugFlags[120] = Flag; /*PGABinaryHammingDistance*/
   ctx->debug.PGADebugFlags[121] = Flag; /*PGABinaryPrint*/
   ctx->debug.PGADebugFlags[122] = Flag; /*PGAGetBinaryInitProb*/
   ctx->debug.PGADebugFlags[123] = Flag; /*PGASetBinaryInitProb*/
}

/*I****************************************************************************
   PGASetDebugFlag32 - Set the debug flags for all functions at debug level 32

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag32(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[150] = Flag; /*PGAIntegerCreateString*/
   ctx->debug.PGADebugFlags[151] = Flag; /*PGAIntegerMutation*/
   ctx->debug.PGADebugFlags[152] = Flag; /*PGAIntegerOneptCrossover*/
   ctx->debug.PGADebugFlags[153] = Flag; /*PGAIntegerTwoptCrossover*/
   ctx->debug.PGADebugFlags[154] = Flag; /*PGAIntegerUniformCrossover*/
   ctx->debug.PGADebugFlags[155] = Flag; /*PGAIntegerPrintString*/
   ctx->debug.PGADebugFlags[156] = Flag; /*PGAIntegerCopyString*/
   ctx->debug.PGADebugFlags[157] = Flag; /*PGAIntegerDuplicate*/
   ctx->debug.PGADebugFlags[158] = Flag; /*PGAIntegerInitString*/
   ctx->debug.PGADebugFlags[159] = Flag; /*PGAIntegerBuildDatatype*/
   ctx->debug.PGADebugFlags[160] = Flag; /*PGASetIntegerAllele*/
   ctx->debug.PGADebugFlags[161] = Flag; /*PGAGetIntegerAllele*/
   ctx->debug.PGADebugFlags[170] = Flag; /*PGASetIntegerInitPermute*/
   ctx->debug.PGADebugFlags[171] = Flag; /*PGASetIntegerInitRange*/
   ctx->debug.PGADebugFlags[172] = Flag; /*PGAGetIntegerInitType*/
   ctx->debug.PGADebugFlags[173] = Flag; /*PGAGetMinIntegerInitValue*/
   ctx->debug.PGADebugFlags[174] = Flag; /*PGAGetMaxIntegerInitValue*/
   ctx->debug.PGADebugFlags[400] = Flag; /*PGASetMutationBoundedFlag*/
   ctx->debug.PGADebugFlags[401] = Flag; /*PGAGetMutationBoundedFlag*/
}

/*I****************************************************************************
   PGASetDebugFlag34 - Set the debug flags for all functions at debug level 34

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag34(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[200] = Flag; /*PGARealCreateString*/
   ctx->debug.PGADebugFlags[201] = Flag; /*PGARealMutation*/
   ctx->debug.PGADebugFlags[202] = Flag; /*PGARealOneptCrossover*/
   ctx->debug.PGADebugFlags[203] = Flag; /*PGARealTwoptCrossover*/
   ctx->debug.PGADebugFlags[204] = Flag; /*PGARealUniformCrossover*/
   ctx->debug.PGADebugFlags[205] = Flag; /*PGARealPrintString*/
   ctx->debug.PGADebugFlags[206] = Flag; /*PGARealCopyString*/
   ctx->debug.PGADebugFlags[207] = Flag; /*PGARealDuplicate*/
   ctx->debug.PGADebugFlags[208] = Flag; /*PGARealInitString*/
   ctx->debug.PGADebugFlags[209] = Flag; /*PGARealBuildDatatype*/
   ctx->debug.PGADebugFlags[210] = Flag; /*PGASetRealAllele*/
   ctx->debug.PGADebugFlags[211] = Flag; /*PGAGetRealAllele*/
   ctx->debug.PGADebugFlags[220] = Flag; /*PGASetRealInitPercent*/
   ctx->debug.PGADebugFlags[221] = Flag; /*PGASetRealInitRange*/
   ctx->debug.PGADebugFlags[222] = Flag; /*PGAGetMinRealInitValue*/
   ctx->debug.PGADebugFlags[223] = Flag; /*PGAGetMaxRealInitValue*/
}

/*I****************************************************************************
   PGASetDebugFlag36 - Set the debug flags for all functions at debug level 36

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag36(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[250] = Flag; /*PGACharacterCreateString*/
   ctx->debug.PGADebugFlags[251] = Flag; /*PGACharacterMutation*/
   ctx->debug.PGADebugFlags[252] = Flag; /*PGACharacterOneptCrossover*/
   ctx->debug.PGADebugFlags[253] = Flag; /*PGACharacterTwoptCrossover*/
   ctx->debug.PGADebugFlags[254] = Flag; /*PGACharacterUniformCrossover*/
   ctx->debug.PGADebugFlags[255] = Flag; /*PGACharacterPrintString*/
   ctx->debug.PGADebugFlags[256] = Flag; /*PGACharacterCopyString*/
   ctx->debug.PGADebugFlags[257] = Flag; /*PGACharacterDuplicate*/
   ctx->debug.PGADebugFlags[258] = Flag; /*PGACharacterInitString*/
   ctx->debug.PGADebugFlags[259] = Flag; /*PGACharacterBuildDatatype*/
   ctx->debug.PGADebugFlags[260] = Flag; /*PGASetCharacterAllele*/
   ctx->debug.PGADebugFlags[261] = Flag; /*PGAGetCharacterAllele*/
   ctx->debug.PGADebugFlags[270] = Flag; /*PGASetCharacterInitType*/
}

/*I****************************************************************************
   PGASetDebugFlag40 - Set the debug flags for all functions at debug level 40

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag40(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[100] = Flag; /*PGABinaryCreateString*/
   ctx->debug.PGADebugFlags[108] = Flag; /*PGABinaryInitString*/
   ctx->debug.PGADebugFlags[122] = Flag; /*PGAGetBinaryInitProb*/
   ctx->debug.PGADebugFlags[123] = Flag; /*PGASetBinaryInitProb*/
   ctx->debug.PGADebugFlags[250] = Flag; /*PGACharacterCreateString*/
   ctx->debug.PGADebugFlags[258] = Flag; /*PGACharacterInitString*/
   ctx->debug.PGADebugFlags[270] = Flag; /*PGASetCharacterInitType*/
   ctx->debug.PGADebugFlags[300] = Flag; /*PGACreate*/
   ctx->debug.PGADebugFlags[301] = Flag; /*PGASetUp*/
   ctx->debug.PGADebugFlags[302] = Flag; /*PGACreatePop*/
   ctx->debug.PGADebugFlags[303] = Flag; /*PGACreateIndividual*/
   ctx->debug.PGADebugFlags[304] = Flag; /*PGAGetRandomInitFlag*/
   ctx->debug.PGADebugFlags[305] = Flag; /*PGASetRandomInitFlag*/
   ctx->debug.PGADebugFlags[150] = Flag; /*PGAIntegerCreateString*/
   ctx->debug.PGADebugFlags[158] = Flag; /*PGAIntegerInitString*/
   ctx->debug.PGADebugFlags[170] = Flag; /*PGASetIntegerInitPermute*/
   ctx->debug.PGADebugFlags[171] = Flag; /*PGASetIntegerInitRange*/
   ctx->debug.PGADebugFlags[172] = Flag; /*PGAGetIntegerInitType*/
   ctx->debug.PGADebugFlags[173] = Flag; /*PGAGetMinIntegerInitValue*/
   ctx->debug.PGADebugFlags[174] = Flag; /*PGAGetMaxIntegerInitValue*/
   ctx->debug.PGADebugFlags[200] = Flag; /*PGARealCreateString*/
   ctx->debug.PGADebugFlags[208] = Flag; /*PGARealInitString*/
   ctx->debug.PGADebugFlags[220] = Flag; /*PGASetRealInitPercent*/
   ctx->debug.PGADebugFlags[221] = Flag; /*PGASetRealInitRange*/
   ctx->debug.PGADebugFlags[222] = Flag; /*PGAGetMinRealInitValue*/
   ctx->debug.PGADebugFlags[223] = Flag; /*PGAGetMaxRealInitValue*/
}

/*I****************************************************************************
   PGASetDebugFlag42 - Set the debug flags for all functions at debug level 42

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag42(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[380] = Flag; /*PGASelect*/
   ctx->debug.PGADebugFlags[381] = Flag; /*PGASelectProportional*/
   ctx->debug.PGADebugFlags[382] = Flag; /*PGASelectSUS*/
   ctx->debug.PGADebugFlags[383] = Flag; /*PGASelectTournament*/
   ctx->debug.PGADebugFlags[384] = Flag; /*PGASelectPTournament*/
   ctx->debug.PGADebugFlags[385] = Flag; /*PGASelectNextIndex*/
   ctx->debug.PGADebugFlags[386] = Flag; /*PGAGetSelectType*/
   ctx->debug.PGADebugFlags[387] = Flag; /*PGAGetPTournamentProb*/
   ctx->debug.PGADebugFlags[388] = Flag; /*PGASetSelectType*/
   ctx->debug.PGADebugFlags[389] = Flag; /*PGASetPTournamentProb*/
}

/*I****************************************************************************
   PGASetDebugFlag44 - Set the debug flags for all functions at debug level 44

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag44(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[101] = Flag; /*PGABinaryMutation*/
   ctx->debug.PGADebugFlags[151] = Flag; /*PGAIntegerMutation*/
   ctx->debug.PGADebugFlags[201] = Flag; /*PGARealMutation*/
   ctx->debug.PGADebugFlags[251] = Flag; /*PGACharacterMutation*/
   ctx->debug.PGADebugFlags[330] = Flag; /*PGAMutate*/
   ctx->debug.PGADebugFlags[331] = Flag; /*PGAGetMutationType*/
   ctx->debug.PGADebugFlags[332] = Flag; /*PGAGetMutationRealValue*/
   ctx->debug.PGADebugFlags[333] = Flag; /*PGAGetMutationIntegerValue*/
   ctx->debug.PGADebugFlags[334] = Flag; /*PGAGetMutationProb*/
   ctx->debug.PGADebugFlags[335] = Flag; /*PGASetMutationType*/
   ctx->debug.PGADebugFlags[336] = Flag; /*PGASetMutationRealValue*/
   ctx->debug.PGADebugFlags[337] = Flag; /*PGASetMutationIntegerValue*/
   ctx->debug.PGADebugFlags[338] = Flag; /*PGASetMutationProb*/
   ctx->debug.PGADebugFlags[400] = Flag; /*PGASetMutationBoundedFlag*/
   ctx->debug.PGADebugFlags[401] = Flag; /*PGAGetMutationBoundedFlag*/
}

/*I****************************************************************************
   PGASetDebugFlag46 - Set the debug flags for all functions at debug level 46

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag46(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[102] = Flag; /*PGABinaryOneptCrossover*/
   ctx->debug.PGADebugFlags[103] = Flag; /*PGABinaryTwoptCrossover*/
   ctx->debug.PGADebugFlags[104] = Flag; /*PGABinaryUniformCrossover*/
   ctx->debug.PGADebugFlags[152] = Flag; /*PGAIntegerOneptCrossover*/
   ctx->debug.PGADebugFlags[153] = Flag; /*PGAIntegerTwoptCrossover*/
   ctx->debug.PGADebugFlags[154] = Flag; /*PGAIntegerUniformCrossover*/
   ctx->debug.PGADebugFlags[202] = Flag; /*PGARealOneptCrossover*/
   ctx->debug.PGADebugFlags[203] = Flag; /*PGARealTwoptCrossover*/
   ctx->debug.PGADebugFlags[204] = Flag; /*PGARealUniformCrossover*/
   ctx->debug.PGADebugFlags[252] = Flag; /*PGACharacterOneptCrossover*/
   ctx->debug.PGADebugFlags[253] = Flag; /*PGACharacterTwoptCrossover*/
   ctx->debug.PGADebugFlags[254] = Flag; /*PGACharacterUniformCrossover*/
   ctx->debug.PGADebugFlags[310] = Flag; /*PGACrossover*/
   ctx->debug.PGADebugFlags[311] = Flag; /*PGAGetCrossoverType*/
   ctx->debug.PGADebugFlags[312] = Flag; /*PGAGetCrossoverProb*/
   ctx->debug.PGADebugFlags[313] = Flag; /*PGAGetUniformCrossoverProb*/
   ctx->debug.PGADebugFlags[314] = Flag; /*PGASetCrossoverType*/
   ctx->debug.PGADebugFlags[315] = Flag; /*PGASetCrossoverProb*/
   ctx->debug.PGADebugFlags[316] = Flag; /*PGASetUniformCrossoverProb*/
}

/*I****************************************************************************
   PGASetDebugFlag48 - Set the debug flags for all functions at debug level 48

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag48(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[110] = Flag; /*PGASetBinaryAllele*/
   ctx->debug.PGADebugFlags[111] = Flag; /*PGAGetBinaryAllele*/
   ctx->debug.PGADebugFlags[160] = Flag; /*PGASetIntegerAllele*/
   ctx->debug.PGADebugFlags[161] = Flag; /*PGAGetIntegerAllele*/
   ctx->debug.PGADebugFlags[210] = Flag; /*PGASetRealAllele*/
   ctx->debug.PGADebugFlags[211] = Flag; /*PGAGetRealAllele*/
   ctx->debug.PGADebugFlags[260] = Flag; /*PGASetCharacterAllele*/
   ctx->debug.PGADebugFlags[261] = Flag; /*PGAGetCharacterAllele*/
   ctx->debug.PGADebugFlags[500] = Flag; /*PGAGetRealFromBinary*/
   ctx->debug.PGADebugFlags[501] = Flag; /*PGAGetRealFromGrayCode*/
   ctx->debug.PGADebugFlags[502] = Flag; /*PGAEncodeRealAsBinary*/
   ctx->debug.PGADebugFlags[503] = Flag; /*PGAEncodeRealAsGrayCode*/
   ctx->debug.PGADebugFlags[504] = Flag; /*PGAMapIntegerToReal*/
   ctx->debug.PGADebugFlags[505] = Flag; /*PGAMapRealToInteger*/
   ctx->debug.PGADebugFlags[506] = Flag; /*PGAEncodeIntegerAsBinary*/
   ctx->debug.PGADebugFlags[507] = Flag; /*PGAEncodeIntegerAsGrayCode*/
   ctx->debug.PGADebugFlags[508] = Flag; /*PGAGetIntegerFromBinary*/
   ctx->debug.PGADebugFlags[509] = Flag; /*PGAGetIntegerFromGrayCode*/
   ctx->debug.PGADebugFlags[510] = Flag; /*PGAEvaluate*/
   ctx->debug.PGADebugFlags[511] = Flag; /*PGASetEvaluation*/
   ctx->debug.PGADebugFlags[512] = Flag; /*PGASetEvaluationUpToDateFlag*/
   ctx->debug.PGADebugFlags[513] = Flag; /*PGAGetEvaluation*/
   ctx->debug.PGADebugFlags[514] = Flag; /*PGAGetEvaluationUpToDateFlag*/
   ctx->debug.PGADebugFlags[605] = Flag; /*PGAEvaluateMS*/
   ctx->debug.PGADebugFlags[715] = Flag; /*PGAGetWorstIndex*/
   ctx->debug.PGADebugFlags[716] = Flag; /*PGAGetBestIndex*/
}

/*I****************************************************************************
   PGASetDebugFlag50 - Set the debug flags for all functions at debug level 50

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag50(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[520] = Flag; /*PGAFitness*/
   ctx->debug.PGADebugFlags[521] = Flag; /*PGAFitnessLinearNormal*/
   ctx->debug.PGADebugFlags[522] = Flag; /*PGAFitnessLinearRank*/
   ctx->debug.PGADebugFlags[523] = Flag; /*PGAFitnessMinReciprocal*/
   ctx->debug.PGADebugFlags[524] = Flag; /*PGAFitnessMinCmax*/
   ctx->debug.PGADebugFlags[525] = Flag; /*PGARank*/
   ctx->debug.PGADebugFlags[526] = Flag; /*PGAGetFitness*/
   ctx->debug.PGADebugFlags[527] = Flag; /*PGAGetFitnessType*/
   ctx->debug.PGADebugFlags[528] = Flag; /*PGAGetFitnessMinType*/
   ctx->debug.PGADebugFlags[529] = Flag; /*PGAGetMaxFitnessRank*/
   ctx->debug.PGADebugFlags[530] = Flag; /*PGASetFitnessType*/
   ctx->debug.PGADebugFlags[531] = Flag; /*PGASetFitnessMinType*/
   ctx->debug.PGADebugFlags[532] = Flag; /*PGASetMaxFitnessRank*/
   ctx->debug.PGADebugFlags[533] = Flag; /*PGASetFitnessCmaxValue*/
   ctx->debug.PGADebugFlags[534] = Flag; /*PGAGetFitnessCmaxValue*/
}

/*I****************************************************************************
   PGASetDebugFlag52 - Set the debug flags for all functions at debug level 52

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag52(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[107] = Flag; /*PGABinaryDuplicate*/
   ctx->debug.PGADebugFlags[157] = Flag; /*PGAIntegerDuplicate*/
   ctx->debug.PGADebugFlags[207] = Flag; /*PGARealDuplicate*/
   ctx->debug.PGADebugFlags[257] = Flag; /*PGACharacterDuplicate*/
   ctx->debug.PGADebugFlags[340] = Flag; /*PGADuplicate*/
   ctx->debug.PGADebugFlags[341] = Flag; /*PGAChange*/
   ctx->debug.PGADebugFlags[342] = Flag; /*PGASetNoDuplicatesFlag*/
   ctx->debug.PGADebugFlags[343] = Flag; /*PGAGetNoDuplicatesFlag*/
}

/*I****************************************************************************
   PGASetDebugFlag54 - Set the debug flags for all functions at debug level 54

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag54(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[370] = Flag; /*PGARestart*/
   ctx->debug.PGADebugFlags[371] = Flag; /*PGAGetRestartFlag*/
   ctx->debug.PGADebugFlags[372] = Flag; /*PGAGetRestartFrequencyValue*/
   ctx->debug.PGADebugFlags[373] = Flag; /*PGAGetRestartAlleleChangeProb*/
   ctx->debug.PGADebugFlags[374] = Flag; /*PGASetRestartFlag*/
   ctx->debug.PGADebugFlags[375] = Flag; /*PGASetRestartFrequencyValue*/
   ctx->debug.PGADebugFlags[376] = Flag; /*PGASetRestartAlleleChangeProb*/
}

/*I****************************************************************************
   PGASetDebugFlag56 - Set the debug flags for all functions at debug level 56

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag56(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[105] = Flag; /*PGABinaryPrintString*/
   ctx->debug.PGADebugFlags[121] = Flag; /*PGABinaryPrint*/
   ctx->debug.PGADebugFlags[155] = Flag; /*PGAIntegerPrintString*/
   ctx->debug.PGADebugFlags[205] = Flag; /*PGARealPrintString*/
   ctx->debug.PGADebugFlags[255] = Flag; /*PGACharacterPrintString*/
   ctx->debug.PGADebugFlags[820] = Flag; /*PGAPrintPopulation*/
   ctx->debug.PGADebugFlags[821] = Flag; /*PGAPrintIndividual*/
   ctx->debug.PGADebugFlags[822] = Flag; /*PGAPrintReport*/
   ctx->debug.PGADebugFlags[823] = Flag; /*PGAPrintContextVariable*/
   ctx->debug.PGADebugFlags[824] = Flag; /*PGAPrintString*/
   ctx->debug.PGADebugFlags[825] = Flag; /*PGAGetPrintFrequencyValue*/
   ctx->debug.PGADebugFlags[826] = Flag; /*PGASetPrintFrequencyValue*/
   ctx->debug.PGADebugFlags[827] = Flag; /*PGASetPrintOptions*/
}

/*I****************************************************************************
   PGASetDebugFlag58 - Set the debug flags for all functions at debug level 58

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag58(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[390] = Flag; /*PGAGetStoppingRuleType*/
   ctx->debug.PGADebugFlags[391] = Flag; /*PGASetStoppingRuleType*/
   ctx->debug.PGADebugFlags[392] = Flag; /*PGAGetMaxGAIterValue*/
   ctx->debug.PGADebugFlags[393] = Flag; /*PGASetMaxGAIterValue*/
   ctx->debug.PGADebugFlags[394] = Flag; /*PGACheckStoppingConditions*/
   ctx->debug.PGADebugFlags[395] = Flag; /*PGASetMaxNoChangeValue*/
   ctx->debug.PGADebugFlags[396] = Flag; /*PGASetMaxSimilarityValue*/
   ctx->debug.PGADebugFlags[397] = Flag; /*PGADone*/
}

/*I****************************************************************************
   PGASetDebugFlag60 - Set the debug flags for all functions at debug level 60

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag60(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[320] = Flag; /*PGASortPop*/
   ctx->debug.PGADebugFlags[324] = Flag; /*PGAGetSortedPopIndex*/
   ctx->debug.PGADebugFlags[810] = Flag; /*PGADblHeapSort*/
   ctx->debug.PGADebugFlags[811] = Flag; /*PGADblHeapify*/
   ctx->debug.PGADebugFlags[812] = Flag; /*PGADblAdjustHeap*/
   ctx->debug.PGADebugFlags[813] = Flag; /*PGAIntHeapSort*/
   ctx->debug.PGADebugFlags[814] = Flag; /*PGAIntHeapify*/
   ctx->debug.PGADebugFlags[815] = Flag; /*PGAIntAdjustHeap*/
}

/*I****************************************************************************
   PGASetDebugFlag62 - Set the debug flags for all functions at debug level 62

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag62(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[750] = Flag; /*PGARandomFlip*/
   ctx->debug.PGADebugFlags[751] = Flag; /*PGARandomInterval*/
   ctx->debug.PGADebugFlags[752] = Flag; /*PGARandom01*/
   ctx->debug.PGADebugFlags[753] = Flag; /*PGARandomUniform*/
   ctx->debug.PGADebugFlags[754] = Flag; /*PGARandomGaussian*/
   ctx->debug.PGADebugFlags[755] = Flag; /*PGAGetRandomSeed*/
   ctx->debug.PGADebugFlags[756] = Flag; /*PGASetRandomSeed*/
}

/*I****************************************************************************
   PGASetDebugFlag64 - Set the debug flags for all functions at debug level 64

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag64(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[700] = Flag; /*PGAError*/
   ctx->debug.PGADebugFlags[702] = Flag; /*PGAUsage*/
   ctx->debug.PGADebugFlags[703] = Flag; /*PGAPrintVersionNumber*/
   ctx->debug.PGADebugFlags[704] = Flag; /*PGAGetMaxMachineIntValue*/
   ctx->debug.PGADebugFlags[705] = Flag; /*PGAGetMinMachineIntValue*/
   ctx->debug.PGADebugFlags[706] = Flag; /*PGAGetMaxMachineDoubleValue*/
   ctx->debug.PGADebugFlags[707] = Flag; /*PGAGetMinMachineDoubleValue*/
   ctx->debug.PGADebugFlags[708] = Flag; /*PGADestroy*/
   ctx->debug.PGADebugFlags[730] = Flag; /*PGAReadCmdLine*/
   ctx->debug.PGADebugFlags[731] = Flag; /*PGAParseDebugArg*/
   ctx->debug.PGADebugFlags[732] = Flag; /*PGAStripArgs*/
}

/*I****************************************************************************
   PGASetDebugFlag66 - Set the debug flags for all functions at debug level 66

   Inputs:
       ctx  - Context variable
       Flag - PGA_TRUE to enable or PGA_FALSE to disable

   Outputs:

   Example:

****************************************************************************I*/
void PGASetDebugFlag66(PGAContext *ctx, int Flag)
{
   ctx->debug.PGADebugFlags[710] = Flag; /*PGAMean*/
   ctx->debug.PGADebugFlags[711] = Flag; /*PGAStddev*/
   ctx->debug.PGADebugFlags[712] = Flag; /*PGACopyIndividual*/
   ctx->debug.PGADebugFlags[713] = Flag; /*PGARound*/
   ctx->debug.PGADebugFlags[714] = Flag; /*PGACheckSum*/
   ctx->debug.PGADebugFlags[715] = Flag; /*PGAGetWorstIndex*/
   ctx->debug.PGADebugFlags[716] = Flag; /*PGAGetBestIndex*/
   ctx->debug.PGADebugFlags[717] = Flag; /*PGAGetIndividual*/
   ctx->debug.PGADebugFlags[718] = Flag; /*PGAUpdateAverage*/
   ctx->debug.PGADebugFlags[719] = Flag; /*PGAUpdateOnline*/
   ctx->debug.PGADebugFlags[720] = Flag; /*PGAUpdateOffline*/
   ctx->debug.PGADebugFlags[721] = Flag; /*PGAComputeSimilarity*/
}
#endif

/*I****************************************************************************
   PGAPrintDebugOptions - prints the list of available debug options

   Inputs:
      ctx - context variable

   Outputs:
      list of available debug options

   Example:
      PGAContext ctx;
      :
      PGAPrintDebugOptions(ctx);
      
****************************************************************************I*/
void PGAPrintDebugOptions(PGAContext *ctx)
{
    PGADebugEntered("PGAPrintDebugOptions");
    
#if OPTIMIZE==0
    fprintf(stderr, "  0 Trace all debug prints\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  1 Reserved for the user\n");
    fprintf(stderr, "    :                   :\n");
    fprintf(stderr, " 10 Reserved for the user\n");
    fprintf(stderr, " 11 Trace high-level functions\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " 20 Trace high-level parallel functions\n");
    fprintf(stderr, " 21 Trace all parallel functions\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " 30 Trace BINARY    functions\n");
    fprintf(stderr, " 32 Trace INTEGER   functions\n");
    fprintf(stderr, " 34 Trace REAL      functions\n");
    fprintf(stderr, " 36 Trace CHARACTER functions\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " 40 Trace population creation functions\n");
    fprintf(stderr, " 42 Trace select functions\n");
    fprintf(stderr, " 44 Trace mutation functions\n");
    fprintf(stderr, " 46 Trace crossover functions\n");
    fprintf(stderr, " 48 Trace function evaluation functions\n");
    fprintf(stderr, " 50 Trace fitness calculation  functions\n");
    fprintf(stderr, " 52 Trace duplicate checking functions\n");
    fprintf(stderr, " 54 Trace restart functions\n");
    fprintf(stderr, " 56 Trace reporting functions\n");
    fprintf(stderr, " 58 Trace stopping functions\n");
    fprintf(stderr, " 60 Trace sorting functions\n");
    fprintf(stderr, " 62 Trace random number functions\n");
    fprintf(stderr, " 64 Trace system routines\n");
    fprintf(stderr, " 66 Trace utility functions\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " 80 Trace memory allocations\n");
    fprintf(stderr, " 82 Trace variable print statements\n");
#else
    fprintf(stderr, " Optimized version; no debug options.\n");
#endif
    PGADestroy(ctx);
    exit(0);
}

