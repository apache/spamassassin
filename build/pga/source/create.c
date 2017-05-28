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
*     FILE: create.c: This file contains functions to create and initialize
*                     data structures and populations.
*
*     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
*              Brian P. Walenz
*****************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
  PGACreate - creates an uninitialized context variable.  The Fortran version
  of this function call contains only the last three arguments

  Category: Generation

  Inputs:
     argc     - address of the count of the number of command line arguments.
     argv     - array of command line arguments.
     datatype - the data type used for the strings.  Must be one of
                PGA_DATATYPE_BINARY, PGA_DATATYPE_CHARACTER,
                PGA_DATATYPE_INTEGER, PGA_DATATYPE_REAL, or PGA_DATATYPE_USER
                to specify binary-valued, character-valued, integer-valued,
                real-valued, or a user-defined datatype, respectively.
     len      - the string length (number of genes).
     maxormin - the direction of optimization. Must be one of PGA_MAXIMIZE or
                PGA_MINIMIZE for maximization or minimization, respectively.

  Outputs:
     A pointer to the context variable.

  Example:

     In C:
     void main(int argc, char **argv) {
         PGAContext *ctx;
         :
         ctx = PGACreate(&argc, argv, PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE);
         :
         //  Set options here
         :
         PGASetUp(ctx);
         :
         //  Run the GA here
         :
         PGADestroy(ctx);
     }

     In FORTRAN:
             integer ctx
             :
             ctx = PGACreate(PGA_DATATYPE_BINARY, 100, PGA_MAXIMIZE)
             :
     c       Set options here
             :
             call PGASetUp(ctx)
             :
     c       Run the GA here
             :
             call PGADestroy(ctx)
             stop
             end

****************************************************************************U*/
PGAContext *PGACreate ( int *argc, char **argv,
                        int datatype, int len, int maxormin )
{
    int i;
    PGAContext *ctx;

    ctx = (PGAContext *) malloc ( sizeof(PGAContext) );

    /*  We cannot make PGA calls until we sort the FuncNameIndex below,
     *  so we just manually print the (rather severe) error message.
     */
    if( ctx == NULL ) {
	fprintf(stderr, "PGACreate: No room to allocate ctx\n");
	exit(-1);
    }

    
    /*  We use this (indirectly) in PGAReadCmdLine -- in processing
     *  -pgahelp and -pgahelp debug.
     */
    MPI_Initialized (&ctx->par.MPIAlreadyInit);

    /* Initialize MPI, only if it isn't already running (fortran)  */
    if (!ctx->par.MPIAlreadyInit)
         MPI_Init (argc, &argv);


#if OPTIMIZE==0
    /*  Sort the FuncNameIndex.  This allows us to use a binary search
     *  for finding the function names.
     */
    PGASortFuncNameIndex(ctx);
#endif

    /* Initialize debug flags, then parse command line arguments.  */
    for (i=0; i<PGA_DEBUG_MAXFLAGS; i++)
        ctx->debug.PGADebugFlags[i] = PGA_FALSE;
    PGAReadCmdLine( ctx, argc, argv );


    /*  The context variable is now initialized enough to allow this
     *  call to complete successfully.
     */
    PGADebugEntered("PGACreate");

    /* required parameter 1: abstract data type */
    switch (datatype)
    {
    case PGA_DATATYPE_BINARY:
    case PGA_DATATYPE_INTEGER:
    case PGA_DATATYPE_REAL:
    case PGA_DATATYPE_CHARACTER:
    case PGA_DATATYPE_USER:
         ctx->ga.datatype  = datatype;
         break;
    default:
         PGAError( ctx, "PGACreate: Invalid value of datatype:",
                  PGA_FATAL, PGA_INT, (void *) &datatype );
    };

    /* required parameter 2: string string length */
    if (len <= 1)
        PGAError( ctx,  "PGACreate: Invalid value of len:",
                  PGA_FATAL, PGA_INT, (void *) &len );
    else
        ctx->ga.StringLen = len;


    /* required parameter 3: optimization direction */
    switch (maxormin) {
        case PGA_MAXIMIZE:
        case PGA_MINIMIZE:
          ctx->ga.optdir = maxormin;
          break;
        default:
          PGAError( ctx, "PGACreate: Invalid value of optdir:",
                    PGA_FATAL, PGA_INT, (void *) &maxormin );
    };


    /*  For datatype == PGA_DATATYPE_BINARY, set how many full words
     *  are used in the packed representation, and how many extra bits
     *  this leaves us with.  Finally, set how many total words are used;
     *  if there are no extra bits, this is just the number of full words,
     *  else, there is one more word used than the number of full words.
     */
    switch (datatype) {
    case PGA_DATATYPE_BINARY:
        ctx->ga.fw = ctx->ga.StringLen/WL;
        ctx->ga.eb = ctx->ga.StringLen%WL;
        if ( ctx->ga.eb == 0 )
            ctx->ga.tw = ctx->ga.fw;
        else
            ctx->ga.tw = ctx->ga.fw+1;
        break;
    default:
        ctx->ga.fw = PGA_UNINITIALIZED_INT;
        ctx->ga.eb = PGA_UNINITIALIZED_INT;
        ctx->ga.tw = PGA_UNINITIALIZED_INT;
        break;
    }

    /*  Clear all the setting.  Later on, PGASetUp() will be called, and then
     *  it will notice which setting are uninitialized, and set them to the
     *  default value.
     */
    ctx->ga.PopSize            = PGA_UNINITIALIZED_INT;
    ctx->ga.StoppingRule       = PGA_STOP_MAXITER;
    ctx->ga.MaxIter            = PGA_UNINITIALIZED_INT;
    ctx->ga.MaxNoChange        = PGA_UNINITIALIZED_INT;
    ctx->ga.MaxSimilarity      = PGA_UNINITIALIZED_INT;
    ctx->ga.NumReplace         = PGA_UNINITIALIZED_INT;
    ctx->ga.CrossoverType      = PGA_UNINITIALIZED_INT;
    ctx->ga.SelectType         = PGA_UNINITIALIZED_INT;
    ctx->ga.FitnessType        = PGA_UNINITIALIZED_INT;
    ctx->ga.FitnessMinType     = PGA_UNINITIALIZED_INT;
    ctx->ga.MutationType       = PGA_UNINITIALIZED_INT;
    ctx->ga.MutateOnlyNoCross  = PGA_UNINITIALIZED_INT;
    ctx->ga.MutateRealValue    = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.MutateIntegerValue = PGA_UNINITIALIZED_INT;
    ctx->ga.MutateBoundedFlag  = PGA_UNINITIALIZED_INT;
    ctx->ga.NoDuplicates       = PGA_UNINITIALIZED_INT;
    ctx->ga.MutationProb       = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.CrossoverProb      = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.UniformCrossProb   = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.PTournamentProb    = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.FitnessRankMax     = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.FitnessCmaxValue   = PGA_UNINITIALIZED_DOUBLE;
    ctx->ga.PopReplace         = PGA_UNINITIALIZED_INT;
    ctx->ga.iter               = 0;
    ctx->ga.ItersOfSame        = 0;
    ctx->ga.PercentSame        = 0;
    ctx->ga.selected           = NULL;
    ctx->ga.SelectIndex        = 0;
    ctx->ga.restart            = PGA_UNINITIALIZED_INT;
    ctx->ga.restartFreq        = PGA_UNINITIALIZED_INT;
    ctx->ga.restartAlleleProb  = PGA_UNINITIALIZED_DOUBLE;

    /* Operations */
    ctx->cops.CreateString      = NULL;
    ctx->cops.Mutation          = NULL;
    ctx->cops.Crossover         = NULL;
    ctx->cops.PrintString       = NULL;
    ctx->cops.CopyString        = NULL;
    ctx->cops.Duplicate         = NULL;
    ctx->cops.InitString        = NULL;
    ctx->cops.BuildDatatype     = NULL;
    ctx->cops.StopCond           = NULL;
    ctx->cops.EndOfGen          = NULL;

    ctx->fops.Mutation          = NULL;
    ctx->fops.Crossover         = NULL;
    ctx->fops.PrintString       = NULL;
    ctx->fops.CopyString        = NULL;
    ctx->fops.Duplicate         = NULL;
    ctx->fops.InitString        = NULL;
    ctx->fops.StopCond          = NULL;
    ctx->fops.EndOfGen          = NULL;

    /* Parallel */
    ctx->par.NumIslands        = PGA_UNINITIALIZED_INT;
    ctx->par.NumDemes          = PGA_UNINITIALIZED_INT;
    ctx->par.DefaultComm       = NULL;
#ifdef FAKE_MPI
    ctx->par.MPIStubLibrary    = PGA_TRUE;
#else
    ctx->par.MPIStubLibrary    = PGA_FALSE;
#endif

    /* Reporting */
    ctx->rep.PrintFreq         = PGA_UNINITIALIZED_INT;
    ctx->rep.PrintOptions      = 0;
    ctx->rep.Online            = 0;
    ctx->rep.Offline           = 0;
    ctx->rep.Best              = PGA_UNINITIALIZED_DOUBLE;
    ctx->rep.starttime         = PGA_UNINITIALIZED_INT;

    /* System
     *
     *  If ctx->sys.UserFortran is not set to PGA_TRUE in pgacreate_ (the
     *  fortran stub to PGACreate), the user program is in C.
     */
    if (ctx->sys.UserFortran != PGA_TRUE) 
         ctx->sys.UserFortran  = PGA_FALSE;
    ctx->sys.SetUpCalled       = PGA_FALSE;
    ctx->sys.PGAMaxInt         = INT_MAX;
    ctx->sys.PGAMinInt         = INT_MIN;
    ctx->sys.PGAMaxDouble      = DBL_MAX;
    ctx->sys.PGAMinDouble      = DBL_MIN;

    /* Debug */
    /* Set above before parsing command line arguments */

    /* Initialization */
    ctx->init.RandomInit        = PGA_UNINITIALIZED_INT;
    ctx->init.BinaryProbability = PGA_UNINITIALIZED_DOUBLE;
    ctx->init.RealType          = PGA_UNINITIALIZED_INT;
    ctx->init.IntegerType       = PGA_UNINITIALIZED_INT;
    ctx->init.CharacterType     = PGA_UNINITIALIZED_INT;
    ctx->init.RandomSeed        = PGA_UNINITIALIZED_INT;

    /*  Allocate and clear arrays to define the minimum and maximum values
     *  allowed by integer and real datatypes.
     */
    switch (datatype)
    {
    case PGA_DATATYPE_INTEGER:
         ctx->init.IntegerMax = (int *) malloc(len * sizeof(PGAInteger));
         if (!ctx->init.IntegerMax)
              PGAError(ctx, "PGACreate: No room to allocate:", PGA_FATAL,
                       PGA_CHAR, (void *) "ctx->init.IntegerMax");
         ctx->init.IntegerMin = (int *) malloc(len * sizeof(PGAInteger));
         if (!ctx->init.IntegerMin)
              PGAError(ctx, "PGACreate: No room to allocate:", PGA_FATAL,
                       PGA_CHAR, (void *) "ctx->init.IntegerMin");
         ctx->init.RealMax = NULL;
         ctx->init.RealMin = NULL;
         for (i = 0; i < len; i++)
         {
              ctx->init.IntegerMin[i] = PGA_UNINITIALIZED_INT;
              ctx->init.IntegerMax[i] = PGA_UNINITIALIZED_INT;
         }
         break;
    case PGA_DATATYPE_REAL:
         ctx->init.RealMax = (PGAReal *) malloc(len * sizeof(PGAReal));
         if (!ctx->init.RealMax)
              PGAError(ctx, "PGACreate: No room to allocate:", PGA_FATAL,
                       PGA_CHAR, (void *) "ctx->init.RealMax");
         ctx->init.RealMin = (PGAReal *) malloc(len * sizeof(PGAReal));
         if (!ctx->init.RealMin)
              PGAError(ctx, "PGACreate: No room to allocate:", PGA_FATAL,
                       PGA_CHAR, (void *) "ctx->init.RealMin");
         ctx->init.IntegerMax = NULL;
         ctx->init.IntegerMin = NULL;
         for (i = 0; i < len; i++)
         {
              ctx->init.RealMin[i] = PGA_UNINITIALIZED_DOUBLE;
              ctx->init.RealMax[i] = PGA_UNINITIALIZED_DOUBLE;
         }
         break;
    default:
         ctx->init.RealMax = NULL;
         ctx->init.RealMin = NULL;
         ctx->init.IntegerMax = NULL;
         ctx->init.IntegerMin = NULL;
         break;
    }

    PGADebugExited("PGACreate");

    return(ctx);
}


/*U****************************************************************************
  PGASetUp - set all uninitialized variables to default values and initialize
  some internal arrays.  Must be called after PGACreate() and before the GA
  is started.

  Category: Generation

  Inputs:
     ctx - context variable

  Outputs:
     Uninitialized values in the context variable are set to defaults, and
     set values are checked for legality.

  Example:
     PGAContext *ctx;
     :
     PGACreate(ctx, ...);
     :
     //  Set options here
     :
     PGASetUp(ctx);

****************************************************************************U*/
void PGASetUp ( PGAContext *ctx )
{
    /*  These are for temporary storage of datatype specific functions.
     *  They allow some (understatement of the yesr!!) cleaning of the
     *  code below.
     */
    void         (*CreateString)(PGAContext *, int, int, int);
    int          (*Mutation)(PGAContext *, int, int, double);
    void         (*Crossover)(PGAContext *, int, int, int, int, int, int);
    void         (*PrintString)(PGAContext *, FILE *, int, int);
    void         (*CopyString)(PGAContext *, int, int, int, int);
    int          (*Duplicate)(PGAContext *, int, int, int, int);
    void         (*InitString)(PGAContext *, int, int);
    MPI_Datatype (*BuildDatatype)(PGAContext *, int, int);
    int err=0, i;

    PGADebugEntered("PGASetUp");
    PGAFailIfSetUp("PGASetUp");

    ctx->sys.SetUpCalled = PGA_TRUE;

    if ( ctx->ga.datatype           == PGA_DATATYPE_BINARY   &&
         ctx->ga.tw                 == PGA_UNINITIALIZED_INT )
      PGAError( ctx,
               "PGASetUp: Binary: Total Words (ctx->ga.tw) == UNINITIALIZED?",
               PGA_FATAL, PGA_INT, (void *) &ctx->ga.tw );

    if ( ctx->ga.datatype           == PGA_DATATYPE_BINARY  &&
         ctx->ga.fw                 == PGA_UNINITIALIZED_INT )
      PGAError( ctx,
               "PGASetUp: Binary: Full Words (ctx->ga.fw) == UNINITIALIZED?",
               PGA_FATAL, PGA_INT,  (void *) &ctx->ga.fw );

    if ( ctx->ga.datatype           == PGA_DATATYPE_BINARY  &&
         ctx->ga.eb                 == PGA_UNINITIALIZED_INT )
      PGAError( ctx,
               "PGASetUp: Binary: Empty Bits (ctx->ga.eb) == UNINITIALIZED?",
               PGA_FATAL, PGA_INT, (void *) &ctx->ga.eb );

    if ( ctx->ga.PopSize            == PGA_UNINITIALIZED_INT)
      ctx->ga.PopSize                = 100;

    if ( ctx->ga.MaxIter            == PGA_UNINITIALIZED_INT)
         ctx->ga.MaxIter             = 1000;

    if ( ctx->ga.MaxNoChange        == PGA_UNINITIALIZED_INT)
         ctx->ga.MaxNoChange         = 100;

    if ( ctx->ga.MaxSimilarity      == PGA_UNINITIALIZED_INT)
         ctx->ga.MaxSimilarity       = 95;

    if ( ctx->ga.NumReplace         == PGA_UNINITIALIZED_INT)
         ctx->ga.NumReplace          = (int) ceil(ctx->ga.PopSize * 0.1);

    if ( ctx->ga.NumReplace          > ctx->ga.PopSize)
         PGAError(ctx, "PGASetUp: NumReplace > PopSize",
                  PGA_FATAL, PGA_VOID, NULL);

    if ( ctx->ga.CrossoverType      == PGA_UNINITIALIZED_INT)
         ctx->ga.CrossoverType       = PGA_CROSSOVER_TWOPT;

    if (ctx->ga.CrossoverType       == PGA_CROSSOVER_TWOPT &&
        ctx->ga.StringLen == 2)
         PGAError(ctx, "PGASetUp: Invalid Crossover type for string of length "
                  "2", PGA_FATAL, PGA_INT, (void *) &ctx->ga.CrossoverType);

    if ( ctx->ga.SelectType        == PGA_UNINITIALIZED_INT)
         ctx->ga.SelectType         = PGA_SELECT_TOURNAMENT;

    if ( ctx->ga.FitnessType       == PGA_UNINITIALIZED_INT)
         ctx->ga.FitnessType        = PGA_FITNESS_RAW;

    if ( ctx->ga.FitnessMinType    == PGA_UNINITIALIZED_INT)
         ctx->ga.FitnessMinType     = PGA_FITNESSMIN_CMAX;

    if ( ctx->ga.MutateOnlyNoCross == PGA_UNINITIALIZED_INT)
         ctx->ga.MutateOnlyNoCross  = PGA_TRUE;

    if ( ctx->ga.MutationProb      == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.MutationProb       = 1. / ctx->ga.StringLen;

    if ( ctx->ga.MutationType      == PGA_UNINITIALIZED_INT) {
        switch (ctx->ga.datatype) {
        case PGA_DATATYPE_BINARY:
        case PGA_DATATYPE_CHARACTER:
        case PGA_DATATYPE_USER:
             /* leave PGA_UNINITIALIZED_INT for these data types */
             break;
        case PGA_DATATYPE_REAL:
             ctx->ga.MutationType   = PGA_MUTATION_GAUSSIAN;
             break;
        case PGA_DATATYPE_INTEGER:
             switch (ctx->init.IntegerType) {
                 case PGA_UNINITIALIZED_INT:
                 case PGA_IINIT_PERMUTE:
                     ctx->ga.MutationType   = PGA_MUTATION_PERMUTE;
                     break;
                 case PGA_IINIT_RANGE:
                     ctx->ga.MutationType   = PGA_MUTATION_RANGE;
                     break;
             }
             break;
        default:
             PGAError( ctx, "PGASetup: Invalid value of ctx->ga.datatype:",
                       PGA_FATAL, PGA_INT, (void *) &(ctx->ga.datatype) );
         }
    }

    if (ctx->ga.MutateRealValue   == PGA_UNINITIALIZED_DOUBLE) {
        switch (ctx->ga.MutationType) {
        case PGA_MUTATION_GAUSSIAN:
            ctx->ga.MutateRealValue   = 0.1;
            break;
        case PGA_MUTATION_UNIFORM:
            ctx->ga.MutateRealValue   = 0.1;
            break;
        case PGA_MUTATION_CONSTANT:
            ctx->ga.MutateRealValue   = 0.01;
            break;
        case PGA_MUTATION_RANGE:
        default:
            ctx->ga.MutateRealValue   = 0.0;
        }
    }

    if ( ctx->ga.MutateIntegerValue == PGA_UNINITIALIZED_INT)
         ctx->ga.MutateIntegerValue  = 1;

    if ( ctx->ga.MutateBoundedFlag == PGA_UNINITIALIZED_INT)
         ctx->ga.MutateBoundedFlag  = PGA_FALSE;

    if ( ctx->ga.NoDuplicates      == PGA_UNINITIALIZED_INT)
         ctx->ga.NoDuplicates       = PGA_FALSE;

    if ( ctx->ga.NoDuplicates && ((ctx->ga.StoppingRule & PGA_STOP_TOOSIMILAR)
                                   == PGA_STOP_TOOSIMILAR))
         PGAError(ctx, "PGASetUp: No Duplicates inconsistent with Stopping "
                  "Rule:", PGA_FATAL, PGA_INT, (void *) &ctx->ga.StoppingRule);

    if ( ctx->ga.CrossoverProb     == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.CrossoverProb      = 0.85;

    if ( ctx->ga.UniformCrossProb  == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.UniformCrossProb   = 0.6;

    if ( ctx->ga.PTournamentProb   == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.PTournamentProb    = 0.6;

    if ( ctx->ga.FitnessRankMax    == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.FitnessRankMax     = 1.2;

    if ( ctx->ga.FitnessCmaxValue  == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.FitnessCmaxValue   = 1.01;

    if ( ctx->ga.PopReplace        == PGA_UNINITIALIZED_INT)
         ctx->ga.PopReplace         = PGA_POPREPL_BEST;

    if ( ctx->ga.restart           == PGA_UNINITIALIZED_INT)
         ctx->ga.restart            = PGA_FALSE;

    if ( ctx->ga.restartFreq       == PGA_UNINITIALIZED_INT)
         ctx->ga.restartFreq        = 50;

    if ( ctx->ga.restartAlleleProb == PGA_UNINITIALIZED_DOUBLE)
         ctx->ga.restartAlleleProb = 0.5;


/* ops */
    /*  If no user supplied "done" function, use the built in one.
     *  No need to check EndOfGen; they only get called if they
     *  are defined.
     */
    if (((void *)ctx->cops.StopCond == (void *)PGADone) ||
	((void *)ctx->fops.StopCond == (void *)PGADone))
	PGAError( ctx,
		 "PGASetUp: Using PGADone as the user stopping condition will"
		 " result in an infinite loop!", PGA_FATAL, PGA_VOID, NULL);

    switch (ctx->ga.datatype) {
    case PGA_DATATYPE_BINARY:
	CreateString  = PGABinaryCreateString;
	BuildDatatype = PGABinaryBuildDatatype;
	Mutation      = PGABinaryMutation;

        switch (ctx->ga.CrossoverType) {
	  case PGA_CROSSOVER_ONEPT:
	    Crossover  = PGABinaryOneptCrossover;
            break;
	  case PGA_CROSSOVER_TWOPT:
	    Crossover  = PGABinaryTwoptCrossover;
            break;
	  case PGA_CROSSOVER_UNIFORM:
	    Crossover  = PGABinaryUniformCrossover;
            break;
        }
	PrintString    = PGABinaryPrintString;
	CopyString     = PGABinaryCopyString;
	Duplicate      = PGABinaryDuplicate;
	InitString     = PGABinaryInitString;
        break;
      case PGA_DATATYPE_INTEGER:
        CreateString   = PGAIntegerCreateString;
        BuildDatatype  = PGAIntegerBuildDatatype;
        Mutation       = PGAIntegerMutation;
        switch (ctx->ga.CrossoverType) {
	  case PGA_CROSSOVER_ONEPT:
	    Crossover  = PGAIntegerOneptCrossover;
            break;
	  case PGA_CROSSOVER_TWOPT:
	    Crossover  = PGAIntegerTwoptCrossover;
            break;
	  case PGA_CROSSOVER_UNIFORM:
	    Crossover  = PGAIntegerUniformCrossover;
            break;
        }
	PrintString    = PGAIntegerPrintString;
	CopyString     = PGAIntegerCopyString;
	Duplicate      = PGAIntegerDuplicate;
	InitString     = PGAIntegerInitString;
        break;
      case PGA_DATATYPE_REAL:
	CreateString   = PGARealCreateString;
	BuildDatatype  = PGARealBuildDatatype;
	Mutation       = PGARealMutation;
        switch (ctx->ga.CrossoverType) {
	  case PGA_CROSSOVER_ONEPT:
	    Crossover  = PGARealOneptCrossover;
            break;
	  case PGA_CROSSOVER_TWOPT:
	    Crossover  = PGARealTwoptCrossover;
            break;
	  case PGA_CROSSOVER_UNIFORM:
	    Crossover  = PGARealUniformCrossover;
            break;
        }
	PrintString    = PGARealPrintString;
	CopyString     = PGARealCopyString;
	Duplicate      = PGARealDuplicate;
	InitString     = PGARealInitString;
        break;
      case PGA_DATATYPE_CHARACTER:
	CreateString   = PGACharacterCreateString;
	BuildDatatype  = PGACharacterBuildDatatype;
	Mutation       = PGACharacterMutation;
        switch (ctx->ga.CrossoverType) {
	  case PGA_CROSSOVER_ONEPT:
	    Crossover  = PGACharacterOneptCrossover;
            break;
	  case PGA_CROSSOVER_TWOPT:
	    Crossover  = PGACharacterTwoptCrossover;
            break;
	  case PGA_CROSSOVER_UNIFORM:
	    Crossover  = PGACharacterUniformCrossover;
            break;
	}
	PrintString    = PGACharacterPrintString;
	CopyString     = PGACharacterCopyString;
	Duplicate      = PGACharacterDuplicate;
	InitString     = PGACharacterInitString;
        break;
      case PGA_DATATYPE_USER:
        if (ctx->cops.CreateString == NULL)
            PGAError( ctx,
		     "PGASetUp: User datatype needs CreateString function:",
                     PGA_WARNING, PGA_INT, (void *) &err );
        if (ctx->cops.Mutation     == NULL)
            PGAError( ctx,
		     "PGASetUp: User datatype needs Mutation function:",
                     PGA_WARNING, PGA_INT, (void *) &err );
        if (ctx->cops.Crossover    == NULL)
            PGAError( ctx,
		     "PGASetUp: User datatype needs Crossover function:",
                     PGA_WARNING, PGA_INT, (void *) &err );
        if (ctx->cops.PrintString  == NULL)
            PGAError( ctx,
		     "PGASetUp: User datatype needs PrintString function:",
                     PGA_WARNING, PGA_INT, (void *) &err );
	if (ctx->cops.Duplicate    == NULL)
            PGAError( ctx,
		     "PGASetUp: User datatype needs Duplicate function:",
                     PGA_WARNING, PGA_INT, (void *) &err );
	if (ctx->cops.CopyString    == NULL)
            PGAError( ctx,
		     "PGASetUp: User datatype needs CopyString function:",
                     PGA_WARNING, PGA_INT, (void *) &err );
        if (ctx->cops.BuildDatatype == NULL)
             PGAError(ctx,
                      "PGASetUp: User datatype needs BuildDatatype "
                      "function:", PGA_FATAL, PGA_INT, (void *) &err );
        break;
    }
    if ((ctx->cops.Mutation     == NULL) && (ctx->fops.Mutation    == NULL))
	ctx->cops.Mutation      = Mutation;
    if ((ctx->cops.Crossover    == NULL) && (ctx->fops.Crossover   == NULL))
	ctx->cops.Crossover     = Crossover;
    if ((ctx->cops.PrintString  == NULL) && (ctx->fops.PrintString == NULL))
	ctx->cops.PrintString   = PrintString;
    if ((ctx->cops.Duplicate    == NULL) && (ctx->fops.Duplicate   == NULL))
	ctx->cops.Duplicate     = Duplicate;
    if ((ctx->cops.InitString   == NULL) && (ctx->fops.InitString  == NULL))
	ctx->cops.InitString    = InitString;
    if (ctx->cops.CreateString  == NULL) 
	ctx->cops.CreateString  = CreateString;
    if (ctx->cops.CopyString    == NULL)
	ctx->cops.CopyString    = CopyString;
    if (ctx->cops.BuildDatatype == NULL)
	ctx->cops.BuildDatatype = BuildDatatype;
    
/* par */
    if ( ctx->par.NumIslands       == PGA_UNINITIALIZED_INT)
         ctx->par.NumIslands        = 1;
    if ( ctx->par.NumDemes         == PGA_UNINITIALIZED_INT)
         ctx->par.NumDemes          = 1;
    if ( ctx->par.DefaultComm      == NULL )
         ctx->par.DefaultComm       = MPI_COMM_WORLD;

    

/* rep */
    if ( ctx->rep.PrintFreq == PGA_UNINITIALIZED_INT)
         ctx->rep.PrintFreq  = 10;

/* sys */
    /* no more sets necessary here. */

/* debug */

/* init */
    if ( ctx->init.RandomInit == PGA_UNINITIALIZED_INT)
         ctx->init.RandomInit  = PGA_TRUE;

    if ( ctx->init.BinaryProbability == PGA_UNINITIALIZED_DOUBLE)
         ctx->init.BinaryProbability  = 0.5;

    if ( ctx->init.RealType == PGA_UNINITIALIZED_INT)
         ctx->init.RealType  = PGA_RINIT_RANGE;
    if ( ctx->init.IntegerType == PGA_UNINITIALIZED_INT)
         ctx->init.IntegerType  = PGA_IINIT_PERMUTE;
    if ( ctx->init.CharacterType == PGA_UNINITIALIZED_INT)
         ctx->init.CharacterType = PGA_CINIT_LOWER;

    switch (ctx->ga.datatype)
    {
    case PGA_DATATYPE_INTEGER:
         for (i = 0; i < ctx->ga.StringLen; i++)
         {
              if (ctx->init.IntegerMin[i] == PGA_UNINITIALIZED_INT)
                   ctx->init.IntegerMin[i] = 0;
              if (ctx->init.IntegerMax[i] == PGA_UNINITIALIZED_INT)
                   ctx->init.IntegerMax[i] = ctx->ga.StringLen - 1;
         }
         break;
    case PGA_DATATYPE_REAL:
         for (i = 0; i < ctx->ga.StringLen; i++)
         {
              if (ctx->init.RealMin[i] == PGA_UNINITIALIZED_DOUBLE)
                   ctx->init.RealMin[i] = 0.;
              if (ctx->init.RealMax[i] == PGA_UNINITIALIZED_DOUBLE)
                   ctx->init.RealMax[i] = 1.;
         }
         break;
    }

    /* If a seed was not specified, get one from a time of day call */
    if ( ctx->init.RandomSeed == PGA_UNINITIALIZED_INT)
         ctx->init.RandomSeed = (int)time(NULL);

    /* seed random number generator with this process' unique seed */
    ctx->init.RandomSeed += PGAGetRank(ctx, MPI_COMM_WORLD);
    PGARandom01( ctx, ctx->init.RandomSeed );

    ctx->ga.selected        = (int *)malloc( sizeof(int) * ctx->ga.PopSize );
    if (ctx->ga.selected == NULL)
         PGAError(ctx, "PGASetUp: No room to allocate ctx->ga.selected",
                  PGA_FATAL, PGA_VOID, NULL);

    ctx->ga.sorted          = (int *)malloc( sizeof(int) * ctx->ga.PopSize );
    if (ctx->ga.sorted == NULL)
         PGAError(ctx, "PGASetUp: No room to allocate ctx->ga.sorted",
                  PGA_FATAL, PGA_VOID, NULL);

    ctx->scratch.intscratch = (int *)malloc( sizeof(int) * ctx->ga.PopSize );
    if (ctx->scratch.intscratch == NULL)
         PGAError(ctx, "PGASetUp: No room to allocate ctx->scratch.intscratch",
                  PGA_FATAL, PGA_VOID, NULL);

    ctx->scratch.dblscratch = (double *)malloc(sizeof(double) * ctx->ga.PopSize);
    if (ctx->scratch.dblscratch == NULL)
         PGAError(ctx, "PGASetUp: No room to allocate ctx->scratch.dblscratch",
                  PGA_FATAL, PGA_VOID, NULL);

    PGACreatePop ( ctx , PGA_OLDPOP );
    PGACreatePop ( ctx , PGA_NEWPOP );

    ctx->rep.starttime = time(NULL);

    PGADebugExited("PGASetUp");
}

/*U****************************************************************************
   PGASetRandomInitFlag - A boolean flag to indicate whether to randomly
   initialize alleles.  Legal values are PGA_TRUE and PGA_FALSE.  Default
   is PGA_TRUE -- randomly initialize alleles.

   Category: Initialization

   Inputs:
      ctx  - context variable
      flag - either PGA_TRUE or PGA_FALSE

   Outputs:
      None

   Example:
      Set the initialization routine to initialize all alleles to zero

      PGAContext *ctx;
      :
      PGASetRandomInitFlag(ctx,PGA_FALSE);

****************************************************************************U*/
void PGASetRandomInitFlag(PGAContext *ctx, int RandomBoolean)
{
    PGADebugEntered("PGASetRandomInitFlag");
    PGAFailIfSetUp("PGASetRandomInitFlag");

  switch (RandomBoolean) {
    case PGA_TRUE:
    case PGA_FALSE:
      ctx->init.RandomInit = RandomBoolean;
      break;
    default:
      PGAError(ctx, "PGASetRandomInitFlag: Invalid value of RandomBoolean:",
               PGA_FATAL, PGA_INT, (void *) &RandomBoolean);
      break;
    }
    PGADebugExited("PGASetRandomInitFlag");
}

/*U***************************************************************************
   PGAGetRandomInitFlag - returns true/false to indicate whether or not
   alleles are randomly initialized.

   Category: Initialization

   Inputs:
      ctx - context variable

   Outputs:
      Returns PGA_TRUE if alleles are randomly initialized.
      Otherwise, returns PGA_FALSE

   Example:
      PGAContext *ctx;
      int raninit;
      :
      raninit = PGAGetRandomInitFlag(ctx);
      switch (raninit) {
      case PGA_TRUE:
          printf("Population is randomly initialized\n");
          break;
      case PGA_FALSE:
          printf("Population initialized to zero\n");
          break;
      }

***************************************************************************U*/
int PGAGetRandomInitFlag (PGAContext *ctx)
{
    PGADebugEntered("PGAGetRandomInitFlag");

    PGAFailIfNotSetUp("PGAGetRandomInitFlag");

    PGADebugExited("PGAGetRandomInitFlag");

    return(ctx->init.RandomInit);
}


/*I****************************************************************************
  PGACreatePop - allocates a population of individuals and calls
  PGACreateIndividual to set up each one

  Inputs:
     ctx - context variable
     pop - symbolic constant of the population to create

  Outputs:
     None

  Example:
     PGAContext *ctx;
     :
     PGACreatePop(ctx, PGA_NEWPOP);

****************************************************************************I*/
void PGACreatePop (PGAContext *ctx, int pop)
{
     int p, flag;

    PGADebugEntered("PGACreatePop");

     switch (pop)
     {
     case PGA_OLDPOP:
          ctx->ga.oldpop = (PGAIndividual *)malloc(sizeof(PGAIndividual) *
                                                   (ctx->ga.PopSize + 2));
          if (ctx->ga.oldpop == NULL)
               PGAError(ctx, "PGACreatePop: No room to allocate "
                        "ctx->ga.oldpop", PGA_FATAL, PGA_VOID, NULL);
          flag = ctx->init.RandomInit;
          break;
     case PGA_NEWPOP:
          ctx->ga.newpop = (PGAIndividual *)malloc(sizeof(PGAIndividual) *
                                                   (ctx->ga.PopSize + 2));
          if (ctx->ga.newpop == NULL)
               PGAError(ctx, "PGACreatePop: No room to allocate "
                        "ctx->ga.newpop", PGA_FATAL, PGA_VOID, NULL);
          flag = PGA_FALSE;
          break;
     default:
          PGAError(ctx, "PGACreatePop: Invalid value of pop:", PGA_FATAL,
                   PGA_INT, (void *) &pop );
          break;
     };
     for (p = 0; p < ctx->ga.PopSize; p++)
          PGACreateIndividual (ctx, p, pop, flag);
     PGACreateIndividual (ctx, PGA_TEMP1, pop, PGA_FALSE);
     PGACreateIndividual (ctx, PGA_TEMP2, pop, PGA_FALSE);

    PGADebugExited("PGACreatePop");
}


/*I****************************************************************************
  PGACreateIndividual - initialize to zero various data structures of an
  individual and call the appropriate function to create and initialize the
  string for the specific data type

  Inputs:
     ctx      - context variable
     p        - string index
     pop      - symbolic constant of the population string p is in
     initflag - if the value is PGA_TRUE, the string is randomly initialized.
                Otherwise it is set to zero.

  Outputs:
     None

  Example:
     PGAContext *ctx;
     int p;
     :
     PGACreateIndividual(ctx, p, PGA_NEWPOP, PGA_TRUE);

****************************************************************************I*/
void PGACreateIndividual (PGAContext *ctx, int p, int pop, int initflag)
{
    PGAIndividual *ind = PGAGetIndividual(ctx, p, pop);

    PGADebugEntered("PGACreateIndividual");

    ind->evalfunc     = 0.0;
    ind->fitness      = 0.0;
    ind->evaluptodate = PGA_FALSE;

    (*ctx->cops.CreateString)(ctx, p, pop, initflag);
    
    PGADebugExited("PGACreateIndividual");
}
