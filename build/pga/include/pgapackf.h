c******************************************************************************
c     FILE: pgapackf.h
c
c     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle,
c              Brian P. Walenz
c*****************************************************************************/
c *** I/O FLAGS
CBARF !! is NULL ok?
      integer STDIN, STDOUT, STDERR, NULL
      parameter(STDIN=5, STDOUT=6, STDERR=6, NULL=0)


c *** ABSTRACT DATA TYPES
      integer PGA_DATATYPE_BINARY
      parameter( PGA_DATATYPE_BINARY =      1)
      integer PGA_DATATYPE_INTEGER
      parameter( PGA_DATATYPE_INTEGER =     2)
      integer PGA_DATATYPE_REAL
      parameter( PGA_DATATYPE_REAL =        3)
      integer PGA_DATATYPE_CHARACTER
      parameter( PGA_DATATYPE_CHARACTER =   4)
      integer PGA_DATATYPE_USER
      parameter( PGA_DATATYPE_USER =        5)

      integer PGA_INT
      parameter( PGA_INT =                   1)
      integer PGA_DOUBLE
      parameter( PGA_DOUBLE =                2)
      integer PGA_CHAR
      parameter( PGA_CHAR =                  3)
      integer PGA_VOID
      parameter( PGA_VOID =                  4)

    
c *** BOOLEANS &  FLAGS
      integer PGA_TRUE
      parameter ( PGA_TRUE =                   1)
      integer PGA_FALSE
      parameter ( PGA_FALSE =                  0)

      integer PGA_FATAL
      parameter ( PGA_FATAL =                 1)
      integer PGA_WARNING
      parameter ( PGA_WARNING =               2)


      integer PGA_UNINITIALIZED_INT
      parameter ( PGA_UNINITIALIZED_INT =    -3827)
      double precision PGA_UNINITIALIZED_DOUBLE
      parameter ( PGA_UNINITIALIZED_DOUBLE = -968.3827)

c *** TEMP & POP REFERENT CONSTANTS
      integer PGA_TEMP1
      parameter ( PGA_TEMP1 =                -1138)
      integer PGA_TEMP2
      parameter ( PGA_TEMP2 =                -4239)

      integer PGA_OLDPOP
      parameter ( PGA_OLDPOP =               -6728)
      integer PGA_NEWPOP
      parameter ( PGA_NEWPOP =               -8376)

c *** DEBUG LEVELS
      integer PGA_DEBUG_ENTERED
      parameter ( PGA_DEBUG_ENTERED =          12)
      integer PGA_DEBUG_EXIT
      parameter ( PGA_DEBUG_EXIT =             13)
      integer PGA_DEBUG_MALLOC
      parameter ( PGA_DEBUG_MALLOC =           80)
      integer PGA_DEBUG_PRINTVAR
      parameter ( PGA_DEBUG_PRINTVAR =         82)
      integer PGA_DEBUG_SEND
      parameter ( PGA_DEBUG_SEND =             22)
      integer PGA_DEBUG_RECV
      parameter ( PGA_DEBUG_RECV =             23)
      integer PGA_DEBUG_MAXPGAPACKFUNCTIONS
      parameter ( PGA_DEBUG_MAXPGAPACKFUNCTIONS =        300)
      integer PGA_DEBUG_MAXFLAGS
      parameter ( PGA_DEBUG_MAXFLAGS =       1000)

c *** DIRECTION
      integer PGA_MAXIMIZE
      parameter ( PGA_MAXIMIZE =            1)
      integer PGA_MINIMIZE
      parameter ( PGA_MINIMIZE =            2)
    
c *** STOPPING CRITERIA
      integer PGA_STOP_MAXITER
      parameter ( PGA_STOP_MAXITER =        1)
      integer PGA_STOP_NOCHANGE
      parameter ( PGA_STOP_NOCHANGE =       2)
      integer PGA_STOP_TOOSIMILAR
      parameter ( PGA_STOP_TOOSIMILAR =     4)

c *** CROSSOVER
      integer PGA_CROSSOVER_ONEPT
      parameter ( PGA_CROSSOVER_ONEPT =     1)
      integer PGA_CROSSOVER_TWOPT
      parameter ( PGA_CROSSOVER_TWOPT =     2)
      integer PGA_CROSSOVER_UNIFORM
      parameter ( PGA_CROSSOVER_UNIFORM =   3)

c *** SELECTION
      integer PGA_SELECT_PROPORTIONAL
      parameter ( PGA_SELECT_PROPORTIONAL = 1)
      integer PGA_SELECT_SUS
      parameter ( PGA_SELECT_SUS =          2)
      integer PGA_SELECT_TOURNAMENT
      parameter ( PGA_SELECT_TOURNAMENT =   3)
      integer PGA_SELECT_PTOURNAMENT
      parameter ( PGA_SELECT_PTOURNAMENT =  4)

c *** FITNESS
      integer PGA_FITNESS_RAW
      parameter ( PGA_FITNESS_RAW =         1)
      integer PGA_FITNESS_NORMAL
      parameter ( PGA_FITNESS_NORMAL =      2)
      integer PGA_FITNESS_RANKING
      parameter ( PGA_FITNESS_RANKING =     3)

c *** FITNESS (MINIMIZATION)
      integer PGA_FITNESSMIN_RECIPROCAL
      parameter ( PGA_FITNESSMIN_RECIPROCAL =  1)
      integer PGA_FITNESSMIN_CMAX
      parameter ( PGA_FITNESSMIN_CMAX =        2)

c *** MUTATION
      integer PGA_MUTATION_CONSTANT
      parameter ( PGA_MUTATION_CONSTANT =  1)
      integer PGA_MUTATION_RANGE
      parameter ( PGA_MUTATION_RANGE    =  2)
      integer PGA_MUTATION_UNIFORM
      parameter ( PGA_MUTATION_UNIFORM  =  3)
      integer PGA_MUTATION_GAUSSIAN
      parameter ( PGA_MUTATION_GAUSSIAN =  4)
      integer PGA_MUTATION_PERMUTE
      parameter ( PGA_MUTATION_PERMUTE  =  5)
    
c *** POPULATION REPLACEMENT
      integer PGA_POPREPL_BEST
      parameter ( PGA_POPREPL_BEST =         1)
      integer PGA_POPREPL_RANDOM_NOREP
      parameter ( PGA_POPREPL_RANDOM_NOREP = 2)
      integer PGA_POPREPL_RANDOM_REP
      parameter ( PGA_POPREPL_RANDOM_REP =   3)

c *** REPORT OPTIONS
      integer PGA_REPORT_ONLINE
      parameter ( PGA_REPORT_ONLINE =   1 )
      integer PGA_REPORT_OFFLINE
      parameter ( PGA_REPORT_OFFLINE =  2 )
      integer PGA_REPORT_HAMMING
      parameter ( PGA_REPORT_HAMMING =  4 )
      integer PGA_REPORT_STRING
      parameter ( PGA_REPORT_STRING =   8 )
      integer PGA_REPORT_WORST
      parameter ( PGA_REPORT_WORST =   16 )
      integer PGA_REPORT_AVERAGE
      parameter ( PGA_REPORT_AVERAGE = 32 )

c *** RANDOMIZER
      integer PGA_IINIT_PERMUTE
      parameter ( PGA_IINIT_PERMUTE =             1)
      integer PGA_IINIT_RANGE
      parameter ( PGA_IINIT_RANGE =               2)
      integer PGA_CINIT_LOWER
      parameter ( PGA_CINIT_LOWER =               1)
      integer PGA_CINIT_UPPER
      parameter ( PGA_CINIT_UPPER =               2)
      integer PGA_CINIT_MIXED
      parameter ( PGA_CINIT_MIXED =               3)

c *** SET USER FUNCTION
      integer PGA_USERFUNCTION_CREATESTRING
      parameter ( PGA_USERFUNCTION_CREATESTRING =       1)
      integer PGA_USERFUNCTION_MUTATION
      parameter ( PGA_USERFUNCTION_MUTATION =           2)
      integer PGA_USERFUNCTION_CROSSOVER
      parameter ( PGA_USERFUNCTION_CROSSOVER =          3)
      integer PGA_USERFUNCTION_PRINTSTRING
      parameter ( PGA_USERFUNCTION_PRINTSTRING  =       4)
      integer PGA_USERFUNCTION_COPYSTRING
      parameter ( PGA_USERFUNCTION_COPYSTRING =         5)
      integer PGA_USERFUNCTION_DUPLICATE
      parameter ( PGA_USERFUNCTION_DUPLICATE =          6)
      integer PGA_USERFUNCTION_INITSTRING
      parameter ( PGA_USERFUNCTION_INITSTRING =         7)
      integer PGA_USERFUNCTION_BUILDDATATYPE
      parameter ( PGA_USERFUNCTION_BUILDDATATYPE =      8)
      integer PGA_USERFUNCTION_STOPCOND
      parameter ( PGA_USERFUNCTION_STOPCOND =           9)
      integer PGA_USERFUNCTION_ENDOFGEN
      parameter ( PGA_USERFUNCTION_ENDOFGEN =          10)

c *** TAGS
      integer PGA_COMM_STRINGTOEVAL
      parameter ( PGA_COMM_STRINGTOEVAL =              1)
      integer PGA_COMM_EVALOFSTRING
      parameter ( PGA_COMM_EVALOFSTRING =              2)
      integer PGA_COMM_DONEWITHEVALS
      parameter ( PGA_COMM_DONEWITHEVALS =             3)
      integer PGAGetBinaryAllele
      double precision PGAGetBinaryInitProb
      character PGAGetCharacterAllele
      integer PGACreate
      integer PGAGetRandomInitFlag
      integer PGAGetCrossoverType
      double precision PGAGetCrossoverProb
      double precision PGAGetUniformCrossoverProb
      integer PGADuplicate
      integer PGAGetNoDuplicatesFlag
      double precision PGAGetEvaluation
      integer PGAGetEvaluationUpToDateFlag
      double precision PGAGetRealFromBinary
      double precision PGAGetRealFromGrayCode
      integer PGAGetIntegerFromBinary
      integer PGAGetIntegerFromGrayCode
      integer PGARank
      double precision PGAGetFitness
      integer PGAGetFitnessType
      integer PGAGetFitnessMinType
      double precision PGAGetMaxFitnessRank
      double precision PGAGetFitnessCmaxValue
      double precision PGAHammingDistance
      integer PGAGetIntegerAllele
      integer PGAGetIntegerInitType
      integer PGAGetMinIntegerInitValue
      integer PGAGetMaxIntegerInitValue
      integer PGAMutate
      integer PGAGetMutationType
      double precision PGAGetMutationRealValue
      integer PGAGetMutationIntegerValue
      integer PGAGetMutationBoundedFlag
      double precision PGAGetMutationProb
      integer PGABuildDatatype
      integer PGAGetRank
      integer PGAGetNumProcs
      integer PGAGetCommunicator
      integer PGAGetDataType
      integer PGAGetOptDirFlag
      integer PGAGetStringLength
      integer PGAGetGAIterValue
      integer PGAGetMutationOrCrossoverFlag
      integer PGAGetMutationAndCrossoverFlag
      integer PGAGetPopSize
      integer PGAGetNumReplaceValue
      integer PGAGetPopReplaceType
      integer PGAGetSortedPopIndex
      integer PGARandomFlip
      integer PGARandomInterval
      double precision PGARandom01
      double precision PGARandomUniform
      double precision PGARandomGaussian
      integer PGAGetRandomSeed
      double precision PGAGetRealAllele
      double precision PGAGetMinRealInitValue
      double precision PGAGetMaxRealInitValue
      integer PGAGetRealInitType
      integer PGAGetPrintFrequencyValue
      integer PGAGetRestartFlag
      integer PGAGetRestartFrequencyValue
      double precision PGAGetRestartAlleleChangeProb
      integer PGASelectNextIndex
      integer PGAGetSelectType
      double precision PGAGetPTournamentProb
      integer PGADone
      integer PGACheckStoppingConditions
      integer PGAGetStoppingRuleType
      integer PGAGetMaxGAIterValue
      integer PGAGetMaxMachineIntValue
      integer PGAGetMinMachineIntValue
      double precision PGAGetMaxMachineDoubleValue
      double precision PGAGetMinMachineDoubleValue
      double precision PGAMean
      double precision PGAStddev
      integer PGARound
      integer PGACheckSum
      integer PGAGetWorstIndex
      integer PGAGetBestIndex

      external PGAGetBinaryAllele
      external PGAGetBinaryInitProb
      external PGAGetCharacterAllele
      external PGACreate
      external PGAGetRandomInitFlag
      external PGAGetCrossoverType
      external PGAGetCrossoverProb
      external PGAGetUniformCrossoverProb
      external PGADuplicate
      external PGAGetNoDuplicatesFlag
      external PGAGetEvaluation
      external PGAGetEvaluationUpToDateFlag
      external PGAGetRealFromBinary
      external PGAGetRealFromGrayCode
      external PGAGetIntegerFromBinary
      external PGAGetIntegerFromGrayCode
      external PGARank
      external PGAGetFitness
      external PGAGetFitnessType
      external PGAGetFitnessMinType
      external PGAGetMaxFitnessRank
      external PGAGetFitnessCmaxValue
      external PGAHammingDistance
      external PGAGetIntegerAllele
      external PGAGetIntegerInitType
      external PGAGetMinIntegerInitValue
      external PGAGetMaxIntegerInitValue
      external PGAMutate
      external PGAGetMutationType
      external PGAGetMutationRealValue
      external PGAGetMutationIntegerValue
      external PGAGetMutationBoundedFlag
      external PGAGetMutationProb
      external PGABuildDatatype
      external PGAGetRank
      external PGAGetNumProcs
      external PGAGetCommunicator
      external PGAGetDataType
      external PGAGetOptDirFlag
      external PGAGetStringLength
      external PGAGetGAIterValue
      external PGAGetMutationOrCrossoverFlag
      external PGAGetMutationAndCrossoverFlag
      external PGAGetPopSize
      external PGAGetNumReplaceValue
      external PGAGetPopReplaceType
      external PGAGetSortedPopIndex
      external PGARandomFlip
      external PGARandomInterval
      external PGARandom01
      external PGARandomUniform
      external PGARandomGaussian
      external PGAGetRandomSeed
      external PGAGetRealAllele
      external PGAGetMinRealInitValue
      external PGAGetMaxRealInitValue
      external PGAGetRealInitType
      external PGAGetPrintFrequencyValue
      external PGAGetRestartFlag
      external PGAGetRestartFrequencyValue
      external PGAGetRestartAlleleChangeProb
      external PGASelectNextIndex
      external PGAGetSelectType
      external PGAGetPTournamentProb
      external PGADone
      external PGACheckStoppingConditions
      external PGAGetStoppingRuleType
      external PGAGetMaxGAIterValue
      external PGAGetMaxMachineIntValue
      external PGAGetMinMachineIntValue
      external PGAGetMaxMachineDoubleValue
      external PGAGetMinMachineDoubleValue
      external PGAMean
      external PGAStddev
      external PGARound
      external PGACheckSum
      external PGAGetWorstIndex
      external PGAGetBestIndex

