#!/usr/local/bin/perl
#
#  This is a simple script to help in upgrading from V0.2 to V1.0.  It will
#  make most (if not all) of the function name and #define name changes, and
#  will print a message where they are done.
#
#  Not guaranteed to work 100%, but should take the majority of the pain
#  out of it.
#
#  One thing to pay careful attention to is PGASetMutateOnlyNoCross.  This
#  was replaced by two functions, PGASetMuataionOrCrossoverFlag and
#  PGASetMuatationAndCrossoverFlag.  Here, we replace it with the first.
#
#  Usage:
#      upgrade_script.pl <FilesToUpgrade>
#
#      It will move the original files to filename.old, and create the 
#      new files with the original name.
#

if (ARGV eq 0) {
    print "Usage: upgrade_script.pl <FilesToUpgrade>\n";
    exit(-1);
}

foreach $filename (@ARGV) {
    rename($filename, "$filename.bak");
    open(INPUT, "$filename.bak");
    open(OUTPUT, ">$filename");
    while (<INPUT>) {
        &do_rename;
        print OUTPUT $_;
    }
    close(OUTPUT);
    close(INPUT);
}


sub do_rename {
    s/PGABinaryBuildIndividualDatatype/PGABinaryBuildDatatype/g;
    s/PGABinaryRandomize/PGABinaryInitString/g;
    s/PGABinaryWrite/PGABinaryPrint/g;
    s/PGABinaryWriteString/PGABinaryPrintString/g;
    s/PGABuildIndividualDatatype/PGABuildDatatype/g;
    s/PGACharacterBuildIndividualDatatype/PGACharacterBuildDatatype/g;
    s/PGACharacterRandomize/PGACharacterInitString/g;
    s/PGACharacterWriteString/PGACharacterPrintString/g;
    s/PGAFitnessLinNor/PGAFitnessLinearNormal/g;
    s/PGAFitnessLinRank/PGAFitnessLinearRank/g;
    s/PGAFitnessMinRecprl/PGAFitnessMinReciprocal/g;
    s/PGAGetEvalUpToDate/PGAGetEvaluationUpToDateFlag/g;
    s/PGAGetEvaluate/PGAGetEvaluation/g;
    s/PGAGetFitnessRankMax/PGAGetMaxFitnessRank/g;
    s/PGAGetBest/PGAGetBestIndex/g;
    s/PGAGetWorst/PGAGetWorstIndex/g;
    s/PGAGetInitIntegerMax/PGAGetMaxIntegerInitValue/g;
    s/PGAGetInitIntegerMin/PGAGetMinIntegerInitValue/g;
    s/PGAGetInitRealMax/PGAGetMaxRealInitValue/g;
    s/PGAGetInitRealMin/PGAGetMinRealInitValue/g;
    s/PGAGetIntegerType/PGAGetIntegerInitType/g;
    s/PGAGetIter/PGAGetGAIterValue/g;
    s/PGAGetMaxDouble/PGAGetMaxMachineDoubleValue/g;
    s/PGAGetMaxInt/PGAGetMaxMachineIntValue/g;
    s/PGAGetMaxIter/PGAGetMaxGAIterValue/g;
    s/PGAGetMinDouble/PGAGetMinMachineDoubleValue/g;
    s/PGAGetMinInt/PGAGetMinMachineIntValue/g;
    s/PGAGetMutateIntegerVal/PGAGetMutationIntegerValue/g;
    s/PGAGetMutateOnlyNoCross/PGAGetMutationAndCrossoverFlag/g;
    s/PGAGetMutateRealVal/PGAGetMutationRealValue/g;
    s/PGAGetNoDuplicates/PGAGetNoDuplicatesFlag/g;
    s/PGAGetNprocs/PGAGetNumProcs/g;
    s/PGAGetNumReplace/PGAGetNumReplaceValue/g;
    s/PGAGetOptDir/PGAGetOptDirFlag/g;
    s/PGAGetPID/PGAGetRank/g;
    s/PGAGetPopReplace/PGAGetPopReplaceType/g;
    s/PGAGetPrintFreq/PGAGetPrintFrequency/g;
    s/PGAGetRandomInit/PGAGetRandomInitFlag/g;
    s/PGAGetRestart/PGAGetRestartFlag/g;
    s/PGAGetRestartFrequency/PGAGetRestartFrequencyValue/g;
    s/PGAGetSortPop/PGAGetSortedPopIndex/g;
    s/PGAGetStoppingRule/PGAGetStoppingRuleType/g;
    s/PGAGetStringLen/PGAGetStringLength/g;
    s/PGAGetUniformCrossProb/PGAGetUniformCrossoverProb/g;
    s/PGAIntegerBuildIndividualDatatype/PGAIntegerBuildDatatype/g;
    s/PGAIntegerRandomize/PGAIntegerInitString/g;
    s/PGAIntegerWriteString/PGAIntegerPrintString/g;
    s/PGAParallelDone/PGADoneMS/g;
    s/PGAParallelEvaluateMS/PGAEvaluateMS/g;
    s/PGAPrintContext/PGAPrintContextVariable/g;
    s/PGAPrintVersion/PGAPrintVersionNumber/g;
    s/PGARealBuildIndividualDatatype/PGARealBuildDatatype/g;
    s/PGARealRandomize/PGARealInitString/g;
    s/PGARealWriteString/PGARealPrintString/g;
    s/PGARunMutateAndCross/PGARunMutationAndCrossover/g;
    s/PGARunMutateOrCross/PGARunMutationOrCrossover/g;
    s/PGASelectNext/PGASelectNextIndex/g;
    s/PGASetCharacterInit/PGASetCharacterInitType/g;
    s/PGASetEvaluate/PGASetEvaluation/g;
    s/PGASetEvalUpToDate/PGASetEvaluationUpToDateFlag/g;
    s/PGASetFitnessRankMax/PGASetMaxFitnessRank/g;
    s/PGASetMaxIter/PGASetMaxGAIterValue/g;
    s/PGASetMaxNoChange/PGASetMaxNoChangeValue/g;
    s/PGASetMaxSimilarity/PGASetMaxSimilarityValue/g;
    s/PGASetMutateOnlyNoCross/PGASetMutationOrCrossoverFlag/g;
    s/PGASetMutationIntegerVal/PGASetMutationIntegerValue/g;
    s/PGASetMutationRealVal/PGASetMutationRealValue/g;
    s/PGASetNoDuplicates/PGASetNoDuplicatesFlag/g;
    s/PGASetNumReplace/PGASetNumReplaceValue/g;
    s/PGASetPopReplacement/PGASetPopReplacementType/g;
    s/PGASetPrintFreq/PGASetPrintFrequencyValue/g;
    s/PGASetRandomInit/PGASetRandomInitFlag/g;
    s/PGASetRestart/PGASetRestartFlag/g;
    s/PGASetRestartFrequency/PGASetRestartFrequencyValue/g;
    s/PGASetStoppingRule/PGASetStoppingRuleType/g;
    s/PGASetSupportingDebugFlags/PGASetDebugFlag/g;
    s/PGASetUniformCrossProb/PGASetUniformCrossoverProb/g;
    s/PGAWriteString/PGAPrintString/g;
}

