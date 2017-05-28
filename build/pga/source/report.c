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

/******************************************************************************
 *     FILE: report.c: This file contains functions for reporting on GA
 *                     parameters, and execution.
 *
 *     Authors: David M. Levine, Philip L. Hallstrom, David M. Noelle
 *              Brian P. Walenz
 ******************************************************************************/

#include "pgapack.h"

/*U****************************************************************************
   PGAPrintReport - prints genetic algorithm statistics.  The statistics
   that are printed are determined by PGASetPrintOptions().

   Category: Reporting

   Inputs:
      ctx - context variable
      fp  - file pointer to print the output to
      pop - symbolic constant of the population whose statistics are printed

   Outputs:
      genetic algorithm statistics are printed to fp

   Example:
      PGAContext *ctx;
      int p;
      :
      PGAPrintReport(ctx, stdout, PGA_NEWPOP);

****************************************************************************U*/
void PGAPrintReport(PGAContext *ctx, FILE *fp, int pop)
{
     int p, best_p;
     double e, best_e;

    PGADebugEntered("PGAPrintReport");

    /*
     * edd  07 Feb 2007  this prints unconditionally, so let's change it
     *                    WAS:  if (ctx->ga.iter == 1)
     */
     if ((ctx->rep.PrintFreq >=0) && !(ctx->ga.iter % ctx->rep.PrintFreq))
/*       fprintf (fp, "Iter #     Field      Value           Time\n");  */
         fprintf (fp, "Iter #     Field      Value\n");


     best_p = PGAGetBestIndex(ctx, pop);
     best_e = PGAGetEvaluation(ctx, best_p, pop);
    /*
     * edd  07 Feb 2007  this prints unconditionally, so let's change it
     *                    WAS:  (!(ctx->ga.iter % ctx->rep.PrintFreq) || ctx->ga.iter == 1)
     */
     if ((ctx->rep.PrintFreq >=0) && !(ctx->ga.iter % ctx->rep.PrintFreq))
     {
          fprintf(fp, "%-11dBest       %e\n", PGAGetGAIterValue(ctx), best_e);
/*        fprintf(fp, "      %ld\n", time(NULL) - ctx->rep.starttime);  */
          if ((ctx->rep.PrintOptions & PGA_REPORT_WORST) == PGA_REPORT_WORST)
          {
               p = PGAGetWorstIndex(ctx, pop);
               e = PGAGetEvaluation(ctx, p, pop);
               fprintf(fp, "           Worst      %e\n", e);
          }

          if ((ctx->rep.PrintOptions & PGA_REPORT_AVERAGE) == PGA_REPORT_AVERAGE)
               fprintf(fp, "           Average    %e\n", ctx->rep.Average);

          if ((ctx->rep.PrintOptions & PGA_REPORT_OFFLINE)
               == PGA_REPORT_OFFLINE)
               fprintf(fp, "           Offline    %e\n", ctx->rep.Offline);

          if ((ctx->rep.PrintOptions & PGA_REPORT_ONLINE) == PGA_REPORT_ONLINE)
               fprintf(fp, "           Online     %e\n", ctx->rep.Online);

          if((ctx->rep.PrintOptions & PGA_REPORT_HAMMING)
             == PGA_REPORT_HAMMING)
               fprintf(fp, "           Hamming    %e\n",
                       PGAHammingDistance(ctx, pop));
          if ((ctx->rep.PrintOptions & PGA_REPORT_STRING) == PGA_REPORT_STRING)
               PGAPrintString(ctx, fp, best_p, pop);
     }
     fflush(fp);

    PGADebugExited("PGAPrintReport");
}

/*U****************************************************************************
   PGASetPrintOptions - set flags to indicate what GA statistics should be
   printed whenever output is printed.  May be called more than once to
   specify different report options.  Valid choices are PGA_REPORT_AVERAGE,
   PGA_REPORT_OFFLINE, PGA_REPORT_ONLINE, PGA_REPORT_WORST, PGA_REPORT_HAMMING,
   and PGA_REPORT_STRING to specify offline analysis, online analysis, the
   worst string in the population, the Hamming distance of the population, and
   the actual allele values of the best string.  The best string is always
   printed. 

   Category: Reporting

   Inputs:
      ctx    - context variable
      option - symbolic constant to specify a print option

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetPrintOptions(ctx, PGA_REPORT_WORST);

****************************************************************************U*/
void PGASetPrintOptions (PGAContext *ctx, int option)
{
    PGADebugEntered("PGASetPrintOptions");

  switch (option) {
    case PGA_REPORT_AVERAGE:
    case PGA_REPORT_OFFLINE:
    case PGA_REPORT_ONLINE:
    case PGA_REPORT_WORST:
    case PGA_REPORT_HAMMING:
    case PGA_REPORT_STRING:
      ctx->rep.PrintOptions |= option;
      break;
    default:
      PGAError (ctx, "PGASetPrintOption: Invalid value of option:",
                PGA_FATAL, PGA_INT, (void *) &option);
      break;
  }

    PGADebugExited("PGASetPrintOptions");
}

/*U****************************************************************************
   PGASetPrintFrequencyValue - Specifies the frequency with which genetic
   algorithm statistics are reported.  The default is every 10 GA iterations.
   Used only if PGARun() is used to run the GA.

   Category: Reporting

   Inputs:
      ctx        - context variable
      print_freq - the genetic algorithm population size to use

   Outputs:
      None

   Example:
      PGAContext *ctx;
      :
      PGASetPrintFrequencyValue(ctx,1);

****************************************************************************U*/
void PGASetPrintFrequencyValue( PGAContext *ctx, int print_freq)
{
    PGADebugEntered("PGASetPrintFrequencyValue");

    if (print_freq < 0)
        PGAError ( ctx,
                  "PGASetPrintFrequencyValue: Invalid value of print_freq:",
                   PGA_FATAL,
                   PGA_INT,
                  (void *) &print_freq);
    else
        ctx->rep.PrintFreq = print_freq;

    PGADebugExited("PGASetPrintFrequencyValue");
}

/*U***************************************************************************
   PGAGetPrintFrequencyValue - returns how often to print statistics reports

   Category: Reporting

   Inputs:
      ctx - context variable

   Outputs:
      The frequency of printing output

   Example:
      PGAContext *ctx;
      int freq;
      :
      freq = PGAGetPrintFrequencyValue(ctx);

***************************************************************************U*/
int PGAGetPrintFrequencyValue (PGAContext *ctx)
{
    PGADebugEntered("PGAGetPrintFrequencyValue");
    PGAFailIfNotSetUp("PGAGetPrintFrequencyValue");

    PGADebugExited("PGAGetPrintFrequencyValue");

    return(ctx->rep.PrintFreq);
}

/*U****************************************************************************
   PGAPrintPopulation - Calls PGAPrintIndividual to print each member of a
   population

   Category: Reporting

   Inputs:
      ctx - context variable
      fp  - file pointer to print the output to
      pop - symbolic constant of the population to be printed

   Outputs:
      The strings and associated fields that make up a population member are
      printed to fp.

   Example:
      PGAContext *ctx;
      :
      PGAPrintPopulation(ctx, stdout, PGA_NEWPOP);

****************************************************************************U*/
void PGAPrintPopulation ( PGAContext *ctx, FILE *fp, int pop )
{
    int i;


    PGADebugEntered("PGAPrintPopulation");

    for ( i=0; i < ctx->ga.PopSize; i++ )
         PGAPrintIndividual ( ctx, fp,  i, pop );
    fprintf(fp,"\n");

    PGADebugExited("PGAPrintPopulation");
}

/*U****************************************************************************
   PGAPrintIndividual - prints the allele values of a string and associated
   fields (evaluation, fitness, etc.) of a string

   Category: Reporting

   Inputs:
      ctx - context variable
      fp  - file pointer to print the output to
      p   - string index
      pop - symbolic constant of the population string p is in

   Outputs:
      The allele values of string p and associated fields are printed to fp

   Example:
      PGAContext *ctx;
      int p;
      :
      PGAPrintIndividual(ctx, stdout, p, PGA_NEWPOP);

****************************************************************************U*/
void PGAPrintIndividual ( PGAContext *ctx, FILE *fp, int p, int pop )
{
    PGAIndividual *ind;

    PGADebugEntered("PGAPrintIndividual");

    ind = PGAGetIndividual ( ctx, p, pop );

    fprintf( fp,"%d  %e %e ", p, ind->evalfunc, ind->fitness);
    if ( ind->evaluptodate )
        fprintf( fp, "T\n" );
    else
        fprintf( fp, "F\n" );
    PGAPrintString ( ctx, fp, p, pop );

    PGADebugExited("PGAPrintIndividual");
}

/*U****************************************************************************
   PGAPrintString - write the allele values in a string to a file

   Category: Reporting

   Inputs:
      ctx - context variable
      fp  - pointer to file to write the string to
      p   - index of the string to write out
      pop - symbolic constant of the population string p is in

   Outputs:
      None

   Example:
      PGAContext *ctx;
      int p;
      :
      PGAPrintString(ctx, stdout, p, PGA_OLDPOP);

****************************************************************************U*/
void PGAPrintString ( PGAContext *ctx, FILE *file, int p, int pop )
{
    int fp;

    PGADebugEntered("PGAPrintString");
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAPrintString",
                  "p   = ", PGA_INT, (void *) &p );
    PGADebugPrint( ctx, PGA_DEBUG_PRINTVAR,"PGAPrintString",
                  "pop = ", PGA_INT, (void *) &pop );
    
    if (ctx->fops.PrintString) {
        fp = ((p == PGA_TEMP1) || (p == PGA_TEMP2)) ? p : p+1;
        (*ctx->fops.PrintString)(&ctx, NULL, &fp, &pop);
    } else {
        (*ctx->cops.PrintString)(ctx, file, p, pop);
    }
    fprintf(file,"\n");

    PGADebugExited("PGAPrintString");
}

/*U****************************************************************************
   PGAPrintContextVariable - prints the value of all the fields in the context
   variable.

   Category: Reporting

   Inputs:
      ctx - context variable
      fp  - file pointer to print the output to

   Outputs:
      The value of all the fields in the context variable are printed to fp.

   Example:
      PGAContext *ctx;
      :
      PGAPrintContextVariable(ctx, stdout);

****************************************************************************U*/
void PGAPrintContextVariable ( PGAContext *ctx, FILE *fp )
{
    PGADebugEntered("PGAPrintContextVariable");

     fprintf( fp,"Algorithm Parameters (Static)\n");

     fprintf( fp,"    Data type                      : ");
     switch(ctx->ga.datatype)
     {
     case PGA_DATATYPE_BINARY:
          fprintf( fp,"Binary\n");
          /*fprintf( fp,"    Bit Type Total Words           : ");
          switch(ctx->ga.tw)
          {
          case PGA_UNINITIALIZED_INT:
               fprintf( fp,"*UNINITIALIZED*\n");
               break;
          default:
               fprintf( fp,"%d\n",ctx->ga.tw);
               break;
          };
          fprintf( fp,"    Bit Type Full Words            : ");
          switch(ctx->ga.fw)
          {
          case PGA_UNINITIALIZED_INT:
               fprintf( fp,"*UNINITIALIZED*\n");
               break;
          default:
               fprintf( fp,"%d\n",ctx->ga.fw);
               break;
          };
          fprintf( fp,"    Bit Type Extra Bits            : ");
          switch(ctx->ga.eb)
          {
          case PGA_UNINITIALIZED_INT:
               fprintf( fp,"*UNINITIALIZED*\n");
               break;
          default:
               fprintf( fp,"%d\n",ctx->ga.eb);
               break;
          };*/
          break;
     case PGA_DATATYPE_INTEGER:
          fprintf( fp,"Integer\n");
          break;
     case PGA_DATATYPE_REAL:
          fprintf( fp,"Real\n");
          break;
     case PGA_DATATYPE_CHARACTER:
          fprintf( fp,"Character\n");
          break;
     case PGA_DATATYPE_USER:
          fprintf( fp,"User Defined\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.datatype);
          break;
     };

     fprintf( fp,"    Optimization Direction         : ");
     switch(ctx->ga.optdir)
     {
     case PGA_MAXIMIZE:
          fprintf( fp,"Maximize\n");
          break;
     case PGA_MINIMIZE:
          fprintf( fp,"Minimize\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.optdir);
          break;
     };

     fprintf( fp,"    Population Size                : ");
     switch(ctx->ga.PopSize)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.PopSize);
          break;
     };

     fprintf( fp,"    String Length                  : ");
     switch(ctx->ga.StringLen)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.StringLen);
          break;
     };
     

     fprintf( fp,"    Copy to Next Population        : ");
     switch(ctx->ga.PopReplace)
     {
     case PGA_POPREPL_BEST:
          fprintf( fp,"Best\n");
          break;
     case PGA_POPREPL_RANDOM_NOREP:
          fprintf( fp,"Random without replacement\n");
          break;
     case PGA_POPREPL_RANDOM_REP:
          fprintf( fp,"Random with replacement\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.PopReplace);
          break;
     };

     
     /*fprintf( fp,"    Stopping Rule (s)              :\n");
     if ((ctx->ga.StoppingRule & PGA_STOP_MAXITER) == PGA_STOP_MAXITER)
          fprintf(fp, "%50s", "Maximum iterations\n");
     if ((ctx->ga.StoppingRule & PGA_STOP_NOCHANGE) == PGA_STOP_NOCHANGE)
          fprintf(fp, "%49s", "No change in best\n");
     if ((ctx->ga.StoppingRule & PGA_STOP_TOOSIMILAR) == PGA_STOP_TOOSIMILAR)
          fprintf(fp, "%54s", "Population Homogeneity\n");
     if (ctx->ga.StoppingRule == PGA_UNINITIALIZED_INT)
          fprintf(fp, "%47s", "*UNINITIALIZED*\n");*/

     fprintf( fp,"    Stop: Maximum Iterations       : ");
     if ((ctx->ga.StoppingRule & PGA_STOP_MAXITER) == PGA_STOP_MAXITER)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");


     fprintf( fp,"        Maximum Iterations         : ");
     switch(ctx->ga.MaxIter)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.MaxIter);
          break;
     };


     fprintf( fp,"    Stop: No Change                : ");
     if ((ctx->ga.StoppingRule & PGA_STOP_NOCHANGE) == PGA_STOP_NOCHANGE)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");

     
     fprintf(fp, "        Max No Change Iterations   : ");
     switch(ctx->ga.MaxNoChange)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "*UNINITIALIZED*\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->ga.MaxNoChange);
          break;
     }

     fprintf( fp,"    Stop: Too Similar              : ");
     if ((ctx->ga.StoppingRule & PGA_STOP_TOOSIMILAR) == PGA_STOP_TOOSIMILAR)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");


     fprintf(fp, "        Percent Similarity         : ");
     switch(ctx->ga.MaxSimilarity)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "*UNINITIALIZED*\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->ga.MaxSimilarity);
          break;
     }

     fprintf( fp,"    No. Strings Replaced per Iter  : ");
     switch(ctx->ga.NumReplace)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.NumReplace);
          break;
     };


     fprintf( fp,"    Mutate [And,Or] Crossover      : ");
     switch(ctx->ga.MutateOnlyNoCross)
     {
     case PGA_TRUE:
          fprintf( fp,"Or\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"And\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.MutateOnlyNoCross);
          break;
     };

     
     fprintf( fp,"    Crossover Type                 : ");
     switch(ctx->ga.CrossoverType)
     {
     case PGA_CROSSOVER_ONEPT:
          fprintf( fp,"One Point\n");
          break;
     case PGA_CROSSOVER_TWOPT:
          fprintf( fp,"Two Point\n");
          break;
     case PGA_CROSSOVER_UNIFORM:
          fprintf( fp,"Uniform\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.CrossoverType);
          break;
     };

     
     fprintf( fp,"    Crossover Probability          : ");
     if (ctx->ga.CrossoverProb == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.CrossoverProb);

    
     fprintf( fp,"    Uniform Crossover Prob.        : ");
     if (ctx->ga.UniformCrossProb == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.UniformCrossProb);

     
     fprintf( fp,"    Mutation Type                  : ");
     switch(ctx->ga.datatype)
     {
     case PGA_DATATYPE_BINARY:
          fprintf( fp,"Binary\n");
          break;
     case PGA_DATATYPE_CHARACTER:
          fprintf( fp,"Character\n");
          break;
     case PGA_DATATYPE_REAL:
     case PGA_DATATYPE_INTEGER:
         switch(ctx->ga.MutationType)
         {
         case PGA_MUTATION_CONSTANT:
              fprintf( fp,"Constant\n");
              break;
         case PGA_MUTATION_RANGE:
              fprintf( fp,"Range\n");
              break;
         case PGA_MUTATION_UNIFORM:
              fprintf( fp,"Uniform\n");
              break;
         case PGA_MUTATION_GAUSSIAN:
              fprintf( fp,"Gaussian\n");
              break;
         case PGA_MUTATION_PERMUTE:
              fprintf( fp,"Permutation\n");
              break;
         case PGA_UNINITIALIZED_INT:
              fprintf( fp,"*UNINITIALIZED*\n");
              break;
         default:
              fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.MutationType);
              break;
         };
     default:
         break;
     };

     
     fprintf( fp,"    Mutation Probability           : ");
     if (ctx->ga.MutationProb == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.MutationProb);

     
     fprintf( fp,"    Real Mutation Constant         : ");
     if (ctx->ga.MutationProb == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.MutateRealValue);


     fprintf(fp, "    Integer Mutation Constant      : ");
     switch(ctx->ga.MutateIntegerValue)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "*UNINITIALIZED*\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->ga.MutateIntegerValue);
          break;
     }

     
     fprintf( fp,"    Mutation Range Bounded         : ");
     switch(ctx->ga.MutateBoundedFlag)
     {
     case PGA_TRUE:
          fprintf( fp,"On\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"Off\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.MutateBoundedFlag);
          break;
     };

     
     fprintf( fp,"    Selection Type                 : ");
     switch(ctx->ga.SelectType)
     {
     case PGA_SELECT_PROPORTIONAL:
          fprintf( fp,"Proportional\n");
          break;
     case PGA_SELECT_SUS:
          fprintf( fp,"Stochastic Universal\n");
          break;
     case PGA_SELECT_TOURNAMENT:
          fprintf( fp,"Binary Tournament\n");
          break;
     case PGA_SELECT_PTOURNAMENT:
          fprintf( fp,"Probabilistic Binary Tournament\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.SelectType);
          break;
     };

     
     fprintf( fp,"    Tournament Selection Param     : ");
     if (ctx->ga.PTournamentProb == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.PTournamentProb);
    
     

     fprintf( fp,"    Restart Operator               : ");
     switch(ctx->ga.restart)
     {
     case PGA_TRUE:
          fprintf( fp,"On\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"Off\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.restart);
          break;
     };

     fprintf( fp,"    Restart Frequency              : ");
     switch(ctx->ga.restartFreq)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.restartFreq);
          break;
     };

     fprintf( fp,"    Restart Allele Change Prob     : ");
     if (ctx->ga.restartAlleleProb == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.restartAlleleProb);

     
     fprintf( fp,"    Allow Duplicates               : ");
     switch(ctx->ga.NoDuplicates)
     {
     case PGA_TRUE:
          fprintf( fp,"No\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"Yes\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.NoDuplicates);
          break;
     };


     fprintf( fp,"    Fitness Type                   : ");
     switch(ctx->ga.FitnessType)
     {
     case PGA_FITNESS_RAW:
          fprintf( fp,"Raw\n");
          break;
     case PGA_FITNESS_NORMAL:
          fprintf( fp,"Linear Normalization\n");
          break;
     case PGA_FITNESS_RANKING:
          fprintf( fp,"Linear Ranking\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.FitnessType);
          break;
     };

     
     if ( ctx->ga.optdir == PGA_MINIMIZE )
     {
          fprintf( fp,"    Fitness Type(Minimization)     : ");
          switch(ctx->ga.FitnessMinType) {
          case PGA_FITNESSMIN_RECIPROCAL:
               fprintf( fp,"Reciprocal\n");
               break;
          case PGA_FITNESSMIN_CMAX:
               fprintf( fp,"CMax\n");
               break;
          case PGA_UNINITIALIZED_INT:
               fprintf( fp,"*UNINITIALIZED*\n");
               break;
          default:
               fprintf( fp,"!ERROR!  =(%d)?\n", ctx->ga.FitnessMinType);
               break;
          };
     }

     
     fprintf( fp,"    Fitness Ranking Parameter      : ");
     if (ctx->ga.FitnessRankMax == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.FitnessRankMax);
     

     fprintf( fp,"    Fitness CMAX Parameter         : ");
     if (ctx->ga.FitnessCmaxValue == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->ga.FitnessCmaxValue);

     
     fprintf( fp,"Algorithm Parameters (Dynamic)\n");

     
     fprintf( fp,"    Current Generation             : ");
     switch(ctx->ga.iter)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.iter);
          break;
     };

     fprintf(fp, "    Num Iters With No Change       : ");
     switch(ctx->ga.ItersOfSame)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "*UNINITIALIZED*\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->ga.ItersOfSame);
          break;
     }

     fprintf(fp, "    Percent Similarity In Pop      : ");
     switch(ctx->ga.PercentSame)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "?UNINITIALZED?\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->ga.PercentSame);
          break;
     }

     fprintf( fp,"    Selection Index                : ");
     switch(ctx->ga.SelectIndex)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->ga.SelectIndex);
          break;
     };

     
/* initialization */
     fprintf( fp,"Initialization\n");

     fprintf( fp,"    Random Initialization          : ");
     switch(ctx->init.RandomInit)
     {
     case PGA_TRUE:
          fprintf( fp,"On\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"Off\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->init.RandomInit);
          break;
     };

     fprintf( fp,"    Initialization Binary Prob     : ");
     if (ctx->init.BinaryProbability == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%f\n",ctx->init.BinaryProbability);


     fprintf( fp,"    Initialization Real            : ");
     switch(ctx->init.RealType)
     {
     case PGA_RINIT_RANGE:
          fprintf( fp,"Range\n");
          break;
     case PGA_RINIT_PERCENT:
          fprintf( fp,"Percent Offset\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->init.RealType);
          break;
     };

     fprintf( fp,"    Initialization Integer         : ");
     switch(ctx->init.IntegerType)
     {
     case PGA_IINIT_RANGE:
          fprintf( fp,"Range\n");
          break;
     case PGA_IINIT_PERMUTE:
          fprintf( fp,"Permutation\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->init.IntegerType);
          break;
     };

     fprintf( fp,"    Initialization Character       : ");
     switch(ctx->init.CharacterType)
     {
     case PGA_CINIT_LOWER:
          fprintf( fp,"Lower Case\n");
          break;
     case PGA_CINIT_UPPER:
          fprintf( fp,"Upper Case\n");
          break;
     case PGA_CINIT_MIXED:
          fprintf( fp,"Mixed Case\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->init.CharacterType);
          break;
     };
     
     fprintf( fp,"    Random Number Seed             : ");
     switch(ctx->init.RandomSeed)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n", ctx->init.RandomSeed);
          break;
     };

     PGADebugExited("PGAPrintContextVariable");


/* par */
    fprintf( fp,"Parallel\n");

    fprintf( fp,"    MPI Library Used               : ");
     switch(ctx->par.MPIStubLibrary)
     {
     case PGA_TRUE:
          fprintf( fp,"Sequential\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"Parallel\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->par.MPIStubLibrary);
          break;
     };


     fprintf( fp,"    MPI Initialized by PGAPack     : ");
     switch(ctx->par.MPIAlreadyInit)
     {
     case PGA_TRUE:
          fprintf( fp,"Yes\n");
          break;
     case PGA_FALSE:
          fprintf( fp,"No\n");
          break;
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"!ERROR!  =(%d)?\n", ctx->par.MPIAlreadyInit);
          break;
     };

     /*fprintf(fp, "    Number Islands                 : ");
     switch(ctx->par.NumIslands)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "*UNINITIALIZED*\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->par.NumIslands);
          break;
     }

     fprintf(fp, "    Number Demes                   : ");
     switch(ctx->par.NumDemes)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf(fp, "*UNINITIALIZED*\n");
          break;
     default:
          fprintf(fp, "%d\n", ctx->par.NumDemes);
          break;
     }*/

     fprintf(fp, "    Default Communicator           : ");
     if (ctx->par.DefaultComm == NULL) 
	 fprintf(fp, "NULL\n");
     else if (ctx->par.DefaultComm == MPI_COMM_WORLD)
         fprintf(fp, "MPI_COMM_WORLD\n");
     else
	 fprintf(fp, "User Defined\n");
 


/* report */
     fprintf( fp,"Report\n");

     fprintf( fp,"    Print Frequency                : ");
     switch(ctx->rep.PrintFreq)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->rep.PrintFreq);
          break;
     };

     fprintf( fp,"    Print Worst Evaluation         : ");
     if ((ctx->rep.PrintOptions & PGA_REPORT_WORST) == PGA_REPORT_WORST)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");

     fprintf( fp,"    Print Average Evaluation       : ");
     if ((ctx->rep.PrintOptions & PGA_REPORT_AVERAGE) == PGA_REPORT_AVERAGE)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");

     fprintf( fp,"    Print Offline Statistics       : ");
     if ((ctx->rep.PrintOptions & PGA_REPORT_OFFLINE) == PGA_REPORT_OFFLINE)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");

     fprintf( fp,"    Print Online Statistics        : ");
     if ((ctx->rep.PrintOptions & PGA_REPORT_ONLINE) == PGA_REPORT_ONLINE)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");

     fprintf( fp,"    Print Hamming Distance         : ");
     if ((ctx->rep.PrintOptions & PGA_REPORT_HAMMING) == PGA_REPORT_HAMMING)
         fprintf( fp,"On\n");
     else
         fprintf( fp,"Off\n");

/* system */
     fprintf( fp,"System\n");

     fprintf( fp,"    Maximum Integer                : ");
     switch(ctx->sys.PGAMaxInt)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->sys.PGAMaxInt);
          break;
     };

     fprintf( fp,"    Minimum Integer                : ");
     switch(ctx->sys.PGAMinInt)
     {
     case PGA_UNINITIALIZED_INT:
          fprintf( fp,"*UNINITIALIZED*\n");
          break;
     default:
          fprintf( fp,"%d\n",ctx->sys.PGAMinInt);
          break;
     };

     fprintf( fp,"    Maximum Double                 : ");
     if (ctx->sys.PGAMaxDouble == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%e\n",ctx->sys.PGAMaxDouble);

     fprintf( fp,"    Minimum Double                 : ");
     if (ctx->sys.PGAMinDouble == PGA_UNINITIALIZED_DOUBLE)
          fprintf( fp,"*UNINITIALIZED*\n");
     else
          fprintf( fp,"%e\n",ctx->sys.PGAMinDouble);



/* ops */
    fprintf( fp,"Operations\n");

    fprintf( fp,"    CreateString  function         : ");
    if (ctx->cops.CreateString == NULL)
	fprintf( fp,"NULL\n");
    else if (ctx->cops.CreateString == PGABinaryCreateString)
	fprintf( fp,"PGABinaryCreateString\n");
    else if (ctx->cops.CreateString == PGAIntegerCreateString)
	fprintf( fp,"PGAIntegerCreateString\n");
    else if (ctx->cops.CreateString == PGARealCreateString)
	fprintf( fp,"PGARealCreateString\n");
    else if (ctx->cops.CreateString == PGACharacterCreateString)
	fprintf( fp,"PGACharacterCreateString\n");
    else
	fprintf( fp,"C User Defined: %p\n",ctx->cops.CreateString);

    
    fprintf( fp,"    InitString    function         : ");
    if (ctx->cops.InitString) {
        if (ctx->cops.InitString == PGABinaryInitString)
	    fprintf( fp,"PGABinaryInitString\n");
        else if (ctx->cops.InitString == PGAIntegerInitString)
            fprintf( fp,"PGAIntegerInitString\n");
        else if (ctx->cops.InitString == PGARealInitString)
    	    fprintf( fp,"PGARealInitString\n");
        else if (ctx->cops.InitString == PGACharacterInitString)
    	    fprintf( fp,"PGACharacterInitString\n");
        else
	    fprintf( fp,"C User Defined: %p\n",ctx->cops.InitString);
    } else {
	if (ctx->fops.InitString) 
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.InitString);
	else
	    fprintf( fp,"NULL\n");
    }
    

    fprintf( fp,"    BuildDatatype function         : ");
    if (ctx->cops.BuildDatatype == NULL)
	fprintf( fp,"NULL\n");
    else if (ctx->cops.BuildDatatype == PGABinaryBuildDatatype)
	fprintf( fp,"PGABinaryBuildDatatype\n");
    else if (ctx->cops.BuildDatatype == PGAIntegerBuildDatatype)
	fprintf( fp,"PGAIntegerBuildDatatype\n");
    else if (ctx->cops.BuildDatatype == PGARealBuildDatatype)
	fprintf( fp,"PGARealBuildDatatype\n");
    else if (ctx->cops.BuildDatatype == PGACharacterBuildDatatype)
	fprintf( fp,"PGACharacterBuildDatatype\n");
    else
	fprintf( fp,"C User Defined: %p\n",ctx->cops.BuildDatatype);

    
    fprintf( fp,"    Mutation      function         : ");
    if (ctx->cops.Mutation) {
	if (ctx->cops.Mutation == PGABinaryMutation)
	    fprintf( fp,"PGABinaryMutation\n");
	else if (ctx->cops.Mutation == PGAIntegerMutation)
	    fprintf( fp,"PGAIntegerMutation\n");
	else if (ctx->cops.Mutation == PGARealMutation)
	    fprintf( fp,"PGARealMutation\n");
	else if (ctx->cops.Mutation == PGACharacterMutation)
	    fprintf( fp,"PGACharacterMutation\n");
	else
	    fprintf( fp,"C User Defined: %p\n",ctx->cops.Mutation);
    } else {
	if (ctx->fops.Mutation) 
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.Mutation);
	else
	    fprintf( fp,"NULL\n");
    }

    
    fprintf( fp,"    Crossover     function         : ");
    if (ctx->cops.Crossover) {
	if (ctx->cops.Crossover == PGABinaryOneptCrossover)
	    fprintf( fp,"PGABinaryOneptCrossover\n");
	else if (ctx->cops.Crossover == PGAIntegerOneptCrossover)
	    fprintf( fp,"PGAIntegerOneptCrossover\n");
	else if (ctx->cops.Crossover == PGARealOneptCrossover)
	    fprintf( fp,"PGARealOneptCrossover\n");
	else if (ctx->cops.Crossover == PGACharacterOneptCrossover)
	    fprintf( fp,"PGACharacterOneptCrossover\n");
	else if (ctx->cops.Crossover == PGABinaryTwoptCrossover)
	    fprintf( fp,"PGABinaryTwoptCrossover\n");
	else if (ctx->cops.Crossover == PGAIntegerTwoptCrossover)
	    fprintf( fp,"PGAIntegerTwoptCrossover\n");
	else if (ctx->cops.Crossover == PGARealTwoptCrossover)
	    fprintf( fp,"PGARealTwoptCrossover\n");
	else if (ctx->cops.Crossover == PGACharacterTwoptCrossover)
	    fprintf( fp,"PGACharacterTwoptCrossover\n");
	else if (ctx->cops.Crossover == PGABinaryUniformCrossover)
	    fprintf( fp,"PGABinarytUniformCrossover\n");
	else if (ctx->cops.Crossover == PGAIntegerUniformCrossover)
	    fprintf( fp,"PGAIntegerUniformCrossover\n");
	else if (ctx->cops.Crossover == PGARealUniformCrossover)
	    fprintf( fp,"PGARealUniformCrossover\n");
	else if (ctx->cops.Crossover == PGACharacterUniformCrossover)
	    fprintf( fp,"PGACharacterUniformCrossover\n");
	else
	    fprintf( fp,"C User Defined: %p\n",ctx->cops.Crossover);
    } else {
	if (ctx->fops.Crossover) 
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.Crossover);
	else
	    fprintf( fp,"NULL\n");
    }

    
    fprintf( fp,"    PrintString   function         : ");
    if (ctx->cops.PrintString) {
	if (ctx->cops.PrintString == PGABinaryPrintString)
	    fprintf( fp,"PGABinaryPrintString\n");
	else if (ctx->cops.PrintString == PGAIntegerPrintString)
	    fprintf( fp,"PGAIntegerPrintString\n");
	else if (ctx->cops.PrintString == PGARealPrintString)
	    fprintf( fp,"PGARealPrintString\n");
	else if (ctx->cops.PrintString == PGACharacterPrintString)
	    fprintf( fp,"PGACharacterPrintString\n");
	else
	    fprintf( fp,"C User Defined: %p\n",ctx->cops.PrintString);
    } else {
	if (ctx->fops.PrintString)
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.PrintString);
	else
	    fprintf( fp,"NULL\n");
    }
    

    fprintf( fp,"    CopyString    function         : ");
    if (ctx->cops.CopyString) {
	if (ctx->cops.CopyString == PGABinaryCopyString)
	    fprintf( fp,"PGABinaryCopyString\n");
	else if (ctx->cops.CopyString == PGAIntegerCopyString)
	    fprintf( fp,"PGAIntegerCopyString\n");
	else if (ctx->cops.CopyString == PGARealCopyString)
	    fprintf( fp,"PGARealCopyString\n");
	else if (ctx->cops.CopyString == PGACharacterCopyString)
	    fprintf( fp,"PGACharacterCopyString\n");
	else
	    fprintf( fp,"C User Defined: %p\n",ctx->cops.CopyString);
    } else {
	if (ctx->cops.CopyString)
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.CopyString);
	else
	    fprintf( fp,"NULL\n");
    }

    
    fprintf( fp,"    Duplicate     function         : ");
    if (ctx->cops.Duplicate) {
	if (ctx->cops.Duplicate == PGABinaryDuplicate)
	    fprintf( fp,"PGABinaryDuplicate\n");
	else if (ctx->cops.Duplicate == PGAIntegerDuplicate)
	    fprintf( fp,"PGAIntegerDuplicate\n");
	else if (ctx->cops.Duplicate == PGARealDuplicate)
	    fprintf( fp,"PGARealDuplicate\n"); 
	else if (ctx->cops.Duplicate == PGACharacterDuplicate)
	    fprintf( fp,"PGACharacterDuplicate\n"); 
	else
	    fprintf( fp,"C User Defined: %p\n",ctx->cops.Duplicate);
    } else {
	if (ctx->fops.Duplicate)
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.Duplicate);
	else
	    fprintf( fp,"NULL\n");
    }


    fprintf( fp,"    Stopping      function         : ");
    if (ctx->cops.StopCond)
	fprintf( fp,"C User Defined: %p\n",ctx->cops.StopCond);
    else
	if (ctx->fops.StopCond)
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.StopCond);
	else
	    fprintf( fp,"PGACheckStoppingConditions\n");


    fprintf( fp,"    End of Generation function     : ");
    if (ctx->cops.EndOfGen)
	fprintf( fp,"C User Defined: %p\n",ctx->cops.EndOfGen);
    else
	if (ctx->cops.EndOfGen)
	    fprintf( fp,"Fortran User Defined: %p\n",ctx->fops.EndOfGen);
	else
	    fprintf( fp,"NULL\n");
    

}
