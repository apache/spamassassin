/*
 *  This program uses PGAPack to do its GA stuff.
 *  ftp://ftp.mcs.anl.gov/pub/pgapack/pgapack.tar.Z
 *  I used this one instead of galib because it uses MPI
 *  to spread load around.  It also seems like the API is a little
 *  cleaner.
 */

#include <pgapack.h>

#include "tmp/scores.h"
#include "tmp/tests.h"

double evaluate(PGAContext *, int, int);
int    myMutation(PGAContext *, int, int, double);
int    GetIntegerParameter(char *query);
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop);
void showSummary(PGAContext *ctx);

const double threshold = 5.0;
const double nybias = 10.0;
const int exhaustive_eval = 1;

const double mutation_rate = 0.2;
const double mutation_noise = 1.0;
const double regression_coefficient = 0.5;

const double crossover_rate = 0.0;

const int pop_size = 100;
const int replace_num = 25;

const int maxiter = 10000;

void init_data()
{
  int  rank;

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  if (rank == 0) {
    loadtests();
    loadscores();
  }
  MPI_Bcast(num_tests_hit, num_tests, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(is_spam, num_tests, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(tests_hit, num_tests*max_hits_per_msg, MPI_SHORT, 0, MPI_COMM_WORLD);
}

int main(int argc, char **argv) {
     PGAContext *ctx;

     MPI_Init(&argc, &argv);
     init_data();

     ctx = PGACreate(&argc, argv, PGA_DATATYPE_REAL, num_scores, PGA_MINIMIZE);

     PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING, (void *)WriteString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN, (void *)showSummary);

     PGASetRealInitRange(ctx, range_lo, range_hi);

     PGASetPopSize(ctx, pop_size);

     PGASetNumReplaceValue(ctx, replace_num);

     PGASetMutationOrCrossoverFlag(ctx, PGA_TRUE);

     PGASetMutationBoundedFlag(ctx, PGA_FALSE);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);

     PGASetCrossoverType(ctx, PGA_CROSSOVER_ONEPT);
     PGASetCrossoverProb(ctx, crossover_rate);

     PGASetPrintFrequencyValue(ctx,300);
     PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE);

     PGASetStoppingRuleType(ctx, PGA_STOP_NOCHANGE);
     PGASetMaxNoChangeValue(ctx, 300);
     PGASetMaxGAIterValue(ctx, maxiter);

     PGASetUp(ctx);

     // Now fix the alleles for the imutable tests
     /*
     for(int i=0; i<num_scores; i++)
     {
       for(int p=0; p<pop_size; p++)
       {
	 PGASetRealAllele(ctx, p, PGA_NEWPOP, i, bestscores[i]);
       }
     }
     */

     PGARun(ctx, evaluate);

     PGADestroy(ctx);

     MPI_Finalize();

     return(0);
}

int ga_yy,ga_yn,ga_ny,ga_nn;
double ynscore,nyscore,yyscore,nnscore;

inline double score_msg(PGAContext *ctx, int p, int pop, int i)
{
  double msg_score = 0.0;
  // For every test the message hit on
  for(int j=num_tests_hit[i]-1; j>=0; j--)
  {
    // Up the message score by the allele for this test in the genome
    msg_score += PGAGetRealAllele(ctx, p, pop, tests_hit[i][j]);
  }

  // Ok, now we know the score for this message.  Let's see how this genome did...
       
  if(is_spam[i])
  {
    if(msg_score > threshold)
    {
      // Good positive
      ga_yy++;
      yyscore += msg_score;
    }
    else
    {
      // False negative
      ga_yn++;
      ynscore += threshold - msg_score;
    }
  }
  else
  {
    if(msg_score > threshold)
    {
      // False positive
      ga_ny++;
      nyscore += msg_score - threshold;
    }
    else
    {
      // Good negative
      ga_nn++;
      nnscore += msg_score;
    }
  }

  return msg_score;
}

double evaluate(PGAContext *ctx, int p, int pop)
{
  double tot_score = 0.0;
  yyscore = ynscore = nyscore = nnscore = 0.0;
  ga_yy=ga_yn=ga_ny=ga_nn=0;

  // For every message
  for (int i=num_tests-1; i>=0; i--)
  {
    tot_score += score_msg(ctx,p,pop,i);
  }
//   yyscore = log(yyscore);
//   ynscore = log(ynscore);
//   nyscore = log(nyscore);
//   nnscore = log(nnscore);

  return (double) ((double)ga_yn)+ynscore + (((double)ga_ny)+nyscore)*nybias + (ynscore-nnscore)/1000.0;
}

/*
 * This mutation function tosses a weighted coin for each allele.  If the allele is to be mutated,
 * then the way it's mutated is to regress it toward the mean of the population for that allele,
 * then add a little gaussian noise.
 */
int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         count=0;

    for (int i=0; i<num_scores; i++)
    {
      if(is_mutatable[i] && PGARandomFlip(ctx, mr))
      {
	double gene_sum=0.0;
	// Find the mean
	for(int j=0; j<pop_size; j++) { if(p!=j) gene_sum += PGAGetRealAllele(ctx, j, pop, i); }
	gene_sum /= (double)(pop_size-1);
	// Regress towards it...
	gene_sum = (1.0-regression_coefficient)*gene_sum+regression_coefficient*PGAGetRealAllele(ctx, p, pop, i);
	// Set this gene in this allele to be the average, plus some gaussian noise
	PGASetRealAllele(ctx, p, pop, i, PGARandomGaussian(ctx, gene_sum, mutation_noise));
	count++;
      }
    }
    return count;
}


void dump()
{
    printf ("\n# SUMMARY:            %6d / %6d\n#\n", ga_ny, ga_yn);
    printf ("# Correctly non-spam: %6d  %3.2f%%  (%3.2f%% overall)\n", ga_nn, (ga_nn / (float) num_nonspam) * 100.0, (ga_nn / (float) num_tests) * 100.0);
    printf ("# Correctly spam:     %6d  %3.2f%%  (%3.2f%% overall)\n", ga_yy, (ga_yy / (float) num_spam) * 100.0, (ga_yy / (float) num_tests) * 100.0);
    printf ("# False positives:    %6d  %3.2f%%  (%3.2f%% overall, %6.0f adjusted)\n", ga_ny, (ga_ny / (float) num_nonspam) * 100.0, (ga_ny / (float) num_tests) * 100.0, nyscore*nybias);
    printf ("# False negatives:    %6d  %3.2f%%  (%3.2f%% overall, %6.0f adjusted)\n", ga_yn, (ga_yn / (float) num_spam) * 100.0, (ga_yn / (float) num_tests) * 100.0, ynscore);
    printf ("# TOTAL:              %6d  %3.2f%%\n#\n", num_tests, 100.0);
}

/*****************************************************************************
 * WriteString sends a visual representation of the chromosome out to fp     *
 *****************************************************************************/
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop)
{
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  if(0 == rank)
  {
    evaluate(ctx,p,pop);
    dump();
    for(int i=0; i<num_scores; i++)
    {
      fprintf(fp,"score %-30s %2.1f\n",score_names[i],PGAGetRealAllele(ctx, p, pop, i));
    }
    fprintf ( fp,"\n" );
  }
}

void showSummary(PGAContext *ctx)
{
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  if(0 == rank)
  {
    if(0 == PGAGetGAIterValue(ctx) % 300)
    {
      int genome = PGAGetBestIndex(ctx,PGA_OLDPOP);
      PGAGetEvaluation(ctx, genome, PGA_OLDPOP);
      dump();
    }
    else if(0 == PGAGetGAIterValue(ctx) % 5)
    {
      printf(".");
    }
  }
}
