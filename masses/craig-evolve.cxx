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
const double nybias = 5.0;
const int pop_size = 20;

int main(int argc, char **argv) {
     PGAContext *ctx;
     int         maxiter;

     loadtests();
     loadscores();
     MPI_Init(&argc, &argv);

     maxiter = GetIntegerParameter("How many iterations?\n");

     ctx = PGACreate(&argc, argv, PGA_DATATYPE_REAL, num_scores, PGA_MINIMIZE);

     PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING, (void *)WriteString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN, (void *)showSummary);
     PGASetRealInitRange(ctx, range_lo, range_hi);

     PGASetPopSize(ctx, pop_size);
     PGASetMutationAndCrossoverFlag(ctx, PGA_TRUE);
     PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE);
     PGASetPrintOptions(ctx, PGA_REPORT_WORST);
     PGASetPrintFrequencyValue(ctx,100000);
     PGASetMaxGAIterValue(ctx, maxiter);

     PGASetUp(ctx);

     for(int i=0; i<num_scores; i++)
     {
       for(int p=0; p<pop_size; p++)
       {
	 PGASetRealAllele(ctx, p, PGA_NEWPOP, i, bestscores[i]);
       }
     }

     PGARun(ctx, evaluate);

     showSummary(ctx);

     PGADestroy(ctx);

     MPI_Finalize();

     return(0);
}

int ga_yy,ga_yn,ga_ny,ga_nn;
double ynscore,nyscore;
double evaluate(PGAContext *ctx, int p, int pop) {

     ynscore = 0.0; nyscore = 0.0;
     ga_yy=ga_yn=ga_ny=ga_nn=0;

     // For every message
     for (int i=0; i<num_tests; i++)
     {
       double msg_score = 0.0;
       // For every test the message hit on
       for(int j=0; j<num_tests_hit[i]; j++)
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
	 }
	 else
	 {
	   // False negative
	   ga_yn++;
	   ynscore += ((threshold - msg_score) / threshold);
	 }
       }
       else
       {
	 if(msg_score > threshold)
	 {
	   // False positive
	   ga_ny++;
	   nyscore += ((msg_score - threshold) / threshold);
	 }
	 else
	 {
	   // Good negative
	   ga_nn++;
	 }
       }
     }

     return (double) ynscore + (nyscore * nybias);
}

int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         count=0;

    for (int i=0; i<num_scores; i++) {
      if(is_mutatable[i])
      {
	if (PGARandomFlip(ctx, mr)) {
	  PGASetRealAllele(ctx, p, pop, i, PGARandomGaussian(ctx, 0.0, 1.0));
	  count++;
	}
      }
    }
    return count;
}


/*  Get an integer parameter from the user.  Since this is
 *  typically a parallel program, we must only do I/O on the
 *  "master" process -- process 0.  Once we read the parameter,
 *  we broadcast it to all the other processes, then every 
 *  process returns the correct value.
 */
int GetIntegerParameter(char *query)
{
    int  rank, tmp;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    if (rank == 0) {
        printf(query);
        scanf("%d", &tmp);
    }
    MPI_Bcast(&tmp, 1, MPI_INT, 0, MPI_COMM_WORLD);
    return(tmp);
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
      int genome = PGAGetBestIndex(ctx,PGA_NEWPOP);
      PGAGetEvaluation(ctx, genome, PGA_NEWPOP);
      printf ( "\n# SUMMARY:            %6d / %6d\n#\n", ga_ny, ga_yn);
      printf ("# Correctly non-spam: %6d  %3.2f%%  (%3.2f%% overall)\n", ga_nn, (ga_nn / (float) num_nonspam) * 100.0, (ga_nn / (float) num_tests) * 100.0);
      printf ("# Correctly spam:     %6d  %3.2f%%  (%3.2f%% overall)\n", ga_yy, (ga_yy / (float) num_spam) * 100.0, (ga_yy / (float) num_tests) * 100.0);
      printf ("# False positives:    %6d  %3.2f%%  (%3.2f%% overall, %6.0f adjusted)\n", ga_ny, (ga_ny / (float) num_nonspam) * 100.0, (ga_ny / (float) num_tests) * 100.0, nyscore);
      printf ("# False negatives:    %6d  %3.2f%%  (%3.2f%% overall, %6.0f adjusted)\n", ga_yn, (ga_yn / (float) num_spam) * 100.0, (ga_yn / (float) num_tests) * 100.0, ynscore);
      printf ( "# TOTAL:              %6d  %3.2f%%\n#\n", num_tests, 100.0);
    }
    else if(0 == PGAGetGAIterValue(ctx) % 5)
    {
      printf(".");
    }
  }
}
