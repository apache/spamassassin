/*
 *  This program uses PGAPack to do its GA stuff.
 *  ftp://ftp.mcs.anl.gov/pub/pgapack/pgapack.tar.Z
 *  I used this one instead of galib because it uses MPI
 *  to spread load around.  It also seems like the API is a little
 *  cleaner.
 */

#include "pgapack.h"

#include <unistd.h>
#include "tmp/scores.h"
#include "tmp/tests.h"


/* Craig's log(score) evaluator, not as aggressive against FPs I think.
 */
//#define USE_LOG_SCORE_EVALUATION

/* Use score ranges derived from hit-frequencies S/O ratio,
 * and numbers of mails hit.  If not defined, score ranges are 
 * from -3.0 to 0.0 (for nice tests) or 0.0 to 3.0 (for normal tests),
 * regardless of hit success rate or frequency.
 */
#define USE_SCORE_RANGES


double evaluate(PGAContext *, int, int);
int    myMutation(PGAContext *, int, int, double);
int    GetIntegerParameter(char *query);
void dump(FILE *);
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop);
void showSummary(PGAContext *ctx);

double threshold = 5.0;
double nybias = 10.0;
const int exhaustive_eval = 1;

const double mutation_rate = 0.01;
const double mutation_noise = 0.5;
const double regression_coefficient = 0.75;
#ifndef USE_SCORE_RANGES
const double SCORE_CAP = 4.0;
const double NEG_SCORE_CAP = -9.0;
#endif

const double crossover_rate = 0.65;

int pop_size = 50;
int replace_num = 20;

const int maxiter = 30000;

int justCount = 0;

void usage()
{
#ifdef USE_MPI
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  if(rank == 0) {
#endif
  printf("usage: evolve [-s size] [args]\n"
     "\n"
     "  -s size = population size (50 recommended)\n"
     "  -r replace = number of individuals to replace each generation (20 recommended)\n"
     "  -b nybias = bias towards false negatives (10.0 default)\n"
     "  -t threshold = threshold for spam/nonspam decision\n"
     "\n"
     "  -C = just count hits and exit, no evolution\n\n");
#ifdef USE_MPI
  }
#endif
  exit (30);
}

void init_data()
{
#ifdef USE_MPI
  int rank;

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);

  if (rank == 0) {
#endif

    loadtests();
    loadscores();
    nybias = nybias*((double)num_spam)/((double)num_nonspam);

#ifdef USE_MPI
  }

  MPI_Bcast(num_tests_hit, num_tests, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(&nybias, 1, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(is_spam, num_tests, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(tests_hit, num_tests*max_hits_per_msg, MPI_SHORT, 0, MPI_COMM_WORLD);
  MPI_Bcast(&num_scores, 1, MPI_INT, 0, MPI_COMM_WORLD);
  MPI_Bcast(is_mutatable, num_scores, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(range_lo, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(range_hi, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(bestscores, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(scores, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
#endif
}

#define LOOKUP_MAX 1999
double lookup[LOOKUP_MAX];

// this is about 35% faster than calling PGAGetRealAllele() directly inside
// score_msg(), in my tests.
void
load_scores_into_lookup(PGAContext *ctx, int p, int pop)
{
  int i;
  if (num_scores >= LOOKUP_MAX) {
    fprintf (stderr, "oops! increase LOOKUP_MAX in load_scores_into_lookup\n");
    exit (1);
  }
  for (i = 0; i < num_scores; i++) {
    lookup[i] = PGAGetRealAllele(ctx, p, pop, i); 
  }
} 

int main(int argc, char **argv) {
    PGAContext *ctx;
    int i,p;
    int arg;

#ifdef USE_MPI
    MPI_Init(&argc, &argv);
#endif

    while ((arg = getopt (argc, argv, "b:r:s:t:C")) != -1) {
      switch (arg) {
        case 'b':
          nybias = atof(optarg);
          break;

         case 't':
           threshold = (double) atof(optarg);
           break;

        case 's':
          pop_size = atoi(optarg);
          break;

	case 'r':
	  replace_num = atoi(optarg);
	  break;

        case 'C':
          justCount = 1;
          break;

        case '?':
          usage();
          break;
      }
    }

     init_data();

     ctx = PGACreate(&argc, argv, PGA_DATATYPE_REAL, num_scores, PGA_MINIMIZE);

     PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING, (void *)WriteString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN, (void *)showSummary);

     PGASetRealInitRange(ctx, range_lo, range_hi);

     /* use a tiny population: we just want to get into the evaluate function */
     if (justCount) {
       pop_size = 2;
       replace_num = 1;
     }

     PGASetPopSize(ctx, pop_size);

     PGASetNumReplaceValue(ctx, replace_num);

     //PGASetMutationOrCrossoverFlag(ctx, PGA_TRUE);

#ifndef USE_SCORE_RANGES

     PGASetMutationBoundedFlag(ctx, PGA_FALSE);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);

#else

     PGASetMutationBoundedFlag(ctx, PGA_FALSE);
     PGASetMutationType(ctx, PGA_MUTATION_RANGE);
     PGASetRealInitRange (ctx, range_lo, range_hi);

#endif

     //PGASetCrossoverType(ctx, PGA_CROSSOVER_ONEPT);
     PGASetCrossoverProb(ctx, crossover_rate);

     if (justCount) {           // don't allow any mutation or crossover
       PGASetMutationType(ctx, PGA_MUTATION_CONSTANT);
       PGASetRealInitRange (ctx, bestscores, bestscores);
       PGASetCrossoverProb(ctx, 0.0);
     }

     PGASetPrintFrequencyValue(ctx,300);
     PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE);

     PGASetStoppingRuleType(ctx, PGA_STOP_NOCHANGE);
     PGASetMaxNoChangeValue(ctx, 300);
     PGASetMaxGAIterValue(ctx, maxiter);

     PGASetUp(ctx);

     // Now initialize the scores
     for(i=0; i<num_scores; i++)
     {
       for(p=0; p<pop_size; p++)
       {
         // just counting?  score[i] = defaultscore[i] in that case
         if (justCount) {
           PGASetRealAllele(ctx, p, PGA_NEWPOP, i, bestscores[i]);
           continue;
         }

#ifndef USE_SCORE_RANGES
	 if (is_mutatable[i]) {
            if(bestscores[i] > SCORE_CAP) bestscores[i] = SCORE_CAP;
	    else if(bestscores[i] < NEG_SCORE_CAP) bestscores[i] = NEG_SCORE_CAP;
	 }
#endif
	 PGASetRealAllele(ctx, p, PGA_NEWPOP, i, bestscores[i]);
       }
     }
     PGARun(ctx, evaluate);

     PGADestroy(ctx);

#ifdef USE_MPI
     MPI_Finalize();
#endif

     return(0);
}

int ga_yy,ga_yn,ga_ny,ga_nn;
double ynscore,nyscore,yyscore,nnscore;

double score_msg(PGAContext *ctx, int p, int pop, int i)
{
  double msg_score = 0.0;
  int j;

  // For every test the message hit on
  for(j=num_tests_hit[i]-1; j>=0; j--)
  {
    // Up the message score by the allele for this test in the genome
    //msg_score += PGAGetRealAllele(ctx, p, pop, tests_hit[i][j]);
    msg_score += lookup[tests_hit[i][j]];
  }

  // Ok, now we know the score for this message.  Let's see how this genome did...
       
  if(is_spam[i])
  {
    if(msg_score >= threshold)
    {
      // Good positive
      ga_yy++;
      yyscore += msg_score; // Each true positive means yyscore += at least 5
    }
    else
    {
      // False negative
      ga_yn++;
      ynscore += msg_score; // Each false negative means that ynscore += less than 5
    }
  }
  else
  {
    if(msg_score >= threshold)
    {
      // False positive
      ga_ny++;
      nyscore += msg_score; // Each false positive means nyscore += more than 5
    }
    else
    {
      // Good negative
      ga_nn++;
      nnscore += msg_score; // Each good negative means nnscore += less than 5
    }
  }

  return msg_score;
}

double evaluate(PGAContext *ctx, int p, int pop)
{
  double tot_score = 0.0;
  double ynweight,nyweight;
  int i;
  yyscore = ynscore = nyscore = nnscore = 0.0;
  ga_yy=ga_yn=ga_ny=ga_nn=0;

  load_scores_into_lookup(ctx, p, pop);

  // For every message
  for (i=num_tests-1; i>=0; i--)
  {
    tot_score += score_msg(ctx,p,pop,i);
  }

  if (justCount) {
    dump(stdout);
    exit (0);
  }

#ifndef USE_LOG_SCORE_EVALUATION

  // just count how far they were from the threshold, in each case
  ynweight = (ga_yn * threshold) - ynscore;
  nyweight = nyscore - (ga_ny * threshold);
  
  return  ynweight +            /* all FNs' points from threshold */
	  nyweight*nybias;      /* all FPs' points from threshold */

#else
  // Craig's: use log(score).
  //
  // off for now, let's see how the more aggressive FP-reducing algo
  // above works
  //
  if(nyscore>3) nyweight = log(nyscore); else nyweight = 0;
  if(ynscore>3) ynweight = log(ynscore); else ynweight = 0;

  return  /*min false-neg*/(double)ga_yn +
	  /*weighted min false-pos*/((double)ga_ny)*nybias +
	  /*min score(false-pos)*/nyweight*nybias +
	  /*max score(false-neg)*/-ynweight;
#endif
}

/*
 * This mutation function tosses a weighted coin for each allele.  If the allele is to be mutated,
 * then the way it's mutated is to regress it toward the mean of the population for that allele,
 * then add a little gaussian noise.
 *
 * Aug 21 2002 jm: we now use ranges and allow PGA to take care of it, if USE_SCORE_RANGES
 * is defined.
 */
#ifndef USE_SCORE_RANGES
int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         count=0;
    int i,j;

    for (i=0; i<num_scores; i++)
    {
      if(is_mutatable[i] && PGARandomFlip(ctx, mr))
      {
	double gene_sum=0.0;
	// Find the mean
	for(j=0; j<pop_size; j++) { if(p!=j) gene_sum += PGAGetRealAllele(ctx, j, pop, i); }
	gene_sum /= (double)(pop_size-1);
	// Regress towards it...
	gene_sum = (1.0-regression_coefficient)*gene_sum+regression_coefficient*PGAGetRealAllele(ctx, p, pop, i);
	// Set this gene in this allele to be the average, plus some gaussian noise
	if(gene_sum > SCORE_CAP) gene_sum = SCORE_CAP; else if(gene_sum < NEG_SCORE_CAP) gene_sum = NEG_SCORE_CAP;
	PGASetRealAllele(ctx, p, pop, i, PGARandomGaussian(ctx, gene_sum, mutation_noise));
	count++;
      }
    }
    return count;
}
#endif


void dump(FILE *fp)
{
   fprintf (fp,"\n# SUMMARY for threshold %3.1f:\n", threshold);
   fprintf (fp,"# Correctly non-spam: %6d  %4.2f%%  (%4.2f%% of non-spam corpus)\n", ga_nn,
       (ga_nn / (float) num_tests) * 100.0,
       (ga_nn / (float) num_nonspam) * 100.0);
   fprintf (fp,"# Correctly spam:     %6d  %4.2f%%  (%4.2f%% of spam corpus)\n", ga_yy,
       (ga_yy / (float) num_tests) * 100.0,
       (ga_yy / (float) num_spam) * 100.0);
   fprintf (fp,"# False positives:    %6d  %4.2f%%  (%4.2f%% of nonspam, %6.0f weighted)\n", ga_ny,
       (ga_ny / (float) num_tests) * 100.0,
       (ga_ny / (float) num_nonspam) * 100.0,
       nyscore*nybias);
   fprintf (fp,"# False negatives:    %6d  %4.2f%%  (%4.2f%% of spam, %6.0f weighted)\n", ga_yn,
       (ga_yn / (float) num_tests) * 100.0,
       (ga_yn / (float) num_spam) * 100.0,
       ynscore);

   fprintf (fp,"# Average score for spam:  %3.1f    nonspam: %3.1f\n",(ynscore+yyscore)/((double)(ga_yn+ga_yy)),(nyscore+nnscore)/((double)(ga_nn+ga_ny)));
   fprintf (fp,"# Average for false-pos:   %3.1f  false-neg: %3.1f\n",(nyscore/(double)ga_ny),(ynscore/(double)ga_yn));

   fprintf (fp,"# TOTAL:              %6d  %3.2f%%\n\n", num_tests, 100.0);
}

/*****************************************************************************
 * WriteString sends a visual representation of the chromosome out to fp     *
 *****************************************************************************/
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop)
{
  int i;

#ifdef USE_MPI
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);

  if(0 == rank)
  {
#endif
    evaluate(ctx,p,pop);
    dump(fp);
    for(i=0; i<num_scores; i++)
    {
      fprintf(fp,"score %-30s %2.3f\n",score_names[i],PGAGetRealAllele(ctx, p, pop, i));
    }
    fprintf ( fp,"\n" );
#ifdef USE_MPI
  }
#endif
}

void showSummary(PGAContext *ctx)
{
#ifdef USE_MPI
  int rank;

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);

  if(0 == rank)
  {
#endif
    if(0 == PGAGetGAIterValue(ctx) % 300)
    {
      int genome = PGAGetBestIndex(ctx,PGA_OLDPOP);
      FILE *scores_file = NULL;
      PGAGetEvaluation(ctx, genome, PGA_OLDPOP);
      scores_file = fopen("craig-evolve.scores","w");
      WriteString(ctx, scores_file, genome, PGA_OLDPOP);
      fclose(scores_file);
      dump(stdout);
    }
    else if(0 == PGAGetGAIterValue(ctx) % 5)
    {
      printf("%d",(PGAGetGAIterValue(ctx)/5)%10);
    }
#ifdef USE_MPI
  }
#endif
}
