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
#define USE_LOG_SCORE_EVALUATION


double       evaluate(PGAContext *, int, int);
int          myMutation(PGAContext *, int, int, double);
void         CreateString     (PGAContext *, int, int, int);
void         Crossover        (PGAContext *, int, int, int, int, int, int);
void         CopyString       (PGAContext *, int, int, int, int);
int          DuplicateString  (PGAContext *, int, int, int, int);
MPI_Datatype BuildDT          (PGAContext *, int, int);

void dump(FILE *);
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop);
void showSummary(PGAContext *ctx);

float threshold = 5.0;
float nybias = 5.0;

const double mutation_rate = 0.01;
const double mutation_noise = 0.5;

const float SCORE_CAP = 3.0;

const double crossover_rate = 0.65;

int pop_size = 50;
int replace_num = 20;

const int maxiter = 50000;

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
    nybias = nybias*((float)num_spam)/((float)num_nonspam);

#ifdef USE_MPI
  }

  MPI_Bcast(num_tests_hit, num_tests, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(&nybias, 1, MPI_FLOAT, 0, MPI_COMM_WORLD);
  MPI_Bcast(is_spam, num_tests, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(tests_hit, num_tests*max_hits_per_msg, MPI_SHORT, 0, MPI_COMM_WORLD);
  MPI_Bcast(&num_scores, 1, MPI_INT, 0, MPI_COMM_WORLD);
  MPI_Bcast(is_mutatable, num_scores, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(range_lo, num_scores, MPI_FLOAT, 0, MPI_COMM_WORLD);
  MPI_Bcast(range_hi, num_scores, MPI_FLOAT, 0, MPI_COMM_WORLD);
  MPI_Bcast(bestscores, num_scores, MPI_FLOAT, 0, MPI_COMM_WORLD);
  MPI_Bcast(scores, num_scores, MPI_FLOAT, 0, MPI_COMM_WORLD);
#endif
}

int main(int argc, char **argv) {
    PGAContext *ctx;
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
           threshold = (float) atof(optarg);
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
     PGASetUserFunction(ctx, PGA_USERFUNCTION_CREATESTRING, (void *)CreateString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER,     (void *)Crossover);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING,   (void *)WriteString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_COPYSTRING,    (void *)CopyString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_DUPLICATE,     (void *)DuplicateString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_BUILDDATATYPE, (void *)BuildDT);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);

     /* use a tiny population: we just want to get into the evaluate function */
     if (justCount) {
       pop_size = 2;
       replace_num = 1;
     }

     PGASetPopSize(ctx, pop_size);

     PGASetNumReplaceValue(ctx, replace_num);

     //PGASetMutationOrCrossoverFlag(ctx, PGA_TRUE);

     PGASetMutationBoundedFlag(ctx, PGA_FALSE);

     //PGASetCrossoverType(ctx, PGA_CROSSOVER_ONEPT);
     PGASetCrossoverProb(ctx, crossover_rate);

     if (justCount) {           // don't allow any mutation or crossover
       PGASetMutationType(ctx, PGA_MUTATION_CONSTANT);
       PGASetCrossoverProb(ctx, 0.0);
     }

     PGASetPrintFrequencyValue(ctx,300);
     PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE);

     PGASetStoppingRuleType(ctx, PGA_STOP_NOCHANGE);
     PGASetMaxNoChangeValue(ctx, 300);
     PGASetMaxGAIterValue(ctx, maxiter);

     PGASetUp(ctx);

     PGARun(ctx, evaluate);

     PGADestroy(ctx);

#ifdef USE_MPI
     MPI_Finalize();
#endif

     return(0);
}

int ga_yy,ga_yn,ga_ny,ga_nn;
float ynscore,nyscore,yyscore,nnscore;

#ifdef __ALTIVEC__
/** This algorithm is going to do vector evaluation of fitness -- basically
  * we're going to parallelize the message scoring, so we determine the total scores for
  * multiple messages at the same time, using altivec operations.  In theory, this
  * should yield a nice speedup.  Also, altivec only does float ops, not double,
  * so that'll probably speed things up as well.  Hopefully the double<->float conversions
  * won't eat up the speed difference.  Unfortunately, PGA only has double evolution function
  * and not float.  Perhaps we can play with the binary genome stuff later -- would probably
  * give even more of a speedup, and besides, it's more of a "real" GA that way...
  */
  
#define max(x,y) (x>y?x:y)

double evaluate(PGAContext *ctx, int p, int pop)
{
   float *myscores;
   float ynweight,nyweight;
   vector float x,y;
   float xfer[4];
   int h,i,j,k,num_hit;
   vector float zero = (vector float)(0);
   yyscore = ynscore = nyscore = nnscore = 0.0;
   ga_yy = ga_yn = ga_ny = ga_nn = 0;

   myscores = (float *)PGAGetIndividual(ctx, p, pop)->chrom;
   // Process messages 4 at a time
   for(i=0; i<num_tests/4-1; i++)
   {
      k = i*4;
      y = zero;
      num_hit = 0;
      for(j=0;j<4;j++)
      {
         if(num_tests_hit[k+j] > num_hit)
            num_hit = num_tests_hit[k+j];
      }
      for(j=0; j<num_hit; j++)
      {
         // Get the score for each of the 4 messages
         for(h=0; h<4; h++)
         {
            if(num_tests_hit[k+h] >= j)
               xfer[h] = myscores[tests_hit[k+h][j]];
            else
               xfer[h] = 0.0f;
         }
         x = vec_ldl(0,xfer);
         // Do the addition
         y = vec_add(x,y);
      }
      // Now y holds the total scores for these 4 messages
      vec_st(y,0,xfer);
      for(j=0; j<4; j++)
      {
         if(is_spam[k+j])
         {
            if(xfer[j] >= threshold)
            {
               // Good positive
               ga_yy++;
               yyscore += xfer[j];
            }
            else
            {
               // False negative
               ga_yn++;
               ynscore += xfer[j];
            }
         }
         else
         {
            if(xfer[j] >= threshold)
            {
               // False positive
               ga_ny++;
               nyscore += xfer[j];
            }
            else
            {
               // Good negative
               ga_nn++;
               nnscore += xfer[j];
            }
         }
      }
   }
   if(justCount)
   {
      dump(stdout);
      exit(0);
   }

#ifndef USE_LOG_SCORE_EVALUTION

   // just count ho far they were from the threshold, in each case
   ynweight = ((float)ga_yn * threshold) - ynscore;
   nyweight = nyscore - ((float)ga_ny * threshold);
   
   return ynweight + nyweight*nybias;

#else

   if(nyscore>3) nyweight = log(nyscore); else nyweight = 0;
   if(ynscore>3) ynweight = log(ynscore); else ynweight = 0;

   return (double)ga_yn + nybias*((double)ga_ny + nyweight) + -ynweight;
#endif USE_LOG_SCORE_EVALUATION
}

#else

float score_msg(float *myscores, int i);

double evaluate(PGAContext *ctx, int p, int pop)
{
  float *myscores;
  float ynweight,nyweight;
  int i;
  yyscore = ynscore = nyscore = nnscore = 0.0;
  ga_yy=ga_yn=ga_ny=ga_nn=0;

  myscores = (float *)PGAGetIndividual(ctx, p, pop)->chrom;
  // For every message
  for (i=num_tests-1; i>=0; i--)
  {
    score_msg(myscores,i);
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
#endif //USE_LOG_SCORE_EVALUATION
}

float score_msg(float *myscores, int i)
{
  float msg_score = 0.0;
  int j;

  // For every test the message hit on
  for(j=num_tests_hit[i]-1; j>=0; j--)
  {
    // Up the message score by the allele for this test in the genome
    msg_score += myscores[tests_hit[i][j]];
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
#endif //__ALTIVEC__

/*
 * Mutate by adding a little gaussian noise (while staying in bounds)
 */
int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         count=0;
    int i;
    float *myscores;
    
    myscores = (float *)PGAGetIndividual(ctx, p, pop)->chrom;

    for (i=0; i<num_scores; i++)
    {
      if(is_mutatable[i] && PGARandomFlip(ctx, mr))
      {
         if(myscores[i] > SCORE_CAP) myscores[i] = SCORE_CAP;
         else if(myscores[i] < (-SCORE_CAP*2.0)) myscores[i] = -SCORE_CAP*2.0;
         myscores[i] += PGARandomGaussian(ctx, myscores[i], mutation_noise);
         count++;
      }
    }
    return count;
}

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
  float *myscores;

#ifdef USE_MPI
  int rank;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);

  if(0 == rank)
  {
#endif
    evaluate(ctx,p,pop);
    dump(fp);
    myscores = (float *)PGAGetIndividual(ctx, p, pop)->chrom;
    for(i=0; i<num_scores; i++)
    {
      fprintf(fp,"score %-30s %2.3f\n",score_names[i],myscores[i]);
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

/*****************************************************************************
 * CreateString allocates and initializes a chromosome.  If InitFlag is      *
 * set to true, then it will randomly initialize the chromosome; otherwise,  *
 * it sets each double to 0.0 and each int to 0.                             *
 *****************************************************************************/
void CreateString(PGAContext *ctx, int p, int pop, int InitFlag) {
    int i;
    float *myscore;
    PGAIndividual *new;

    new = PGAGetIndividual(ctx, p, pop);
    if (!(new->chrom = malloc(sizeof(float)*num_scores))) {
        fprintf(stderr, "No room for new->chrom");
        exit(1);
    }
    myscore = (float *)new->chrom;
    if (InitFlag) {
        for(i=0; i<num_scores; i++)
        {
           myscore[i] = bestscores[i];
        }
    } else {
        for(i=0; i<num_scores; i++)
        {
           myscore[i] = 0.0;
        }
    }
}


/*****************************************************************************
 * Crossover implements uniform crossover on the chromosome.                 *
 *****************************************************************************/
void Crossover(PGAContext *ctx, int p1, int p2, int pop1, int t1, int t2,
               int pop2) {
    int i;
    float *parent1, *parent2, *child1, *child2;
    double pu;

    parent1 = (float *)PGAGetIndividual(ctx, p1, pop1)->chrom;
    parent2 = (float *)PGAGetIndividual(ctx, p2, pop1)->chrom;
    child1  = (float *)PGAGetIndividual(ctx, t1, pop2)->chrom;
    child2  = (float *)PGAGetIndividual(ctx, t2, pop2)->chrom;

    pu = PGAGetUniformCrossoverProb(ctx);

    for (i = 0; i < num_scores; i++)
    {
		if (PGARandomFlip(ctx, pu)) {
			child1[i] = parent1[i];
			child2[i] = parent2[i];
		} else {
			child1[i] = parent2[i];
			child2[i] = parent1[i];
		}
    }
}


/*****************************************************************************
 * CopyString makes a copy of the chromosome at (p1, pop1) and puts it at    *
 * (p2, pop2).                                                               *
 *****************************************************************************/
void CopyString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    void *d, *s;

     s = PGAGetIndividual(ctx, p1, pop1)->chrom;
     d = PGAGetIndividual(ctx, p2, pop2)->chrom;
     memcpy(d, s, sizeof(float)*num_scores);
}


/*****************************************************************************
 * DuplicateString compares two chromosomes and returns 1 if they are the    *
 * same and 0 if they are different.                                         *
 *****************************************************************************/
int DuplicateString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    void *a, *b;

     a = PGAGetIndividual(ctx, p1, pop1)->chrom;
     b = PGAGetIndividual(ctx, p2, pop2)->chrom;
     return (!memcmp(a, b, sizeof(float)*num_scores));
}


/*****************************************************************************
 * BuildDatattype builds an MPI datatype for sending strings to other        *
 * processors.  Consult your favorite MPI manual for more information.       *
 *****************************************************************************/
MPI_Datatype BuildDT(PGAContext *ctx, int p, int pop) {
  int             counts[3];
  MPI_Aint        displs[3];
  MPI_Datatype    types[3];
  MPI_Datatype    DT_PGAIndividual;
  PGAIndividual  *P;

  P = PGAGetIndividual(ctx, p, pop);

  /*  Build the MPI datatype.  Every user defined function needs these.
   *  The first two calls are stuff that is internal to PGAPack, but 
   *  the user still must include it.  See pgapack.h for details one the
   *  fields (under PGAIndividual)
   */
  MPI_Address(&P->evalfunc, &displs[0]);
  counts[0] = 2;
  types[0]  = MPI_DOUBLE;

  /*  Next, we have an integer, evaluptodate.  */  
  MPI_Address(&P->evaluptodate, &displs[1]);
  counts[1] = 1;
  types[1]  = MPI_INT;

  /*  Finally, we have the actual user-defined string.  */
  MPI_Address(P->chrom, &displs[2]);
  counts[2] = num_scores;
  types[2]  = MPI_FLOAT;

  MPI_Type_struct(3, counts, displs, types, &DT_PGAIndividual);
  MPI_Type_commit(&DT_PGAIndividual);
  return(DT_PGAIndividual);
}
