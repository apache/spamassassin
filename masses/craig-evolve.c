/* @COPYRIGHT */
/*
 *  This program uses PGAPack to do its GA stuff.
 *  ftp://ftp.mcs.anl.gov/pub/pgapack/pgapack.tar.Z
 *  I used this one instead of galib because it uses MPI
 *  to spread load around.  It also seems like the API is a little
 *  cleaner.
 */

#include "pgapack.h"

#include <unistd.h>
#include <math.h>
#include "tmp/scores.h"
#include "tmp/tests.h"


/* Craig's log(score) evaluator, not as aggressive against FPs I think.
 */
/* #define USE_LOG_SCORE_EVALUATION */

/* Use score ranges derived from hit-frequencies S/O ratio,
 * and numbers of mails hit.
 */
#define USE_SCORE_RANGES

#define USE_VARIABLE_MUTATIONS

/* Lamarkian evolution? */
#define LAMARK

double evaluate(PGAContext *, int, int);
int    GetIntegerParameter(char *query);
void dump(FILE *);
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop);
void showSummary(PGAContext *ctx);

#if defined(USE_VARIABLE_MUTATIONS) || (! defined(USE_SCORE_RANGES))
int    myMutation(PGAContext *, int, int, double);
# ifdef LAMARK
int adapt(PGAContext *, int, int, int, int,int);
# endif
#endif

#ifdef USE_VARIABLE_MUTATIONS
void         CreateString     (PGAContext *, int, int, int);
void         Crossover        (PGAContext *, int, int, int, int, int, int);
void         CopyString       (PGAContext *, int, int, int, int);
int          DuplicateString  (PGAContext *, int, int, int, int);
MPI_Datatype BuildDT          (PGAContext *, int, int);
#endif

void dump(FILE *);
void WriteString(PGAContext *ctx, FILE *fp, int p, int pop);
void showSummary(PGAContext *ctx);

double evaluate_inner();



double threshold = 5.0;
double nybias = 10.0;
/* const int exhaustive_eval = 1; */

int no_change_val = 300;

#ifdef USE_VARIABLE_MUTATIONS
double mutation_rate = 0.03;
double base_mutation_rate = 0.03;
#ifdef LAMARK
int adapt_yn = 0;
int adapt_ny = 0;
#endif
double mutation_rate_modifier = 0.85;
int num_better_same = 0;
int num_worse = 0;
#else
const double mutation_rate = 0.03;
#endif

const double mutation_noise = 0.5;
#ifdef USE_VARIABLE_MUTATIONS
const double min_mutation_noise = 0.1;
#endif
const double regression_coefficient = 0.75;
#ifndef USE_SCORE_RANGES
const double SCORE_CAP = 4.0;
const double NEG_SCORE_CAP = -9.0;
#endif

#ifdef USE_VARIABLE_MUTATIONS
const double crossover_rate = 0.5;
#else
const double crossover_rate = 0.65;
#endif

int pop_size = 50;
int replace_num = 33;

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
     "  -t threshold = threshold for spam/nonspam decision (5 default)\n"
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
#ifdef USE_VARIABLE_MUTATIONS
    mutation_rate_modifier = (double)pow(mutation_rate_modifier,
					(double)1/num_mutable);
#endif

#ifdef USE_MPI
  }

  MPI_Bcast(num_tests_hit, num_nondup, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(&nybias, 1, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(is_spam, num_nondup, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(tests_hit, num_nondup*max_hits_per_msg, MPI_SHORT, 0,
	    MPI_COMM_WORLD);
#ifdef USE_VARIABLE_MUTATIONS
  MPI_Bcast(&mutation_rate_modifier, 1, MPI_DOUBLE, 0, MPI_COMM_WORLD);
#endif
  MPI_Bcast(is_mutatable, num_scores, MPI_CHAR, 0, MPI_COMM_WORLD);
  MPI_Bcast(range_lo, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(range_hi, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(bestscores, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
  MPI_Bcast(scores, num_scores, MPI_DOUBLE, 0, MPI_COMM_WORLD);
#endif
}

/* this is about 35% faster than calling PGAGetRealAllele() directly inside
 * score_msg(), in my tests. */
void
load_scores_into_lookup(PGAContext *ctx, int p, int pop)
{
  int i;
  for (i = 0; i < num_mutable; i++) {
    lookup[i] = PGAGetRealAllele(ctx, p, pop, i); 
#ifdef LAMARK
    yn_hit[i] = ny_hit[i] = 0;
#endif
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

     PGASetUserFunction(ctx, PGA_USERFUNCTION_PRINTSTRING,
			(void *)WriteString);
     PGASetUserFunction(ctx, PGA_USERFUNCTION_ENDOFGEN, (void *)showSummary);

     /* use a tiny population - just want to get into the evaluate function */
     if (justCount) {
       pop_size = 2;
       replace_num = 1;
     }

     PGASetPopSize(ctx, pop_size);

     PGASetRealInitRange (ctx, range_lo, range_hi);

     PGASetMutationBoundedFlag(ctx, PGA_FALSE);

     PGASetNumReplaceValue(ctx, replace_num);

     /* Defaults to this - Allen */
     /* PGASetMutationOrCrossoverFlag(ctx, PGA_TRUE); */

     if (justCount) {           /* don't allow any mutation or crossover */
       PGASetMutationType(ctx, PGA_MUTATION_CONSTANT);
       PGASetRealInitRange (ctx, bestscores, bestscores);
       PGASetCrossoverProb(ctx, 0.0);
       for(i=0; i<num_scores; i++) {
	 for(p=0; p<pop_size; p++) {
	   /* just counting?  score[i] = defaultscore[i] in that case */
           PGASetRealAllele(ctx, p, PGA_NEWPOP, i, bestscores[i]);
	 }
       }
     } else {
#if (! defined(USE_SCORE_RANGES)) || defined(USE_VARIABLE_MUTATIONS)
       PGASetUserFunction(ctx, PGA_USERFUNCTION_MUTATION, (void *)myMutation);
#else
     PGASetMutationType(ctx, PGA_MUTATION_RANGE);
#endif

       /* PGASetCrossoverType(ctx, PGA_CROSSOVER_ONEPT); */
     PGASetCrossoverProb(ctx, crossover_rate);

#ifdef USE_VARIABLE_MUTATIONS
       mutation_rate = 0.15/sqrt(num_mutable);
       base_mutation_rate = mutation_rate;
       PGASetMutationProb(ctx, mutation_rate);
       PGASetUserFunction(ctx, PGA_USERFUNCTION_CROSSOVER,
			  (void *)Crossover);
       PGASetUserFunction(ctx, PGA_USERFUNCTION_CREATESTRING,
			  (void *)CreateString);
       PGASetUserFunction(ctx, PGA_USERFUNCTION_COPYSTRING,
			  (void *)CopyString);
       PGASetUserFunction(ctx, PGA_USERFUNCTION_DUPLICATE,
			  (void *)DuplicateString);
       PGASetUserFunction(ctx, PGA_USERFUNCTION_BUILDDATATYPE,
			  (void *)BuildDT);
#endif
     }

     PGASetPrintFrequencyValue(ctx,300);
     PGASetPrintOptions(ctx, PGA_REPORT_AVERAGE);

     PGASetStoppingRuleType(ctx, PGA_STOP_NOCHANGE);
     PGASetMaxNoChangeValue(ctx, no_change_val);
     PGASetMaxGAIterValue(ctx, maxiter);

     PGASetUp(ctx);

#ifndef USE_VARIABLE_MUTATIONS
     if (! justCount) {
       /* Now initialize the scores */
       for(i=0; i<num_scores; i++) {
	 for(p=0; p<pop_size; p++) {

#ifndef USE_SCORE_RANGES
	 if (is_mutatable[i]) {
            if(bestscores[i] > SCORE_CAP) bestscores[i] = SCORE_CAP;
	     else if(bestscores[i] < NEG_SCORE_CAP) bestscores[i] =
						      NEG_SCORE_CAP;
	 }
#endif
	 PGASetRealAllele(ctx, p, PGA_NEWPOP, i, bestscores[i]);
       }
     }
     }
#endif /* ! USE_VARIABLE_MUTATIONS */

     PGARun(ctx, evaluate);

     PGADestroy(ctx);

#ifdef USE_MPI
     MPI_Finalize();
#endif

     return(0);
}

int ga_yy,ga_yn,ga_ny,ga_nn;
#ifdef USE_VARIABLE_MUTATIONS
int num_mutated = 0;
int var_mutated = 0;
int iters_same_passed = 0;
#ifdef LAMARK
int weight_balance;
int adapt_times = 0;
int adapt_crossover = 0;
int adapt_repeat = 0;
int adapt_overshot = 0;
int adapt_fp_add = 0;
int adapt_fn_add = 0;
#endif
#endif
double ynscore,nyscore,yyscore,nnscore;

double score_msg(PGAContext *ctx, int p, int pop, int i)
{
  double msg_score = 0.0;
  int j;

  /* For every test the message hit on */
  for(j=num_tests_hit[i]-1; j>=0; j--)
  {
    /* Up the message score by the allele for this test in the genome
     * msg_score += PGAGetRealAllele(ctx, p, pop, tests_hit[i][j]); */
    msg_score += lookup[tests_hit[i][j]];
  }

  msg_score += scores[i];	/* base from non-mutable */

  /* Ok, now we know the score for this message.
   * Let's see how this genome did... */
       
  if(is_spam[i])
  {
    if(msg_score >= threshold)
    {
      /* Good positive */
      ga_yy += tests_count[i];
      yyscore += msg_score*tests_count[i];
      /* Each true positive means yyscore += at least 5 */
    }
    else
    {
      /* False negative */
      ga_yn += tests_count[i];
      ynscore += msg_score*tests_count[i];
      /* Each false negative means that ynscore += less than 5 */
#ifdef LAMARK
      for(j=num_tests_hit[i]-1; j>=0; j--)
	yn_hit[tests_hit[i][j]] = 1;
#endif
    }
  }
  else
  {
    if(msg_score >= threshold)
    {
      /* False positive */
      ga_ny += tests_count[i];
      nyscore += msg_score*tests_count[i];
      /* Each false positive means nyscore += more than 5 */
#ifdef LAMARK
      for(j=num_tests_hit[i]-1; j>=0; j--)
	ny_hit[tests_hit[i][j]] = 1;
#endif
    }
    else
    {
      /* Good negative */
      ga_nn += tests_count[i];
      nnscore += msg_score*tests_count[i];
      /* Each good negative means nnscore += less than 5 */
    }
  }

  return msg_score*tests_count[i];
}

double evaluate(PGAContext *ctx, int p, int pop)
{
  double tot_score = 0.0;
  int i;

  yyscore = ynscore = nyscore = nnscore = 0.0;
  ga_yy=ga_yn=ga_ny=ga_nn=0;

  load_scores_into_lookup(ctx, p, pop);

  /* For every message */
  for (i=num_nondup-1; i>=0; i--)
  {
    tot_score += score_msg(ctx,p,pop,i);
  }

  if (justCount) {
    dump(stdout);
    exit (0);
  }

  return evaluate_inner();
}

/* So can figure out how would evaluate without above - Allen */

double evaluate_inner() {
  double ynweight,nyweight;
#if defined(USE_LOG_SCORE_EVALUATION) && defined(LAMARK)
  double yn_balance, ny_balance;
#endif

#ifndef USE_LOG_SCORE_EVALUATION

  /* just count how far they were from the threshold, in each case */
  ynweight = (ga_yn * threshold) - ynscore;
  nyweight = nyscore - (ga_ny * threshold);
  
#ifdef LAMARK
  if (ynweight > (nyweight*nybias))
    weight_balance = -1;
  else if (ynweight < (nyweight*nybias))
    weight_balance = 1;
  else
    weight_balance = 0;
#endif

  return  ynweight +            /* all FNs' points from threshold */
	  nyweight*nybias;      /* all FPs' points from threshold */

#else
  /* Craig's: use log(score).
   *
   * off for now, let's see how the more aggressive FP-reducing algo
   * above works
   */
  if(nyscore>3) nyweight = log(nyscore); else nyweight = 0;
  if(ynscore>3) ynweight = log(ynscore); else ynweight = 0;

#ifdef LAMARK
  yn_balance = (double)ga_yn + ynweight;
  ny_balance = ((double)ga_ny + nyweight)*nybias;

  if (yn_balance > ny_balance)
    weight_balance = -1;
  else if (yn_balance < ny_balance)
    weight_balance = 1;
  else
    weight_balance = 0;
#endif

  return  /*min false-neg*/(double)ga_yn +
	  /*weighted min false-pos*/((double)ga_ny)*nybias +
	  /*min score(false-pos)*/nyweight*nybias +
	  /*max score(false-neg)*/-ynweight;
#endif
}

#ifdef LAMARK
int adapt(PGAContext *ctx, int p, int pop, int done_eval, int threshold,
	  int repeat) {
  double *myscores;
  int i;
  int changed = 0;
  double tmp,old_evaluation,new_evaluation;

  if (justCount) {
    return 0;
  }

  adapt_times++;

  if (done_eval && PGAGetEvaluationUpToDateFlag(ctx, p, pop))
    old_evaluation = PGAGetEvaluation(ctx, p, pop);
  else {
    old_evaluation = evaluate(ctx, p, pop);
    PGASetEvaluation(ctx, p, pop, old_evaluation);
    PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);
  }

  if ((double)ga_yn > ((double)ga_ny*nybias))
    weight_balance--;
  else if ((double)ga_yn < ((double)ga_ny*nybias))
    weight_balance++;

  if ((weight_balance < (threshold-1)) &&
      (weight_balance > -threshold))
    return 0;

  myscores = PGAGetIndividual(ctx, p, pop)->chrom;

  if (repeat) {
    for (i = 0; i < num_mutable; i++) {
      if ((yn_hit[i] && (weight_balance < 0)) ||
	  (ny_hit[i] && (weight_balance > 0))) {
	if (((weight_balance < 0) &&
#ifdef USE_SCORE_RANGES
	     (myscores[i] < range_hi[i]) &&
#endif
	     (myscores[i] < -(double)0.01)) ||
	    ((weight_balance > 0) &&
#ifdef USE_SCORE_RANGES
	     (myscores[i] > range_lo[i]) &&
#endif
	     (myscores[i] > (double)0.01))) {
          tmp_scores[i][0] = (double)0.001*rint(myscores[i]); /* reducing */
#ifdef USE_SCORE_RANGES
	  if (((myscores[i] < -(double)0.01) && ((myscores[i] - tmp_scores[i][0]) > range_hi[i])) ||
	      ((myscores[i] > (double)0.01) && ((myscores[i] - tmp_scores[i][0]) < range_lo[i]))) {
	    tmp_scores[i][0] = 0;
	  }
#endif
	  if (tmp_scores[i][0]) {
	    changed = 1;
	    lookup[i] = 0;
	  }
	} else
	  tmp_scores[i][0] = 0;
      } else
	tmp_scores[i][0] = 0;
    }

    if (! changed)		/* if can't reduce, don't do anything - safe */
      return 0;

    /* For every message */
    for (i=num_nondup-1; i>=0; i--) {
      tmp_total[i] = scores[i];
      scores[i] =
	score_msg(ctx,p,pop,i)/tests_count[i]; /* score sans ones modifying */
    }

    for (i = 0; i < num_mutable; i++) {
      if (tmp_scores[i][0]) {
	lookup[i] = myscores[i];
	tmp_scores[i][1] = 1;
	if (weight_balance < 0) {
	  yn_hit[i] = 1;
	  ny_hit[i] = 0;
	} else {
	  ny_hit[i] = 1;
	  yn_hit[i] = 0;
	}
      } else {
	lookup[i] = 0;
	tmp_scores[i][1] = 0;
	yn_hit[i] = ny_hit[i] = 0;
      }
    }

    while (1) {
      changed = 0;
      for (i = 0; i < num_mutable; i++) {
	if (((tmp_scores[i][0] < 0) && yn_hit[i] && /* going up */
#ifdef USE_SCORE_RANGES
             ((lookup[i] - tmp_scores[i][0]) < range_hi[i]) &&
#endif
             (weight_balance < 0) && (lookup[i] < -(double)0.01)) ||
	    ((tmp_scores[i][0] > 0) && ny_hit[i] && /* going down */
#ifdef USE_SCORE_RANGES
             ((lookup[i] - tmp_scores[i][0]) > range_lo[i]) &&
#endif
	     (weight_balance > 0) &&
             (lookup[i] > (double)0.01))) {
	  lookup[i] -= tmp_scores[i][0];
	  changed = 1;
	} else
	  tmp_scores[i][0] = 0;
	yn_hit[i] = ny_hit[i] = 0;
      }

      if (changed) {
	if (weight_balance > 0)
	  adapt_ny++;
	else
	  adapt_yn++;
	adapt_repeat++;
      } else
	break;

      yyscore = ynscore = nyscore = nnscore = 0.0;
      ga_yy=ga_yn=ga_ny=ga_nn=0;

      for (i=num_nondup-1; i>=0; i--)
	(void)score_msg(ctx,p,pop,i);

      new_evaluation = evaluate_inner();

      if (new_evaluation > old_evaluation) {
	for (i = 0; i < num_mutable; i++) {
	  if (tmp_scores[i][0])
	    lookup[i] += tmp_scores[i][0];
	}
	new_evaluation = old_evaluation;
	adapt_overshot++;
	break;
      } else
	old_evaluation = new_evaluation;

      if ((double)ga_yn > ((double)ga_ny*nybias))
	weight_balance--;
      else if ((double)ga_yn < ((double)ga_ny*nybias))
	weight_balance++;
      
      if ((weight_balance < (threshold-1)) &&
	  (weight_balance > -threshold))
	break;
    }
    for (i=num_nondup-1; i>=0; i--)
      scores[i] = tmp_total[i];

    for (i=0; i < num_mutable; i++) {
      if (tmp_scores[i][1])
	myscores[i] = lookup[i];
    }

    PGASetEvaluation(ctx, p, pop, new_evaluation);
    PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);

    return 1;
  } else {
    for (i = 0; i < num_mutable; i++) {
      if ((yn_hit[i] && (weight_balance < 0)) ||
	  (ny_hit[i] && (weight_balance > 0))) {
        tmp = (double)0.001*rint(myscores[i]);
	if (! tmp) {
	  if (myscores[i] > (double)0.01)
            tmp = (double)0.001;
	  else if (myscores[i] < -(double)0.01)
            tmp = -(double)0.001;
	}
#ifdef USE_SCORE_RANGES
	if (tmp && (((myscores[i] > 0) &&
		     ((myscores[i] - tmp) < range_lo[i])) ||
		    ((myscores[i] < 0) &&
		     ((myscores[i] - tmp) > range_hi[i]))))
	  tmp = 0;
#endif
	if (tmp) {
	  myscores[i] -= tmp;
	  changed = 1;
	}
      }
    }
    
    if (changed) {
      if (weight_balance > 0)
	adapt_ny++;
      else
	adapt_yn++;
      return 1;
    } else
      return 0;
  }
}
#endif

/*
 * This mutation function tosses a weighted coin for each allele.
 * If the allele is to be mutated, then the way it's mutated is to regress it
 * toward the mean of the population for that allele, then add a little
 * gaussian noise.
 *
 * [To the _mean_? Weird... - Allen]
 *
 * Aug 21 2002 jm: we now use ranges and allow PGA to take care of it, if
 * USE_SCORE_RANGES is defined.
 *
 * Modified for variable mutations - 9/26/02 - Allen
 *
 */
#if defined(USE_VARIABLE_MUTATIONS) || (! defined(USE_SCORE_RANGES))
int myMutation(PGAContext *ctx, int p, int pop, double mr) {
    int         count=0;
    int i;
# ifdef USE_VARIABLE_MUTATIONS
    double *myscores;
    double old_evaluation,new_evaluation,min_score,max_score;

    myscores = PGAGetIndividual(ctx, p, pop)->chrom;
    if (PGAGetEvaluationUpToDateFlag(ctx, p, pop))
      old_evaluation = PGAGetEvaluation(ctx, p, pop);
    else {
      old_evaluation = evaluate(ctx, p, pop);
      PGASetEvaluation(ctx, p, pop, old_evaluation);
      PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);
    }

    for (i=0; i<num_mutable; i++) {
      tmp_scores[i][0] = 0;
      if (PGARandomFlip(ctx, mr)) {
#ifdef USE_SCORE_RANGES
	min_score = range_lo[i];
	max_score = range_hi[i];
#else
	min_score = SCORE_CAP;
	max_score = NEG_SCORE_CAP;
#endif
	if (myscores[i] > max_score)
	  myscores[i] = max_score;
	else if (myscores[i] < min_score)
	  myscores[i] = min_score;
	
	tmp_scores[i][1] = (max_score - min_score)/4;

	myscores[i+num_scores] *=
	  pow(2,(PGARandomGaussian(ctx,0,mutation_noise*2)));

	if (myscores[i+num_scores] < min_mutation_noise)
	  myscores[i+num_scores] = min_mutation_noise;
	else if (myscores[i+num_scores] > tmp_scores[i][1])
	  myscores[i+num_scores] = tmp_scores[i][1];

	while (! tmp_scores[i][0]) {
	  tmp_scores[i][0] = PGARandomGaussian(ctx,0,
					       myscores[i+num_scores]);
#ifdef USE_SCORE_RANGES
	  if (((double)(myscores[i] + tmp_scores[i][0]) >= max_score) ||
	      ((double)(myscores[i] + tmp_scores[i][0]) <= min_score)) {
	    if (myscores[i+num_scores] > mutation_noise) {
	      myscores[i+num_scores] =
		(myscores[i+num_scores] + mutation_noise)/2;
	      tmp_scores[i][0] = 0;
	    } else if ((double)(myscores[i] + tmp_scores[i][0]) >= max_score) {
	      tmp_scores[i][0] = max_score - myscores[i] - (double)0.001;
	      break;
	    } else {
	      tmp_scores[i][0] = min_score - myscores[i] + (double)0.001;
	      break;
	    }
	  }
#endif
	}
	myscores[i] += tmp_scores[i][0];
	count++;
      }
    }

    if (count > 0) {
      var_mutated++;
      new_evaluation = evaluate(ctx, p, pop);

      if (new_evaluation > old_evaluation) {
	/* Did previous try go too far away? */
	if (iters_same_passed) { /* in 2nd phase */
	  count = 0;
	  for (i=0; i<num_mutable; i++) {
	    if (tmp_scores[i][0]) {
	      if (myscores[i+num_scores] > mutation_noise) {
		tmp_scores[i][1] = PGARandomGaussian(ctx,0,mutation_noise);
		count++;
	      } else
		tmp_scores[i][1] =
		  PGARandomGaussian(ctx,0,myscores[i+num_scores]);
	      tmp_scores[i][1] = copysign(tmp_scores[i][1],tmp_scores[i][0]);
#ifdef USE_SCORE_RANGES
              if ((double)(myscores[i] + tmp_scores[i][1]
                           - tmp_scores[i][0]) >= range_hi[i]) {
                tmp_scores[i][1] = range_hi[i] - myscores[i] +
                  tmp_scores[i][0] - (double)0.001;
              } else if ((double)(myscores[i] + tmp_scores[i][1]
                                  - tmp_scores[i][0]) <= range_lo[i]) {
                tmp_scores[i][1] = range_lo[i] - myscores[i] +
                  tmp_scores[i][0] + (double)0.001;
              }
#endif
	      myscores[i] += tmp_scores[i][1] - tmp_scores[i][0];
	    }
	  }
	  
	  if (count > 0) {
	    num_mutated++;
	    new_evaluation = evaluate(ctx, p, pop);
	    if (PGAGetNoDuplicatesFlag(ctx) == PGA_FALSE) {
	      /* Hack to avoid redoing evaluation without need - Allen */
	      count = 0;
	      PGASetEvaluation(ctx, p, pop, new_evaluation);
	      PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);
	    }
	    if (new_evaluation <= old_evaluation) {
	      /* Previous try went too far away */
	      if (mr < base_mutation_rate)
		num_better_same++;
	      for (i=0; i<num_mutable; i++) {
		if (tmp_scores[i][0] &&
		    (myscores[i+num_scores] > mutation_noise)
		    && (fabs(tmp_scores[i][1]) < fabs(tmp_scores[i][0])))
		  myscores[i+num_scores] =
		    (myscores[i+num_scores] + mutation_noise)/2;
	      }
	    } else {
#ifdef LAMARK
	      if (mr < base_mutation_rate) {
		count = adapt(ctx,p,pop,1,1,0);
		if (count) {
		  count = adapt(ctx,p,pop,0,2,1);
		  if (count)
		    new_evaluation = PGAGetEvaluation(ctx, p, pop);
		  else
		    new_evaluation = evaluate(ctx, p, pop);
		  if (new_evaluation > old_evaluation)
		    num_worse++;
		  else
		    num_better_same++; /* only had to adapt once */
		  
		  if (PGAGetNoDuplicatesFlag(ctx) == PGA_FALSE) {
		    /* Hack to avoid redoing evaluation without need - Allen */
		    count = 0;
		    PGASetEvaluation(ctx, p, pop, new_evaluation);
		    PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);
		  }
		} else
		  num_worse++;
	      } else
#endif
		num_worse++;
	    }
	  } else {		/* didn't decrease mutation SD */
#ifdef LAMARK
	    if (mr < base_mutation_rate) {
	      count = adapt(ctx,p,pop,0,1,0);
	      new_evaluation = evaluate(ctx, p, pop);
	    }
#endif
	    if (new_evaluation > old_evaluation) {
#ifdef LAMARK
	      if ((mr < base_mutation_rate) && count) {
		count = adapt(ctx,p,pop,1,2,1);
		if (count) {
		  new_evaluation = PGAGetEvaluation(ctx, p, pop);
		  if (new_evaluation > old_evaluation)
		    num_worse++;
		  else
		    num_better_same++;
		} else
		  num_worse++;
	      } else
#endif
		num_worse++;
	    } else
	      num_better_same++;
	    if (PGAGetNoDuplicatesFlag(ctx) == PGA_FALSE) {
	      /* Hack to avoid redoing evaluation without need - Allen */
	      count = 0;
	      PGASetEvaluation(ctx, p, pop, new_evaluation);
	      PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);
	    }
	  }

	  if ((! count) &&
	      (PGAGetNoDuplicatesFlag(ctx) == PGA_TRUE))
	    count++;

	} else
	  num_worse++;
      } else {
	if (PGAGetNoDuplicatesFlag(ctx) == PGA_FALSE) {
	  /* Hack to avoid redoing evaluation without need - Allen */
	  count = 0;
	  PGASetEvaluation(ctx, p, pop, new_evaluation);
	  PGASetEvaluationUpToDateFlag(ctx, p, pop, PGA_TRUE);
	}
	num_better_same++;
      }
    }
#ifdef LAMARK
    else if (mr < base_mutation_rate) {
      count = adapt(ctx,p,pop,1,2,0);
      if (! count)
	num_better_same++;	/* adapt not working, use mutation */
    }
#endif

# else /* USE_VARIABLE_MUTATIONS */
    int j;

    for (i=0; i<num_mutable; i++)
    {
      if(PGARandomFlip(ctx, mr))
      {
	double gene_sum=0.0;
	/* Find the mean */
	for(j=0; j<pop_size; j++) {
	  if(p!=j)
	    gene_sum += PGAGetRealAllele(ctx, j, pop, i);
	}
	gene_sum /= (double)(pop_size-1);
	/* Regress towards it... */
	gene_sum = (1.0-regression_coefficient)*gene_sum+regression_coefficient*PGAGetRealAllele(ctx, p, pop, i);
	/* Set this gene in this allele to be the average, plus some gaussian noise */
	if(gene_sum > SCORE_CAP)
	  gene_sum = SCORE_CAP;
	else if(gene_sum < NEG_SCORE_CAP)
	  gene_sum = NEG_SCORE_CAP;
	PGASetRealAllele(ctx, p, pop, i,
			 PGARandomGaussian(ctx, gene_sum, mutation_noise));
	count++;
      }
    }
# endif /* !USE_VARIABLE_MUTATIONS */
    return count;
}
#endif /* USE_VARIABLE_MUTATIONS || !USE_SCORE_RANGES */

void dump(FILE *fp)
{
   fprintf (fp,"\n# SUMMARY for threshold %3.1f:\n", threshold);
  fprintf (fp,
	   "# Correctly non-spam: %6d  %4.2f%%  (%4.2f%% of non-spam corpus)\n",
	   ga_nn,
       (ga_nn / (float) num_tests) * 100.0,
       (ga_nn / (float) num_nonspam) * 100.0);
  fprintf (fp,
	   "# Correctly spam:     %6d  %4.2f%%  (%4.2f%% of spam corpus)\n",
	   ga_yy,
       (ga_yy / (float) num_tests) * 100.0,
       (ga_yy / (float) num_spam) * 100.0);
  fprintf (fp,
	   "# False positives:    %6d  %4.2f%%  (%4.2f%% of nonspam, %6.0f weighted)\n",
	   ga_ny,
       (ga_ny / (float) num_tests) * 100.0,
       (ga_ny / (float) num_nonspam) * 100.0,
       nyscore*nybias);
  fprintf (fp,
	   "# False negatives:    %6d  %4.2f%%  (%4.2f%% of spam, %6.0f weighted)\n",
	   ga_yn,
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
      fprintf(fp,"score %-30s %2.3f\n",
	      score_names[i],PGAGetRealAllele(ctx, p, pop, i));
    }
    fprintf ( fp,"\n" );
#ifdef USE_MPI
  }
#endif
}

#ifdef USE_VARIABLE_MUTATIONS
double last_best = 0;
#endif

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
      (void)evaluate(ctx, genome, PGA_OLDPOP);
      PGAGetEvaluation(ctx, genome, PGA_OLDPOP);
      scores_file = fopen("craig-evolve.scores","w");
      WriteString(ctx, scores_file, genome, PGA_OLDPOP);
      fclose(scores_file);
#ifdef USE_VARIABLE_MUTATIONS
      if (! justCount) {
	printf("\nPop size, replacement: %d %d\n",
	       pop_size, replace_num);
	printf("\nMutations (rate, good, bad, var, num): %3.7f %d %d %d %d\n",
	       mutation_rate, num_better_same, num_worse, var_mutated,
	       num_mutated);
	var_mutated = 0;
	num_mutated = 0;
	if (! iters_same_passed) {
	  if (! last_best)
	    last_best = ctx->rep.Best;
	  else if ((last_best*0.999) < ctx->rep.Best) /* too slow! */
	    iters_same_passed = 1;
	  else
	    last_best = ctx->rep.Best;
	}
#ifdef LAMARK
	printf("\n");
	printf("Adapt (t, fneg, fneg_add, fpos, fpos_add): %d %d %d %d %d\n",
	       adapt_times,adapt_yn,adapt_fn_add,adapt_ny,adapt_fp_add);
	printf("Adapt (over, cross, repeat): %d %d %d\n",
	       adapt_overshot,adapt_crossover,adapt_repeat);
	adapt_times = adapt_overshot = adapt_crossover = adapt_repeat =
	  adapt_yn = adapt_ny = adapt_fn_add = adapt_fp_add = 0;
#endif
      }
#endif
      dump(stdout);
    }
    else if(0 == PGAGetGAIterValue(ctx) % 5)
    {
      printf("%d",(PGAGetGAIterValue(ctx)/5)%10);
    }

#ifdef USE_VARIABLE_MUTATIONS
    if (! justCount) {
      if ((num_better_same*4) >= num_worse)
	mutation_rate /= mutation_rate_modifier;
      else if ((num_better_same*4) < num_worse) {
	if ((mutation_rate > base_mutation_rate) || iters_same_passed)
	  mutation_rate *= mutation_rate_modifier;
	else if (ctx->ga.ItersOfSame >= (no_change_val/2)) {
	  iters_same_passed = 1;
	  mutation_rate *= mutation_rate_modifier;
	  printf("\nMutation rate %3.7f (ItersOfSame %d)\n",
		 mutation_rate,ctx->ga.ItersOfSame);
	} else
	  return;
      }
      
      if (mutation_rate > mutation_rate_modifier) {
	mutation_rate = mutation_rate_modifier;
	printf("\nMutation rate max: %3.7f\n",mutation_rate);
      } else if (mutation_rate < 0.05/sqrt(num_mutable)) {
	mutation_rate = 0.05/sqrt(num_mutable);
	printf("\nMutation rate min: %3.7f\n",mutation_rate);
      }
      
      PGASetMutationProb(ctx, mutation_rate);
      
      num_better_same = 0;
      num_worse = 0;
    }
#endif

#ifdef USE_MPI
  }
#endif
}

#ifdef USE_VARIABLE_MUTATIONS
/*****************************************************************************
 * CreateString allocates and initializes a chromosome.  If InitFlag is      *
 * set to true, then it will initialize the chromosome using the best known  *
 * values; otherwise, it sets each double to 0.0 and each int to 0.          *
 *****************************************************************************/
void CreateString(PGAContext *ctx, int p, int pop, int InitFlag) {
    int i;
    double *myscore;

    PGAIndividual *new;

    new = PGAGetIndividual(ctx, p, pop);
    if (!(new->chrom = malloc(sizeof(double)*num_scores*2))) {
        fprintf(stderr, "No room for new->chrom");
        exit(1);
    }
    myscore = new->chrom;
    if (InitFlag) {
      for(i=0; i<num_scores; i++)
	myscore[i] = bestscores[i];
      for(i=num_scores; i<num_scores*2; i++)
	myscore[i] = mutation_noise;
    } else {
      for(i=0; i<num_scores*2; i++)
	myscore[i] = 0.0;
    }
}


/*****************************************************************************
 * Crossover implements uniform crossover on the chromosome.                 *
 *****************************************************************************/
void Crossover(PGAContext *ctx, int p1, int p2, int pop1, int t1, int t2,
               int pop2) {
    int i;
    double *parent1, *parent2, *child1, *child2;
    double pu;
#ifdef LAMARK
    double parent1_eval, parent2_eval, child1_eval, child2_eval;
#endif

    parent1 = PGAGetIndividual(ctx, p1, pop1)->chrom;
    parent2 = PGAGetIndividual(ctx, p2, pop1)->chrom;
    child1  = PGAGetIndividual(ctx, t1, pop2)->chrom;
    child2  = PGAGetIndividual(ctx, t2, pop2)->chrom;

    pu = PGAGetUniformCrossoverProb(ctx);

    for (i = 0; i < num_mutable; i++) {
      if (PGARandomFlip(ctx, pu)) {
	child1[i] = parent2[i];
	child2[i] = parent1[i];
	if (num_mutated > 0) {
	  if (fabs(parent1[i+num_scores] - mutation_noise) >
	      fabs(parent1[i+num_scores] - parent2[i+num_scores]))
	    child2[i+num_scores] =
	      (parent1[i+num_scores] + parent2[i+num_scores])/2;
	  else
	    child2[i+num_scores] =
	      (parent1[i+num_scores] + mutation_noise)/2;
	  if (fabs(parent2[i+num_scores] - mutation_noise) >
	      fabs(parent2[i+num_scores] - parent1[i+num_scores]))
	    child1[i+num_scores] =
	      (parent2[i+num_scores] + parent1[i+num_scores])/2;
	  else
	    child1[i+num_scores] =
	      (parent2[i+num_scores] + mutation_noise)/2;
	} else {
	  /* Doing intermediate recombination due to usage
	   * of exponential multiplication in mutation - Allen */
	  child1[i+num_scores] = child2[i+num_scores] =
	    (parent1[i+num_scores] + parent2[i+num_scores])/2;
	}
      } else {
	child1[i] = parent1[i];
	child2[i] = parent2[i];
	if (pu < 0.5) {		/* more grouped */
	  child1[i+num_scores] = parent1[i+num_scores];
	  child2[i+num_scores] = parent2[i+num_scores];
	} else {
	  if (num_mutated > 0) {
	    if (fabs(parent1[i+num_scores] - mutation_noise) >
		fabs(parent1[i+num_scores] - parent2[i+num_scores]))
	      child1[i+num_scores] =
		(parent1[i+num_scores] + parent2[i+num_scores])/2;
	    else
	      child1[i+num_scores] =
		(parent1[i+num_scores] + mutation_noise)/2;
	    if (fabs(parent2[i+num_scores] - mutation_noise) >
		fabs(parent2[i+num_scores] - parent1[i+num_scores]))
	      child2[i+num_scores] =
		(parent2[i+num_scores] + parent1[i+num_scores])/2;
	    else
	      child2[i+num_scores] =
		(parent2[i+num_scores] + mutation_noise)/2;
	  } else {
	    /* Doing intermediate recombination due to usage
	     * of exponential multiplication in mutation - Allen */
	    child1[i+num_scores] = child2[i+num_scores] =
	      (parent1[i+num_scores] + parent2[i+num_scores])/2;
	  }
	}
      }
    }
    for (i = num_mutable; i < num_scores; i++) {
      child1[i] = parent1[i];
      child2[i] = parent2[i];
      child1[i+num_scores] = parent1[i+num_scores];
      child2[i+num_scores] = parent2[i+num_scores];
    }

#ifdef LAMARK
    if ((PGAGetMutationAndCrossoverFlag(ctx) == PGA_FALSE) &&
	(mutation_rate < base_mutation_rate) &&
	(PGAGetEvaluationUpToDateFlag(ctx, p1, pop1) == PGA_TRUE) &&
	(PGAGetEvaluationUpToDateFlag(ctx, p2, pop1) == PGA_TRUE)) {
      parent1_eval = PGAGetEvaluation(ctx, p1, pop1);
      parent2_eval = PGAGetEvaluation(ctx, p2, pop1);

      if (PGARandomFlip(ctx, (double)0.5)) {
	child1_eval = evaluate(ctx, t1, pop2);
	if ((child1_eval > parent1_eval) &&
	    (child1_eval > parent2_eval)) {
	  /* Urk! */
	  if (PGARandomFlip(ctx, (double)(mutation_rate/base_mutation_rate)))
	    adapt_crossover += adapt(ctx, t1, pop2, 1, 2, 0);
	  else {		/* low mr */
	    if (adapt(ctx, t1, pop2, 1, 1, 0))
	      adapt_crossover += adapt(ctx, t1, pop2, 0, 2, 1) + 1;
	    adapt_crossover += adapt(ctx, t2, pop2, 0, 2, 0);
	  }
	} else {
	  PGASetEvaluation(ctx, t1, pop2, child1_eval);
	  PGASetEvaluationUpToDateFlag(ctx, t1, pop2, PGA_TRUE);
	}
      } else {
	child2_eval = evaluate(ctx, t2, pop2);

	if ((child2_eval > parent1_eval) &&
	    (child2_eval > parent2_eval)) {
	  /* Urk! */
	  if (PGARandomFlip(ctx, (double)(mutation_rate/base_mutation_rate)))
	    adapt_crossover += adapt(ctx, t2, pop2, 1, 2, 0);
	  else {		/* low mr */
	    if (adapt(ctx, t2, pop2, 1, 1, 0))
	      adapt_crossover += adapt(ctx, t2, pop2, 0, 2, 1) + 1;
	    adapt_crossover += adapt(ctx, t1, pop2, 0, 2, 0);
	  }
	} else {
	  PGASetEvaluation(ctx, t2, pop2, child2_eval);
	  PGASetEvaluationUpToDateFlag(ctx, t2, pop2, PGA_TRUE);
	}
      }
    }

#endif
}


/*****************************************************************************
 * CopyString makes a copy of the chromosome at (p1, pop1) and puts it at    *
 * (p2, pop2).                                                               *
 *****************************************************************************/
void CopyString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    void *d, *s;

     s = PGAGetIndividual(ctx, p1, pop1)->chrom;
     d = PGAGetIndividual(ctx, p2, pop2)->chrom;
     memcpy(d, s, sizeof(double)*num_scores*2);
}


/*****************************************************************************
 * DuplicateString compares two chromosomes and returns 1 if they are the    *
 * same and 0 if they are different.                                         *
 *****************************************************************************/
int DuplicateString(PGAContext *ctx, int p1, int pop1, int p2, int pop2) {
    void *a, *b;

     a = PGAGetIndividual(ctx, p1, pop1)->chrom;
     b = PGAGetIndividual(ctx, p2, pop2)->chrom;
     return (!memcmp(a, b, sizeof(double)*num_scores*2));
}

/*****************************************************************************
 * BuildDatattype builds an MPI datatype for sending strings to other        *
 * processors.  Consult your favorite MPI manual for more information.       *
 *****************************************************************************/
MPI_Datatype BuildDT(PGAContext *ctx, int p, int pop) {
  MPI_Datatype    DT_PGAIndividual;
#ifdef USE_MPI
  int             counts[3];
  MPI_Aint        displs[3];
  MPI_Datatype    types[3];
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
  counts[2] = num_scores*2;
  types[2]  = MPI_DOUBLE;

  MPI_Type_struct(3, counts, displs, types, &DT_PGAIndividual);
#endif /* defined(USE_MPI) */
  MPI_Type_commit(&DT_PGAIndividual);
  return(DT_PGAIndividual);
}
#endif /* defined(USE_VARIABLE_MUTATIONS) */
