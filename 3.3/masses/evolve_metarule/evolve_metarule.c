/* This program uses a genetic algorithm to optimize a phrase-based rule such as
 * the NIGERIAN or ADVANCE_FEE rule.
 *
 * <@LICENSE>
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at:
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </@LICENSE>
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

/* GAUL: Genetic Algorithm Utility Library.  http://gaul.sourceforge.net/ */
#include <gaul.h>

/* Config files */
char * hits_file = "hits.dat";	/* The data file containing the matrix. */
char * rules_file = "rules.dat";	/* The data file containing rule names. */

/* Fitness function parameters */
int maximum_relevant_hits = 4;	/* How many hits is the rule going to look for. */
int target_num_rules = 50;	/* How many sub-rules would we like the meta rule to use? */
double target_flex_rules = 5;	/* How flexible the GA should be.  Half-life of the fitness function. */

/* The fitness function is based on:
 * min(num_hits, maximum_relevant_hits)^hits_exponent * count * ...
 * (if ham: -num_hits ^ penalty_exponent) */
double hits_exponent = 3.0;
double penalty_exponent = 9.0;

/* GA parameters */
/* The number of individuals in the population */
int population_size = 100;
/* The maximal number of generations that the simluation is to run for.	*/
int max_generations = 10000;
/* The probability of a cross-over. */
double crossover_prob = 1.0;
/* The probability of one boolean allele being switched. */
double mutation_prob = 0.1;

int num_rules;		/* The number of rules being optimized. */
int max_hits;		/* The maximal number of hits in a unique pattern. */
int num_patterns;	/* The number of unique patterns. */
int * pattern_data;	/* A compressed matrix containing the patterns. */
int * pattern_size_data;	/* The width of each row in the above matrix. */
int * pattern_count_data;	/* The number of occurrences of the pattern. */
int * class_data;	/* The class that each pattern belongs to (ham, spam). */

/* Some #defines for fast access to the compressed matrix. */
#define pattern(i,j) (pattern_data[(i)*max_hits + (j)])
#define pattern_size(i) (pattern_size_data[(i)])
#define pattern_count(i) (pattern_count_data[(i)])
#define class(i) (class_data[(i)])

#define max(x,y) ((x)>(y)?(x):(y))
#define min(x,y) ((x)<(y)?(x):(y))

/* Loads the compressed matrix into memory.  */
void load_patterns () {
	FILE * pfile;
	int p;

	pfile = fopen(hits_file, "r");
	if ( ! pfile ) {
		perror (hits_file);
		exit(1);
	}

	if ( fscanf (pfile, "%d %d %d", &num_rules, &max_hits, &num_patterns) != 3 ) {
		fprintf (stderr, "%s missing header.\n", hits_file);
		exit (1);
	}

	assert(pattern_data = (int*)malloc(sizeof(int) * max_hits * num_patterns));
	assert(pattern_size_data = (int*)malloc(sizeof(int) * num_patterns));
	assert(pattern_count_data = (int*)malloc(sizeof(int) * num_patterns));
	assert(class_data = (int*)malloc(sizeof(int) * num_patterns));

	for (p = 0; p < num_patterns; p++) {
		int i;

		if (fscanf(pfile, "%d %d %d", class_data+p, pattern_count_data+p, pattern_size_data+p) != 3) {
			fprintf (stderr, "%s truncated (entry %d)\n", hits_file, p);
			exit (1);
		}
		assert(pattern_size_data[p] <= max_hits);
		for (i = 0; i < pattern_size(p); i++) {
			if (fscanf(pfile, "%d", pattern_data+p*max_hits+i) != 1) {
				fprintf (stderr, "%s truncated (entry %d)\n", hits_file, p);
				exit(1);
			}
		}
	}
}

/* The fitness function is:
 * sum_{all individuals}
 * 	min(num_hits, maximum_relevant_hits)^hits_exponent * count * ...
 * 	(if ham: -num_hits ^ penalty_exponent)
 * / exp(abs(target_num_rules - num_rules_present) * log(2) / target_flex_rules)
 * */
static boolean pattern_score(population *pop, entity *entity) {
	int i, j, num_hits, num_rules_present;

	entity->fitness = 0;

	/* Count up the number of rules present in this individual's
	 * chromosome. */
	num_rules_present = 0;
	for (i = 0; i < num_rules; i++) {
		if (((boolean*)entity->chromosome[0])[i]) {
			num_rules_present++;
		}
	}

	/* An individual with no rules present in its chromosome has 0 fitness,
	 * so we take a short cut. */
	if (num_rules_present == 0) {
		return true;
	}

	/* Compute the fitness function as described above. */
	for (i = 0; i < num_patterns; i++) {
		num_hits = 0;
		/* This counts how many rules in the chromosome also hit the
		 * pattern */
		for (j = 0; j < pattern_size(i); j++) {
			if (((boolean*)entity->chromosome[0])[pattern(i,j)]) {
				num_hits++;
			}
		}
		
		/* See above for a description of what this does and why it
		 * does it. */
		entity->fitness += pow(min(num_hits,maximum_relevant_hits),hits_exponent) * pattern_count(i) * (class(i) ? 1 : -pow(num_hits,penalty_exponent));
	}
	
	/* This divisor is bound to 1, to prevent overflow.  exp(0) is undefined
	 * so we just skip this part (it's unnecessary).  */
	if ( target_num_rules - num_rules_present ) {
		entity->fitness /= max(exp(fabs(target_num_rules - num_rules_present) * log(2) / target_flex_rules),1);
	}

	/* Negative fitnesses make roulette wheels go owwie. */
	if ( entity->fitness < 0 ) {
		entity->fitness = 0;
	}

	return true;
}

/* This is to print out the final result. */
void print_entity (entity * entity) {
	FILE * rfile;
	char buf[BUFSIZ];
	int i;
	int count = 0;
	int histogram[2][maximum_relevant_hits+1], num_hits;

	assert(rfile = fopen (rules_file, "r"));

	/* The rules in rules.dat are supposed to correspond to column
	 * numbers. */
	for (i = 0; i < num_rules; i++) {
		if ( ! fgets(buf, BUFSIZ, rfile) ) {
			perror ("fgets");
			exit (1);
		}

		/* Print out the rule name if the corresponding allele is
		 * present on the chromosome. */
		if ( ((boolean *)entity->chromosome[0])[i] == 1 ) {
			count++;
			printf ("%s", buf);
		}
	}

	fprintf (stderr, "fitness: %f\n", entity->fitness);
	fprintf (stderr, "rule count: %d\n", count);

	/* Zero the histogram, just in case the compiler han't done it for us. */
	bzero (histogram, sizeof(histogram));

	/* Compute the histogram by scanning through the training data. */
	for (i = 0; i < num_patterns; i++) {
		int j;

		num_hits = 0;
		for (j = 0; j < pattern_size(i); j++) {
			if (((boolean*)entity->chromosome[0])[pattern(i,j)]) {
				num_hits++;
				if ( num_hits == maximum_relevant_hits ) {
					break;
				}
			}
		}
		for (j = 0; j <= num_hits; j++) {
			histogram[class(i)][j] += pattern_count(i);
		}
	}

	/* Print the histogram. */
	fprintf (stderr, "\t %8s %8s %8s %8s %8s\n",
			"HAM",
			"HAM%",
			"SPAM",
			"SPAM%",
			"S/O");
	for (i = 0; i <= maximum_relevant_hits; i++) {
		fprintf (stderr, ">=%d hits:%8d %8.4f %8d %8.4f %8.4f\n", i,
				histogram[0][i],
				100.0 * histogram[0][i] / histogram[0][0],
				histogram[1][i],
				100.0 * histogram[1][i] / histogram[1][0],
				((double)histogram[1][i] / histogram[1][0]) / ((double)histogram[1][i] / histogram[1][0] + (double)histogram[0][i] / histogram[0][0]));
	}
}

void usage () {
	printf ("usage: evolve_metarule [args]\n"
			"\n"
			"Config parameters:\n"
			"  -h hits_file\n"
			"  -r rules_fule\n"
			"\nFitness function parameters:\n"
			"  -m maximum_relevant_hits\n"
			"  -t target_num_rules\n"
			"  -l target_flex_rules\n"
			"  -e hits_exponent\n"
			"  -p penalty_exponent\n"
			"\nGA parameters:\n"
			"  -s population_size\n"
			"  -g max_generations\n"
			"  -x crossover_prob\n"
			"  -u mutation_prob\n"
			"\n  -? = print this help\n"
			"\n");

	exit(0);
}

int main (int argc, char ** argv) {
	population *pop = 0;
	char arg;

	while ((arg = getopt (argc, argv, "h:r:m:t:l:e:p:s:g:x:u:?")) != -1) {
		switch (arg) {
			case 'h':
				hits_file = optarg;
				break;
			case 'r':
				rules_file = optarg;
				break;
			case 'm':
				maximum_relevant_hits = atoi(optarg);
				break;
			case 't':
				target_num_rules = atoi(optarg);
				break;
			case 'l':
				target_flex_rules = atoi(optarg);
				break;
			case 'e':
				hits_exponent = atof(optarg);
				break;
			case 'p':
				penalty_exponent = atof(optarg);
				break;
			case 's':
				population_size = atoi(optarg);
				break;
			case 'g':
				max_generations = atoi(optarg);
				break;
			case 'x':
				crossover_prob = atof(optarg);
				break;
			case 'u':
				mutation_prob = atof(optarg);
				break;
			case '?':
				usage ();
		}
	}

	load_patterns();

	random_init();
	random_seed(time(0));

	pop = ga_genesis_boolean(
		population_size,	/* const int              population_size */
		1,		/* const int              num_chromo */
		num_rules,	/* const int              len_chromo */
		NULL,		/* GAgeneration_hook      generation_hook */
		NULL,		/* GAiteration_hook       iteration_hook */
		NULL,		/* GAdata_destructor      data_destructor */
		NULL,		/* GAdata_ref_incrementor data_ref_incrementor */
		pattern_score,	/* GAevaluate             evaluate */
		ga_seed_boolean_random,	/* GAseed                 seed */
		NULL,			/* GAadapt                adapt */
		ga_select_one_roulette,	/* GAselect_one           select_one */
		ga_select_two_roulette,	/* GAselect_two           select_two */
		ga_mutate_boolean_singlepoint,	/* GAmutate               mutate */
		ga_crossover_boolean_allele_mixing,	/* GAcrossover            crossover */
		ga_replace_by_fitness,	/* GAreplace            replace */
		NULL		/* vpointer             User data */
	);

	ga_population_set_parameters(
		pop,			/* population           *pop */
		GA_SCHEME_DARWIN,	/* const ga_scheme_type         scheme */
		GA_ELITISM_NULL,	/* const ga_elitism_type        elitism */
		crossover_prob,		/* double               crossover */
		mutation_prob,		/* double               mutation */
		0.0			/* double               migration */
	);

	ga_evolution_steady_state(
		pop,			/* population           *pop */
		max_generations		/* const int            max_generations */
	);

	print_entity(ga_get_entity_from_rank(pop, 0));

	return 0;
}
