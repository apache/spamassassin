#include <stdio.h>
#include <stdlib.h>
#include "scores.h"
#include "tests.h"

/*

	gcc -O2 perturb.c -o perturb

*/

// ---------------------------------------------------------------------------

int nn, ny, yn, yy;
int orignn, origny, origyn, origyy;

int threshold = 5;

// ---------------------------------------------------------------------------

void printhits (FILE *fout) {
  if (num_tests == 0) {
    num_tests = 1;
  }

  fprintf (fout, "Correctly non-spam: %6d  %3.2f%%\n",
        nn, (nn / (float) num_tests) * 100.0);
  fprintf (fout, "Correctly spam:     %6d  %3.2f%%\n",
        yy, (yy / (float) num_tests) * 100.0);
  fprintf (fout, "False positives:    %6d  %3.2f%%\n",
        ny, (ny / (float) num_tests) * 100.0);
  fprintf (fout, "False negatives:    %6d  %3.2f%%\n",
        yn, (yn / (float) num_tests) * 100.0);
  fprintf (fout, "TOTAL:              %6d  %3.2f%%\n",
        num_tests, 100.0);
}

// ---------------------------------------------------------------------------

void writescores (FILE *fout) {
  int i;

  for (i = 0; i < num_scores; i++) {
    fprintf (fout, "score %s %d\n",
		score_names[i], scores[i]);
  }
}

// ---------------------------------------------------------------------------

void counthits (void) {
  int file, hits, i, maxtestshit;

  nn = ny = yn = yy = 0;

  for (file = 0; file < num_tests; file++) {
    hits = 0;
    for (i = num_tests_hit[file]-1; i >= 0; i--) {
      hits += scores[tests_hit[file][i]];

      if (0) {
	printf ("JMD %d %d %d %d %d h=%d\n",
	  	file, i, tests_hit[file][i],
		origscores[tests_hit[file][i]],
		scores[tests_hit[file][i]], hits);
      }
    }

    if (is_spam[file]) {
      if (hits > threshold) {
	yy++;
      } else {
	yn++;
      }
    } else {
      if (hits > threshold) {
	ny++;
      } else {
	nn++;
      }
    }
  }
}

// ---------------------------------------------------------------------------

void iterate (void) {
  int iter, j;
  int numperturbed;

  for (iter = 1; iter != 0; iter++) {
    if (iter % 1000 == 0) { printf ("Progress: %d\n", iter); }

    memcpy (scores, origscores, sizeof(origscores));

    numperturbed = (rand() % 5) + 1;
    for (j = 0; j < numperturbed; ) {
      int delta, snum, score;

      delta = (rand() % 8) - 3;
      if (delta == 0) { continue; }

      snum = rand() % num_scores;
      score = scores[snum];
      score += delta;
      if (score <= 0) { continue; }
      scores[snum] = score;

      j++;
    }

    counthits();

    //if (1)
    if (yn <= origyn && ny <= origny && !(ny == ny && yn == yn))
    {
      FILE *fout;
      char namebuf[255];

      printf ("Improved results at %d:\n", iter);
      printhits(stdout);

      snprintf (namebuf, 255, "perturb.good.%d", iter);
      fout = fopen (namebuf, "w");
      printhits (fout);
      writescores (fout);
      fclose (fout);

      // TODO
    }
  }
}

// ---------------------------------------------------------------------------

int
main (int argc, char **argv) {
  loadscores ();
  loadtests ();

  memcpy (scores, origscores, sizeof(origscores));
  counthits();
  printf ("At start...\n");
  printhits(stdout);

  orignn = nn;
  origny = ny;
  origyn = yn;
  origyy = yy;

  srand (time(NULL) ^ getpid());
  iterate();
}
