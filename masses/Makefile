
CC = mpicc
USE_MPI = -DUSE_MPI
#CC = gcc
#USE_MPI =

OPT = -O9 -march=athlon
PGALIB = pgapack


all: evolve

evolve: tmp/tests.h craig-evolve.c
	$(CC) -Wall $(OPT) $(USE_MPI) -Dlinux -DWL=2 -DOPTIMIZE -L$(PGALIB)/lib/linux -I$(PGALIB)/include craig-evolve.c -o evolve -lpgaO -lm
	strip evolve

tmp/tests.h: tmp tmp/ranges.data logs-to-c
	./logs-to-c

tmp/ranges.data: tmp freqs score-ranges-from-freqs
	./score-ranges-from-freqs < freqs

tmp/rules.pl: tmp ../rules/50_scores.cf
	./parse-rules-for-masses

freqs: spam.log nonspam.log tmp/rules.pl
	./hit-frequencies -x -p > freqs

tmp:
	-mkdir tmp

clean:
	rm -rf *.o evolve tmp freqs

