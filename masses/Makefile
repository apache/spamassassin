
CC = mpicc
USE_MPI = -DUSE_MPI
#CC = gcc
#USE_MPI =

OPT = -O9 -march=athlon
PGALIB = pgapack

#GALIB = galib245

all: evolve tmp/scores.data
#echo "Either do  make evolve  or  make craig-evolve"

#evolve: tmp/tests.h evolve.o
#g++ -Wall $(OPT) -fexceptions -L$(GALIB)/ga evolve.o -o evolve -lga -lm
## cp evolve evolve.unstripped
#strip evolve

evolve: tmp/tests.h craig-evolve.c
	$(CC) -Wall $(OPT) $(USE_MPI) -Dlinux -DWL=2 -DOPTIMIZE -L$(PGALIB)/lib/linux -I$(PGALIB)/include craig-evolve.c -o evolve -lpgaO -lm
	strip evolve

tmp/scores.data tmp/tests.h: spam.log nonspam.log tmp/ranges.data logs-to-c
	./logs-to-c

tmp/ranges.data: freqs score-ranges-from-freqs
	./score-ranges-from-freqs < freqs

freqs: spam.log nonspam.log
	-rm -rf tmp
	mkdir tmp
	./hit-frequencies -x -p > freqs

%.o: %.cxx
	g++ -Wall $(OPT) -fexceptions -I$(GALIB) -c $< -o $@

clean:
	rm -rf *.o evolve tmp
