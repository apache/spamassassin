
#CC = mpiCC
#USE_MPI = -DUSE_MPI
CC = g++
USE_MPI =

OPT = -O9 -march=athlon
PGALIB = pgapack

#GALIB = galib245

all: craig-evolve
	#echo "Either do  make evolve  or  make craig-evolve"

#evolve: tmp/tests.h evolve.o
	#g++ -Wall $(OPT) -fexceptions -L$(GALIB)/ga evolve.o -o evolve -lga -lm
	## cp evolve evolve.unstripped
	#strip evolve

craig-evolve: tmp/tests.h craig-evolve.cxx
	$(CC) -Wall $(OPT) -Dlinux -DWL=2 -DOPTIMIZE -L$(PGALIB)/lib/linux -I$(PGALIB)/include craig-evolve.cxx -o craig-evolve -lpgaO -lm
	strip craig-evolve

tmp/tests.h: spam.log nonspam.log tmp/ranges.data logs-to-c
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
	rm -rf *.o craig-evolve tmp
