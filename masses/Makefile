
OPT = -O6
GALIB =	galib245
PGALIB = pgapack

all: evolve craig-evolve
	strip evolve
	strip craig-evolve

evolve: tmp/tests.h evolve.o
	g++ -Wall $(OPT) -fexceptions -L$(GALIB)/ga evolve.o -o evolve -lga -lm

craig-evolve: tmp/tests.h craig-evolve.cxx
	mpiCC -Wall $(OPT) -Dlinux -DWL=2 -DOPTIMIZE -L$(PGALIB)/lib/linux -I$(PGALIB)/include -lpgaO -lm craig-evolve.cxx -o craig-evolve

tmp/tests.h: spam.log nonspam.log tmp/ranges.data logs-to-c
	./logs-to-c

tmp/ranges.data: freqs score-ranges-from-freqs
	./score-ranges-from-freqs < freqs

freqs: spam.log nonspam.log
	-rm -rf tmp
	mkdir tmp
	./hit-frequencies > freqs

%.o: %.cxx
	g++ -Wall $(OPT) -fexceptions -I$(GALIB) -c $< -o $@

clean:
	rm -rf *.o evolve tmp
