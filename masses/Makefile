
CC = mpicc
USE_MPI = -DUSE_MPI
#CC = gcc
#USE_MPI =

OPT = -O3 -mcpu=750 -faltivec
PGALIB = pgapack


all: evolve

evolve: tmp/tests.h craig-evolve.c
	$(CC) -Wall $(OPT) $(USE_MPI) -Dlinux -DWL=2 -DOPTIMIZE -L$(PGALIB)/lib/freebsd -I$(PGALIB)/include craig-evolve.c -o evolve -lpgaO -lm
	strip evolve

tmp/tests.h: tmp/.created tmp/ranges.data logs-to-c
	./logs-to-c

tmp/ranges.data: tmp/.created freqs score-ranges-from-freqs
	./score-ranges-from-freqs < freqs

freqs: spam.log nonspam.log
	./hit-frequencies -x -p > freqs

tmp/.created:
	-mkdir tmp
	touch tmp/.created

clean:
	rm -rf *.o evolve tmp freqs

