# Pick whether or not to use MPI here
# Allowed values are yes, no
MPI = no

# Pick a platform to build for - currently support linux, macosx
PLATFORM = linux

# Pick where you have PGApack installed
PGAPATH = pgapack

# What rule scoreset are we using?
SCORESET = 0

#### Should be no need to modify below this line

ifeq ($(MPI),yes)
  CC = mpicc
  USE_MPI = -DUSE_MPI
else
  CC = gcc
  USE_MPI =
endif

PGAINC = $(PGAPATH)/include

ifeq ($(PLATFORM),macosx)
  OPT = -O3 -mcpu=750 -faltivec
  PGALIB = $(PGAPATH)/lib/freebsd
  EXTRALIBS =
else
  OPT = -O9 -mcpu=athlon
  PGALIB = $(PGAPATH)/lib/linux
  EXTRALIBS = -lm
endif

all: badrules evolve

evolve: tmp/tests.h craig-evolve.c
	$(CC) -Wall $(OPT) $(USE_MPI) -DWL=2 -DOPTIMIZE -L$(PGALIB) -I$(PGAINC) craig-evolve.c -o evolve -lpgaO $(EXTRALIBS)
	strip evolve

tmp/tests.h: tmp/.created tmp/ranges.data logs-to-c
	./logs-to-c --scoreset=$(SCORESET)

tmp/ranges.data: tmp/.created freqs score-ranges-from-freqs
	./score-ranges-from-freqs ../rules $(SCORESET) < freqs

freqs: spam.log ham.log
	./hit-frequencies -x -p -s $(SCORESET) > freqs

badrules: freqs
	./lint-rules-from-freqs < freqs > badrules

tmp/.created:
	-mkdir tmp
	touch tmp/.created

clean:
	rm -rf *.o evolve tmp freqs

