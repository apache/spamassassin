CFLAGS=-g -O2 -Wall
LDFLAGS=-lgaul -lgaul_util -lm

all: evolve_metarule hits.dat rules.dat

hits.dat rules.dat: preproc.pl ../../rules/*.cf ../ham.log ../spam.log
	perl preproc.pl ../ham.log ../spam.log

evolve_metarule: evolve_metarule.o
	${CC} ${LDFLAGS} -o $@ $^

clean:
	rm -f *.o evolve_metarule hits.dat rules.dat
