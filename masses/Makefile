
GALIB =	/local2/galib245

all: evolve
	strip evolve

evolve: tmp/tests.h evolve.o
	g++ -Wall -O6 -fexceptions -L$(GALIB)/ga evolve.o -o evolve -lga -lm

tmp/tests.h: spam.log nonspam.log tmp/ranges.data
	./logs-to-c

tmp/ranges.data: freqs
	./score-ranges-from-freqs < freqs

freqs: spam.log nonspam.log
	-rm -rf tmp
	mkdir tmp
	./hit-frequencies > freqs

%.o: %.cxx
	g++ -Wall -O6 -fexceptions -I$(GALIB) -c $< -o $@

clean:
	rm -rf *.o evolve tmp
