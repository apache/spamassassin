
GALIB =	/local2/galib245

all: evolve
	strip evolve

evolve: tmp/tests.h evolve.o
	g++ -Wall -O6 -fexceptions -L$(GALIB)/ga evolve.o -o evolve -lga -lm

tmp/tests.h: spam.log nonspam.log
	./logs-to-c

%.o: %.cxx
	g++ -Wall -O6 -fexceptions -I$(GALIB) -c $< -o $@

clean:
	rm -rf *.o evolve tmp
