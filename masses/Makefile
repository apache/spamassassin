
GALIB =	/local2/galib245

all: evolve
	echo true

evolve: tmp/tests.h evolve.o
	g++ -Wall -O -fexceptions -L$(GALIB)/ga evolve.o -o evolve -lga -lm

tmp/tests.h: spam.log nonspam.log
	./logs-to-c

%.o: %.cxx
	g++ -Wall -O -fexceptions -I$(GALIB) -c $< -o $@

clean:
	rm -rf *.o evolve tmp
