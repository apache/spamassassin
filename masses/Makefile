
all: evolve
	echo true

evolve: tmp/tests.h evolve.o
	g++ -Wall -O -fexceptions -Lgalib245/ga evolve.o -o evolve -lga -lm

tmp/tests.h: spam.log
	./logs-to-c

%.o: %.cxx
	g++ -Wall -O -fexceptions -Igalib245 -c $< -o $@

clean:
	rm -rf *.o evolve tmp
