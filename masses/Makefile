CC=		gcc
CFLAGS=		-g -O2 -Wall 
LDFLAGS=	-lm

# What rule scoreset are we using?
SCORESET =	0

#### Should be no need to modify below this line

all: badrules perceptron

perceptron: perceptron.o
	$(CC) -o perceptron perceptron.o $(LDFLAGS)

perceptron.o: tmp/rules.pl tmp/tests.h tmp/scores.h
	$(CC) $(CFLAGS) -c -o perceptron.o perceptron.c

tmp/rules.pl: tmp/.created parse-rules-for-masses
	perl parse-rules-for-masses -d ../rules -s $(SCORESET)

tmp/tests.h: tmp/.created tmp/ranges.data logs-to-c
	perl logs-to-c --scoreset=$(SCORESET)

tmp/scores.h: tmp/tests.h

tmp/ranges.data: tmp/.created freqs score-ranges-from-freqs
	perl score-ranges-from-freqs ../rules $(SCORESET) < freqs

freqs: spam.log ham.log
	perl hit-frequencies -x -p -s $(SCORESET) > freqs

badrules: freqs
	perl lint-rules-from-freqs < freqs > badrules

tmp/.created:
	-mkdir tmp
	touch tmp/.created

clean:
	rm -rf *.o perceptron tmp freqs

