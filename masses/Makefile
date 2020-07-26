CC=		gcc
CFLAGS=		-g -O2 -Wall 
LDFLAGS=	-lm

PGAPACK=	../build/pga
PGAPACKLIBDIR=  $(PGAPACK)/lib/linux    # linux
#PGAPACKLIBDIR=  $(PGAPACK)/lib/sun4     # solaris

# What rule scoreset are we using?
include config

# what rules directory are we reading rules from?
RULES=          ../rules

#### Should be no need to modify below this line

all: perceptron

perceptron: perceptron.o
	$(CC) -o perceptron perceptron.o $(LDFLAGS)

perceptron.o: tmp/rules_${SCORESET}.pl tmp/tests.h tmp/scores.h
	$(CC) $(CFLAGS) -c -o perceptron.o perceptron.c

garescorer: tmp/rules_${SCORESET}.pl tmp/tests.h tmp/scores.h garescorer.c
	(cd ../build/pga/source; make)
	$(CC) $(CFLAGS) -DWL=2 -DOPTIMIZE -L $(PGAPACKLIBDIR) \
          -I $(PGAPACK)/include garescorer.c -o garescorer -lpgaO $(LDFLAGS)

tmp/rules_${SCORESET}.pl: tmp/.created ../build/parse-rules-for-masses
	perl ../build/parse-rules-for-masses -d $(RULES) -s $(SCORESET) \
            -o tmp/rules_${SCORESET}.pl

tmp/tests.h: tmp/.created tmp/ranges.data logs-to-c
	perl logs-to-c --cffile=$(RULES) --scoreset=$(SCORESET)

tmp/scores.h: tmp/tests.h

tmp/ranges.data: tmp/.created freqs score-ranges-from-freqs
	perl score-ranges-from-freqs $(RULES) $(SCORESET) < freqs

freqs: spam.log ham.log
	perl hit-frequencies -c $(RULES) -x -p -s $(SCORESET) > freqs

badrules: freqs
	perl lint-rules-from-freqs < freqs > badrules

tmp/.created:
	-mkdir tmp
	touch tmp/.created

clean:
	rm -rf *.o perceptron tmp freqs badrules \
          perceptron.scores garescorer garescorer.scores \
          ../build/pga/lib/linux/*

