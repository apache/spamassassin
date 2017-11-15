#!/bin/bash

# generate-new-scores - generate scores for rules promoted after initial
#                       release mass-check scoring run
#
# usage: generate-new-scores (0|1|2|3)
#
# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

PROGDIR=`dirname $0`
[[ "$PROGDIR" = "." ]] && PROGDIR=`pwd`
PROGNAME=`basename $0 .sh`
HOST=`hostname -f`

DOW=`date +%w`

TMP="/usr/local/spamassassin/automc/tmp/$PROGNAME"

SCORESET=$1
OPTION=$2
CORPUS_SRC_DIR="/usr/local/spamassassin/automc/rsync/corpus"

MINHAMCONTRIBS=10
MINSPAMCONTRIBS=10
MINHAMCOUNT=150000
MINSPAMCOUNT=150000
HAMHISTORY=84
SPAMHISTORY=2

if [[ "$OPTION" = "force" ]]; then
  MINHAMCONTRIBS=8
  MINSPAMCONTRIBS=8
  MINHAMCOUNT=100000
  MINSPAMCOUNT=100000
  HAMHISTORY=96
  SPAMHISTORY=3
fi

if [ ! $SCORESET ]; then
  echo "Missing scoreset number parameter"
  exit
fi

mkdir -p $TMP/corpus
cd $TMP

pwd

date
echo "[ rsyncing logs ]"

# if running on sa-vm1.apache.org rsync locally, otherwise rsync remotely
if [[ -e "$CORPUS_SRC_DIR" ]]; then
  echo "[ rsyncing logs locally ]"
  rsync -artv --delete --exclude="*am-rescore-*" $CORPUS_SRC_DIR/*.log corpus/. || exit $?
else
  echo "[ rsyncing logs remotely ]"
  # load rsync credentials from RSYNC-CREDS file
  # RSYNC_USERNAME="username"
  # RSYNC_PASSWORD="password"
  . $PROGDIR/RSYNC-CREDS
  export RSYNC_PASSWORD
  rsync -artvz --delete --exclude="*am-rescore-*" $RSYNC_USERNAME@rsync.spamassassin.org::corpus/*.log corpus/. || exit $?
fi


date
echo "[ selecting log files to use for scoreset $SCORESET ]"

# select a usable corpus (it'll use all available logs for the wanted score set
# with the most recent revision found among logs for that score set)
rm -rf corpus/usable-corpus-set$SCORESET
mkdir corpus/usable-corpus-set$SCORESET || exit $?

if [ $SCORESET -eq 3 ]; then
  for FILE in `find corpus -type f -name "*am-bayes-net-*"`; do
    FILE=`echo $FILE | cut -d"/" -f2-`
    ln corpus/$FILE corpus/usable-corpus-set${SCORESET}/$FILE || exit $?
    echo "Linked $FILE to corpus/usable-corpus-set${SCORESET}/$FILE"
  done
elif [ $SCORESET -eq 2 ]; then
  for FILE in `find corpus -type f -name "*am-bayes-*" | grep -v net-`; do
    FILE=`echo $FILE | cut -d"/" -f2-`
    ln corpus/$FILE corpus/usable-corpus-set${SCORESET}/$FILE || exit $?
    echo "Linked $FILE to corpus/usable-corpus-set${SCORESET}/$FILE"
  done
elif [ $SCORESET -eq 1 ]; then
  for FILE in `find corpus -type f -name "*am-net-*"`; do
    FILE=`echo $FILE | cut -d"/" -f2-`
    ln corpus/$FILE corpus/usable-corpus-set${SCORESET}/$FILE || exit $?
    echo "Linked $FILE to corpus/usable-corpus-set${SCORESET}/$FILE"
  done
elif [ $SCORESET -eq 0 ]; then
  for FILE in `find corpus -type f -name "*am-*" | grep -v net- | grep -v bayes-`; do
    FILE=`echo $FILE | cut -d"/" -f2-`
    ln corpus/$FILE corpus/usable-corpus-set${SCORESET}/$FILE || exit $?
    echo "Linked $FILE to corpus/usable-corpus-set${SCORESET}/$FILE"
  done
else
  echo "Unknown score set: $SCORESET"
  exit
fi
  
# cthielen's ham logs seem to have a shitload of spam in them
rm -f corpus/usable-corpus-set${SCORESET}/*cthielen.log

# Get the majority SVN revision
REVISION=`head -5 corpus/usable-corpus-set${SCORESET}/*.log | awk '/SVN revision:/ {print $4}' | uniq -c | sort -rn | head -1 | awk '{print $2}'`
if [[ -z "$REVISION" ]]; then
  echo "No logs for scoreset"
  exit 1
fi
 
echo -e "\nMajority SVN revision found: $REVISION\n"

# DEBUG
#echo "test"
#exit 1

for FILE in `find corpus/usable-corpus-set$SCORESET -type f`; do
  echo "Checking $FILE for SVN $REVISION..."
  head $FILE | grep "SVN revision: $REVISION" || (rm $FILE; echo "$FILE does not meet the requirements")
done

# check to make sure that we have enough corpus submitters
HAMCONTRIBS=`ls -l corpus/usable-corpus-set$SCORESET/ham-*.log | wc -l`
SPAMCONTRIBS=`ls -l corpus/usable-corpus-set$SCORESET/spam-*.log | wc -l`

echo " HAM CONTRIBUTORS FOUND: $HAMCONTRIBS (required $MINHAMCONTRIBS)"
echo "SPAM CONTRIBUTORS FOUND: $SPAMCONTRIBS (required $MINSPAMCONTRIBS)"

if [ $HAMCONTRIBS -lt $MINHAMCONTRIBS ]; then
  echo "Insufficient ham corpus contributors; aborting."
  exit 6
fi

if [ $SPAMCONTRIBS -lt $MINSPAMCONTRIBS ]; then
  echo "Insufficient spam corpus contributors; aborting."
  exit 7
fi

date
echo "[ checking out code from svn repository ]"

# make note of what logs we are going to use
echo "# Using score set $SCORESET logs for revision $REVISION from:" > scores-set$SCORESET
echo "#" `ls corpus/usable-corpus-set$SCORESET` >> scores-set$SCORESET
echo >> scores-set$SCORESET

# prep the ruleset checkout
rm -rf trunk-new-rules-set$SCORESET

set -x
svn co -r $REVISION http://svn.apache.org/repos/asf/spamassassin/trunk trunk-new-rules-set$SCORESET || exit $?
svn co http://svn.apache.org/repos/asf/spamassassin/tags/spamassassin_release_3_3_0/rules trunk-new-rules-set$SCORESET/rules-base || exit $?
svn co http://svn.apache.org/repos/asf/spamassassin/trunk/rules trunk-new-rules-set$SCORESET/rules-current || exit $?

svn up -r $REVISION trunk-new-rules-set${SCORESET}/rulesrc/ || exit $?

# use the newest masses/ directory so that we can fix bugs in the masses/ stuff
# and not have the net-enabled scores broken all week
svn up trunk-new-rules-set$SCORESET/masses/
svn up trunk-new-rules-set$SCORESET/build/

#set +x

# we need to patch the Makefile to get it to mangle some data for us
cd trunk-new-rules-set${SCORESET}/masses
patch < rule-update-score-gen/masses-Makefile.patch || exit $?

# copy the support scripts to masses/ of the scoreset's checkout; this lets us
# contain all the new score generation scripts in their own directory and keeps
# us from having to pass the checkout path as an argument to each of the scripts
# NOTE: lock-scores now uses existing scores (even commented out) in 72_active.cf
# as absolute maximum values to be inserted in tmp/ranges.data
cp rule-update-score-gen/lock-scores .
cp rule-update-score-gen/extract-new-scores .
cp rule-update-score-gen/add-hitless-active-to-freqs .

cd ..

date
echo "[ generating active ruleset via make ]"

perl Makefile.PL < /dev/null || exit $?
make > make.out 2>&1 || exit $?

# strip scores from new rules so that the garescorer can set them
grep -v ^score rules/72_active.cf > rules/72_active.cf-scoreless
mv -f rules/72_active.cf-scoreless rules/72_active.cf

date
echo "[ running log-grep-recent ]"
pwd

# only use recent spam to generate scores; use a lot of ham history to avoid FPs - Increases Ham to 84 months on 8/8/2012 to try and get a masscheck out the door.
echo -e "\nmasses/log-grep-recent -m $HAMHISTORY ../corpus/usable-corpus-set$SCORESET/ham-*.log > masses/ham-full.log"
masses/log-grep-recent -m $HAMHISTORY ../corpus/usable-corpus-set$SCORESET/ham-*.log > masses/ham-full.log
echo -e "\nmasses/log-grep-recent -m $SPAMHISTORY ../corpus/usable-corpus-set$SCORESET/spam-*.log > masses/spam-full.log"
masses/log-grep-recent -m $SPAMHISTORY ../corpus/usable-corpus-set$SCORESET/spam-*.log > masses/spam-full.log

# make sure that we have enough mass-check results to actually generate reasonable scores
# NOTE: currently we only check for a minimum number of messages
HAMCOUNT=`wc -l masses/ham-full.log | sed -e 's/^[ \t]*//' | cut -d" " -f1`
SPAMCOUNT=`wc -l masses/spam-full.log | sed -e 's/^[ \t]*//' | cut -d" " -f1`

echo " HAM: $HAMCOUNT ($MINHAMCOUNT required)"
echo "SPAM: $SPAMCOUNT ($MINSPAMCOUNT required)"

if [[ "$HAMCOUNT" -lt "$MINHAMCOUNT" ]]; then
  echo "Insufficient ham corpus to generate scores; aborting."
  exit 8
fi

if [[ "$SPAMCOUNT" -lt "$MINSPAMCOUNT" ]]; then
  echo "Insufficient spam corpus to generate scores; aborting."
  exit 9
fi

# set config to chosen scoreset
cp masses/config.set$SCORESET masses/config
. masses/config
NAME="set$SCORESET"
LOGDIR="gen-$NAME-$HAM_PREFERENCE-$THRESHOLD-$EPOCHS-ga"

date
echo "[ running make freqs ]"

# generate new ruleset
cd masses
pwd

set -x 
make clean || exit $?
set +x 
rm -rf ORIG NSBASE SPBASE ham-validate.log spam-validate.log ham.log spam.log
ln -s ham-full.log ham.log
ln -s spam-full.log spam.log

set -x 
make freqs SCORESET=$SCORESET || exit $?
make > make.out 2>&1 || exit $?
set +x 

rm -rf ORIG NSBASE SPBASE ham-validate.log spam-validate.log ham.log spam.log
mkdir ORIG
for CLASS in ham spam ; do
  ln $CLASS-full.log ORIG/$CLASS.log
  for I in 0 1 2 3 ; do
    ln -s $CLASS.log ORIG/$CLASS-set$I.log
  done
done

date
echo "[ starting runGA ]"

# generate the new scores
./runGA || exit $?

date
echo "[ generating fp-fn-statistics ]"

# generate stats on the old rules to compare against the new rules and their scores
./fp-fn-statistics --ham ham-test.log --spam spam-test.log --scoreset $SCORESET \
	--cffile=../rules-base --fnlog $LOGDIR/false_negatives_original \
	--fplog $LOGDIR/false_positives_original > $LOGDIR/stats-set$SCORESET-original-test

./fp-fn-statistics --ham ham.log --spam spam.log --scoreset $SCORESET \
	--cffile=../rules-base --fnlog $LOGDIR/false_negatives_original \
	--fplog $LOGDIR/false_positives_original > $LOGDIR/stats-set$SCORESET-original-full

date
echo "[ extracting new scores ]"

# extract the new scores
./extract-new-scores
cat $LOGDIR/scores-new >> ../../scores-set$SCORESET

# new active.list rules that didn't hit enough get zeroed... add the zero scores
# for them, otherwise SA will assign 1.0 defaults (or use whatever was in the sandbox)
if [ -s scores-active-zeroed ]; then
  echo "# in active.list but have no hits in recent corpus" >> ../../scores-set$SCORESET
  cat scores-active-zeroed >> ../../scores-set$SCORESET
fi

cd ../..
cat scores-set$SCORESET

# collect some stats
echo "##### WITH NEW RULES AND SCORES #####" > stats-set$SCORESET
head -10 trunk-new-rules-set$SCORESET/masses/$LOGDIR/scores >> stats-set$SCORESET
cat trunk-new-rules-set$SCORESET/masses/$LOGDIR/test >> stats-set$SCORESET
echo >> stats-set$SCORESET
echo "##### WITHOUT NEW RULES AND SCORES #####" >> stats-set$SCORESET
cat trunk-new-rules-set$SCORESET/masses/$LOGDIR/stats-set$SCORESET-original-full >> stats-set$SCORESET
cat trunk-new-rules-set$SCORESET/masses/$LOGDIR/stats-set$SCORESET-original-test >> stats-set$SCORESET

date
echo "[ completed ]"
