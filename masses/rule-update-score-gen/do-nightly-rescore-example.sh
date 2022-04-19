#!/bin/bash

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

# Shares the temp dir with $PROGDIR/generate-new-scores.sh
# that it calls below.
TMP="/usr/local/spamassassin/automc/tmp/generate-new-scores"

rm -rf $TMP
mkdir -p $TMP
cd $TMP || exit 1

set -e

rm -rf scores scores-set0 scores-set1 scores-set2 scores-set3 stats-set0 stats-set1 stats-set2 stats-set3

if [[ "$DOW" -eq 0 ]]; then
  echo 'Beginning of Week.  Running with 0 first.'
  $PROGDIR/generate-new-scores.sh 0 $1
  $PROGDIR/generate-new-scores.sh 1 $1
  SCORESET=1
  REVISION=`grep "revision .*" scores-set$SCORESET | cut -d" " -f9`
else
  echo 'Not Beginning of Week.  Running with 1 first.'
  $PROGDIR/generate-new-scores.sh 1 $1
  $PROGDIR/generate-new-scores.sh 0 $1
  SCORESET=0
  REVISION=`grep "revision .*" scores-set$SCORESET | cut -d" " -f9`
fi

echo "Finished generating new scores"
pwd

# 20101106 - temporarily s/0.000/0.001/g scores - bug 6510
sed -i -e 's/\b0\.000/0.001 # force non-zero/g' scores-set0
sed -i -e 's/\b0\.000/0.001 # force non-zero/g' scores-set1

cp scores-set0 scores-set2
cp scores-set1 scores-set3
trunk-new-rules-set$SCORESET/masses/rule-update-score-gen/merge-scoresets $SCORESET
cat scores

svn co https://svn.apache.org/repos/asf/spamassassin/trunk/rulesrc/scores trunk-rulesrc-scores

cp scores trunk-rulesrc-scores/72_scores.cf
cp scores-set* stats-set* trunk-rulesrc-scores/.

svn ci trunk-rulesrc-scores/ -m "updated scores for revision $REVISION active rules added since last mass-check"

