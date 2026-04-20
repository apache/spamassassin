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

score_failure_reason() {
  case $1 in
    0) echo "ok" ;;
    6) echo "insufficient ham contributors" ;;
    7) echo "insufficient spam contributors" ;;
    8) echo "insufficient ham message count" ;;
    9) echo "insufficient spam message count" ;;
    *) echo "exited with $1" ;;
  esac
}

# Proactively check out existing scores from SVN so that:
#   - per-set fallback scores are available if a scoring run fails
#   - a fallback REVISION is available if the active scoreset fails
# This checkout is updated and reused for the final commit.
svn co https://svn.apache.org/repos/asf/spamassassin/trunk/rulesrc/scores trunk-rulesrc-scores

for SET in 0 1 2 3; do
  $PROGDIR/extract-scoreset trunk-rulesrc-scores/72_scores.cf $SET \
    > scores-set${SET}-fallback
done

FALLBACK_REVISION=`svn info trunk-rulesrc-scores | awk '/^Last Changed Rev:/ {print $4}'`
if [[ -z "$FALLBACK_REVISION" ]]; then
  echo "Warning: could not determine fallback revision from SVN; fallback revision will be logged as <UNKNOWN>."
  FALLBACK_REVISION="<UNKNOWN>"
fi

# Run both scoresets independently, capturing exit codes.
# set -e is suspended for these calls so that a failure in one does not
# prevent the other from running.
set +e

if [[ "$DOW" -eq 0 ]]; then
  echo 'Beginning of Week.  Running with 0 first.'
  $PROGDIR/generate-new-scores.sh 0 $1
  RC0=$?
  $PROGDIR/generate-new-scores.sh 1 $1
  RC1=$?
  SCORESET=1
else
  echo 'Not Beginning of Week.  Running with 1 first.'
  $PROGDIR/generate-new-scores.sh 1 $1
  RC1=$?
  $PROGDIR/generate-new-scores.sh 0 $1
  RC0=$?
  SCORESET=0
fi

set -e

REASON0=$(score_failure_reason $RC0)
REASON1=$(score_failure_reason $RC1)

if [[ $RC0 -ne 0 && $RC1 -ne 0 ]]; then
  echo "Both scoresets failed (set0: $REASON0; set1: $REASON1), aborting."
  exit 1
fi

# Emergency off switch: touch this file to block publication regardless of
# scoring outcome. Placed after the status checks so the log still shows how
# the scoring runs fared before the halt.
SENTINEL="/usr/local/spamassassin/automc/DISABLE_PUBLISH"
if [[ -f "$SENTINEL" ]]; then
  echo "Publication blocked by $SENTINEL (set0: $REASON0; set1: $REASON1); aborting."
  exit 1
fi

# Apply fallback scores for any failed set.
PARTIAL_NOTE=""

if [[ $RC1 -ne 0 ]]; then
  echo "Set 1 scoring failed ($REASON1); carrying forward existing scores from SVN revision $FALLBACK_REVISION."
  cp scores-set1-fallback scores-set1
  cp scores-set3-fallback scores-set3
  PARTIAL_NOTE="${PARTIAL_NOTE} [set1 carried forward r$FALLBACK_REVISION: $REASON1]"
fi

if [[ $RC0 -ne 0 ]]; then
  echo "Set 0 scoring failed ($REASON0); carrying forward existing scores from SVN revision $FALLBACK_REVISION."
  cp scores-set0-fallback scores-set0
  cp scores-set2-fallback scores-set2
  PARTIAL_NOTE="${PARTIAL_NOTE} [set0 carried forward r$FALLBACK_REVISION: $REASON0]"
fi

# Fallback files no longer needed; remove before any glob operations.
rm -f scores-set[0-3]-fallback

echo "Finished generating new scores"
pwd

# 20101106 - temporarily s/0.000/0.001/g scores - bug 6510
sed -i -e 's/\b0\.000/0.001 # force non-zero/g' scores-set0
sed -i -e 's/\b0\.000/0.001 # force non-zero/g' scores-set1

# Copy freshly-generated sets to their bayes counterparts.
# Skipped if the fallback already populated the bayes set from SVN.
[[ $RC0 -eq 0 ]] && cp scores-set0 scores-set2
[[ $RC1 -eq 0 ]] && cp scores-set1 scores-set3

$PROGDIR/merge-scoresets $SCORESET
cat scores

REVISION=`grep "revision .*" scores-set$SCORESET | cut -d" " -f9`
[[ -z "$REVISION" ]] && REVISION=$FALLBACK_REVISION

# Update the checkout before committing in case changes landed during scoring.
svn update trunk-rulesrc-scores
cp scores trunk-rulesrc-scores/72_scores.cf
cp scores-set[0-3] trunk-rulesrc-scores/.
ls stats-set* >/dev/null 2>&1 && cp stats-set* trunk-rulesrc-scores/.

svn ci trunk-rulesrc-scores/ -m "updated scores for revision $REVISION active rules added since last mass-check${PARTIAL_NOTE}"
