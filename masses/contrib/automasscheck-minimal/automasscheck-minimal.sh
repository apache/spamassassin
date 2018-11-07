#!/bin/sh

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.



setup_masscheck() {
  [ ! -d "$WORKDIR/$TYPE/masses/spamassassin" ] && mkdir -p "$WORKDIR/$TYPE/masses/spamassassin"
  cd "$WORKDIR/$TYPE/masses" || { echo "ERROR: cd $WORKDIR/$TYPE/masses failed" >&2; exit 1; }
  rm -f spamassassin/*
  echo "" > spamassassin/user_prefs # not used, local.cf works better for admin commands also
  echo "bayes_auto_learn 0" > spamassassin/local.cf
  echo "lock_method flock" >> spamassassin/local.cf
  echo "score ANY_BOUNCE_MESSAGE 0" >> spamassassin/local.cf
  echo "score BOUNCE_MESSAGE 0" >> spamassassin/local.cf
  [ -n "${TRUSTED_NETWORKS}" -o -n "${INTERNAL_NETWORKS}" ] && \
    echo "clear_trusted_networks
clear_internal_networks" >> spamassassin/local.cf
  [ -n "${TRUSTED_NETWORKS}" ] && echo "trusted_networks ${TRUSTED_NETWORKS}" >> spamassassin/local.cf
  [ -n "${INTERNAL_NETWORKS}" ] && echo "internal_networks ${INTERNAL_NETWORKS}" >> spamassassin/local.cf
  [ -n "${CUSTOM_PREFS}" ] && cat ${CUSTOM_PREFS} >> spamassassin/local.cf
  rm -f "$WORKDIR/$TYPE/rules/99_custom.cf"
  [ -n "${CUSTOM_RULES}" ] && cat ${CUSTOM_RULES} > "$WORKDIR/$TYPE/rules/99_custom.cf"
}

setup_checktype() {
  [ ! -d "$WORKDIR" ] && mkdir "$WORKDIR"
  DOW=$(date +%w)
  if [ "$DOW" -ne 6 ] || [ "$1" = "--nightly" ]; then
    # Run nightly_mass_check
    TYPE=nightly_mass_check
    echo "Syncing $TYPE"
    rsync -qrz --delete rsync://rsync.spamassassin.org/tagged_builds/$TYPE/ "$WORKDIR/$TYPE/"
    RC=$?
    NET=
    LOGTYPE=
  else
    # If Saturday, run the weekly_mass_check
    TYPE=weekly_mass_check
    echo "Syncing $TYPE"
    rsync -qrz --delete rsync://rsync.spamassassin.org/tagged_builds/$TYPE/ "$WORKDIR/$TYPE/"
    RC=$?
    NET=--net
    [ ! -z "$REUSE" ] && NET="$REUSE $NET"
    LOGTYPE=net-
  fi
  if [ "$RC" -ne 0 ]; then
    echo "ERROR: rsync failure $RC, aborting..." >&2
    exit 1
  else
    SVNREV=$(awk '/Revision:/ {print $2}' "$WORKDIR/$TYPE/masses/svninfo.tmp")
    [ ! -z "$SVNREV" ] && echo "SVN revision = $SVNREV"
  fi
}

run_masscheck() {
  CORPUSNAME=$1
  shift
  if [ "$CORPUSNAME" = "single-corpus" ]; then
    # Use this if you have only a single corpus
    LOGSUFFIX=
  else
    LOGSUFFIX="-${CORPUSNAME}"
  fi
  LOGFILE=${LOGTYPE}${LOGPREFIX}${LOGSUFFIX}.log
  rm -f ham-${LOGFILE} spam-${LOGFILE}
  set -x
  $PERL ./mass-check --hamlog=ham-${LOGFILE} --spamlog=spam-${LOGFILE} \
             -j $JOBS $NET --progress \
             "$@"
  LOGLIST="$LOGLIST ham-${LOGFILE} spam-${LOGFILE}"
  set +x
  ln -s ham-${LOGFILE} ham.log
  ln -s spam-${LOGFILE} spam.log
}

upload_results() {
  # Occasionally rsync server fails to respond on first attempt,
  # so attempt upload a few times before giving up.
  if [ -z "$RSYNC_PASSWORD" ] || [ "$RSYNC_PASSWORD" = "YOUR-PASSWORD" ]; then
    return 0
  fi
  TRY=0
  while [ "$TRY" -le 5 ]; do
    TRY=$((TRY+1))
    ARGS="-qPcvz $LOGLIST $RSYNC_USERNAME@rsync.spamassassin.org::corpus/"
    echo "rsync $ARGS"
    RSYNC_PASSWORD=$RSYNC_PASSWORD rsync $ARGS && break
    sleep 5m
  done
}

# Sanitize Environment
unset LOGPREFIX
unset RSYNC_USERNAME
unset RSYNC_PASSWORD
unset WORKDIR
unset CHECKDIR
unset REUSE

# Configure
if [ -e "$HOME/.automasscheck.cf" ]; then
  . $HOME/.automasscheck.cf
else
  echo "ERROR: Configuration file expected at $HOME/.automasscheck.cf" >&2
  echo "       See https://wiki.apache.org/spamassassin/NightlyMassCheck" >&2
  exit 255
fi

# Run
JOBS=${JOBS:=8}
setup_checktype "$@"
setup_masscheck
unset LOGLIST
run_all_masschecks
upload_results
exit 0
