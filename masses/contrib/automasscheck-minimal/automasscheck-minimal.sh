#!/bin/bash

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
    mkdir -p spamassassin
    rm -f spamassassin/*
    echo "bayes_auto_learn 0" > spamassassin/user_prefs
    echo "lock_method flock" >> spamassassin/user_prefs
    echo "bayes_store_module Mail::SpamAssassin::BayesStore::SDBM" >> spamassassin/user_prefs
    echo "use_auto_whitelist 0" >> spamassassin/user_prefs
    echo "whitelist_bounce_relays example.com" >> spamassassin/user_prefs
    echo " score ANY_BOUNCE_MESSAGE 0" >> spamassassin/user_prefs
    echo " score BOUNCE_MESSAGE 0" >> spamassassin/user_prefs
    if [ -n "${TRUSTED_NETWORKS}" ]; then
        echo "trusted_networks ${TRUSTED_NETWORKS}" >> spamassassin/user_prefs
    fi
    if [ -n "${INTERNAL_NETWORKS}" ]; then
        echo "internal_networks ${INTERNAL_NETWORKS}" >> spamassassin/user_prefs
    fi
}

setup_checktype() {
    unset NET LOGTYPE
    export RSYNC_PASSWORD
    [ ! -d $WORKDIR ] && mkdir $WORKDIR
if [ "$1" == "--nightly" ]; then
        # Run nightly_mass_check
        TYPE=nightly_mass_check
        echo "Syncing $TYPE"
        rsync -qrz --delete rsync://rsync.spamassassin.org/tagged_builds/$TYPE/ $WORKDIR/$TYPE/
        retval=$?
        JOBS=${JOBS}
        LOGTYPE=
        RSYNCMOD=corpus
   elif date +%w |grep -q ^6; then
        # If Saturday, run the weekly_mass_check
        TYPE=weekly_mass_check
        echo "Syncing $TYPE"
        rsync -qrz --delete rsync://rsync.spamassassin.org/tagged_builds/$TYPE/ $WORKDIR/$TYPE/
        retval=$?
        JOBS=${JOBS}
        NET=--net
        LOGTYPE=net-
        RSYNCMOD=corpus
    else
        # Run nightly_mass_check
        TYPE=nightly_mass_check
        echo "Syncing $TYPE"
        rsync -qrz --delete rsync://rsync.spamassassin.org/tagged_builds/$TYPE/ $WORKDIR/$TYPE/
        retval=$?
        JOBS=${JOBS}
        LOGTYPE=
        RSYNCMOD=corpus
    fi
    if [ $retval -ne 0 ]; then
        echo "ERROR: rsync failed in some way, aborting..."
        exit 1
    fi
}

run_masscheck() {
    CORPUSNAME=$1
    shift
    if [ "$CORPUSNAME" == "single-corpus" ]; then
        # Use this if you have only a single corpus
        LOGSUFFIX=
    else
        LOGSUFFIX="-${CORPUSNAME}"
    fi
    LOGNAME=${LOGTYPE}${LOGPREFIX}${LOGSUFFIX}.log
    rm -f ham-${LOGNAME} spam-${LOGNAME}
    set -x
    ./mass-check --hamlog=ham-${LOGNAME} --spamlog=spam-${LOGNAME} \
             -j $JOBS $NET --progress  \
             "$@"
    LOGLIST="$LOGLIST ham-${LOGNAME} spam-${LOGNAME}"
    set +x
    ln -s ham-${LOGNAME} ham.log
    ln -s spam-${LOGNAME} spam.log
}

upload_results() {
    # Occasionally rsync server fails to respond on first attempt,
    # so attempt upload a few times before giving up.
    [ -z "$RSYNCMOD" ] && return 0
    if [ -z "$RSYNC_PASSWORD" ] || [ "$RSYNC_PASSWORD" == "YOUR-PASSWORD" ]; then
        return 0
    fi
    for num in `seq 1 5`; do
        ARGS="-qPcvz $LOGLIST $RSYNC_USERNAME@rsync.spamassassin.org::$RSYNCMOD/"
        echo "rsync $ARGS"
        rsync $ARGS
        retval=$?
        if [ $retval -eq 0 ]; then
            break
        fi
        sleep 5m
    done
}

# Sanitize Environment
unset LOGPREFIX
unset RSYNC_USERNAME
unset RSYNC_PASSWORD
unset WORKDIR
unset CHECKDIR

# Configure
if [ -e ~/.auto-mass-check.cf ]; then
    . ~/.auto-mass-check.cf
else
    echo "ERROR: Configuration file expected at ~/.auto-mass-check.cf"
    echo "       See https://fedorahosted.org/amc/"
    exit 255
fi

# Run
JOBS=${JOBS:=8}
setup_checktype $@
mkdir -p $WORKDIR/$TYPE
cd $WORKDIR/$TYPE
cd masses
setup_masscheck
unset LOGLIST
run_all_masschecks
upload_results
exit 0
