#!/bin/sh

# Copyright 2007,2008 Duncan Findlay <duncf@debian.org>
# Copyright 2008-2020 Noah Meyerhans <noahm@debian.org>
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#       http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

# Daily maintenance script for SpamAssassin updates.  This is
# typically invoked by cron or a systemd timer.

test -f /etc/default/spamassassin && . /etc/default/spamassassin

show_usage() {
    cmd=$(basename "$0")
    cat <<EOF

$cmd performs periodic spamassassin maintainance, including executing sa-update
and sa-compile.  It is typically executed via the spamassassin-maintenance.timer
timer or cron.

$cmd takes no options

EOF
}

# If there's a problem with the ruleset or configs, print the output
# of spamassassin --lint (which will typically get emailed to root)
# and abort.
die_with_lint() {
    env -i LANG="$LANG" PATH="$PATH" start-stop-daemon \
        --chuid debian-spamd:debian-spamd --start \
        --exec /usr/bin/spamassassin -- -D --lint 2>&1
    exit 1
}

do_compile() {
    if command -v re2c > /dev/null 2>&1 &&
            [ -x /usr/bin/sa-compile ]; then
        env -i LANG="$LANG" PATH="$PATH" start-stop-daemon \
            --chuid debian-spamd:debian-spamd --start \
            --exec /usr/bin/sa-compile -- --quiet

        # Fixup perms -- group and other should be able to
        # read and execute, but never write.  Works around
        # sa-compile's failure to obey umask.
        runuser -u debian-spamd -- \
                chmod -R go-w,go+rX /var/lib/spamassassin/compiled
    fi
}

# Tell a running spamd to reload its configs and rules.
reload() {
    # Reload spamd if it's running
    if command -v spamd > /dev/null 2>&1 &&
            [ -f /run/spamd.pid ]; then
        if which invoke-rc.d >/dev/null 2>&1; then
            invoke-rc.d --quiet spamd status > /dev/null && \
                invoke-rc.d spamd reload > /dev/null
        else
            /etc/init.d/spamd reload > /dev/null
        fi
    fi
    if [ -d /etc/spamassassin/sa-update-hooks.d ]; then
        run-parts --lsbsysinit /etc/spamassassin/sa-update-hooks.d
    fi
}

if [ "$#" -gt 0 ]; then
    show_usage
    exit 0
fi
    
test -x /usr/bin/sa-update || exit 0
command -v gpg > /dev/null || exit 0

# Update
umask 022
env -i LANG="$LANG" PATH="$PATH" http_proxy="$http_proxy" \
    https_proxy="$https_proxy" \
    start-stop-daemon --chuid debian-spamd:debian-spamd --start \
    --exec /usr/bin/sa-update -- \
    --gpghomedir /var/lib/spamassassin/sa-update-keys 2>&1

case $? in
    0)
        # got updates!
        env -i LANG="$LANG" PATH="$PATH" start-stop-daemon \
            --chuid debian-spamd:debian-spamd --start \
            --exec /usr/bin/spamassassin -- --lint 2>&1 || die_with_lint
        do_compile
        reload
        ;;
    1)
        # no updates
        exit 0
        ;;
    2)
        # lint failed!
        die_with_lint
        ;;
    *)
        echo "sa-update failed for unknown reasons" 1>&2
        exit 1
        ;;
esac

exit 0

# Local variables:
# mode: shell-script
# tab-width: 4
# indent-tabs-mode: nil
# end:
