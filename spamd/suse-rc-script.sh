#! /bin/bash
# Author:   Malte S. Stretz <spamassassin-contrib (at) msquadrat.de>
# Skeleton: Kurt Garloff <feedback (at) suse.de>
#
# init.d/spamd
#
#   and symbolic its link
#
# /usr/local/sbin/rcspamd
#
# System startup script for the SpamAssassin daemon spamd.
#
# Install: 1. Put this script into your /etc/init.d directory.
#          2. Create a symlink in /usr/local/sbin with
#             `ln -s /etc/init.d/spamd /usr/local/sbin/rcspamd`
#          3. Tell the system about the existence of this script with
#             `insserv /etc/init.d/spamd`
#          4. Add the following line to your /etc/rc.config file to have
#             the spamd process spawned on every boot:
#             START_SPAMD=yes
#          5. You can configure spamd with two more options in rc.config:
#             SPAMD_OPTS="..."  add these options to the spamd command line
#                               (read `man spamd`).
#             SPAMD_AWL=yes     Enable the autowhitelist. The same as adding
#                               "-a" to SPAMD_OPTS.
#             SPAMD_NICE=<prio> Set the scheduling priority to <prio>; keeps
#                               spamd from soaking up your system resources.
#                               "yes" is equivalent to "5".
#
# Warning: The SuSE Boot Concept has changed with SuSE 8.0. More information
#          is available at <http://sdb.suse.de/en/sdb/html/mmj_network80.html>
#
### BEGIN INIT INFO
# Provides:       spamd
# Required-Start: $remote_fs $syslog $network
# Required-Stop:  $remote_fs $syslog $network
# Default-Start:  3 5
# Default-Stop:   0 1 2 6
# Description:    spamd is a daemon process which uses SpamAssassin to check email messages for SPAM. It is normally called by spamc from an MDA.
### END INIT INFO

# Source SuSE config
. /etc/rc.config

# Determine the base and follow a runlevel link name.
base=${0##*/}
link=${base#*[SK][0-9][0-9]}

# Force execution if not called by a runlevel directory.
test $link = $base && START_SPAMD=yes
test "$START_SPAMD" = yes || exit 0

# Find the spamd binary
for p in local/sbin local/bin sbin bin; do
    SPAMD_BIN=/usr/$p/spamd
    test -x $SPAMD_BIN && break
done
test -x $SPAMD_BIN || exit 5

# Some options
test "$SPAMD_AWL" == "yes"  && SPAMD_OPTS="$SPAMD_OPTS -a"
test "$SPAMD_NICE" == "yes" && SPAMD_NICE=5
test -n "$SPAMD_NICE"       && SPAMD_NICE="-n $SPAMD_NICE"

# Shell functions sourced from /etc/rc.status:
#      rc_check         check and set local and overall rc status
#      rc_status        check and set local and overall rc status
#      rc_status -v     ditto but be verbose in local rc status
#      rc_status -v -r  ditto and clear the local rc status
#      rc_failed        set local and overall rc status to failed
#      rc_failed <num>  set local and overall rc status to <num><num>
#      rc_reset         clear local rc status (overall remains)
#      rc_exit          exit appropriate to overall rc status
. /etc/rc.status

# First reset status of this service
rc_reset

# Return values acc. to LSB for all commands but status:
# 0 - success
# 1 - generic or unspecified error
# 2 - invalid or excess argument(s)
# 3 - unimplemented feature (e.g. "reload")
# 4 - insufficient privilege
# 5 - program is not installed
# 6 - program is not configured
# 7 - program is not running
# 
# Note that starting an already running service, stopping
# or restarting a not-running service as well as the restart
# with force-reload (in case signalling is not supported) are
# considered a success.

case "$1" in
    start)
	echo -n "Starting spamd"
	## Start daemon with startproc(8). If this fails
	## the echo return value is set appropriate.

	# NOTE: startproc return 0, even if service is 
	# already running to match LSB spec.
	startproc $SPAMD_NICE $SPAMD_BIN -d -r /var/run/spamd.pid $SPAMD_OPTS

	# Remember status and be verbose
	rc_status -v
	;;
    stop)
	echo -n "Shutting down spamd"
	## Stop daemon with killproc(8) and if this fails
	## set echo the echo return value.

	killproc -TERM spamd

	# Remember status and be verbose
	rc_status -v
	;;
    try-restart)
	## Stop the service and if this succeeds (i.e. the 
	## service was running before), start it again.
	## Note: try-restart is not (yet) part of LSB (as of 0.7.5)
	$0 status >/dev/null &&  $0 restart

	# Remember status and be quiet
	rc_status
	;;
    restart)
	## Stop the service and regardless of whether it was
	## running or not, start it again.
	$0 stop
	$0 start

	# Remember status and be quiet
	rc_status
	;;
    force-reload)
	## Signal the daemon to reload its config. Most daemons
	## do this on signal 1 (SIGHUP).
	## If it does not support it, restart.

	$0 reload

	rc_status
	;;
    reload)
	## Like force-reload, but if daemon does not support
	## signalling, do nothing (!)

	# If it supports signalling:
	echo -n "Reload service spamd"
	killproc -HUP $SPAMD_BIN
	touch /var/run/spamd.pid
	rc_status -v
	
	## Otherwise if it does not support reload:
	#rc_failed 3
	#rc_status -v
	;;
    status)
	echo -n "Checking for spamd: "
	## Check status with checkproc(8), if process is running
	## checkproc will return with exit status 0.

	# Status has a slightly different for the status command:
	# 0 - service running
	# 1 - service dead, but /var/run/  pid  file exists
	# 2 - service dead, but /var/lock/ lock file exists
	# 3 - service not running

	# NOTE: checkproc returns LSB compliant status values.
	checkproc $SPAMD_BIN
	rc_status -v
	;;
    probe)
	## Optional: Probe for the necessity of a reload,
	## give out the argument which is required for a reload.

	test /etc/mail/spamassassin/local.cf -nt /var/run/spamd.pid && echo force-reload
	;;
    *)
	echo "Usage: $0 {start|stop|status|try-restart|restart|force-reload|reload|probe}"
	exit 1
	;;
esac
rc_exit
