#!/bin/sh
#
# spamassassin This script starts and stops the spamd daemon
#
# chkconfig: 2345 80 30
#
# description: spamd is a daemon process which uses SpamAssassin to check
#              email messages for SPAM.  It is normally called by spamc
#	       from a MDA.

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ ${NETWORKING} = "no" ] && exit 0

[ -f /usr/bin/spamd -o -f /usr/local/bin/spamd ] || exit 0
PATH=$PATH:/usr/bin:/usr/local/bin

# See how we were called.
case "$1" in
  start)
	# Start daemon.
	echo -n "Starting spamd: "
	daemon spamd -d -c -a
	RETVAL=$?
	touch /var/lock/spamd
	echo
	;;
  stop)
	# Stop daemons.
	echo -n "Shutting down spamd: "
	killproc spamd
	RETVAL=$?
	rm -f /var/lock/spamd
	echo
	;;
  restart)
	$0 stop
	$0 start
	;;
  status)
	status spamd
	;;
  *)
	echo "Usage: $0 {start|stop|restart|status}"
	exit 1
esac

exit 0
