#!/bin/sh
#
# spamassassin This script starts and stops the spamd daemon
#
# chkconfig: 2345 80 30
#
# description: spamd is a daemon process which uses SpamAssassin to check
#              email messages for SPAM.  It is normally called by spamc
#	           from a MDA.
# processname:	spamassassin
# pidfile:	/var/run/spamassassin.pid

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Source configureation.
if [ -f /etc/sysconfig/spamassassin ] ; then
	. /etc/sysconfig/spamassassin
fi

# Check that networking is up.
if is_no "${NETWORKING}"; then
	msg_Network_Down SpamAssassin
	exit 1
fi

# See how we were called.
case "$1" in
  start)
	# Start daemon.
	if [ ! -f /var/lock/subsys/spamd ]; then
		msg_starting SpamAssassin
		daemon spamd -d -c -a
		RETVAL=$?
		[ $RETVAL -eq 0 ] && touch /var/lock/subsys/spamd
	else
		msg_Not_Running SpamAssassin
	fi
	;;
  stop)
	# Stop daemons.
	if [ -f /var/lock/subsys/spamd ]; then
		echo -n "Shutting down spamd: "
		killproc spamd
		RETVAL=$?
		rm -f /var/lock/subsys/spamd
	else
		msg_Already_Running SpamAssassin
	fi
	;;
  restart)
	$0 stop
	$0 start
	;;
  status)
	status spamd
	;;
  *)
	msg_Usage "$0 {start|stop|restart|status}"
	exit 1
esac

exit $RETVAL
