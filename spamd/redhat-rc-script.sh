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

# Source spamd configuration.
if [ -f /etc/sysconfig/spamassassin ] ; then
        . /etc/sysconfig/spamassassin
else
        SPAMDOPTIONS="-d -c -a -m5 -H"
fi

[ -f /usr/bin/spamd -o -f /usr/local/bin/spamd ] || exit 0
PATH=$PATH:/usr/bin:/usr/local/bin

# See how we were called.
case "$1" in
  start)
	# Start daemon.
	echo -n "Starting spamd: "
	daemon spamd $SPAMDOPTIONS
	RETVAL=$?
        echo
        [ $RETVAL = 0 ] && touch /var/lock/subsys/spamassassin
        ;;
  stop)
        # Stop daemons.
        echo -n "Shutting down spamd: "
        killproc spamd
        RETVAL=$?
        echo
        [ $RETVAL = 0 ] && rm -f /var/lock/subsys/spamassassin
        ;;
  restart)
        $0 stop
        $0 start
        ;;
  condrestart)
       [ -e /var/lock/subsys/spamassassin ] && $0 restart
       ;;
  status)
	status spamd
	;;
  *)
	echo "Usage: $0 {start|stop|restart|status|condrestart}"
	exit 1
esac

exit 0
