#!/bin/sh
#
# spamassassin This script starts and stops the spamd daemon
#
# chkconfig: - 78 30
# processname: spamd
# description: spamd is a daemon process which uses SpamAssassin to check \
#              email messages for SPAM.  It is normally called by spamc \
#	       from a MDA.

# Source function library.
. /etc/rc.d/init.d/functions

prog="spamd"

# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ ${NETWORKING} = "no" ] && exit 0

# Set default spamd configuration.
SPAMDOPTIONS="-d -c -m5 -H"
SPAMD_PID=/var/run/spamd.pid

# Source spamd configuration.
if [ -f /etc/sysconfig/spamassassin ] ; then
	. /etc/sysconfig/spamassassin
fi

[ -f /usr/bin/spamd -o -f /usr/local/bin/spamd ] || exit 0
PATH=$PATH:/usr/bin:/usr/local/bin

# By default it's all good
RETVAL=0

# See how we were called.
case "$1" in
  start)
	# tell portreserve to release the port
	[ -x /sbin/portrelease ] && /sbin/portrelease spamd &>/dev/null || :
	# Start daemon.
	echo -n $"Starting $prog: "
	daemon $NICELEVEL spamd $SPAMDOPTIONS -r $SPAMD_PID
	RETVAL=$?
        echo
	if [ $RETVAL = 0 ]; then
		touch /var/lock/subsys/spamd
	fi
        ;;
  stop)
        # Stop daemons.
        echo -n $"Stopping $prog: "
        killproc spamd
        RETVAL=$?
        echo
	if [ $RETVAL = 0 ]; then
		rm -f /var/lock/subsys/spamd
		rm -f $SPAMD_PID
	fi
        ;;
  restart)
        $0 stop
	sleep 3
        $0 start
        ;;
  condrestart)
       [ -e /var/lock/subsys/spamd ] && $0 restart
       ;;
  status)
	status spamd
	RETVAL=$?
	;;
  *)
	echo "Usage: $0 {start|stop|restart|status|condrestart}"
	RETVAL=1
	;;
esac

exit $RETVAL
