#!/bin/sh

# Spamd init script for Slackware 10.0
# August, 2th 2003
# Martin Ostlund, nomicon


PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin
DAEMON=/usr/bin/spamd
NAME=spamd
SNAME=rc.spamassassin
DESC="SpamAssassin Mail Filter Daemon"
PIDFILE="/var/run/$NAME.pid"
PNAME="spamd"
DOPTIONS="-d --pidfile=$PIDFILE"

KILL="/bin/kill"
KILLALL="/bin/killall"
# Defaults - don't touch, edit /etc/spamassassin.conf
ENABLED=0
OPTIONS=""

test -f /etc/spamassassin.conf && . /etc/spamassassin.conf

test "$ENABLED" != "0" || exit 0

test -f $DAEMON || exit 0

set -e

case "$1" in
  start)
	echo -n "Starting $DESC: "
	$PNAME $OPTIONS $DOPTIONS 

	echo "$NAME."
	;;
  stop)
	echo -n "Stopping $DESC: "
        $KILL `cat $PIDFILE`
	/bin/rm -f $PIDFILE
	echo "$NAME."
	;;
  restart|force-reload)
	$0 stop
	$0 start
	;;
  *)
	ME=/etc/rc.d/$SNAME
	echo "Usage: $ME {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0

