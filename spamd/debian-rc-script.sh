#! /bin/sh

# Spamd init script
# November 2001
# Duncan Findlay

# Based on skeleton by Miquel van Smoorenburg and Ian Murdock

# Please do not name this script /etc/init.d/spamd.  It may cause problems.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/bin/spamd
PNAME=spamd
NAME=spamd
DESC="SpamAssasin Mail Filter Daemon"

test -r /etc/spamd.conf && . /etc/spamd.conf

test "$ENABLED" != "0" || exit 0

test -f $DAEMON || exit 0

set -e

case "$1" in
  start)
	echo -n "Starting $DESC: "
	start-stop-daemon --start --quiet --name $PNAME \
		--oknodo --startas $DAEMON -- -d $OPTIONS

	echo "$NAME."
	;;
  stop)
	echo -n "Stopping $DESC: "
	start-stop-daemon --stop --quiet --oknodo --name $PNAME
	echo "$NAME."
	;;
  restart|force-reload)
	echo -n "Restarting $DESC: "
	start-stop-daemon --stop --quiet --name $PNAME --oknodo
	sleep 1
	start-stop-daemon --start --quiet --name $PNAME \
		--oknodo --startas $DAEMON -- -d $OPTIONS
	echo "$NAME."
	;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
