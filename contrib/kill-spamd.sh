#!/bin/sh

PFILE=/var/run/spamd.pid

if [[ -e $PFILE && ! -z $PFILE ]]; then
	PID=$(cat $PFILE 2>/dev/null)
	if [[ "$PID" =~ ^[0-9]+$ ]]; then
		PROC="/proc/$PID/cmdline"
		if [[ -e $PROC ]]; then
			C=$(grep -c spamd $PROC)
			if [[ "x$C" != "x0" ]]; then
				echo "killing spamd process: $PID";
				kill $PID;
				exit $?
			fi
		fi
	fi
fi
exit 1