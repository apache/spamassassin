#!/sbin/sh
# 
# From: skod@ises-llc.com (Scott Griffith, ISES-LLC)
# To: <craig@stanfordalumni.org>, <spamassassin-talk@lists.sourceforge.net>
# Subject: Re: [Spamassassin-talk] SysV-style startup script
# Date: Sat, 24 Nov 2001 12:09:16 -0700
#
# In case there are any Solaris folks out there who aren't comfortable
# with their own rc scripts, here's what I've been using for Solaris 7
# from day 1 with no problems. Filename:
# 
# /etc/rc2.d/S78spamd

PATH=$PATH:/usr/bin:/usr/local/bin

case "$1" in
'start')
	if [ -x /usr/bin/spamd -o -x /usr/local/bin/spamd ]
	then
		spamd -d -c
	fi

	;;

'stop')
	/usr/bin/pkill -9 -x -u 0 '(spamd)'
	;;

*)
	echo "Usage: $0 { start | stop }"
	exit 1
	;;
esac
exit 0

