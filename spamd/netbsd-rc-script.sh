#! /bin/sh
#
# $NetBSD$
#
# The 'spamd' daemon checks emails provided by the 'spamc' client for signs
# of spam
#
# PLEASE read the file @PREFIX@/share/doc/spamassassin/spamd/README.spamd,
# especially the section about security.
#

# PROVIDE: spamd
# REQUIRE: LOGIN
# BEFORE: mail

PATH=/sbin:/usr/sbin:/bin:/usr/bin:@PREFIX@/sbin:@PREFIX@/bin
export PATH

if [ -f /etc/rc.subr ]
then
	. /etc/rc.subr
else
	echo "$0: /etc/rc.subr is missing"
	exit 1
fi

name="spamd"
rcvar=$name
command_interpreter="@PERL5@"
command="@PREFIX@/bin/spamd"
pidfile="/var/run/${name}.pid"
sig_stop="TERM"
command_args="-d -r ${pidfile}"
spamd_flags="-c -a"

INTERPRETER_SUPPORT=@INTERPRETER_SUPPORT@

if checkyesno INTERPRETER_SUPPORT; then
  : # support for 'command_interpreter' was added in NetBSD 1.6
else
  start_cmd="spamd_start"
  stop_cmd="spamd_stop"
  status_cmd="spamd_status"
  the_spamd_pid=`check_pidfile ${pidfile} ${command_interpreter}`
fi

spamd_start()
{
	if [ -n "${the_spamd_pid}" ]; then
		echo "${command} already running as pid ${the_spamd_pid}."
		return 1
	fi
	echo "Starting spamd"
	${command} ${spamd_flags} ${command_args}
}

spamd_stop()
{
	if [ -z "${the_spamd_pid}" ]; then
		echo "${command} not running? (check ${pidfile})."
		return 1
	fi
	echo "Stopping spamd"
	kill -${sig_stop} ${the_spamd_pid}
}

spamd_status()
{
	if [ -z "${the_spamd_pid}" ]; then
		echo "${command} is not running? (check ${pidfile})."
	else
		echo "${command} is running as pid ${the_spamd_pid}."
		
	fi
	
}

load_rc_config $name
run_rc_command "$1"
