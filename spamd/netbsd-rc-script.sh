#!@RCD_SCRIPTS_SHELL@
#
# $NetBSD$
#
# The 'spamd' daemon checks emails provided by the 'spamc' client for signs
# of spam
#
# PLEASE read the file
#   @PREFIX@/share/doc/spamassassin/spamd/README.spamd
# especially the section about security.

## only for NetBSD
# PROVIDE: spamd
# REQUIRE: LOGIN
# BEFORE: mail
# KEYWORD: shutdown
##

PATH=/sbin:/bin:/usr/sbin:/usr/bin:@PREFIX@/bin
export PATH

if [ -f /etc/rc.subr ]
then
	. /etc/rc.subr
fi

name="spamd"
rcvar=$name
command_interpreter="@PERL5@"
command="@PREFIX@/bin/spamd"
pidfile="/var/run/${name}.pid"
sig_stop="TERM"
command_args="-d -r ${pidfile}"

# default values, may be overridden on NetBSD by setting them in /etc/rc.conf
spamd_flags=${spamd_flags-"-H -c -a"}
spamd=${spamd:-NO}

OPSYS=@OPSYS@ # set during package build
INTERPRETER_SUPPORT=@INTERPRETER_SUPPORT@ # set during package build

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

if [ "${OPSYS}" = "NetBSD" ]; then
	if checkyesno INTERPRETER_SUPPORT; then
	  : # support for 'command_interpreter' was added in NetBSD 1.6
	else
	  start_cmd="spamd_start"
	  stop_cmd="spamd_stop"
	  status_cmd="spamd_status"
	  the_spamd_pid=`check_pidfile ${pidfile} ${command_interpreter}`
	fi

	load_rc_config $name
	run_rc_command "$1"

else # not NetBSD

	if [ -f ${pidfile} ];  then
		the_spamd_pid=`head -1 ${pidfile}`
	else
		the_spamd_pid=
	fi

	case ${1+"$@"} in
	start)
		spamd_start
		;;
	stop)
		spamd_stop
		;;
	restart)
		spamd_stop
		sleep 1
		spamd_start
		;;
	status)
		spamd_status
		;;
	*) 
		echo "Usage: ${0} (start|stop|restart|status)"
		;;

	esac
fi
