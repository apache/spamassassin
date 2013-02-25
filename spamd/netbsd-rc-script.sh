#!@RCD_SCRIPTS_SHELL@
#
# $NetBSD$
#
# Start script for 'spamd' installed by the pkgsrc package collection
# running on *BSD, MacOS X, Solaris, Linux, and various other U*IX-like
# systems.
#
# The 'spamd' daemon checks emails provided by the 'spamc' client for signs
# of spam
#
# PLEASE read the file
#   @PREFIX@/share/doc/spamassassin/spamd/README
# especially the section about security.

## only for DragonFlyBSD/NetBSD
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
extra_commands="reload"
sig_reload="HUP"

# default values, may be overridden on NetBSD/DragonFlyBSD by setting them
# in /etc/rc.conf
spamd_flags=${spamd_flags-"-H -c"}
spamd=${spamd:-NO}
spamd_fdlimit=${spamd_fdlimit-"128"}

# both set during package build
OPSYS=@OPSYS@
INTERPRETER_SUPPORT=@INTERPRETER_SUPPORT@

# A default limit of 64 on NetBSD may be too low for many
# people (eg with addional RBL rules)
SOFT_FDLIMIT=`ulimit -S -n`
HARD_FDLIMIT=`ulimit -H -n`

if [ ${spamd_fdlimit} -gt ${SOFT_FDLIMIT} ]; then
  if [ ${spamd_fdlimit} -le ${HARD_FDLIMIT} ]; then 
    ulimit -S -n ${spamd_fdlimit}
  else
    ulimit -S -n ${HARD_FDLIMIT}
  fi
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

spamd_reload()
{
	if [ -z "${the_spamd_pid}" ]; then
		echo "${command} not running? (check ${pidfile})."
		return 1
	fi
	echo "Reloading spamd"
	kill -${sig_reload} ${the_spamd_pid}
}

if [ "${OPSYS}" = "NetBSD" -o "${OPSYS}" = "DragonFly" ]; then
	if checkyesno INTERPRETER_SUPPORT; then
	  : # support for 'command_interpreter' was added in NetBSD 1.6
	else
	  start_cmd="spamd_start"
	  stop_cmd="spamd_stop"
	  status_cmd="spamd_status"
	  reload_cmd="spamd_reload"
	  the_spamd_pid=`check_pidfile ${pidfile} ${command_interpreter}`
	fi

	load_rc_config $name
	run_rc_command "$1"

else # not NetBSD or DragonFlyBSD

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
	reload)
		spamd_reload
		;;
	*) 
		echo "Usage: ${0} (start|stop|restart|status|reload)"
		;;

	esac
fi
