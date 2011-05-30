#!/usr/bin/perl -w
use strict;

use Mail::SpamAssassin::Spamd::Config ();
use Mail::SpamAssassin::Util          ();    # heavy, loads M::SA
use Sys::Hostname qw(hostname);
use File::Spec ();
use Cwd        ();

=head1 NAME

apache-spamd -- start spamd with Apache as backend

=head1 SYNOPSIS

  apache-spamd --pidfile ... [ OPTIONS ]

OPTIONS:
  --httpd_path=path      path to httpd, eg. /usr/sbin/httpd.prefork
  --httpd_opt=opt        option for httpd    (can occur multiple times)
  --httpd_directive=line directive for httpd (can occur multiple times)
  -k CMD                 passed to httpd (see L<httpd(1)> for values)
  --apxs=path            path to apxs, eg /usr/sbin/apxs
  --httpd_conf=path      just write a config file for Apache and exit

See L<spamd(1)> for other options.

If some modules are not in @INC, invoke this way:
  perl -I/path/to/modules apache-spamd.pl \
       --httpd_directive "PerlSwitches -I/path/to/modules"

Note: pass the -H / --helper-home-dir option; there is no reasonable default.

=head1 DESCRIPTION

Starts spamd with Apache as a backend.  Apache is configured according to
command line options, compatible to spamd where possible and makes sense.

If this script doesn't work for you, complain.

=head1 TODO

 * misc MPMs
 * testing on different platforms and configurations
 * fix FIXME's
 * review XXX's
 * --create-prefs (?), --help, --virtual-config-dir
 * current directory (home_dir_for_helpers?)

=cut

# NOTE: the amount of code here and list of loaded modules doesn't matter;
# we exec() anyway.

# NOTE: no point in using -T, it'd only mess up code with workarounds;
# we don't process any user input but command line options.

my $opt = Mail::SpamAssassin::Spamd::Config->new(
	{
		defaults => { daemonize => 1, port => 783, },
		moreopts => [
			qw(httpd_path|httpd-path=s httpd_opt|httpd-opt=s@
			  httpd_directive|httpd-directive=s@ k:s apxs=s
			  httpd_conf|httpd-conf=s)
		],
	}
);

# only standalone spamd implements these options.
# you miss vpopmail?  get a real MTA.
for my $option (
	qw(round-robin setuid-with-sql setuid-with-ldap socketpath
	socketowner socketgroup socketmode paranoid vpopmail)
  )
{
	die "ERROR: --$option can't be used with apache-spamd\n"
	  if defined $opt->{$option};
}

#
# XXX: move these options (and sanity checks for them) to M::SA::S::Config?
#

die "ERROR: '$opt->{httpd_path}' does not exist or not executable\n"
  if exists $opt->{httpd_path}
  and !-f $opt->{httpd_path} || !-x _;
$opt->{httpd_path} ||= 'httpd';    # FIXME: find full path

$opt->{pidfile} ||= '/var/run/apache-spamd.pid'    # reasonable default
  if -w '/var/run/' && -x _ && !-e '/var/run/apache-spamd.pid';
die "ERROR: --pidfile is mandatory\n"    # this seems ugly, but has advantages
  unless $opt->{pidfile};                # we won't be able to stop otherwise
$opt->{pidfile} = File::Spec->rel2abs($opt->{pidfile});
if (-d $opt->{pidfile}) {
	die "ERROR: can't write pid, '$opt->{pidfile}' directory not writable\n"
	  unless -x _ && -w _;
	$opt->{pidfile} = File::Spec->catfile($opt->{pidfile}, 'apache-spamd.pid');
}

if (exists $opt->{k}) {                  # XXX: other option name?  or not?
	die "ERROR: can't use -k with --httpd_conf\n" if exists $opt->{httpd_conf};
	## I'm not sure if this toggle idea is a good one...
	## useful for development.
	$opt->{k} ||= -e $opt->{pidfile} ? 'stop' : 'start';
	die "ERROR: -k start|stop|restart|reload|graceful|graceful-stop"
	  . " or empty for toggle\n"
	  unless $opt->{k} =~ /^(?:start|stop|restart|reload|graceful(?:-stop)?)$/;
}
$opt->{k} ||= 'start';

if (exists $opt->{httpd_conf}) {
	die "ERROR: --httpd_conf must be a regular file\n"
	  if -e $opt->{httpd_conf} && !-f _;
	$opt->{httpd_conf} = File::Spec->rel2abs($opt->{httpd_conf})
	  unless $opt->{httpd_conf} eq '-';
}

unless ($opt->{username}) {
	warn "$0:  Running as root, huh?  Asking for trouble, aren't we?\n" if $< == 0;
	$opt->{username} = getpwuid($>);	# weird apache behaviour on 64bit machines if it's missing
	warn "$0:  setting User to '$opt->{username}', pass --username to override\n"
		if $opt->{debug} =~ /\b(?:all|info|spamd|prefork|config)\b/;
}

#
# start processing command line and preparing config / cmd line for Apache
#

my @directives;    # -C ... (or write these to a temporary config file)
my @run = (        # arguments to exec()
	$opt->{httpd_path},
	'-k', $opt->{k},
	'-d', Cwd::cwd(),    # XXX: smarter... home_dir_for_helpers?
);

if ($opt->{debug} =~ /\ball\b/) {
	push @run,        qw(-e debug);
	push @directives, 'LogLevel debug';
}

push @run, '-X' if !$opt->{daemonize};
push @run, @{ $opt->{httpd_opts} } if exists $opt->{httpd_opts};

push @directives, 'ServerName ' . hostname(),
  qq(PidFile "$opt->{pidfile}"),
  qq(ErrorLog "$opt->{'log-file'}");

#
# only bother with these when we're not stopping
#
if ($opt->{k} !~ /stop|graceful/) {
	my $modlist = join ' ', static_apache_modules($opt->{httpd_path});

	push @directives,
	  'LoadModule perl_module ' . apache_module_path('mod_perl.so')
	  if $modlist !~ /\bmod.perl\.c\b/i;

	# StartServers, MaxClients, etc
	my $mpm = lc(
		(
			$modlist =~ /\b(prefork|worker|mpm_winnt|mpmt_os2
          |mpm_netware|beos|event|metuxmpm|peruser)\.c\b/ix
		)[0]
	);
	die "ERROR: unable to figure out which MPM is in use\n" unless $mpm;
	push @directives, mpm_specific_config($mpm);

	# directives from command line; might require mod_perl.so, so let's
	# ignore these unless we're starting -- shouldn't be critical anyway
	push @directives, @{ $opt->{httpd_directive} }
	  if exists $opt->{httpd_directive};

	push @directives, "TimeOut $opt->{'timeout-tcp'}" if $opt->{'timeout-tcp'};

	# Listen
	push @directives, defined $opt->{'listen-ip'}
	  && @{ $opt->{'listen-ip'} }
	  ? map({ 'Listen ' . ($_ =~ /:/ ? "[$_]" : $_) . ":$opt->{port}" }
		@{ $opt->{'listen-ip'} })
	  : "Listen $opt->{port}";

	if ($opt->{ssl}) {
		push @directives,
		  'LoadModule ssl_module ' . apache_module_path('mod_ssl.so')
		  if $modlist !~ /\bmod.ssl\.c\b/i;    # XXX: are there other variants?
		push @directives, qq(SSLCertificateFile "$opt->{'server-cert'}")
		  if exists $opt->{'server-cert'};
		push @directives, qq(SSLCertificateKeyFile "$opt->{'server-key'}")
		  if exists $opt->{'server-key'};
		push @directives, 'SSLEngine on';
		my $random = -r '/dev/urandom' ? 'file:/dev/urandom 256' : 'builtin';
		push @directives, "SSLRandomSeed startup $random",
		  "SSLRandomSeed connect $random";
		##push @directives, 'SSLProtocol all -SSLv2';       # or v3 only?
	}

	# XXX: available in Apache 2.1+; previously in core (AFAIK);
	# should we parse httpd -v?
	push @directives,
	  'LoadModule ident_module ' . apache_module_path('mod_ident.so'),
	  'IdentityCheck on'
	  if $opt->{'auth-ident'};
	push @directives, "IdentityCheckTimeout $opt->{'ident-timeout'}"
	  if $opt->{'auth-ident'} && defined $opt->{'ident-timeout'};

	# SA stuff
	push @directives,
	  'PerlLoadModule Mail::SpamAssassin::Spamd::Apache2::Config',
	  'SAenabled on';
	push @directives, "SAAllow from @{$opt->{'allowed-ips'}}"
	  if exists $opt->{'allowed-ips'};
	push @directives, 'SAtell on' if $opt->{'allow-tell'};
	push @directives, "SAtimeout $opt->{'timeout-child'}"
	  if exists $opt->{'timeout-child'};
	push @directives, "SAdebug $opt->{debug}" if $opt->{debug};
	push @directives, 'SAident on'
	  if $opt->{'auth-ident'};

	push @directives, qq(SANew rules_filename "$opt->{configpath}")
	  if defined $opt->{configpath};
	push @directives, qq(SANew site_rules_filename "$opt->{siteconfigpath}")
	  if defined $opt->{siteconfigpath};
	push @directives,
	  qq(SANew home_dir_for_helpers "$opt->{home_dir_for_helpers}")
	  if defined $opt->{home_dir_for_helpers};
	push @directives, qq(SANew local_tests_only $opt->{local})
	  if defined $opt->{local};
	push @directives, map qq(SANew $_ "$opt->{$_}"), grep defined $opt->{$_},
	  qw(PREFIX DEF_RULES_DIR LOCAL_RULES_DIR LOCAL_STATE_DIR);
	push @directives, 'SANew paranoid 1' if $opt->{paranoid};
	push @directives, qq(SAConfigLine "$_") for @{ $opt->{cf} };

	my @users;
	push @users, 'local' if $opt->{'user-config'};
	push @users, 'sql'   if $opt->{'sql-config'};
	push @users, 'ldap'  if $opt->{'ldap-config'};
	push @directives, join ' ', 'SAUsers', @users if @users;
}

# write directives to conf file (or STDOUT) and exit
if ($opt->{httpd_conf}) {
	my $fh;
	if ($opt->{httpd_conf} eq '-') {
		open $fh, '>&STDOUT' or die "open >&STDOUT: $!";
	}
	else {
		open $fh, '>', $opt->{httpd_conf}
		  or die "open >'$opt->{httpd_conf}': $!";
	}
	print $fh join "\n",
	  "# generated by $0 on " . localtime(time),
	  @directives,
	  "# vim: filetype=apache\n";
	close $fh or warn "close: $!";
	exit 0;    # user is supposed to run Apache himself
}

#
# add directives to command line and run Apache
#

push @run, '-f',
  File::Spec->devnull(),    # XXX: will work on a non-POSIX platform?
  map { ; '-C' => $_ } @directives;

warn map({ /^-/ ? "\n    $_" : "  $_" } @run), "\n"
  if $opt->{debug} =~ /\ball|spamd|config|info\b/;

undef $opt;                 # there is no DESTROY... but could be one ;-)
exec @run;                  # we are done

#
# helper functions
#

sub get_libexecdir {
	get_libexecdir_A2BC() || get_libexecdir_apxs();
}

# read it from Apache2::BuildConfig
sub get_libexecdir_A2BC {
	$INC{'Apache2/Build.pm'}++;    # hack... needlessly required by BuildConfig
	require Apache2::BuildConfig;
	my $cfg = Apache2::BuildConfig->new;
	$cfg->{APXS_LIBEXECDIR} || $cfg->{MODPERL_APXS_LIBEXECDIR};
}

# `apxs -q LIBEXECDIR`
sub get_libexecdir_apxs {
	my @cmd = (($opt->{apxs} || 'apxs'), '-q', 'LIBEXECDIR');
	chomp(my $modpath = get_cmd_output(@cmd));
	die "ERROR: failed to obtain module path from '@cmd'\n"
	  unless length $modpath;
	die "ERROR: '$modpath' returned by '@cmd' is not an existing directory\n"
	  unless -d $modpath;
	$modpath;
}

# as above, cached version
use vars '$apache_module_path';
sub apache_module_path {
	my $modname = shift;
	$apache_module_path ||= get_libexecdir();    # path is cached
	my $module = File::Spec->catfile($apache_module_path, $modname);
	die "ERROR: '$module' does not exist\n" if !-e $module;
	$module;
}

# httpd -l
# XXX: can MPM be a DSO?
sub static_apache_modules {
	my $httpd = shift;
	my @cmd = ($httpd, '-l');
	my $out = get_cmd_output(@cmd);
	my @modlist = $out =~ /\b(\S+\.c)\b/gi;
	die "ERROR: failed to get list of static modules from '@cmd'\n"
	  unless @modlist;
	@modlist;
}

sub get_cmd_output {
	my @cmd = @_;
	my $output = `@cmd` or die "ERROR: failed to run '@cmd': $!\n";
	$output;
}

sub mpm_specific_config {
	my $mpm = shift;
	my @ret;

	if ($mpm =~ /^prefork|worker|beos|mpmt_os2$/) {
		push @ret, "User $opt->{username}"   if $opt->{username};
		push @ret, "Group $opt->{groupname}" if $opt->{groupname};
	}
	elsif ($opt->{username} || $opt->{groupname}) {
		die "ERROR: username / groupname not supported with MPM $mpm\n";
	}

	if ($mpm eq 'prefork') {
		push @ret, "StartServers $opt->{'min-spare'}";
		push @ret, "MinSpareServers $opt->{'min-spare'}";
		push @ret, "MaxSpareServers $opt->{'max-spare'}";
		push @ret, "MaxClients $opt->{'max-children'}";
	}
	elsif ($mpm eq 'worker') {    # XXX: we could be smarter here
		push @ret, grep length, map { s/^\s+//; s/\s*\b#.*$//; $_ } split /\n/,
		  <<"    EOF";
      StartServers 1
      ServerLimit 1
      MinSpareThreads $opt->{'min-spare'}
      MaxSpareThreads $opt->{'max-spare'}
      ThreadLimit $opt->{'max-children'}
      ThreadsPerChild $opt->{'max-children'}
    EOF
	}
	else {
		warn "WARNING: MPM $mpm not supported, using defaults for performance settings\n";
		warn "WARNING: prepare for huge memory usage and maybe an emergency reboot\n";
	}

	push @ret, "MaxRequestsPerChild $opt->{'max-conn-per-child'}"
	  if defined $opt->{'max-conn-per-child'};

	@ret;
}

# vim: ts=4 sw=4 noet
