package Mail::SpamAssassin::Spamd::Config;
use strict;

use Mail::SpamAssassin::Util ();
use File::Spec ();
use Getopt::Long qw(GetOptions :config bundling);    # configuration is global

=head1 NAME

Mail::SpamAssassin::Spamd::Config -- parse spamd command line options

=head1 SYNOPSIS

  my $conf = Mail::SpamAssassin::Spamd::Config->new(
    {
      argv     => \@ARGV,
      defaults => { 'user-config' => 0, },
      moreopts => [ qw( foo-option|f=s@ bar-option|b=i ) ],
    }
  );

=head1 DESCRIPTION

This module uses Getopt::Long to parse and validate spamd command line options.

Returns blessed hash reference, containing coherent set of options.
Dies on error.

See source and L<spamd(1)> for list of valid options.

=head1 WARNING

This interface is considered experimental and likely to change.  Notify the dev
list if you're planning to rely on it.

Getopt::Long::Configure is used to modify global L<Getopt::Long(3)>
configuration.  If you don't want C<:bundling> and / or wish to enable /
disable something else for whatever reason... well, keep that in mind.

=head1 BUGS

Error messages are not unified.

See <http://bugzilla.spamassassin.org/>

=head1 SEE ALSO

L<spamd(1)>,
L<apache-spamd(1)>

=cut

my %defaults = (
  'user-config'   => 1,
  'ident-timeout' => 5.0,

  # scaling settings; some of these aren't actually settable via cmdline
  'server-scale-period' => 2,    # how often to scale the # of kids, secs
  'min-children'        => 1,    # min kids to have running
  'min-spare'           => 1,    # min kids that must be spare
  'max-spare'           => 2,    # max kids that should be spare
  'max-children'        => 5,
  'max-conn-per-child'  => 200,
  'timeout-child'       => 300,
  'timeout-tcp'         => 30,

  # substituted at 'make' time
  PREFIX          => '/usr',
  DEF_RULES_DIR   => '/usr/share/spamassassin',
  LOCAL_RULES_DIR => '/etc/mail/spamassassin',
  LOCAL_STATE_DIR => '/var/lib',
);

sub new {
  my ($class, $parms) = @_;
  $parms ||= {};
  die 'usage: ' . __PACKAGE__
    . '->new({ argv=>\@, defaults=>\%, moreopts=>\@ })'
    if ref $parms ne 'HASH'
    or exists $parms->{argv}     && ref $parms->{argv}     ne 'ARRAY'
    or exists $parms->{defaults} && ref $parms->{defaults} ne 'HASH'
    or exists $parms->{moreopts} && ref $parms->{moreopts} ne 'ARRAY';
  $parms->{argv} ||= \@ARGV;

  local *ARGV = [@{ $parms->{argv} }];

  my $self = { exists $parms->{defaults} ? %{ $parms->{defaults} } : () };

  Getopt::Long::Configure('bundling');
  GetOptions(
    $self,

    # !xargs -n1|sort|column|expand
    qw(
      allowed-ips|A=s@                round-robin!
      allow-tell|l                    server-cert=s
      auth-ident                      server-key=s
      cf=s@                           setuid-with-ldap
      configpath|C=s                  setuid-with-sql|Q
      create-prefs|c!                 siteconfigpath=s
      daemonize|d!                    socketgroup=s
      debug|D:s                       socketmode=s
      groupname|g=s                   socketowner=s
      help|h                          socketpath=s
      ident-timeout=f                 sql-config|q!
      ldap-config!                    ssl
      listen-ip|ip-address|i:s@       syslog-socket=s
      local|L!                        syslog|s=s
      max-children|m=i                timeout-child|t=i
      max-conn-per-child=i            timeout-tcp|T=i
      max-spare=i                     user-config!
      min-children=i                  username|u=s
      min-spare=i                     version|V
      paranoid|P!                     virtual-config-dir=s
      pidfile|r=s                     vpopmail|v!
      port|p=s

      home_dir_for_helpers|helper-home-dir|H:s
      PREFIX=s
      DEF_RULES_DIR=s
      LOCAL_RULES_DIR=s
      LOCAL_STATE_DIR=s
      ),

    x => sub { $self->{'user-config'} = 0 },

    # NOTE: These are old options.  We should ignore (but warn about)
    # the ones that are now defaults.  Everything else gets a die (see note2)
    # so the user doesn't get us doing something they didn't expect.
    #
    # NOTE2: 'die' doesn't actually stop the process, GetOptions() catches
    # it, then passes the error on, so we'll end up doing a Usage statement.
    # You can avoid that by doing an explicit exit in the sub.

    # last in 2.3
    'F:i' => sub {
      die "spamd: the -F option has been removed from spamd,",
        " please remove from your commandline and re-run\n";
    },
    'add-from!' => sub {
      die "spamd: the --add-from option has been removed from spamd,",
        " please remove from your commandline and re-run\n";
    },

    # last in 2.4
    'stop-at-threshold|S' => sub {
      warn "spamd: the --stop-at-threshold|-S option has been deprecated",
        " and is no longer supported, ignoring\n";
    },

    (exists $parms->{moreopts} ? @{$parms->{moreopts}} : ()),
  ) or die 'GetOptions() failed';

  # XXX: uncomment this?
  #$self = { map { y/-/_/; $_ => $self->{$_}; } keys %$self };
  bless $self, $class;


  $self->_validate_logging;
  $self->_validate;

  $self;
}


# check & set some factory settings
sub _validate {
  my ($self) = @_;

  # sanity checking on parameters: if --socketpath is used, it means that we're
  # using UNIX domain sockets, none of the IP params are allowed. The code would
  # probably work ok if we didn't check it, but it's better if we detect the
  # error and report it lest the admin find surprises.
  if (exists $self->{'socketpath'}) {
    die "ERROR: --socketpath mutually exclusive with"
      . " --allowed-ips/--ssl/--auth-ident/--port params"
      if exists $self->{'allowed-ips'} && @{ $self->{'allowed-ips'} } > 0
      || exists $self->{'ssl'}
      || exists $self->{'auth-ident'}
      || exists $self->{'port'};
  }
  else {
    die "ERROR: --socketowner/group/mode requires --socketpath param"
      if exists $self->{'socketowner'}
      || exists $self->{'socketgroup'}
      || exists $self->{'socketmode'};

    # These can be changed on command line with -A flag,
    # but only if we're not using UNIX domain sockets
    # warning: no validation here
    $self->{'allowed-ips'} =
      exists $self->{'allowed-ips'} && @{ $self->{'allowed-ips'} }
      ? [map { split /,/, $_; } @{ $self->{'allowed-ips'} }]
      : ['127.0.0.1'];

    $self->{'listen-ip'} =
      !exists $self->{'listen-ip'}
      ? ['127.0.0.1']
      : defined $self->{'listen-ip'} && grep(length, @{ $self->{'listen-ip'} })
        ? [grep length, map { split /,/, $_; } @{ $self->{'listen-ip'} }]
        : undef;          # handle !defined elsewhere
  }

  # bug 2228: make the values of (almost) all parameters which accept file paths
  # absolute, so they are still valid after daemonize()
  for my $opt (
    grep(exists $self->{$_},
    qw(configpath siteconfigpath socketpath pidfile server-cert server-key
       PREFIX DEF_RULES_DIR LOCAL_RULES_DIR LOCAL_STATE_DIR)),
    grep { exists $self->{$_} && $self->{$_} }
    qw(home_dir_for_helpers)    # value is optional
    )
  {
    $self->{$opt} = Mail::SpamAssassin::Util::untaint_file_path(
      File::Spec->rel2abs($self->{$opt})    # rel2abs taints the new value!
    );
  }

  # -d
  for my $opt (
    grep(exists $self->{$_},
    qw(configpath siteconfigpath
       PREFIX DEF_RULES_DIR LOCAL_RULES_DIR LOCAL_STATE_DIR)),
    grep { exists $self->{$_} && $self->{$_} }
    qw(home_dir_for_helpers)    # value is optional
    )
  {
    die "ERROR: --$opt='$self->{$opt}' does not exist or not a directory\n"
      unless -d $self->{$opt};
  }

  # >= 0
  for my $opt (grep exists $self->{$_}, qw(min-spare max-spare)) {
    die "ERROR: --$opt must be >= 0\n" if $self->{$opt} <= 0;
  }

  # >= 1
  for my $opt (
    grep exists $self->{$_},
    qw(timeout-tcp timeout-child min-children max-children max-conn-per-child)
    )
  {
    next if $self->{$opt} >= 1;
    warn "ERROR: --$opt must be >= 1, ignoring\n";    # die?
    delete $self->{$opt};
  }

  # ident-based spamc user authentication
  if ($self->{'auth-ident'}) {
    eval { sub Net::Ident::_export_hooks(); require Net::Ident };
    die "spamd: ident-based authentication requested,",
      " but Net::Ident is unavailable\n"
      if $@;

    if (exists $self->{'ident-timeout'} && $self->{'ident-timeout'} <= 0) {
      die "ERROR: --ident-timeout must be > 0\n";
    }
    ##import Net::Ident qw(ident_lookup);
  }

  # let's not modify %ENV here...
  my $home =
    (exists $ENV{HOME} && defined $ENV{HOME} && -d $ENV{HOME})
    ? $ENV{HOME}
    : undef;

  if (exists $self->{username})
  {    # spamd is going to run as another user, so reset $HOME
    if (my $nh = (getpwnam($self->{username}))[7]) {
      $home = $nh;
    }
    else {
      die "spamd: unable to determine home directory for user"
        . " '$self->{username}'\n";
    }
  }

  if (!exists $self->{home_dir_for_helpers}) {
    die "ERROR: \$HOME='$home' does not exist or not a directory\n"
      unless defined $home && -d $home;
    $self->{home_dir_for_helpers} = $home;
  }

  if (exists $self->{'max-spare'}) {
    if (exists $self->{'min-spare'}) {
      ## emulate Apache behaviour:
      ## http://httpd.apache.org/docs-2.0/mod/prefork.html#maxspareservers
      $self->{'max-spare'} = $self->{'min-spare'} + 1
        if $self->{'max-spare'} < $self->{'min-spare'};
    }
    else {
      $self->{'min-spare'} = $self->{'max-spare'};
    }
  }
  elsif (exists $self->{'min-spare'}) {
    $self->{'max-spare'} = $self->{'min-spare'};
  }

  # set other defaults
  for my $opt (keys %defaults) {
    $self->{$opt} = $defaults{$opt} if !exists $self->{$opt};
  }

  # check for server certs, must be done after setting other defaults
  if ($self->{'ssl'}) {
    $self->{'server-key'}  ||= "$self->{LOCAL_RULES_DIR}/certs/server-key.pem";
    $self->{'server-cert'} ||= "$self->{LOCAL_RULES_DIR}/certs/server-cert.pem";
    eval { require IO::Socket::SSL };
    die "spamd: SSL encryption requested, but IO::Socket::SSL is unavailable\n"
      if $@;
    die "spamd: server key file '$self->{'server-key'}' does not exist\n"
      unless -f $self->{'server-key'};
    die "spamd: server certificate file '$self->{'server-cert'}' does not exist\n"
      unless -f $self->{'server-cert'};
  }

  # XXX: delete LOCAL_{RULES,STATE}_DIR and PREFIX if eq $defaults{$_}?

  1;
}

sub _validate_logging {
  my $self = shift;

  # Enable debugging, if any areas were specified.  We do this already here,
  # accessing some non-public API so we can use the convenient dbg() routine.
  # Don't do this at home (aka any 3rd party tools), kids!
  $self->{debug} ||= 'all' if exists $self->{debug};

  # always turn on at least info-level debugging for spamd
  $self->{debug} ||= 'info';

  $self->{'syslog-socket'} = lc $self->{'syslog-socket'} || 'unix';
  $self->{'log-facility'} = $self->{syslog} || 'mail';

  # This is the default log file; it can be changed on the command line
  # via a --syslog flag containing non-word characters.
  $self->{'log-file'} = 'spamd.log';

  if ($self->{'log-facility'} =~ /[^a-z0-9]/) {
    # A specific log file was given (--syslog=/path/to/file).
    $self->{'log-file'}      = $self->{'log-facility'};
    $self->{'syslog-socket'} = 'file';
  }
  elsif ($self->{'log-facility'} eq 'file') {
    # The generic log file was requested (--syslog=file).
    $self->{'syslog-socket'} = 'file';
  }
  else {
    # The casing is kept only if the facility specified a file.
    $self->{'log-facility'} = lc $self->{'log-facility'};
  }

  if ($self->{'syslog-socket'} eq 'file') {
    # Either above or at the command line the socket was set
    # to 'file' (--syslog-socket=file).
    $self->{'log-facility'} = 'file';
  }
  elsif ($self->{'syslog-socket'} eq 'none') {
    # The socket 'none' (--syslog-socket=none) historically
    # represents logging to STDERR.
    $self->{'log-facility'} = 'stderr';
  }

  # Either above or at the command line the facility was set
  # to 'stderr' (--syslog=stderr).
  $self->{'syslog-socket'} = 'file' if $self->{'log-facility'} eq 'stderr';

  1;
}

sub option {
  my ($self, $opt) = @_;
  return exists $self->{$opt}
    ? $self->{$opt}
    : undef;
}

1;

# vim: ts=8 sw=2 et
