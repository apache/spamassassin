package Mail::SpamAssassin::Spamd::Apache2::Config;
use strict;

use Apache2::ServerUtil ();
my $server = Apache2::ServerUtil->server() or die 'serverutil->server';
$server->push_handlers(
  PerlPostConfigHandler => [\&post_config, \&add_version_string,],);

=head1 NAME

Mail::SpamAssassin::Spamd::Apache2::Config -- configure Apache with SpamAssassin

=head1 SYNOPSIS

 LoadModule     perl_module     modules/mod_perl.so
 PerlLoadModule Mail::SpamAssassin::Spamd::Apache2::Config
 SAEnabled      On      # default off

 SAAllow from   127.0.0.1 192.168.0.0/24 ::1
 SAIdent        Off
 SATell         Off
 SATimeout      300     # reasonable: around 30s
 SADebug        info
 SAMsgSizeLimit 512000

=head1 DESCRIPTION

Provides Apache config directives for configuring spamd.  Initializes the
L<Mail::SpamAssassin> object.

Note, that the defaults here apply to *this* code; L<apache-spamd.pl(1)>
sets different ones to be compatible with L<spamd(1)>.

=head1 DIRECTIVES

=over

=cut

use Apache2::Module   ();
use Apache2::CmdParms ();
use Apache2::Const -compile =>
  qw(OK RSRC_CONF ITERATE ITERATE2 FLAG TAKE1 TAKE2 :log SERVER_ERROR);

{
  my @directives;

=item C<SAEnabled { On | Off }>

Enables / disables SA for given vhost.  Adds two handlers:

 SetHandler modperl
 PerlProcessConnectionHandler Mail::SpamAssassin::Spamd::Apache2
 PerlPreConnectionHandler     Mail::SpamAssassin::Spamd::Apache2::AclIP

Defaults to Off.

=cut

push @directives, {    # not inherited
  name         => 'SAEnabled',
  args_how     => Apache2::Const::FLAG,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SAEnable { On | Off }',
};

=item C<SAAllow from 127.0.0.1 192.168/16 ::1 ...>

Similar to C<Allow from ...> directive from C<mod_authz_vhost>.  Spamd's
C<--allowed-ips> arguments should go here.

Default is empty, meaning access is denied.

=cut

push @directives, {    # inherited
  name         => 'SAAllow',
  args_how     => Apache2::Const::ITERATE2,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SAAllow from 127.0.0.1 192.168/16 ::1 ...',
};

=item C<SAIdent { On | Off }>

Enables RFC 1413 (ident) checks incoming connections.  Note, that checking
if a *remote* login matches a *local* one is usually pointless.  See
L<Mail::SpamAssassin::Apache2::AclRFC1413(3)> for more details.

Adds a handler:

 PerlPreConnectionHandler     Mail::SpamAssassin::Spamd::Apache2::AclRFC1413

Requires C<IdentityCheck on> in current configuration scope.  This directive
is provided by the C<mod_ident> module, separated from core in Apache 2.1.

Default off.

=cut

push @directives, {    # inherited
  name         => 'SAIdent',
  args_how     => Apache2::Const::FLAG,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SAIdent { On | Off }',
};

=item C<SATell { On | Off }>

Allow clients to issue the C<TELL> command.  Default off.

=cut

push @directives, {    # inherited
  name         => 'SATell',
  args_how     => Apache2::Const::FLAG,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SATell { On | Off }',
};

=item C<SATimeout 300>

Timeout for SpamAssassin checks.  25 seconds is a reasonable value.

Default C<0> (unlimited).

=cut

push @directives, {    # inherited
  name         => 'SATimeout',
  args_how     => Apache2::Const::TAKE1,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SATimeout 300  # unit: seconds',
};

=item C<SADebug debug_level>

Debug level for SpamAssassin.

=cut

push @directives, {    # inherited
  name         => 'SADebug',
  args_how     => Apache2::Const::TAKE1,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SADebug { debug_level | 0 }',
};

=item C<SAMsgSizeLimit 512000>

Maximum message size which will be processed.  You're strongly encouraged to
set this value.  Unit: bytes.

=cut

push @directives, {    # inherited
  name => 'SAMsgSizeLimit',
  args_how     => Apache2::Const::TAKE1,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SAMsgSizeLimit limit_in_bytes',
};

=item C<SANew key "value">

Additional arguments to C<Mail::SpamAssassin->new()>.  Refer to
L<Mail::SpamAssassin(3)>.

=cut

push @directives, {
  name => 'SANew',
  args_how     => Apache2::Const::TAKE2,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SANew rules_filename "/some/path"',
};

=item C<SAUsers { none | local | sql | ldap }>

Databases which should be checked for user information.
Will be checked in the order specified.

Default C<none>.

=cut

push @directives, {    # inherited
  name         => 'SAUsers',
  args_how     => Apache2::Const::ITERATE,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SAUsers { none | local | sql | ldap }',
};

=item C<SALocale xx_XX>

Value of the LANG environment variable SpamAssassin should run with.

Default C<none>, unless you set Apache otherwise somehow.

=cut

push @directives, {    # inherited
  name         => 'SALocale',
  args_how     => Apache2::Const::TAKE1,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SALocale xx_XX',
};

=item C<SAConfigLine "config line">

Equivalent of the C<--cf> option for spamassassin / spamd / sa-learn.

=cut

push @directives, {    # inherited
  name         => 'SAConfigLine',
  args_how     => Apache2::Const::TAKE1,
  req_override => Apache2::Const::RSRC_CONF,
  errmsg       => 'SAConfigLine "body NEWRULE /text/"',
};

  Apache2::Module::add(__PACKAGE__, \@directives);
}

=back

=cut


# executed whenever directive is seen
sub SAEnabled {
  my ($self, $parms, $arg) = @_;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{saenabled} = $arg;
}

sub SAAllow {    # can't use mod_authz_host; it is HTTP-centric
  my ($self, $parms, $key, $val) = @_;
  die 'usage: SAAllow from ... ... ...' unless $key eq 'from';
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  push @{ $srv_cfg->{allowed_ips} }, $val;
}

sub SAIdent {
  my ($self, $parms, $arg) = @_;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{auth_ident} = $arg;
}

sub SATell {
  my ($self, $parms, $arg) = @_;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{allow_tell} = $arg;
}

sub SATimeout {
  my ($self, $parms, $arg) = @_;
  die "SATimeout accepts *seconds*\n" if $arg !~ /^\d+$/;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{satimeout} = $arg;
}

sub SADebug {
  my ($self, $parms, $arg) = @_;
  die "SADebug can't be used in vhost, see bug #4963\n"
    if $parms->server->is_virtual;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{sa_debug} = $arg;
}

sub SAMsgSizeLimit {
  my ($self, $parms, $arg) = @_;
  die "MsgSizeLimit accepts *number*\n" if $arg !~ /^\d+$/;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{msg_size_limit} = $arg;
}

sub SANew {
  my ($self, $parms, $key, $val) = @_;
  die "SANew can't be used in vhost, see bug #4963\n"
    if $parms->server->is_virtual;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{sa_args_to_new}->{$key} = $val;
}

sub SAUsers {
  my ($self, $parms, $arg) = @_;
  $arg = lc $arg;
  die "SAUsers: bad value\n" unless $arg =~ /^(?:none|local|sql|ldap)$/;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  push @{ $srv_cfg->{sa_users} }, $arg;
}


sub SALocale {
  my ($self, $parms, $arg) = @_;
  die "SALocale can't be used in vhost, see bug #4963\n"
    if $parms->server->is_virtual;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{sa_locale} = $arg;
}


sub SAConfigLine {
  my ($self, $parms, $arg) = @_;
  my $srv_cfg = Apache2::Module::get_config($self, $parms->server);
  $srv_cfg->{post_config_text} .=
    ( $srv_cfg->{post_config_text} ? "\n" : '' ) . $arg;
}


# executed after (XXX: not before?) SA* for every server (vhost or main)
sub SERVER_CREATE {
  my ($class, $parms) = @_;
  bless { saenabled => 0, satimeout => 300, }, #msg_size_limit => 500*1024, },
    $class;
}

# executed for every vhost, after processing SAOptions and SERVER_CREATE
sub SERVER_MERGE {
  my ($base, $add) = @_;
  my $new = { saenabled => $add->{saenabled}, };

  # SAallow in vhost completely overrides SAAllow in base, otherwise
  # inherit; maybe not very intuitive, but will do until better idea
  $new->{allowed_ips} =
      exists $add->{allowed_ips}  ? [@{ $add->{allowed_ips} }]
    : exists $base->{allowed_ips} ? [@{ $base->{allowed_ips} }]
    : [warn('warning: access denied for everyone in vhost') && ()];

  for my $opt (
    qw(auth_ident ident_timeout allow_tell
    sa_debug sa_args_to_new sa_users sa_locale)
    )
  {
    $new->{$opt} =
        exists $add->{$opt}  ? $add->{$opt}
      : exists $base->{$opt} ? $base->{$opt}
      : 0;
  }

  $new->{satimeout} =
      exists $add->{satimeout}  ? $add->{satimeout}
    : exists $base->{satimeout} ? $base->{satimeout}
    : die 'should not happen';

  bless $new, ref $base;
}

use APR::Const -compile => qw(:error SUCCESS);
use Apache2::ServerRec ();    # $s->is_virtual
use Apache2::Log       ();
use File::Temp         ();    # tempdir
use File::Path         ();    # rmpath

# PerlPostConfigHandler
sub post_config {
  my ($conf_pool, $log_pool, $temp_pool, $serv) = @_;
  my ($num_vhosts, $num_configured);
  my $hackish_tmp_ref;

  for (my $s = $serv; $s; $s = $s->next) {
    die "\$num_vhosts>5000; loop?" if ++$num_vhosts > 1000;
    my $srv_cfg = Apache2::Module::get_config(__PACKAGE__, $s) || '';

    # hack: if default server is configured with SAEnabled On, and a vhost
    # is not, the vhost inherits On value.  I don't know how to prevent it
    # other way...  check $hackish_tmp_ref use later.       --radek
    $hackish_tmp_ref = $srv_cfg unless $s->is_virtual;

    # is SA enabled for this vhost?
    if (!$srv_cfg->{saenabled}
      or $s->is_virtual && $srv_cfg eq $hackish_tmp_ref)
    {
      my $msg = 'SAEnabled off for ' . _vhost_id($s);

      # it inherits handler too
      $msg .= ' and on in default server; it probably won\'t work as'
        . ' you intend it to -- either Apache or this code is broken'
        if $hackish_tmp_ref->{saenabled} && $srv_cfg && !$srv_cfg->{saenabled};

      $s->log_serror(Apache2::Log::LOG_MARK(),
        Apache2::Const::LOG_DEBUG | Apache2::Const::LOG_STARTUP,
        APR::Const::SUCCESS, $msg);
      next;
    }

    # check options
    if (ref $srv_cfg->{sa_users}
      && grep { $_ eq 'none' } @{ $srv_cfg->{sa_users} })
    {
      if (@{ $srv_cfg->{sa_users} } > 1) {
        die "if you add 'none' to SAUsers, it's pointless to add anything else\n";
      }
      else {
        delete $srv_cfg->{sa_users};
      }
    }

    # create list of allowed networks
    use APR::IpSubnet ();
    for my $net (@{ $srv_cfg->{allowed_ips} }) {
      my $ais = APR::IpSubnet->new($conf_pool, split m#/#, $net, 2)
        or die "APR::IpSubnet->new($net) failed";
      push @{ $srv_cfg->{allowed_networks} }, $ais;
    }

    my @cfg = (
      'SetHandler modperl',
      'PerlProcessConnectionHandler Mail::SpamAssassin::Spamd::Apache2',
      'PerlPreConnectionHandler Mail::SpamAssassin::Spamd::Apache2::AclIP',
    );

    require Mail::SpamAssassin::Spamd::Apache2;
    require Mail::SpamAssassin::Spamd::Apache2::AclIP;

    if ($srv_cfg->{auth_ident}) {
      require Mail::SpamAssassin::Spamd::Apache2::AclRFC1413;
      push @cfg, 'PerlPreConnectionHandler '
        . 'Mail::SpamAssassin::Spamd::Apache2::AclRFC1413';
    }

    $s->add_config(\@cfg);

    if (!$Mail::SpamAssassin::Spamd::Apache2::spamtest) {
      require Mail::SpamAssassin;
      local $/ = $/;    # Razor resets this

      # Is there a way to toggle these settings in handler?  See bug #4963.
      # Problem: if other vhost defined eg. SALocal, it would be silently
      # ignored, as this block executes only for the first SAEnabled seen.
      # Workaround: forcing these settings to be unavailable in vhosts
      # until the bug is resolved.
      my $sa = Mail::SpamAssassin->new({
##      dont_copy_prefs      => $dontcopy,
##      rules_filename       => ($srv_cfg->{configpath} || 0),
##      site_rules_filename  => ($srv_cfg->{siteconfigpath} || 0),
        debug            => ($srv_cfg->{sa_debug} || 0),
##      paranoid             => ($srv_cfg->{paranoid} || 0),
##      PREFIX          => $PREFIX,
##      DEF_RULES_DIR   => $DEF_RULES_DIR,
##      LOCAL_RULES_DIR => $LOCAL_RULES_DIR,
##      LOCAL_STATE_DIR => $LOCAL_STATE_DIR,
        ($srv_cfg->{sa_args_to_new} ? %{ $srv_cfg->{sa_args_to_new} } : ()),
      }) or die 'Mail::SpamAssassin->new() failed';

      # initialize SA configuration
      my $tmphome = File::Temp::tempdir()
        or die "creating temp directory failed: $!";
      my $tmpsadir = File::Spec->catdir($tmphome, '.spamassassin');
      mkdir $tmpsadir, 0700 or die "spamd: cannot create $tmpsadir: $!";
      $ENV{HOME} = $tmphome;
      $sa->compile_now(0, 1);
      delete $ENV{HOME};
      File::Path::rmtree($tmphome);
      $Mail::SpamAssassin::Spamd::Apache2::spamtest = $sa;
      Mail::SpamAssassin::Spamd::backup_config($sa);
    }

    $num_configured++;
    $s->log_serror(Apache2::Log::LOG_MARK(),
      Apache2::Const::LOG_DEBUG | Apache2::Const::LOG_STARTUP,
      APR::Const::SUCCESS,
      'spamd handler configured for ',
      _vhost_id($s)
    );
  }

  if (!$num_configured) {
    $serv->log_serror(Apache2::Log::LOG_MARK(),
      Apache2::Const::LOG_NOTICE | Apache2::Const::LOG_STARTUP,
      APR::Const::EGENERAL, 'no spamd handlers configured');
  }

  return Apache2::Const::OK;
}

sub _vhost_id {
  my $s = shift;    # ServerRec
  $s->is_virtual()
    ? 'vhost ' . $s->server_hostname() . ':' . $s->port()
    : 'default server';
}

# PerlPostConfigHandler
sub add_version_string {
  my ($conf_pool, $log_pool, $temp_pool, $serv) = @_;
  my $version = Mail::SpamAssassin->VERSION || '?';
  $serv->add_version_component("SpamAssassin/$version");
  return Apache2::Const::OK;
}


=head1 EXAMPLES

You'll need some basic Apache directives in each configuration; that should be
obvious.

  PidFile "/var/run/apache-spamd.pid"
  ServerName localhost
  TimeOut 30

  StartServers 1
  MinSpareServers 1
  MaxSpareServers 2
  MaxClients 5
  MaxRequestsPerChild 200

If the Mail::SpamAssassin::* perl modules are installed somewhere outside of
C<@INC>, you can use something like:

  PerlSwitches -I/home/users/someuser/lib

=head2 simple

  Listen 127.0.0.1:30783
  LoadModule perl_module /usr/lib/apache/mod_perl.so
  PerlLoadModule Mail::SpamAssassin::Spamd::Apache2::Config
  SAenabled on
  SAAllow from 127.0.0.1
  SAtimeout 25
  SAdebug info
  SANew DEF_RULES_DIR "/usr/share/spamassassin"
  SANew LOCAL_RULES_DIR "/etc/mail/spamassassin"
  SANew LOCAL_STATE_DIR "/var/lib"
  SAUsers local sql

=head2 vhosts with different config

  Listen 127.0.0.1:30783
  Listen 30784
  LoadModule perl_module /usr/lib/apache/mod_perl.so
  PerlLoadModule Mail::SpamAssassin::Spamd::Apache2::Config
  SAenabled off
  SAtimeout 25
  SAdebug info
  SANew DEF_RULES_DIR "/usr/share/spamassassin"
  SANew LOCAL_RULES_DIR "/etc/mail/spamassassin"
  SANew LOCAL_STATE_DIR "/var/lib"

  LoadModule ident_module /usr/lib/apache/mod_ident.so

  # local, ident-authenticated users only; search in /etc/passwd,
  # if that fails, try SQL
  <VirtualHost _default_:30783>
    IdentityCheck on
    IdentityCheckTimeout 4
    SAenabled on
    SAident on
    SAAllow from 127.0.0.1
    SAUsers local sql
  </VirtualHost>

  # serve for whole LAN, but don't read user configuration
  <VirtualHost _default_:30784>
    SAenabled on
    SAtimeout 30
    SAAllow from 127.0.0.1 192.168.0.0/24
    SAUsers none
  </VirtualHost>

=head1 BUGS

See <http://bugzilla.spamassassin.org/>.

=head1 SEE ALSO

L<httpd(8)>,
L<spamd(1)>,
L<apache-spamd(1)>,
L<Mail::SpamAssassin::Spamd::Apache2(3)>,
L<Mail::SpamAssassin::Spamd::Apache2::AclIP(3)>,
L<Mail::SpamAssassin::Spamd::Apache2::AclRFC1413(3)>

=cut

1;

# vim: ts=2 sw=2 et
