package Mail::SpamAssassin::Spamd;

use vars qw(%conf_backup %msa_backup);

use Mail::SpamAssassin::Logger;
eval { use Time::HiRes qw(time); };

our $SPAMD_VER = '1.3';
our %resphash = (
  EX_OK          => 0,     # no problems
  EX_USAGE       => 64,    # command line usage error
  EX_DATAERR     => 65,    # data format error
  EX_NOINPUT     => 66,    # cannot open input
  EX_NOUSER      => 67,    # addressee unknown
  EX_NOHOST      => 68,    # host name unknown
  EX_UNAVAILABLE => 69,    # service unavailable
  EX_SOFTWARE    => 70,    # internal software error
  EX_OSERR       => 71,    # system error (e.g., can't fork)
  EX_OSFILE      => 72,    # critical OS file missing
  EX_CANTCREAT   => 73,    # can't create (user) output file
  EX_IOERR       => 74,    # input/output error
  EX_TEMPFAIL    => 75,    # temp failure; user is invited to retry
  EX_PROTOCOL    => 76,    # remote error in protocol
  EX_NOPERM      => 77,    # permission denied
  EX_CONFIG      => 78,    # configuration error
  EX_TIMEOUT     => 79,    # read timeout
);

=head1 NAME

Mail::SpamAssassin::Spamd

=head1 SYNOPSIS

 use base qw(Mail::SpamAssassin::Spamd);
 sub ... { ... }
 ...

=head1 DESCRIPTION

This module contains a skeleton for handling client request in spamd
implementation.  Must not be used directly, but subclassed.

An instance should have lifetime of a single request.

Interface is likely to change.

See the source code of L<spamd(1)> and L<Mail::SpamAssassin::Spamd::Apache2(3)>.

=head2 METHODS

=over

=item C<log_connection()>

Call as soon as the connection is accepted.

=cut

sub log_connection {
  my ($self) = @_;
  info(sprintf "connection from %s [%s] at port %s\n",
    $self->_remote_host, $self->_remote_ip, $self->_remote_port);
}

=item C<log_start_work()>

Call after C<parse_msgids()>.

=cut

sub log_start_work {
  my ($self) = @_;
  info(
    sprintf "%s message %s%s for %s:%d\n",
    ($self->{method} eq 'PROCESS' ? 'processing' : 'checking'),
    (defined $self->{msgid}  ? $self->{msgid}           : '(unknown)'),
    (defined $self->{rmsgid} ? 'aka ' . $self->{rmsgid} : ''),
    $self->user,
    $>,
  );
}

=item C<log_end_work()>

Call after C<pass_through_sa()>.

=cut

sub log_end_work {
  my ($self) = @_;
  if ($self->{method} eq 'TELL') {
    my $info_str;
    $info_str .= 'Setting' . join ',', @{ $self->{did_set} }
      if @{ $self->{did_set} };
    $info_str .= 'Removing' . join ',', @{ $self->{did_remove} }
      if @{ $self->{did_remove} };
    info(
      sprintf 'spamd: Tell: %s for $current_user:%d in'
        . ' %.1f seconds, %d bytes',
      (defined $info_str ? $info_str : 'Did nothing'),
      $>,
      $self->{scan_time},
      $self->{actual_length},
    );
  }
  else {
    info(
      sprintf "%s (%.1f/%.1f) for %s:%d in %.1f seconds, %d bytes.\n",
      ($self->status->is_spam ? 'identified spam' : 'clean message'),
      $self->status->get_score,
      $self->status->get_required_score,
      $self->user,
      $>,
      $self->{scan_time},
      $self->{actual_length},
    );
  }
}

=item C<log_result()>

Call as late as possible, after sending response to the client.

=cut

sub log_result {
  my ($self) = @_;
  my @extra = (
    'scantime=' . sprintf('%.1f', $_[0]->{scan_time}),
    'size=' . $self->{actual_length},
    'user=' . $self->user,
    'uid=' . $>,
    'required_score=' . $self->status->get_required_score,
    'rhost=' . $self->_remote_host,
    'raddr=' . $self->_remote_ip,
    'rport=' . $self->_remote_port,
  );
  {
    (my $safe = defined $self->{msgid} ? $self->{msgid} : '(unknown)') =~
      s/[\x00-\x20\s,]/_/gs;
    push @extra, "mid=$safe";
  }
  if ($self->{rmsgid}) {
    (my $safe = $self->{rmsgid}) =~ s/[\x00-\x20\s,]/_/gs;
    push @extra, "rmid=$safe";
  }
  push @extra, "bayes=" . $self->status->{bayes_score}
    if defined $self->status->{bayes_score};
  push @extra, "autolearn=" . $self->status->get_autolearn_status;
  my $yorn = $self->status->is_spam ? 'Y' : '.';
  my $tests = join ",", sort grep length, $self->status->get_names_of_tests_hit;
  access_info(sprintf "result: %s %2d - %s %s\n",
    $yorn, $self->status->get_score, $tests, join ',', @extra);
}


=item C<check_headers()>

Sanity checks on headers sent by the client.
Sends status line indicating error to the client and returns false on
first problem found.

=cut

sub check_headers {
  my $self = shift;

  if ($self->cfg->{auth_ident}) {
    unless (exists $self->headers_in->{user}) {
      $self->service_unavailable_error('User header required');
      return 0;
    }
    $self->auth_ident($self->headers_in->{user})
      or return 0;
  }

  my $content_length = $self->headers_in->{content_length};
  if (defined $content_length) {    # sanity check
    if ( $content_length !~ /^\d{1,15}$/
      || $content_length == 0)
    {
      $self->protocol_error('Content-Length too ugly');
      return 0;
    }
    elsif ($self->cfg->{msg_size_limit}
      && $content_length > $self->cfg->{msg_size_limit})
    {
      $self->service_unavailable_error('Content-Length exceeds limit');
      return 0;
    }
  }


  if ($self->cfg->{allow_tell} && $self->{method} eq 'TELL') {
    my ($set_local, $set_remote, $remove_local, $remove_remote) = (
      $self->headers_in->{set}    =~ /local/,
      $self->headers_in->{set}    =~ /remote/,
      $self->headers_in->{remove} =~ /local/,
      $self->headers_in->{remove} =~ /remote/,
    );

    if ($set_local && $remove_local) {
      $self->protocol_error(
        "Unable to set local and remove local in the same operation.");
      return 0;
    }

    if ($set_remote && $remove_remote) {
      $self->protocol_error(
        "Unable to set remote and remove remote in the same operation.");
      return 0;
    }
  }

  1;
}


=item C<parse_msgids()>

Extract the Message-Id(s) for logging purposes.

=cut

sub parse_msgids {
  my $self = shift;

  # Extract the Message-Id(s) for logging purposes.
  $self->{msgid}  = $self->{parsed}->get_pristine_header("Message-Id");
  $self->{rmsgid} = $self->{parsed}->get_pristine_header("Resent-Message-Id");

  foreach my $id (grep $self->{$_}, qw(msgid rmsgid)) {
    1 while $self->{$id} =~ s/\([^\(\)]*\)//;    # remove comments and
    $self->{$id} =~ s/^\s+|\s+$//g;          # leading and trailing spaces
    $self->{$id} =~ s/\s+/ /g;               # collapse whitespaces
    $self->{$id} =~ s/^.*?<(.*?)>.*$/$1/;    # keep only the id itself
    $self->{$id} =~ s/[^\x21-\x7e]/?/g;      # replace all weird chars
    $self->{$id} =~ s/[<>]/?/g;              # plus all dangling angle brackets
    $self->{$id} =~ s/^(.+)$/<$1>/;          # re-bracket the id (if not empty)
  }
}


=item C<service_unavailable_error('error message')>

=item C<protocol_error('error message')>

=item C<service_timeout('error message')>

Send appropiate status line to the client and log the error.

=cut

sub service_unavailable_error { 
  my $self = shift;
  my $msg = join '', @_;
  $self->send_status_line('EX_UNAVAILABLE', $msg);
  warn "spamd: service unavailable: $msg\n";
}

sub protocol_error { 
  my $self = shift;
  my $msg = join '', @_;
  $self->send_status_line('EX_PROTOCOL', $msg);
  warn "spamd: bad protocol: header error: $msg\n";
}

sub service_timeout {
  my $self = shift;
  my $msg = join '', @_;
  $self->send_status_line('EX_TIMEOUT', $msg);
  warn "spamd: timeout: $msg\n";
}

=item C<send_status_line('EX_FOO', 'message')>

EX_error constant defaults to C<EX_OK>.
Message defaults to the name of the constant.

=cut

sub send_status_line { 
  my $self = shift;
  my ($resp, $msg) = @_;
  $resp = defined $resp ? $resp : 'EX_OK';
  $msg  = defined $msg  ? $msg  : $resp;
  $self->send_buffer("SPAMD/$SPAMD_VER $resphash{$resp} $msg\r\n");
}


=item C<send_response()>

Generates response (headers and body, no status line) to the request and sends
it to the client.

=cut

sub send_response { 
  my $self = shift;
  my $msg_resp = '';

  if ($self->{method} eq 'PROCESS') {
    $self->status->set_tag('REMOTEHOSTNAME', $self->_remote_host);
    $self->status->set_tag('REMOTEHOSTADDR', $self->_remote_ip);

    # Build the message to send back and measure it
    $msg_resp = $self->status->rewrite_mail;
    #$self->status->finish;
    #delete $self->{status};

    # Spamc protocol 1.3 means multi hdrs are OK
    $self->send_buffer($self->spamhdr)
      if $self->{client_version} >= 1.3;

    # Spamc protocol 1.2 means it accepts content-length
    # Earlier than 1.2 didn't accept content-length
    $self->send_buffer('Content-length: ' . length($msg_resp) . "\r\n\r\n")
      if $self->{client_version} >= 1.2;
  }
  elsif ($self->{method} eq 'TELL') {
    my $response;
    $response .= 'DidSet: ' . join(',', @{ $self->{did_set} }) . "\r\n"
      if @{ $self->{did_set} };
    $response .= 'DidRemove: ' . join(',', @{ $self->{did_remove} }) . "\r\n"
      if @{ $self->{did_remove} };
    $self->send_buffer($response, "Content-Length: 0\r\n", "\r\n");
  }
  else {                   # $method eq 'CHECK' et al
    if ($self->{method} eq 'CHECK') {
      ## just headers
    }
    elsif ($self->{method} eq 'REPORT'
      or $self->{method} eq 'REPORT_IFSPAM' && $self->status->is_spam)
    {
      $msg_resp = $self->status->get_report;
    }
    elsif ($self->{method} eq 'REPORT_IFSPAM') {
      ## message is ham, $msg_resp remains empty
    }
    elsif ($self->{method} eq 'SYMBOLS') {
      $msg_resp = $self->status->get_names_of_tests_hit;
      $msg_resp .= "\r\n" if $self->{client_version} < 1.3;
    }
    else {    # FIXME: this should *never* happen, yet it does...
      die "spamd: unknown method '$self->{method}'";
    }

    # Spamc protocol 1.3 means multi hdrs are OK
    $self->send_buffer('Content-length: ' . length($msg_resp) . "\r\n")
      if $self->{client_version} >= 1.3;
    $self->send_buffer($self->spamhdr, "\r\n");
  }

  $self->send_buffer($msg_resp);

  # any better place to do it?
  $self->{scan_time} = time - $self->{start_time};
}

=item C<pass_through_sa()>

Runs the actual tests.  Wrap it with C<eval()> to implement timeout.

=cut

sub pass_through_sa {
  my $self = shift;

  if ($self->{method} eq 'TELL') {

    # bleh, three copies of the message here... :-/
    # do it in read_body?
    if ($self->{parsed}->get_header("X-Spam-Checker-Version")) {
      my $new_mail =
        $self->spamtest->parse(
        $self->spamtest->remove_spamassassin_markup($self->{parsed}), 1);
      $self->{parsed}->finish;
      $self->{parsed} = $new_mail;
    }

    my ($set_local, $set_remote, $remove_local, $remove_remote) = (
      $self->headers_in->{set}    =~ /local/,
      $self->headers_in->{set}    =~ /remote/,
      $self->headers_in->{remove} =~ /local/,
      $self->headers_in->{remove} =~ /remote/,
    );

    if ($set_local) {
      my $status =
        $self->spamtest->learn($mail, undef,
        ($self->headers_in->{message_class} eq 'spam' ? 1 : 0), 0);
      push @{ $self->{did_set} }, 'local' if $status->did_learn;
      $status->finish;
    }

    if ($remove_local) {
      my $status = $self->spamtest->learn($mail, undef, undef, 1);
      push @{ $self->{did_remove} }, 'local' if $status->did_learn;
      $status->finish;
    }

    if ($set_remote) {
      require Mail::SpamAssassin::Reporter;
      my $msgrpt =
        Mail::SpamAssassin::Reporter->new($self->spamtest, $self->{parsed});
      push @{ $self->{did_set} }, 'remote' if $msgrpt->report;
    }

    if ($remove_remote) {
      require Mail::SpamAssassin::Reporter;
      my $msgrpt =
        Mail::SpamAssassin::Reporter->new($self->spamtest, $self->{parsed});
      push @{ $self->{did_remove} }, 'remote' if $msgrpt->revoke;
    }
  }
  else {
    $self->{status} = $self->spamtest->check($self->{parsed})
      unless $self->{method} eq 'TELL';
  }

  # we don't access this object anymore, but can't destroy
  # it yet or something will complain... a lot.
  $self->{parsed}->finish;
}


=item C<spamhdr()>

Generates the C<Spam: status ; score / threshold> response header.

=cut

sub spamhdr { 
  my $self = shift;

  my $msg_score     = sprintf('%.1f', $self->status->get_score);
  my $msg_threshold = sprintf('%.1f', $self->status->get_required_score);

  my $response_spam_status;
  if ($self->status->is_spam) {
    $response_spam_status =
      $self->{method} eq 'REPORT_IFSPAM' ? 'Yes' : 'True';
  }
  else {
    $response_spam_status =
      $self->{method} eq 'REPORT_IFSPAM' ? 'No' : 'False';
  }

  return "Spam: $response_spam_status ; $msg_score / $msg_threshold\r\n";
}



=item C<read_user_config()>

Read config for the current user and register a cleanup handler to
restore state of the SA object later.  This is a wrapper around the
handle_user_* methods.

=cut

# Yes, I could have made %mapping non-lexical, so one could add something
# there.  But I don't think it would be the right way to provide this
# functionality; contact the dev list if you need it.
{
  my %mapping = (
    'local' => 'handle_user_local',
    'sql'   => 'handle_user_sql',
    'ldap'  => 'handle_user_ldap',
  );

  # This function should run only once per connection (reason: cleanup_register).
  sub read_user_config {
    my $self = shift;
    return unless defined $self->headers_in->{user};
    for my $src (
      grep $self->can($_),
      map { exists $mapping{$_} ? $mapping{$_} : $_ }
      @{ $self->cfg->{sa_users} }
      )
    {
      my $ret = $self->$src($self->headers_in->{user});
      next unless $ret;
      $self->cleanup_register(\&restore_config, $self->spamtest);
      return $ret;
    }
    return 0;
  }
}

=item C<handle_user_sql('username')>

load_scoreonly_sql for the given user.
Do not call this directly.

=cut

sub handle_user_sql { 
  my $self = shift;
  my ($username) = @_;
  $self->spamtest->load_scoreonly_sql($username)
    or return 0;
  $self->spamtest->signal_user_changed({ username => $username, user_dir => undef, });
  return 1;
}

=item C<handle_user_ldap()>

load_scoreonly_ldap for the given user.
Do not call this directly.

=cut

sub handle_user_ldap { 
  my $self = shift;
  my ($username) = @_;
  dbg("ldap: entering handle_user_ldap($username)");
  $self->spamtest->load_scoreonly_ldap($username)
    or return 0;
  $self->spamtest->signal_user_changed({ username => $username, user_dir => undef, });
  return 1;
}


=item C<status()>

Returns the Mail::SpamAssassin::PerMsgStatus object.  Only valid after
C<pass_through_sa()>.

=item C<spamtest()>

Returns the Mail::SpamAssassin object.

=cut

sub status   { $_[0]->{status} }      
sub spamtest { $_[0]->{spamtest} }    

=item C<access_info()>

=cut

sub access_info { info(@_) }              

=item C<user()>

Returns username as supplied by client in the User header or string
'(unknown)'.  Use for logging purposes.

=cut

# FIXME: tidy this one, might contain trash
sub user {    
  defined $_[0]->headers_in->{user} ? $_[0]->headers_in->{user} : '(unknown)';
}

=item C<cfg()>

Returns Mail::SpamAssassin::Spamd::Config object (or hash reference with
resembling values).

=cut

sub cfg { $_[0]->{cfg} }

=item C<headers_in()>

Hash ref containing headers sent by the client.

=cut

sub headers_in { $_[0]->{headers_in} }

=item C<cleanup_register(sub { ... }, $argument)>

APR::Pool functionality -- call a piece of code when the object is
destroyed.

=cut

sub cleanup_register {
  my $self = shift;
  $self->{pool} ||= Mail::SpamAssassin::Pool->new;
  $self->{pool}->cleanup_register(@_);
}





=back

The following methods must be overloaded:

=over

=cut

=item C<_remote_host()>

=item C<_remote_ip()>

=item C<_remote_port()>

Information about the client.

=item C<new( spamtest => $sa_object, foo => 'bar', ... )>

Creates new object; C<shift && bless { @_ }>, basically.

=item C<handle_user_local('username')>

read_scoreonly_config for the given user.  You might want to change uid,
chdir, set $ENV, etc.  Do not call this directly.

=item C<read_body()>

Read body from the client, run $self->spamtest->parse and store result
as the C<parsed> key.

=item C<read_headers()>

Read method and headers from the client.  Set various properties
accordingly.

=item C<send_buffer('list of', 'buffers to send')>

Send buffers to the client.

=item C<auth_ident()>

XXX

=cut




#
# we need these two functions until SA has some sort of config namespace
#

# called in Config/Apache2.pm
# (yuck, at least 500K wasted memory... for each interpreter)
sub backup_config { # -: a
  my $spamtest = shift;
  for my $key (qw(username user_dir userstate_dir learn_to_journal)) {
    $msa_backup{$key} = $spamtest->{$key} if exists $spamtest->{$key};
  }
  $spamtest->copy_config(undef, \%conf_backup)
    || die "spamd: error returned from copy_config\n";
}

# this should be registered as $c->pool->cleanup_register if we add some user
# config;  warning: if we'll ever support persistent connections, this should
# be done in the request pool (or behaviour defined in some other way)
sub restore_config { # -: a
  my $spamtest = shift;
  for my $key (keys %msa_backup) {
    $spamtest->{$key} = $msa_backup{$key};
  }
  $spamtest->copy_config(\%conf_backup, undef)
    || die "spamd: error returned from copy_config\n";
}




# simulate APR::Pool
package Mail::SpamAssassin::Pool;
{
  local $@;
  eval { require APR::Pool; };
}

sub new {
  $INC{'APR/Pool.pm'} ? APR::Pool->new : bless [], shift;
}

sub cleanup_register {
  my $self = shift;
  push @$self, [@_];
}

sub DESTROY {
  my $self = shift;
  for my $cleaner (@$self) {
    (shift @$cleaner)->(@$cleaner);
  }
}

1;

# vim: ts=2 sw=2 et
