package Mail::SpamAssassin::Spamd::Apache2;
use strict;

use Apache2::Const -compile =>
  qw(OK FORBIDDEN NOT_FOUND MODE_GETLINE MODE_READBYTES SERVER_ERROR);
use Apache2::Connection ();
use Apache2::Filter     ();
use Apache2::Module     ();
use Apache2::ServerRec  ();
use Apache2::ServerUtil ();

use APR::Const -compile => qw(SUCCESS SO_NONBLOCK BLOCK_READ);
use APR::Brigade  ();
use APR::Bucket   ();
use APR::Error    ();
use APR::Pool     ();    # cleanup_register
use APR::SockAddr ();
use APR::Socket   ();
use APR::Status   ();

eval { use Time::HiRes qw(time); };

use vars qw($spamtest);

use Mail::SpamAssassin ();
use Mail::SpamAssassin::Message ();
use Mail::SpamAssassin::PerMsgStatus ();
use Mail::SpamAssassin::Logger;

use base qw(Mail::SpamAssassin::Spamd);

=head1 NAME

Mail::SpamAssassin::Spamd::Apache2 -- spamd protocol handler for Apache2

=head1 SYNOPSIS

  SetHandler modperl
  PerlProcessConnectionHandler Mail::SpamAssassin::Spamd::Apache2

=head1 DESCRIPTION

What is this obsession with documentation?  Don't you have the source?
                           -- Michael G Schwern on makemaker@perl.org

This is a protocol handler, to be run as C<PerlProcessConnectionHandler>.  It's
different from regular HTTP handlers (C<PerlResponseHandler>) -- we don't have
the C<$r> object (unless we create it) and the only other run-time Apache hook
which will run is C<PerlPreConnectionHandler>.

This means you can't use modules which hook themselves in, for example,
C<PerlAccessHandler>.  If there is a clean way to enable it, don't hesitate to
drop me an e-mail.

=head1 INTERNALS

handler() runs read_headers(), then check_headers().  If the User header has
been provided by the client and user configuration has been enabled, it runs
read_user_config().  Then it reads body, passes it through SA and sends reply.

=cut

sub handler { # -: c
  my ($c) = @_;    # Apache2::Connection
  $c->client_socket->opt_set(APR::Const::SO_NONBLOCK => 0);    # ?

  my $self = __PACKAGE__->new(c => $c, spamtest => $spamtest, pool => $c->pool);
  $self->log_connection;

  # we might be done after this in case of client error or SKIP / PING
  if (defined(my $ret = $self->read_headers)) {
    return $ret;
  }

  $self->check_headers
    or return Apache2::Const::FORBIDDEN;

  # should we complain if returns 0 and --paranoid?
  $self->read_user_config;

  if (defined(my $ret = $self->read_body)) {
    return $ret;
  }

  $self->parse_msgids;

  $self->log_start_work;

  eval {
    if ($self->cfg->{satimeout}) {
      local $SIG{ALRM} = sub { die 'child processing timeout' };
      alarm $self->cfg->{satimeout};
      $self->pass_through_sa; # do the checking
      alarm 0;
    }
    else {
      $self->pass_through_sa; # do the checking
    }
  };

  if ($@) {
    if ( $@ =~ /child processing timeout/ ) {
      $self->service_timeout(
        sprintf '(%d second timeout while trying to %s)',
        $self->cfg->{satimeout},
        $self->{method}
      );
    }
    else {
      warn "spamd: $@";
    }
    return Apache2::Const::SERVER_ERROR;
  }

  $self->send_status_line('EX_OK');
  $self->send_response;
  $self->log_end_work;
  $self->log_result;

  return Apache2::Const::OK;
}



sub new {    # -: A
  my $class = shift;
  my $self  = {@_};    # requires: c, spamtest
  $self->{start_time} ||= time;
  bless $self, (ref $class || $class);
  ##$self->{c} ||= $self->r->connection if $self->r;
  $self->{in}  ||= APR::Brigade->new($self->c->pool, $self->c->bucket_alloc);
  $self->{out} ||= APR::Brigade->new($self->c->pool, $self->c->bucket_alloc);
  $self->{cfg} ||=
    Apache2::Module::get_config('Mail::SpamAssassin::Spamd::Apache2::Config',
    $self->_server);
  $self->{headers_in} ||= {};
  $self;
}


sub DESTROY { # -: a
  my $self = shift;
  if (exists $self->{parsed}) {
    delete $self->{parsed};
    $self->{parsed}->finish if $self->{parsed}; # can't do it before status->rewrite_mail
  }
  if (exists $self->{status}) {
    $self->status->finish if $self->status;
    delete $self->{status};
  }
  $self->in->destroy;
  $self->out->destroy;
}


sub c       { $_[0]->{c} }          # -: A
sub in      { $_[0]->{in} }         # -: a
sub out     { $_[0]->{out} }        # -: a

sub _server      { $_[0]->c->base_server }          # -: a
sub _remote_host { $_[0]->c->get_remote_host }      # -: a
sub _remote_ip   { $_[0]->c->remote_ip }            # -: a
sub _remote_port { $_[0]->c->remote_addr->port }    # -: a


sub send_buffer { # -: A
  my $self = shift;
  for my $buffer (@_) {
    $self->out->insert_tail(APR::Bucket->new($self->out->bucket_alloc, $buffer));
  }
  $self->c->output_filters->fflush($self->out);
}


sub auth_ident { # -: 
  my $self = shift;
  my ($username) = @_;
  my $ident_username =
    Mail::SpamAssassin::Spamd::Apache2::AclRFC1413::get_ident($username);
  my $dn = $ident_username || 'NONE';    # display name
  # we might also log $c->remote_addr->ip_get(), $c->remote_addr->port()
  # dbg("ident: ident_username = $dn, spamc_username = $username\n");
  if (!defined($ident_username) || $username ne $ident_username) {
    info( "ident username ($dn) does not match "
        . "spamc username ($username)");
    return 0;
  }
  1;
}


#sub read_line {  # -: A
#  my $self = shift;
#}


sub getline {
  my $self = shift;
  my $rc   =
    $self->c->input_filters->get_brigade($self->in,
    Apache2::Const::MODE_GETLINE);
  last if APR::Status::is_EOF($rc);
  die APR::Error::strerror($rc) unless $rc == APR::Const::SUCCESS;
  next unless $self->in->flatten(my $line);
  $self->in->cleanup;
  $line =~ y/\r\n//d;
  return $line;
}



sub read_headers { # -: A
  my $self = shift;
  my $line_num;
  while (my $line = $self->getline) {

    # XXX: lower this to 10?
    if (++$line_num > 255) {
      $self->protocol_error('(too many headers)');
      return Apache2::Const::FORBIDDEN;
    }

    if (length $line > 200) {
      $self->protocol_error('(line too long)' . length $line);
      return Apache2::Const::FORBIDDEN;
    }

    # get method name
    unless ($self->{method}) {
      if ($line =~ /^(SKIP|PING|PROCESS|CHECK|SYMBOLS|REPORT|HEADERS|REPORT_IFSPAM|TELL)
                    \ SPAMC\/(\d{1,2}\.\d{1,3})\b/x) {
        $self->{method} = $1;
        $self->{client_version} = $2;
        if ($self->{method} eq 'PING') {
          $self->send_status_line('EX_OK', 'PONG');
          return Apache2::Const::OK;
        }
        elsif ($self->{method} eq 'SKIP') {
          return Apache2::Const::OK;
        }
        elsif ($self->{method} eq 'TELL' && !$self->cfg->{allow_tell}) {
          $self->service_unavailable_error('TELL commands have not been enabled.');
          return Apache2::Const::FORBIDDEN;
        }
        next;
      }
      elsif ($line =~ /^GET /) { # treat this like ping
        $self->send_buffer(
          join "\r\n",
          'HTTP/1.0 200 SA running',
          'Content-Type: text/plain',
          'Content-Length: 0', ''
        );
        return Apache2::Const::OK;
      }
      $self->protocol_error('method required' . ": '$line'");
      return Apache2::Const::NOT_FOUND;    # something more reasonable?
    }

    last unless length $line;    # end of headers

    # get headers, ignore unknown
    my ($header, $value) = split /:\s+/, $line, 2;
    unless (defined $header && length $header
         && defined $value  && length $value) {
      $self->protocol_error("(header not in 'Name: value' format)");
      return Apache2::Const::FORBIDDEN;
    }

    return Apache2::Const::FORBIDDEN
      if $header =~ /[^a-z\d_-]/i || $value =~ /[^\x20-\xFF]/;    # naughty

    if ($header =~ /^(?:Content-[Ll]ength|User|Message-[Cc]lass|Set|Remove)$/) {
      $header =~ y/A-Z-/a-z_/;
      $self->headers_in->{$header} = $value;
    }
    else {    # FIXME: remove
      warn "unknown header: '$header'='$value'";
    }
  }
  undef;
}


sub read_body { # -: A
  my $self = shift;
  my ($message, $len) = ('', 0);
  my $content_length = $self->headers_in->{content_length};

  while (1) {
    my $rc =
      $self->c->input_filters->get_brigade($self->in, Apache2::Const::MODE_READBYTES,
      APR::Const::BLOCK_READ,
      ($content_length ? $content_length - $len : ()));
    last if APR::Status::is_EOF($rc);
    die APR::Error::strerror($rc) unless $rc == APR::Const::SUCCESS;    # timeout
    next unless $self->in->flatten(my $chunk);
    $self->in->cleanup;

    my $chlen = length $chunk;
    $len += $chlen;

    # this is never true, actually...  get_brigade ensures we won't get
    # more bytes...  well, at least it's logically correct. ;-)
    # we could check if $message ends with "\n" to detect weird cases.
    if ($content_length && $len > $content_length) {
      $self->protocol_error('(Content-Length mismatch: Expected'
          . " $content_length bytes, got $len bytes");
      return Apache2::Const::FORBIDDEN;
    }

    $message .= $chunk;
    last if $content_length && $len == $content_length;
  }

  $self->{actual_length} = $len;
  $self->{parsed} = $self->spamtest->parse($message , 0);

  undef;
}




#
# Code to deal with user configuration.
#
# Run handle_* directly (ie. not from read_user_config) only if you know
# what you are doing.
#
# Change handle_* to return undef if not found and 0 if something's wrong?
#


sub handle_user_local { # -: a
  require File::Spec;
  my $self = shift;
  my($username) = @_;
  my ($name, $uid, $gid, $dir) = (getpwnam $username)[0, 2, 3, 7];

  unless (defined $uid) {
    my $errmsg = "handle_user unable to find user: '$username'";
    if ($self->spamtest->{'paranoid'}) {  # FIXME: return something? die? whatever?
      $self->service_unavailable_error($errmsg);
    }
    else {
      # if we are given a username, but can't look it up, maybe name
      # services are down?  let's break out here to allow them to get
      # 'defaults' when we are not running paranoid
      info($errmsg);
    }
    return 0;
  }

  my $cf_dir  = File::Spec->catdir($dir,     '.spamassassin');
  my $cf_file = File::Spec->catfile($cf_dir, 'user_prefs');
  if (!-l $cf_dir && -d _ && !-d $cf_file && -f _ && -s _) {
    $self->spamtest->read_scoreonly_config($cf_file);

    # if the $cf_dir group matches ours, assume we can write there
    my $user_dir = $) == (stat $cf_dir)[5] ? $dir : undef;

    $self->spamtest->signal_user_changed(
      { username => $username, user_dir => $user_dir, });
  }
  return 1;
}


=head1 TODO

Timeout...

NetSet

=head1 BUGS

See <http://bugzilla.spamassassin.org/>.

=head1 SEE ALSO

L<httpd(8)>,
L<spamd(1)>,
L<apache-spamd(1)>,
L<Mail::SpamAssassin::Spamd::Apache2::Config(3)>

=cut

1;

# vim: ts=2 sw=2 et
