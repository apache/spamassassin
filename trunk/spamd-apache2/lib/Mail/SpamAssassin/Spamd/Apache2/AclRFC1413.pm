package Mail::SpamAssassin::Spamd::Apache2::AclRFC1413;
use strict;

use Apache2::Const -compile => qw(OK FORBIDDEN SERVER_ERROR);
use Apache2::Connection  ();
use Apache2::RequestUtil ();    # RequestRec->new
use Apache2::RequestRec  ();
use Apache2::Access      ();    # $r->get_remote_logname

use APR::SockAddr ();           # $c->remote_addr->...
use APR::Table    ();           # $c->notes

=head1 NAME

Mail::SpamAssassin::Spamd::Apache2::AclRFC1413 - check spamd's client ident

=head1 SYNOPSIS

 ##### in httpd.conf:
 # engine; module has been separated in Apache 2.1
 LoadModule ident_module modules/mod_ident.so
 IdentityCheck   on
 IdentityTimeout 4

 # enable check
 PerlLoadModule Mail::SpamAssassin::Spamd::Apache2::Config
 SAident on

 ##### in PerlProcessConnectionHandler:
 Mail::SpamAssassin::Spamd::Apache2::AclRFC1413::check_ident($c, "user")
   or return Apache2::Const::FORBIDDEN;

 # or like this:
 my $remote_logname =
   Mail::SpamAssassin::Spamd::Apache2::AclRFC1413::get_ident($c)

=head1 DESCRIPTION

Queries remote ident server using mod_ident.so, saves result in
C<$c->notes()>.

Returns C<Apache2::Const::FORBIDDEN> on failure.

The C<SAident On> directive actually does this:
 PerlPreConnectionHandler Mail::SpamAssassin::Spamd::Apache2::AclRFC1413

=head1 NOTE

Doing ident for non-localhost users is rather pointless.  Unless you
know what you're doing, listen only on C<127.0.0.1> and/or C<::1>, if
you want to prevent users from lying about their identity.  Or use SSL
with client certificates (refer to C<mod_ssl> documentation for details).

=head1 FUNCTIONS
 
=cut

sub handler {
  my ($c) = @_;

  # is there a point in doing ident for remote users?
  #$c->remote_ip eq $c->local_ip
  #  or return Apache2::Const::FORBIDDEN;

  my $r = Apache2::RequestRec->new($c)
    or die 'Apache2::RequestRec->new($c) failed';

  my $remote_user = $r->get_remote_logname;

  unless (defined $remote_user && length $remote_user) {
    warn 'rfc1413 check: failed to obtain info for '
      . $c->remote_addr->ip_get() . ':'
      . $c->remote_addr->port() . "\n";
    return Apache2::Const::FORBIDDEN;
  }

  my $notes = $c->notes    # APR::Table
    or die '$c->notes failed';
  $notes->{remote_user} = $remote_user;
  $c->notes($notes);

  return Apache2::Const::OK;
}

=head2 check_ident($c, $username)

Returns remote username (might be "0"), as returned by the ident server, if it
matches supplied $username; undef otherwise.

=cut

sub check_ident {
  my ($c, $user) = @_;
  my $remote_user = $c->notes->{remote_user};
  die "rfc1413 check: no query result for user=$user ip="
    . $c->remote_addr->ip_get()
    . ' port='
    . $c->remote_addr->port()
    unless defined $remote_user && length $remote_user;
  return $remote_user if $user eq $remote_user;
  warn "ident mismatch for [$user] from "
    . $c->remote_addr->ip_get() . ':'
    . $c->remote_addr->port()
    . "; remote identd returned [$remote_user]\n";
  0;
}

=head2 get_ident($c)

Returns remote username (might be "0"), as returned by the ident server.

=cut

sub get_ident {
  my ($c) = @_;
  $c->notes->{remote_user};
}

=head1 EXPORTS

Nothing.

=head1 BUGS

See <http://bugzilla.spamassassin.org/>

=head1 SEE ALSO

L<Mail::SpamAssassin::Spamd::Apache2::Config(3)>

=cut

1;

# vim: ts=8 sw=2 et
