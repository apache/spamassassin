package Mail::SpamAssassin::Spamd::Apache2::AclIP;
use strict;
use Apache2::Connection ();
use Apache2::Const -compile => qw(OK FORBIDDEN SERVER_ERROR);

use Apache2::Module    ();
use Apache2::ServerRec ();

use Mail::SpamAssassin::Logger;

=head1 NAME

Mail::SpamAssassin::Spamd::Apache2::AclIP - host-based spamd access control

=head1 SYNOPSIS

 ##### in httpd.conf:
 PerlLoadModule Mail::SpamAssassin::Spamd::Apache2::Config
 SAallow from 127.0.0.1 192.168.0.0/24

=head1 DESCRIPTION

Allows / denies access to spamd basing on client's network address.
This is a simple version of C<mod_authz_host> (which, unfortunately,
is too HTTP-centric to use here).

Should be before C<Mail::SpamAssassin::Spamd::Apache2::AclRFC1413>
in the handler chain.

=head1 NOTE

This module doesn't prevent Apache from accepting a connection; child
(and therefore we) get control after client actually sends something.
It's possible to open C<$toomany> connections to the parent server and
DoS this way.

=head1 BUGS

See <http://bugzilla.spamassassin.org/>

=head1 SEE ALSO

L<Mail::SpamAssassin::Spamd::Apache2::Config(3)>

=cut

use APR::IpSubnet ();

sub handler {
  my ($c) = @_;

  my $srv_cfg =
    Apache2::Module::get_config('Mail::SpamAssassin::Spamd::Apache2::Config',
    $c->base_server);

  # TODO: log it somewhere (or not?) -- means all denied
  return Apache2::Const::SERVER_ERROR
    unless $srv_cfg && exists $srv_cfg->{allowed_ips};

  # use NetAddr::IP::Lite ();
  # my $ip = NetAddr::IP::Lite->new($c->remote_ip)
  #   or return Apache2::Const::SERVER_ERROR;   # log it, shouldn't happen

  my $remote = $c->remote_addr;
  for my $allowed (@{ $srv_cfg->{allowed_networks} }) {
    # depends on allowed_ips format; TODO; if NetAddr::IP::Lite:
    # return Apache2::Const::OK if $allowed->contains($ip);
    return Apache2::Const::OK if $allowed->test($remote);
  }

  info(sprintf "access denied for '%s'", $c->remote_ip);
  return Apache2::Const::FORBIDDEN;
}

1;

# vim: ts=8 sw=2 et
