=head1 NAME

RelayCountry - add message metadata indicating the country code of each relay

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::RelayCountry

=cut

package Mail::SpamAssassin::Plugin::RelayCountry;

use Mail::SpamAssassin::Plugin;
use strict;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);
  return $self;
}

# and the eval rule itself
sub extract_metadata {
  my ($self, $opts) = @_;

  my $reg;

  eval {
    require IP::Country::Fast;
    $reg = IP::Country::Fast->new();
  };
  if ($@) {
    dbg ("failed to load 'IP::Country::Fast', skipping");
    return 1;
  }

  my $msg = $opts->{msg};

  my $countries = '';
  foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
    my $ip = $relay->{ip};
    my $cc = $reg->inet_atocc($ip);
    $countries .= $cc." ";
  }

  chop $countries;
  $msg->put_metadata ("X-Relay-Countries", $countries);
  dbg ("metadata: X-Relay-Countries: $countries");

  return 1;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
