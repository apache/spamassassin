#

package Mail::SpamAssassin::EvalTests;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Dns;
use IO::Socket;
use Carp;
use strict;

use vars qw{
	$KNOWN_BAD_DIALUP_RANGES $IP_IN_RESERVED_RANGE
	$EXISTING_DOMAIN $IS_DNS_AVAILABLE
};

# persistent spam sources. These are not in the RBL though :(
$KNOWN_BAD_DIALUP_RANGES = q(
    .da.uu.net .prod.itd.earthlink.net .pub-ip.psi.net .prserv.net
);

$EXISTING_DOMAIN = 'microsoft.com.';

$IP_IN_RESERVED_RANGE = undef;

$IS_DNS_AVAILABLE = undef;

###########################################################################
# HEAD TESTS:
###########################################################################

sub check_for_from_mx {
  my ($self) = @_;
  local ($_);

  $_ = $self->get ('From');
  return 0 unless (/\@(\S+)/);
  $_ = $1;

  # First check that DNS is available, if not do not perform this check
  return 0 unless $self->is_dns_available();

  # Try 5 times to protect against temporary outages
  for my $i (1..5) {
    my @mx = mx ($self->{res}, $_);
    if (scalar @mx >= 0) { return 0; }
    sleep 10;
  }

  return 1;
}

###########################################################################

sub check_for_bad_dialup_ips {
  my ($self) = @_;
  local ($_);

  my $knownbad = $KNOWN_BAD_DIALUP_RANGES;
  $knownbad =~ s/^\s+//g;
  $knownbad =~ s/\s+$//g;
  $knownbad =~ s/\./\\./g;
  $knownbad =~ s/\s+/\|/g;

  $_ = $self->get ('Received');
  /${knownbad}/o;
}

###########################################################################

sub check_for_from_to_equivalence {
  my ($self) = @_;
  my $from = $self->get ('From');
  my $to = $self->get ('To');

  ($from eq $to);
}

###########################################################################

sub check_for_bad_helo {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('X-Authentication-Warning');

  (/host \S+ \[(\S+)\] claimed to be.*\[(\S+)\]/i && $1 ne $2);
}

###########################################################################

sub check_subject_for_lotsa_8bit_chars {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('Subject');

  my @highbits = /[\200-\377]/g; my $numhis = $#highbits+1;
  my $numlos = length($_) - $numhis;

  ($numlos < $numhis && $numhis > 3);
}

###########################################################################

sub check_rbl {
  my ($self, $rbl_domain) = @_;
  local ($_);
  my $rcv = $self->get ('Received');

  my @ips = ($rcv =~ /\[(\d+\.\d+\.\d+\.\d+)\]/g);
  return 0 unless ($#ips >= 0);

  # First check that DNS is available, if not do not perform this check
  return 0 unless $self->is_dns_available();

  if ($#ips > 1) {
    @ips = @ips[$#ips-1 .. $#ips];        # only check the originating 2
  }

  init_rbl_check_reserved_ips();
  my $found = 0;

  # First check that DNS is available, if not do not perform this check.
  # Stop after the first positive.
  eval q{
    foreach my $ip (@ips) {
      next if ($ip =~ /${IP_IN_RESERVED_RANGE}/o);
      next unless ($ip =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/);
      $found = $self->do_rbl_lookup ("$4.$3.$2.$1.".$rbl_domain, $found);
    }
  };

  $found;
}

###########################################################################
# BODY TESTS:
###########################################################################

sub check_for_very_long_text {
  my ($self, $body) = @_;
  (scalar @{$body} > 500);
}

###########################################################################
# FULL-MESSAGE TESTS:
###########################################################################

sub check_razor {
  my ($self, $fulltext, $site) = @_;

  return 0 unless ($self->is_razor_available());
  return $self->razor_lookup ($site, $fulltext);
}

###########################################################################

1;
