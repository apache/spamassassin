#

package Mail::SpamAssassin::EvalTests;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Carp;
use strict;

use vars qw{
	$KNOWN_BAD_DIALUP_RANGES $IP_IN_RESERVED_RANGE
	$EXISTING_DOMAIN
};

# persistent spam sources
$KNOWN_BAD_DIALUP_RANGES = q(
    .da.uu.net .prod.itd.earthlink.net .pub-ip.psi.net .prserv.net
);

$EXISTING_DOMAIN = 'microsoft.com.';

$IP_IN_RESERVED_RANGE = undef;

###########################################################################
# HEAD TESTS:
###########################################################################

sub check_for_from_mx {
  my ($self, $head) = @_;
  local ($_);

  $_ = $self->get_header ('From');
  return 0 unless (/\@(\S+)/);
  $_ = $1;

  my $found_mx = 0;
  eval '
    use Net::DNS; my $res = new Net::DNS::Resolver;

    # First check that DNS is available, if not do not perform this check
    # Try 5 times to protect against temporary outages
    if (mx($res, $EXISTING_DOMAIN)) {
      for my $i (1..5) {
	if (mx ($res, $_)) { $found_mx = 1; last; }
	sleep 10;
      }
    }
  1;' or $found_mx = 1;     # return OK if Net:DNS is not available

  (!$found_mx);
}

###########################################################################

sub check_for_bad_dialup_ips {
  my ($self, $head) = @_;
  local ($_);

  my $knownbad = $KNOWN_BAD_DIALUP_RANGES;
  $knownbad =~ s/^\s+//g;
  $knownbad =~ s/\s+$//g;
  $knownbad =~ s/\./\\./g;
  $knownbad =~ s/\s+/\|/g;

  $_ = $self->get_header ('Received');
  /${knownbad}/o;
}

###########################################################################

sub check_for_from_to_equivalence {
  my ($self, $head) = @_;
  my $from = $self->get_header ('From');
  my $to = $self->get_header ('To');

  ($from eq $to);
}

###########################################################################

sub check_for_bad_helo {
  my ($self, $head) = @_;
  local ($_);
  $_ = $self->get_header ('X-Authentication-Warning');

  (/host \S+ \[(\S+)\] claimed to be.*\[(\S+)\]/i && $1 ne $2);
}

###########################################################################

sub check_subject_for_lotsa_8bit_chars {
  my ($self, $head) = @_;
  local ($_);
  $_ = $self->get_header ('Subject');

  my @highbits = /[\200-\377]/g; my $numhis = $#highbits+1;
  my $numlos = length($_) - $numhis;

  ($numlos < $numhis && $numhis > 3);
}

###########################################################################

sub check_rbl {
  my ($self, $head, $rbl_domain) = @_;
  local ($_);
  my $rcv = $self->get_header ('Received');

  my @ips = ($rcv =~ /\[(\d+\.\d+\.\d+\.\d+)\]/g);
  return 0 unless ($#ips >= 0);

  if ($#ips > 1) {
    @ips = @ips[$#ips-1 .. $#ips];        # only check the originating 2
  }

  init_rbl_check_reserved_ips();
  my $found = 0;

  eval q{
    use Net::DNS; my $res = new Net::DNS::Resolver;

    sub do_rbl_lookup {
      return if $found;
      my $q = $res->search ($_[0]); if ($q) {
	foreach my $rr ($q->answer) {
	  if ($rr->type eq "A") {
	    $found++;
	    $self->test_log ("RBL check: found relay ".$_[0]);
	  }
	}
      }
    }

    # First check that DNS is available, if not do not perform this check.
    # Stop after the first positive.
    my @mx = mx ($res, $EXISTING_DOMAIN);
    if ($#mx >= 0) {
      foreach my $ip (@ips) {
	next if ($ip =~ /${IP_IN_RESERVED_RANGE}/o);
	next unless ($ip =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/);
	&do_rbl_lookup ("$4.$3.$2.$1.".$rbl_domain);
      }
    }
  };

  $found;
}

# Initialize a regexp for reserved IPs, i.e. ones that could be
# used inside a company and be the first or second relay hit by
# a message. Some companies use these internally and translate
# them using a NAT firewall. These are listed in the RBL as invalid
# originators -- which is true, if you receive the mail directly
# from them; however we do not, so we should ignore them.
#
sub init_rbl_check_reserved_ips {
  return unless defined ($IP_IN_RESERVED_RANGE);

  $IP_IN_RESERVED_RANGE = '^(?:';
  foreach my $top8bits (qw(
                    [012]
                    5
                    7
                    10
                    23
                    27
                    31
                    37
                    39
                    41
                    42
                    58
                    59
                    60
                    6[5-9]
                    [789][0-9]
                    1[01][0-9]
                    12[0-7]
                    197
                    21[7-9]
                    22[0-3]
                    24[0-9]
                    25[0-5]
                  ))
  {
    $IP_IN_RESERVED_RANGE .= $top8bits . '\.|';
  }
  $IP_IN_RESERVED_RANGE =~ s/\|$/\)/;
}

###########################################################################
# BODY TESTS:
###########################################################################

sub check_for_very_long_text {
  my ($self, $body) = @_;
  (scalar @{$body} > 500);
}

###########################################################################

1;
