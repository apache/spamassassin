#

package Mail::SpamAssassin::Dns;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use IO::Socket;
use Carp;
use strict;

use vars qw{
	$KNOWN_BAD_DIALUP_RANGES $IP_IN_RESERVED_RANGE
	$EXISTING_DOMAIN $IS_DNS_AVAILABLE
};

$EXISTING_DOMAIN = 'microsoft.com.';

$IP_IN_RESERVED_RANGE = undef;

$IS_DNS_AVAILABLE = undef;

###########################################################################

sub do_rbl_lookup {
  my ($self, $dom, $ip, $found) = @_;
  return $found if $found;

  my $q = $self->{res}->search ($dom);
  if ($q) {
    foreach my $rr ($q->answer) {
      if ($rr->type eq "A") {
	my $addr = $rr->address();

	if ($addr ne '127.0.0.2' && $addr ne '127.0.0.3') {
	  $self->test_log ("RBL check: found relay ".$dom.", type: ".$addr);
	} else {
	  # 127.0.0.2 is the traditional boolean indicator, don't log it
	  # 127.0.0.3 now also means "is a dialup IP"
	  $self->test_log ("RBL check: found relay ".$dom);
	}

	$self->{rbl_IN_As_found} .= $addr.' ';
	$self->{rbl_matches_found} .= $ip.' ';
	return ($found+1);
      }
    }
  }
  return 0;
}

# Initialize a regexp for reserved IPs, i.e. ones that could be
# used inside a company and be the first or second relay hit by
# a message. Some companies use these internally and translate
# them using a NAT firewall. These are listed in the RBL as invalid
# originators -- which is true, if you receive the mail directly
# from them; however we do not, so we should ignore them.
#
sub init_rbl_check_reserved_ips {
  return if defined ($IP_IN_RESERVED_RANGE);

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

sub is_razor_available {
  my ($self) = @_;
  my $razor_avail = 0;

  eval {
    require Razor::Client;
    require Razor::Signature; 
    require Razor::String;
    $razor_avail = 1;
    1;
  };

  dbg ("is Razor available? $razor_avail");

  return $razor_avail;
}

sub razor_lookup {
  my ($self, $fulltext) = @_;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor");
    return 0;
  }

  my @msg = split (/^/m, $$fulltext);

  my $timeout = 10;		# seconds
  my $response = undef;
  my $config = $self->{conf}->{razor_config};
  my %options = (
    # 'debug'	=> 1
  );

  if (!eval {
    require Razor::Client;
    require Razor::Signature; 
    $response = Razor::Client->new($config, %options)->check (\@msg);
  1;})
  {
    warn ("$! $@") unless ($@ eq "timeout\n");
    warn "razor check timed out after $timeout secs.\n";
  }

  if ($response) { return 1; }
  return 0;
}

###########################################################################

sub load_resolver {
  my ($self) = @_;

  if (defined $self->{res}) { return 1; }
  $self->{no_resolver} = 1;

  eval {
    require Net::DNS;
    $self->{res} = new Net::DNS::Resolver;
    if (defined $self->{res}) {
      $self->{no_resolver} = 0;
    }
    1;
  };   #  or warn "eval failed: $@ $!\n";
  dbg ("is Net::DNS::Resolver unavailable? $self->{no_resolver}");

  return (!$self->{no_resolver});
}

sub lookup_mx {
  my ($self, $dom) = @_;

  return 0 unless $self->load_resolver();
  my $ret = 0;

  dbg ("looking up MX for '$dom'");

  eval {
    if (Net::DNS::mx ($self->{res}, $dom)) { $ret = 1; }
  1; } or sa_die (71, "MX lookup died: $@ $!\n");

  # 71 == EX_OSERR.  MX lookups are not supposed to crash and burn!

  dbg ("MX for '$dom' exists? $ret");

  return $ret;
}

sub is_dns_available {
  my ($self) = @_;

  return $IS_DNS_AVAILABLE if (defined $IS_DNS_AVAILABLE);

  $IS_DNS_AVAILABLE = 0;
  goto done if ($self->{main}->{local_tests_only});
  goto done unless $self->load_resolver();

  # TODO: retry every now and again if we get this far, but the
  # next test fails?  could be because the ethernet cable has
  # simply fallen out ;)
  goto done unless $self->lookup_mx ($EXISTING_DOMAIN);

  $IS_DNS_AVAILABLE = 1;

done:
  dbg ("is DNS available? $IS_DNS_AVAILABLE");
  return $IS_DNS_AVAILABLE;
}

###########################################################################

1;
