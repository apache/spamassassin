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
	$EXISTING_DOMAIN $IS_DNS_AVAILABLE $VERSION
};

$EXISTING_DOMAIN = 'microsoft.com.';

$IP_IN_RESERVED_RANGE = undef;

$IS_DNS_AVAILABLE = undef;

$VERSION = 'bogus';     # avoid CPAN.pm picking up razor ver

###########################################################################

BEGIN {
  # some trickery. Load these modules right here, if possible; that way, if
  # the module exists, we'll get it loaded now.  Very useful to avoid attempted
  # loads later (which will happen).  If we do a fork(), we could wind up
  # attempting to load these modules in *every* subprocess.
  #
  # We turn off strict and warnings, because Net::DNS and Razor both contain
  # crud that -w complains about (perl 5.6.0).  Not that this seems to work,
  # mind ;)

  no strict;
  local ($^W) = 0;

  eval {
    require Net::DNS;
    require Net::DNS::Resolver;
  };
  eval {
    require Razor::Client;
  };
  eval {
    require MIME::Base64;
  };
};

###########################################################################

sub do_rbl_lookup {
  my ($self, $set, $dom, $ip, $found) = @_;
  return $found if $found;

  my $q = $self->{res}->search ($dom);

  if ($q) {
    foreach my $rr ($q->answer) {
      if ($rr->type eq "A") {
	my $addr = $rr->address();
	dbg ("record found for $dom = $addr");

	if ($addr ne '127.0.0.2' && $addr ne '127.0.0.3') {
	  $self->test_log ("RBL check: found ".$dom.", type: ".$addr);
	} else {
	  # 127.0.0.2 is the traditional boolean indicator, don't log it
	  # 127.0.0.3 now also means "is a dialup IP"
	  $self->test_log ("RBL check: found ".$dom);
	}

	$self->{$set}->{rbl_IN_As_found} .= $addr.' ';
	$self->{$set}->{rbl_matches_found} .= $ip.' ';
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

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor");
    return 0;
  }

  eval {
    require Razor::Client;
  };
  
  if ($@) {
    dbg ("Razor is not available");
    return 0;
  }
  else {
    dbg ("Razor is available");
    return 1;
  }
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
    'debug'	=> $Mail::SpamAssassin::DEBUG
  );

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  my $oldslash = $/;

  eval {
    require Razor::Client;
    require Razor::Agent;
    local ($^W) = 0;		# argh, warnings in Razor

    local $SIG{ALRM} = sub { die "alarm\n" };
    alarm 10;

    my $rc = Razor::Client->new ($config, %options);
    die "undefined Razor::Client\n" if (!$rc);

    my $ver = $Razor::Client::VERSION;
    if ($ver >= 1.12) {
      my $respary = $rc->check ('spam' => \@msg);
      # response can be "0" or "1". there can be many responses.
      # so if we get 5 responses, and one of them's 1, we
      # wind up with "00010", which +0 below turns to 10, ie. != 0.
      for my $resp (@$respary) { $response .= $resp; }

    } else {
      $response = $rc->check (\@msg);
    }

    alarm 0;
  };

  if ($@) {
    if ($@ =~ /alarm/) {
      dbg ("razor check timed out after $timeout secs.");
    } else {
      warn ("razor check skipped: $! $@");
    }
  }

  $/ = $oldslash;		# argh! pollution!

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  if ((defined $response) && ($response+0)) { return 1; }
  return 0;
}

###########################################################################

sub load_resolver {
  my ($self) = @_;

  if (defined $self->{res}) { return 1; }
  $self->{no_resolver} = 1;

  eval {
    require Net::DNS;
    $self->{res} = Net::DNS::Resolver->new;
    if (defined $self->{res}) {
      $self->{no_resolver} = 0;
      $self->{res}->retry(1); # If it fails, it fails
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
  };
  if ($@) {
    # 71 == EX_OSERR.  MX lookups are not supposed to crash and burn!
    sa_die (71, "MX lookup died: $@ $!\n");
  }

  dbg ("MX for '$dom' exists? $ret");
  return $ret;
}

sub lookup_ptr {
  my ($self, $dom) = @_;

  return undef unless $self->load_resolver();
  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, not looking up PTR");
    return undef;
  }

  dbg ("looking up PTR record for '$dom'");
  my $name = '';

  eval {
        my $query = $self->{res}->search($dom);
        if ($query) {
	  foreach my $rr ($query->answer) {
	    if ($rr->type eq "PTR") {
	      $name = $rr->ptrdname; last;
	    }
	  }
        }

  };
  if ($@) {
    # 71 == EX_OSERR.  PTR lookups are not supposed to crash and burn!
    sa_die (71, "PTR lookup died: $@ $!\n");
  }

  dbg ("PTR for '$dom': '$name'");

  # note: undef is never returned, unless DNS is unavailable.
  return $name;
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
