#

package Mail::SpamAssassin::Dns;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use File::Spec;
use IO::Socket;
use IPC::Open2;
use POSIX ":sys_wait_h";        # sorry Craig ;)

use Carp;
use strict;

use vars qw{
	$KNOWN_BAD_DIALUP_RANGES $IP_IN_RESERVED_RANGE
	@EXISTING_DOMAINS $IS_DNS_AVAILABLE $VERSION
};

# don't lookup SpamAssassin.org -- use better-connected sites
# instead ;)
@EXISTING_DOMAINS = qw{
                       kernel.org
                       slashdot.org
                       google.com
                       google.de
                       microsoft.com
                       yahoo.com
                       yahoo.de
                       amazon.com
                       amazon.de
                       nytimes.com
                       leo.org
                       gwdg.de
                    };

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
    require Razor2::Client::Agent;
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
  my ($self, $set, $dom, $ip, $found, $dialupreturn, $needresult) = @_;
  my $socket;
  my @addr=();
  my $maxwait=$self->{conf}->{rbl_timeout};
  return $found if $found;

  my $gotdialup=0;
  my $domainonly;
  ($domainonly = $dom) =~ s/^\d+\.\d+\.\d+\.\d+.//;
  $domainonly =~ s/\.?$/./;

  if (defined $self->{dnscache}->{rbl}->{$dom}->{result}) {
    dbg("Found $dom in our DNS cache. Yeah!", "rbl", -1);
    @addr = @{$self->{dnscache}->{rbl}->{$dom}->{result}};
  } elsif (not defined $self->{dnscache}->{rbl}->{$dom}->{socket}) {
    dbg("Launching DNS query for $dom in the background", "rbl", -1);
    $self->{dnscache}->{rbl}->{$dom}->{socket}=$self->{res}->bgsend($dom);
    $self->{dnscache}->{rbl}->{$dom}->{time}=time;
    return 0;
  } elsif (not $needresult) {
    dbg("Second batch query for $dom, ignoring since we have one pending", "rbl", -1);
    return 0;
  } else {
    timelog("RBL -> Waiting for result on $dom", "rbl", 1);
    $socket=$self->{dnscache}->{rbl}->{$dom}->{socket};
    
    while (not $self->{res}->bgisready($socket)) {
      last if (time - $self->{dnscache}->{rbl}->{$dom}->{time} > $maxwait);
      sleep 1;
    }

    if (not $self->{res}->bgisready($socket)) {
      timelog("RBL -> Timeout on $dom", "rbl", 2);
      dbg("Query for $dom timed out after $maxwait seconds", "rbl", -1);
      return 0;
    } else {
      my $packet = $self->{res}->bgread($socket);
      undef($socket);
      foreach $_ ($packet->answer) {
	dbg("Query for $dom yielded: ".$_->rdatastr, "rbl", -2);
	if ($_->type eq "A") {
	  push(@addr, $_->rdatastr);
	}
      }
      $self->{dnscache}->{rbl}->{$dom}->{result} = \@addr;
    }
  }

  if (@addr) {
    foreach my $addr (@addr) {

      # 127.0.0.2 is the traditional boolean indicator, don't log it
      # 127.0.0.3 now also means "is a dialup IP" (only if set is dialup
      # -- Marc)
      if ($addr ne '127.0.0.2' and 
	      not ($addr eq '127.0.0.3' and $set =~ /^dialup/)) {
	$self->test_log ("RBL check: found ".$dom.", type: ".$addr);
      } else {
	$self->test_log ("RBL check: found ".$dom);
      }
      dbg("RBL check: found $dom, type: $addr", "rbl", -2);

      $self->{$set}->{rbl_IN_As_found} .= $addr.' ';
      $self->{$set}->{rbl_matches_found} .= $ip.' ';

      # If $dialupreturn is a reference to a hash, we were told to ignore
      # dialup IPs, let's see if we have a match
      if ($dialupreturn) {
	my $toign;
	dbg("Checking dialup_codes for $addr as a DUL code for $domainonly", "rbl", -2);

	foreach $toign (keys %{$dialupreturn}) {
	  dbg("Comparing against $toign/".$dialupreturn->{$toign}, "rbl", -3);
	  $toign =~ s/\.?$/./;
	  if ($domainonly eq $toign and $addr eq $dialupreturn->{$toign}) {
	    dbg("Got $addr in $toign for $ip, good, we'll take it", "rbl", "-3");
	    $gotdialup=1;  
	    last;
	  }
	}

	if (not $gotdialup) {
	  dbg("Ignoring return $addr for $ip, not known as dialup for $domainonly in dialup_code variable", "rbl", -2);
	  next;
	}
      }

      timelog("RBL -> match on $dom", "rbl", 2);
      return 1;
    }
  }
  timelog("RBL -> No match on $dom", "rbl", 2);
  return 0;
}

# Initialize a regexp for reserved IPs, i.e. ones that could be
# used inside a company and be the first or second relay hit by
# a message. Some companies use these internally and translate
# them using a NAT firewall. These are listed in the RBL as invalid
# originators -- which is true, if you receive the mail directly
# from them; however we do not, so we should ignore them.
# cf. http://www.iana.org/assignments/ipv4-address-space .
#
# Last update by Matt Kettler - mail to SpamAssassin-devel, Mon 12 Aug
# 2002, msgid <5.1.0.14.0.20020812211512.00a33cc0@192.168.50.2>.
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
                    7[0-9]
                    8[2-9]
                    9[0-9]
                    1[01][0-9]
                    12[0-7]
                    192\.168
                    197
                    22[23]
                    24[0-9]
                    25[0-5]
                  ))
  {
    $IP_IN_RESERVED_RANGE .= $top8bits . '\.|';
  }
  $IP_IN_RESERVED_RANGE =~ s/\|$/\)/;
}

###########################################################################

sub is_razor1_available {
  my ($self) = @_;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor1", "razor", -1);
    return 0;
  }

  eval { require Razor::Client; };
  
  if ($@) {
    dbg ("Razor1 is not available", "razor", -1);
    return 0;
  }
  else {
    dbg ("Razor1 is available", "razor", -1);
    return 1;
  }
}

sub razor1_lookup {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{conf}->{razor_timeout};

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor1", "razor", -1);
    return 0;
  }

  timelog("Razor1 -> Starting razor test ($timeout secs max)", "razor", 1);
  
  my $response = undef;

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  my $oldslash = $/;

  {
    eval {
      require Razor::Client;
      require Razor::Agent;
      local ($^W) = 0;		# argh, warnings in Razor
  
      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm $timeout;
  
      my $config = $self->{conf}->{razor_config};
      $config ||= $self->{main}->sed_path ("~/razor.conf");
      my %options = (
        'debug'	=> ($Mail::SpamAssassin::DEBUG->{enabled} and $Mail::SpamAssassin::DEBUG->{razor} < -2)
      );

      my $rc = Razor::Client->new ($config, %options);
  
      if ($rc) {
        my $ver = $Razor::Client::VERSION;
        my @msg = split (/^/m, $$fulltext);

        if ($ver >= 1.12) {
          my $respary = $rc->check ('spam' => \@msg);
          # response can be "0" or "1". there can be many responses.
          # so if we get 5 responses, and one of them's 1, we
          # wind up with "00010", which +0 below turns to 10, ie. != 0.
          for my $resp (@$respary) { $response .= $resp; }
  
        }
        else {
            $response = $rc->check (\@msg);
        }
      }
      else {
          warn "Problem while trying to load Razor1: $! $Razor::Client::errstr";
      }
      
      alarm 0;
    };
  
    alarm 0;    # just in case

    if ($@) {
      $response = undef;
      if ($@ =~ /alarm/) {
        dbg ("razor check timed out after $timeout secs.", "razor", -1);
        timelog("Razor1 -> interrupted after $timeout secs", "razor", 2);
      } else {
        warn ("razor check skipped: $! $@");
      }
    }
  }

  $/ = $oldslash;		# argh! pollution!

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  if ((defined $response) && ($response+0)) {
      timelog("Razor1 -> Finished razor test: confirmed spam", "razor", 2);
      return 1;
  }
  timelog("Razor1 -> Finished razor test: not known spam", "razor", 2);
  return 0;
}

###########################################################################

sub is_razor2_available {
  my ($self) = @_;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor2", "razor", -1);
    return 0;
  }

  # Use Razor2 if it's available, Razor1 otherwise
  eval { require Razor2::Client::Agent; };
  if ($@) {
    dbg("Razor2 is not available", "razor", -1);
    return 0;
  }
  else {
    dbg("Razor2 is available", "razor", -1);
    return 1;
  }
}

sub razor2_lookup {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{conf}->{razor_timeout};

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor2", "razor", -1);
    return 0;
  }

  timelog("Razor2 -> Starting razor test ($timeout secs max)", "razor", 1);
  
  my $response = undef;

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  my $oldslash = $/;

  {
    eval {
      local ($^W) = 0;    # argh, warnings in Razor

      require Razor2::Client::Agent;

      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm $timeout;

      my $rc =
        Razor2::Client::Agent->new('razor-check')
        ;                 # everything's in the module!

      if ($rc) {
        my %opt = (
            debug      => ($Mail::SpamAssassin::DEBUG->{enabled} and
                 $Mail::SpamAssassin::DEBUG->{razor} < -2), 
	    foreground => 1,
            config     => $self->{conf}->{razor_config}
        );
        $rc->{opt} = \%opt;
        $rc->do_conf() or die $rc->errstr;

        my @msg     = ($fulltext);
        my $objects = $rc->prepare_objects( \@msg )
          or die "error in prepare_objects";
        $rc->get_server_info() or die $rc->errprefix("checkit");
        my $sigs = $rc->compute_sigs($objects)
          or die "error in compute_sigs";

        # 
        # if mail is whitelisted, its not spam, so abort.
        #   
        if ( $rc->local_check( $objects->[0] ) ) {
          $response = 0;
        }
        else {
          $rc->connect() or die $rc->errprefix("checkit");
          $rc->check($objects) or die $rc->errprefix("checkit");
          $rc->disconnect() or die $rc->errprefix("checkit");
          $response = $objects->[0]->{spam};
        }
      }
      else {
        warn "undefined Razor2::Client::Agent\n";
      }
  
      alarm 0;
    };

    alarm 0;    # just in case
  
    if ($@) {
      $response = undef;
      if ( $@ =~ /alarm/ ) {
        dbg("razor2 check timed out after $timeout secs.");
        }
        else {
        warn("razor2 check skipped: $! $@");
        }
      }
  }

  $/ = $oldslash;		# argh! pollution!

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  if ((defined $response) && ($response+0)) {
      timelog("Razor2 -> Finished razor test: confirmed spam", "razor", 2);
      return 1;
  }
  timelog("Razor2 -> Finished razor test: not known spam", "razor", 2);
  return 0;
}

###########################################################################

sub is_dcc_available {
  my ($self) = @_;
  my (@resp);

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring DCC");
    return 0;
  }

  my $dccproc = $self->{conf}->{dcc_path} || '';
  unless ($dccproc) {
    foreach my $path (File::Spec->path()) {
      $dccproc = File::Spec->catfile ($path, 'dccproc');
      if (-x $dccproc) {
        dbg ("DCC was found at $dccproc");
        $self->{conf}->{dcc_path} = $dccproc;
        last;
      }
    }
  }
  unless (-x $dccproc) {
    dbg ("DCC is not available: dccproc not found");
    return 0;
  }

  dbg ("DCC is available: ".join(" ", @resp));
  return 1;
}

use Symbol qw(gensym);

sub dcc_lookup {
  my ($self, $fulltext) = @_;
  my $response = undef;
  my %count;
  my $left;
  my $right;
  my $timeout=$self->{conf}->{dcc_timeout};

  $count{body} = 0;
  $count{fuz1} = 0;
  $count{fuz2} = 0;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring DCC");
    return 0;
  }

  timelog("DCC -> Starting test ($timeout secs max)", "dcc", 1);

  eval {
    my ($dccin, $dccout, $pid);

    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm($timeout);

    $dccin = gensym();
    $dccout = gensym();

    $pid = open2($dccout, $dccin, join(' ', $self->{conf}->{dcc_path}, '-H', $self->{conf}->{dcc_options}, '2>&1'));

    print $dccin $$fulltext;
    
    close ($dccin);

    $response = <$dccout>;
        
    dbg("DCC: got response: $response");

    waitpid ($pid, 0);

    alarm(0);
  };

  if ($@) {
    $response = undef;
    if ($@ =~ /alarm/) {
      dbg ("DCC check timed out after 10 secs.");
      timelog("DCC -> interrupted after $timeout secs", "dcc", 2);
      return 0;
    } elsif ($@ =~ /brokenpipe/) {
      dbg ("DCC -> check failed - Broken pipe.");
      timelog("dcc check failed, broken pipe", "dcc", 2);
      return 0;
    } else {
      warn ("DCC -> check skipped: $! $@");
      timelog("dcc check skipped", "dcc", 2);
      return 0;
    }
  }

  if ($response !~ /^X-DCC/) {
    dbg ("DCC -> check failed - no X-DCC returned (did you create a map file?): $response");
    timelog("dcc check failed", "dcc", 2);
    return 0;
  }

  if ($self->{conf}->{dcc_add_header}) {
    if ($response =~ /^(X-DCC.*): (.*)$/) {
      $left  = $1;
      $right = $2;
      $self->{msg}->put_header($left, $right);
    }
  }
 
  $response =~ s/many/999999/ig;
  $response =~ s/ok\d?/0/ig;

  if ($response =~ /Body=(\d+)/) {
    $count{body} = $1+0;
  }
  if ($response =~ /Fuz1=(\d+)/) {
    $count{fuz1} = $1+0;
  }
  if ($response =~ /Fuz2=(\d+)/) {
    $count{fuz2} = $1+0;
  }

  if ($count{body} >= $self->{conf}->{dcc_body_max} || $count{fuz1} >= $self->{conf}->{dcc_fuz1_max} || $count{fuz2} >= $self->{conf}->{dcc_fuz2_max}) {
    dbg ("DCC: Listed! BODY: $count{body} of $self->{conf}->{dcc_body_max} FUZ1: $count{fuz1} of $self->{conf}->{dcc_fuz1_max} FUZ2: $count{fuz2} of $self->{conf}->{dcc_fuz2_max}");
    timelog("DCC -> got hit", "dcc", 2);
    return 1;
  }
  
  timelog("DCC -> no match", "dcc", 2);
  return 0;
}

sub is_pyzor_available {
  my ($self) = @_;
  my (@resp);

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Pyzor");
    return 0;
  }

  my $pyzor = $self->{conf}->{pyzor_path} || '';
  unless ($pyzor) {
    foreach my $path (File::Spec->path()) {
      $pyzor = File::Spec->catfile ($path, 'pyzor');
      if (-x $pyzor) {
        dbg ("Pyzor was found at $pyzor");
        $self->{conf}->{pyzor_path} = $pyzor;
        last;
      }
    }
  }
  unless (-x $pyzor) {
    dbg ("Pyzor is not available: pyzor not found");
    return 0;
  }

  dbg ("Pyzor is available: ".join(" ", @resp));
  return 1;
}

use Symbol qw(gensym);

sub pyzor_lookup {
  my ($self, $fulltext) = @_;
  my $response = undef;
  my $pyzor_count;
  my $pyzor_whitelisted;
  my $timeout=$self->{conf}->{pyzor_timeout};

  $pyzor_count = 0;
  $pyzor_whitelisted = 0;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Pyzor");
    return 0;
  }

  timelog("Pyzor -> Starting test ($timeout secs max)", "pyzor", 1);

  eval {
    my ($pyzorin, $pyzorout, $pid);

    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm($timeout);

    $pyzorin = gensym();
    $pyzorout = gensym();

    $pid = open2($pyzorout, $pyzorin, join(' ', $self->{conf}->{pyzor_path}, 'check', '2>&1'));

    print $pyzorin $$fulltext;
    
    close ($pyzorin);

    $response = <$pyzorout>;
        
    dbg("Pyzor: got response: $response");

    waitpid ($pid, 0);

    alarm(0);
  };

  if ($@) {
    $response = undef;
    if ($@ =~ /alarm/) {
      dbg ("Pyzor check timed out after 10 secs.");
      timelog("Pyzor -> interrupted after $timeout secs", "pyzor", 2);
      return 0;
    } elsif ($@ =~ /brokenpipe/) {
      dbg ("Pyzor -> check failed - Broken pipe.");
      timelog("Pyzor check failed, broken pipe", "pyzor", 2);
      return 0;
    } else {
      warn ("Pyzor -> check skipped: $! $@");
      timelog("Pyzor check skipped", "pyzor", 2);
      return 0;
    }
  }

  # made regexp a little more forgiving (jm)
  if ($response =~ /^\S+\t.*?\t(\d+)\t(\d+)\s*$/) {
    $pyzor_whitelisted = $2+0;
    if ($pyzor_whitelisted == 0) {
      $pyzor_count = $1+0;
    }

  } else {
    # warn on failures to parse (jm)
    dbg ("Pyzor: couldn't grok response \"$response\"");
  }

  # moved this around a bit; no point in testing RE twice (jm)
  if ($self->{conf}->{pyzor_add_header}) {
    if ($pyzor_whitelisted) {
      $self->{msg}->put_header("X-Pyzor", "Whitelisted.");
    } else {
      $self->{msg}->put_header("X-Pyzor", "Reported $pyzor_count times.");
    }
  }

  if ($pyzor_count >= $self->{conf}->{pyzor_max}) {
    dbg ("Pyzor: Listed! $pyzor_count of $self->{conf}->{pyzor_max} and whitelist is $pyzor_whitelisted");
    timelog("Pyzor -> got hit", "pyzor", 2);
    return 1;
  }
  
  timelog("Pyzor -> no match", "pyzor", 2);
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
    my @mxrecords = Net::DNS::mx($self->{res}, $dom);
    $ret = 1 if @mxrecords;
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
  my $dnsopt = $self->{conf}->{dns_available};
  my @domains;

  return $IS_DNS_AVAILABLE if (defined $IS_DNS_AVAILABLE);

  $IS_DNS_AVAILABLE = 0;
  if ($dnsopt eq "no") {
    dbg ("dns_available set to no in config file, skipping test", "dnsavailable", -1);
    return $IS_DNS_AVAILABLE;
  }
  if ($dnsopt eq "yes") {
    $IS_DNS_AVAILABLE = 1;
    dbg ("dns_available set to yes in config file, skipping test", "dnsavailable", -1);
    return $IS_DNS_AVAILABLE;
  }
  
  goto done if ($self->{main}->{local_tests_only});
  goto done unless $self->load_resolver();

  if ($dnsopt =~ /test:\s+(.+)$/) {
    my $servers=$1;
    dbg("servers: $servers");
    @domains = split (/\s+/, $servers);
    dbg("Looking up MX records for user specified servers: ".join(", ", @domains), "dnsavailable", -1);
  } else {
    @domains = @EXISTING_DOMAINS;
  }

  # TODO: retry every now and again if we get this far, but the
  # next test fails?  could be because the ethernet cable has
  # simply fallen out ;)
  for(my $retry = 3; $retry > 0 and $#domains>-1; $retry--) {
    my $domain = splice(@domains, rand(@domains), 1);
    dbg ("trying ($retry) $domain...", "dnsavailable", -2);
    if($self->lookup_mx($domain)) {
      dbg ("MX lookup of $domain succeeded => Dns available (set dns_available to hardcode)", "dnsavailable", -1);
      $IS_DNS_AVAILABLE = 1;
      last;
    }
  }

  dbg ("All MX queries failed => DNS unavailable (set dns_available to override)", "dnsavailable", -1) if ($IS_DNS_AVAILABLE == 0);

done:
  # jm: leaving this in!
  dbg ("is DNS available? $IS_DNS_AVAILABLE");
  return $IS_DNS_AVAILABLE;
}

###########################################################################

1;
