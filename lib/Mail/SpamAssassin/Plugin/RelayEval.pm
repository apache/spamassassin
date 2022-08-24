# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::RelayEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

my $IPV4_ADDRESS = IPV4_ADDRESS;

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_for_numeric_helo"); # type does not matter
  $self->register_eval_rule("check_for_illegal_ip"); # type does not matter
  $self->register_eval_rule("check_all_trusted"); # type does not matter
  $self->register_eval_rule("check_no_relays"); # type does not matter
  $self->register_eval_rule("check_relays_unparseable"); # type does not matter
  $self->register_eval_rule("check_for_sender_no_reverse"); # type does not matter
  $self->register_eval_rule("check_for_from_domain_in_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_received_trail"); # type does not matter
  $self->register_eval_rule("check_for_forged_received_ip_helo"); # type does not matter
  $self->register_eval_rule("helo_ip_mismatch"); # type does not matter
  $self->register_eval_rule("check_for_no_rdns_dotcom_helo"); # type does not matter

  return $self;
}

# tvd: why isn't this just RegistrarBoundaries ?
sub hostname_to_domain {
  my ($hostname) = @_;

  if ($hostname !~ /[a-zA-Z]/) { return $hostname; }	# IP address

  my @parts = split(/\./, $hostname);
  if (@parts > 1 && $parts[-1] =~ /(?:\S{3,}|ie|fr|de)/) {
    return join('.', @parts[-2..-1]);
  }
  elsif (@parts > 2) {
    return join('.', @parts[-3..-1]);
  }
  else {
    return $hostname;
  }
}

sub _helo_forgery_welcomelisted {
  my ($helo, $rdns) = @_;
  if ($helo eq 'msn.com' && $rdns eq 'hotmail.com') { return 1; }
  0;
}

sub check_for_numeric_helo {
  my ($self, $pms) = @_;

  my $rcvd = $pms->{relays_untrusted_str};

  if ($rcvd) {
    local $1;
    # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
    if ($rcvd =~ /\bhelo=($IPV4_ADDRESS)(?=[\000-\040,;\[()<>]|\z)/i  # Bug 5878
        && $1 !~ IS_IP_PRIVATE) {
      return 1;
    }
  }
  return 0;
}

sub check_for_illegal_ip {
  my ($self, $pms) = @_;
  # Bug 6295, no longer in use, kept for compatibility with old rules
  dbg('eval: the "check_for_illegal_ip" eval rule no longer available, '.
      'please update your rules');
  return 0;
}

# note using IPv4 addresses for now due to empty strings matching IP_ADDRESS
# due to bug in pure IPv6 address regular expression
sub helo_ip_mismatch {
  my ($self, $pms) = @_;

  for my $relay (@{$pms->{relays_untrusted}}) {
    # is HELO usable?
    next unless ($relay->{helo} =~ IS_IPV4_ADDRESS &&
		 $relay->{helo} !~ IS_IP_PRIVATE);
    # compare HELO with IP
    return 1 if ($relay->{ip} =~ IS_IPV4_ADDRESS &&
		 $relay->{ip} !~ IS_IP_PRIVATE &&
		 $relay->{helo} ne $relay->{ip} &&
		 # different IP is okay if in same /24
		 $relay->{helo} =~ /^(\d+\.\d+\.\d+\.)/ &&
		 index($relay->{ip}, $1) != 0);
  }

  return 0;
}

###########################################################################

sub check_all_trusted {
  my ($self, $pms) = @_;
  return $pms->{num_relays_trusted}
        && !$pms->{num_relays_untrusted}
        && !$pms->{num_relays_unparseable};
}

sub check_no_relays {
  my ($self, $pms) = @_;
  return !$pms->{num_relays_trusted}
        && !$pms->{num_relays_untrusted}
        && !$pms->{num_relays_unparseable};
}

sub check_relays_unparseable {
  my ($self, $pms) = @_;
  return $pms->{num_relays_unparseable} ? 1 : 0;
}

# Check if the apparent sender (in the last received header) had
# no reverse lookup for it's IP
#
# Look for headers like:
#
#   Received: from mx1.eudoramail.com ([204.32.147.84])
sub check_for_sender_no_reverse {
  my ($self, $pms) = @_;

  # Sender received header is the last in the sequence
  my $srcvd = $pms->{relays_untrusted}->
				[$pms->{num_relays_untrusted} - 1];

  return 0 unless (defined $srcvd);

  # Ignore if the from host is domainless (has no dot)
  return 0 unless ($srcvd->{rdns} =~ /\./);

  # Ignore if the from host is from a private IP range
  return 0 if ($srcvd->{ip_private});

  return 1;
} # check_for_sender_no_reverse()

#Received: from dragnet.sjc.ebay.com (dragnet.sjc.ebay.com [10.6.21.14])
#	by bashir.ebay.com (8.10.2/8.10.2) with SMTP id g29JpwB10940
#	for <rod@begbie.com>; Sat, 9 Mar 2002 11:51:58 -0800

sub check_for_from_domain_in_received_headers {
  my ($self, $pms, $domain, $desired) = @_;
  
  if (exists $pms->{from_domain_in_received}) {
      if (exists $pms->{from_domain_in_received}->{$domain}) {
	  if ($desired eq 'true') {
	      # See use of '0e0' below for why we force int() here:
	      return int($pms->{from_domain_in_received}->{$domain});
	  }
	  else {
	      # And why we deliberately do NOT use integers here:
	      return !$pms->{from_domain_in_received}->{$domain};
	  }
      }
  } else {
      $pms->{from_domain_in_received} = {};
  }

  my $from = $pms->get('From:addr');
  if ($from !~ /\b\Q$domain\E/i) {
      # '0e0' is Perl idiom for "true but zero":
      $pms->{from_domain_in_received}->{$domain} = '0e0';
      return 0;
  }

  my $rcvd = $pms->{relays_trusted_str}."\n".$pms->{relays_untrusted_str};

  if ($rcvd =~ / rdns=\S*\b${domain} [^\]]*by=\S*\b${domain} /) {
      $pms->{from_domain_in_received}->{$domain} = 1;
      return ($desired eq 'true');
  }

  $pms->{from_domain_in_received}->{$domain} = 0;
  return ($desired ne 'true');   
}

sub check_for_no_rdns_dotcom_helo {
  my ($self, $pms) = @_;
  if (!exists $pms->{no_rdns_dotcom_helo}) { $self->_check_received_helos($pms); }
  return $pms->{no_rdns_dotcom_helo} ? 1 : 0;
}

# Bug 1133

# Some spammers will, through HELO, tell the server that their machine
# name *is* the relay; don't know why. An example:

# from mail1.mailwizards.com (m448-mp1.cvx1-b.col.dial.ntli.net
#        [213.107.233.192])
#        by mail1.mailwizards.com

# When this occurs for real, the from name and HELO name will be the
# same, unless the "helo" name is localhost, or the from and by hostsnames
# themselves are localhost
sub _check_received_helos {
  my ($self, $pms) = @_;

  for (my $i = 0; $i < $pms->{num_relays_untrusted}; $i++) {
    my $rcvd = $pms->{relays_untrusted}->[$i];

    # Ignore where IP is in private IP space
    next if ($rcvd->{ip_private});

    my $from_host = $rcvd->{rdns};
    my $helo_host = $rcvd->{helo};
    my $by_host = $rcvd->{by};
    my $no_rdns = $rcvd->{no_reverse_dns};

    next unless defined($helo_host);

    # Check for a faked dotcom HELO, e.g.
    # Received: from mx02.hotmail.com (www.sucasita.com.mx [148.223.251.99])...
    # this can be a stronger spamsign than the normal case, since the
    # big dotcoms don't screw up their rDNS normally ;), so less FPs.
    # Since spammers like sending out their mails from the dotcoms (esp.
    # hotmail and AOL) this will catch those forgeries.
    #
    # allow stuff before the dot-com for both from-name and HELO-name,
    # so HELO="outgoing.aol.com" and from="mx34853495.mx.aol.com" works OK.
    #
    $pms->{no_rdns_dotcom_helo} = 0;
    if ($helo_host =~ /(?:\.|^)(lycos\.com|lycos\.co\.uk|hotmail\.com
		|localhost\.com|excite\.com|caramail\.com
		|cs\.com|aol\.com|msn\.com|yahoo\.com|drizzle\.com)$/ix)
    {
      my $dom = $1;

      # ok, let's catch the case where there's *no* reverse DNS there either
      if ($no_rdns) {
	dbg2("eval: Received: no rDNS for dotcom HELO: from=$from_host HELO=$helo_host");
	$pms->{no_rdns_dotcom_helo} = 1;
      }
    }
  }
} # _check_received_helos()

# FORGED_RCVD_TRAIL
sub check_for_forged_received_trail {
  my ($self, $pms) = @_;
  $self->_check_for_forged_received($pms) unless exists $pms->{mismatch_from};
  return ($pms->{mismatch_from} > 1);
}

# FORGED_RCVD_IP_HELO
sub check_for_forged_received_ip_helo {
  my ($self, $pms) = @_;
  $self->_check_for_forged_received($pms) unless exists $pms->{mismatch_ip_helo};
  return ($pms->{mismatch_ip_helo} > 0);
}

sub _check_for_forged_received {
  my ($self, $pms) = @_;

  $pms->{mismatch_from} = 0;
  $pms->{mismatch_ip_helo} = 0;

  my $IP_PRIVATE = IP_PRIVATE;

  my @fromip = map { $_->{ip} } @{$pms->{relays_untrusted}};
  # just pick up domains for these
  my @by = map {
               hostname_to_domain ($_->{lc_by});
             } @{$pms->{relays_untrusted}};
  my @from = map {
               hostname_to_domain ($_->{lc_rdns});
             } @{$pms->{relays_untrusted}};
  my @helo = map {
               hostname_to_domain ($_->{lc_helo});
             } @{$pms->{relays_untrusted}};
 
  for (my $i = 0; $i < $pms->{num_relays_untrusted}; $i++) {
    next if (!defined $by[$i] || $by[$i] !~ /^\w+(?:[\w.-]+\.)+\w+$/);

    if (defined ($from[$i]) && defined($fromip[$i])) {
      if ($from[$i] =~ /^localhost(?:\.localdomain)?$/) {
        if ($fromip[$i] eq '127.0.0.1') {
          # valid: bouncing around inside 1 machine, via the localhost
          # interface (freshmeat newsletter does this).  TODO: this
	  # may be obsolete, I think we do this in Received.pm anyway
          $from[$i] = undef;
        }
      }
    }

    my $frm = $from[$i];
    my $hlo = $helo[$i];
    my $by = $by[$i];

    dbg2("eval: forged-HELO: from=".(defined $frm ? $frm : "(undef)").
			" helo=".(defined $hlo ? $hlo : "(undef)").
			" by=".(defined $by ? $by : "(undef)"));

    # note: this code won't catch IP-address HELOs, but we already have
    # a separate rule for that anyway.

    next unless ($by =~ /^\w+(?:[\w.-]+\.)+\w+$/);

    my $fip = $fromip[$i];

    if (defined($hlo) && defined($fip)) {
      if ($hlo =~ /^\d+\.\d+\.\d+\.\d+$/
		  && $fip =~ /^\d+\.\d+\.\d+\.\d+$/
		  && $fip ne $hlo)
      {
	$hlo =~ /^(\d+\.\d+)\.\d+\.\d+$/; my $hclassb = $1;
	$fip =~ /^(\d+\.\d+)\.\d+\.\d+$/; my $fclassb = $1;

	# allow private IP addrs here, could be a legit screwup
	if ($hclassb && $fclassb && 
		$hclassb ne $fclassb &&
		$hlo !~ IS_IP_PRIVATE)
	{
	  dbg2("eval: forged-HELO: massive mismatch on IP-addr HELO: '$hlo' != '$fip'");
	  $pms->{mismatch_ip_helo}++;
	}
      }
    }

    my $prev = $from[$i-1];
    if (defined($prev) && $i > 0
		&& $prev =~ /^\w+(?:[\w.-]+\.)+\w+$/
		&& $by ne $prev && !_helo_forgery_welcomelisted($by, $prev))
    {
      dbg2("eval: forged-HELO: mismatch on from: '$prev' != '$by'");
      $pms->{mismatch_from}++;
    }
  }
}

###########################################################################

# support eval-test verbose debugs using "-Deval"
sub dbg2 {
  if (would_log('dbg', 'eval') == 2) {
    dbg(@_);
  }
}

1;
