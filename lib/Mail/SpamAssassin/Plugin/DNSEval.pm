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

package Mail::SpamAssassin::Plugin::DNSEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);

use strict;
use warnings;
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

  # this is done this way so that the same list can be used here and in
  # check_start()
  $self->{'evalrules'} = [
    'check_rbl_accreditor',
    'check_rbl',
    'check_rbl_txt',
    'check_rbl_sub',
    'check_rbl_results_for',
    'check_rbl_from_host',
    'check_rbl_envfrom',
    'check_dns_sender',
  ];

  foreach(@{$self->{'evalrules'}}) {
    $self->register_eval_rule($_);
  }

  return $self;
}

# this is necessary because PMS::run_rbl_eval_tests() calls these functions
# directly as part of PMS
sub check_start {
  my ($self, $opts) = @_;

  foreach(@{$self->{'evalrules'}}) {
    $opts->{'permsgstatus'}->register_plugin_eval_glue($_);
  }
}

sub ip_list_uniq_and_strip_private {
  my ($self, @origips) = @_;
  my @ips = ();
  my %seen = ();
  my $IP_PRIVATE = IP_PRIVATE;
  foreach my $ip (@origips) {
    next unless $ip;
    next if (exists ($seen{$ip})); $seen{$ip} = 1;
    next if ($ip =~ /$IP_PRIVATE/o);
    push(@ips, $ip);
  }
  return @ips;
}

# check an RBL if the message contains an "accreditor assertion,"
# that is, the message contains the name of a service that will vouch
# for their practices.
#
sub check_rbl_accreditor {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest, $accreditor) = @_;

  if (!defined $pms->{accreditor_tag}) {
    $self->message_accreditor_tag($pms);
  }
  if ($pms->{accreditor_tag}->{$accreditor}) {
    $self->check_rbl_backend($pms, $rule, $set, $rbl_server, 'A', $subtest);
  }
  return 0;
}

# Check for an Accreditor Assertion within the message, that is, the name of
#	a third-party who will vouch for the sender's practices. The accreditor
#	can be asserted in the EnvelopeFrom like this:
#
#	    listowner@a--accreditor.mail.example.com
#
#	or in an 'Accreditor" Header field, like this:
#
#	    Accreditor: accreditor1, parm=value; accreditor2, parm-value
#
#	This implementation supports multiple accreditors, but ignores any
#	parameters in the header field.
#
sub message_accreditor_tag {
  my ($self, $pms) = @_;
  my %acctags;

  if ($pms->get('EnvelopeFrom:addr') =~ /[@.]a--([a-z0-9]{3,})\./i) {
    (my $tag = $1) =~ tr/A-Z/a-z/;
    $acctags{$tag} = -1;
  }
  my $accreditor_field = $pms->get('Accreditor');
  if (defined($accreditor_field)) {
    my @accreditors = split(/,/, $accreditor_field);
    foreach my $accreditor (@accreditors) {
      my @terms = split(' ', $accreditor);
      if ($#terms >= 0) {
	  my $tag = $terms[0];
	  $tag =~ tr/A-Z/a-z/;
	  $acctags{$tag} = -1;
      }
    }
  }
  $pms->{accreditor_tag} = \%acctags;
}

sub check_rbl_backend {
  my ($self, $pms, $rule, $set, $rbl_server, $type, $subtest) = @_;
  local ($_);

  # First check that DNS is available, if not do not perform this check
  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 unless $pms->is_dns_available();
  $pms->load_resolver();

  if (($rbl_server !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) &&
      (index($rbl_server, '.') >= 0) &&
      ($rbl_server !~ /\.$/)) {
    $rbl_server .= ".";
  }

  dbg("dns: checking RBL $rbl_server, set $set");

  # ok, make a list of all the IPs in the untrusted set
  my @fullips = map { $_->{ip} } @{$pms->{relays_untrusted}};

  # now, make a list of all the IPs in the external set, for use in
  # notfirsthop testing.  this will often be more IPs than found
  # in @fullips.  It includes the IPs that are trusted, but
  # not in internal_networks.
  my @fullexternal = map {
	(!$_->{internal}) ? ($_->{ip}) : ()
      } @{$pms->{relays_trusted}};
  push (@fullexternal, @fullips);	# add untrusted set too

  # Make sure a header significantly improves results before adding here
  # X-Sender-Ip: could be worth using (very low occurance for me)
  # X-Sender: has a very low bang-for-buck for me
  my $IP_ADDRESS = IP_ADDRESS;
  my @originating = ();
  for my $header ('X-Originating-IP', 'X-Apparently-From') {
    my $str = $pms->get($header);
    next unless $str;
    push (@originating, ($str =~ m/($IP_ADDRESS)/g));
  }

  # Let's go ahead and trim away all private ips (KLC)
  # also uniq the list and strip dups. (jm)
  my @ips = $self->ip_list_uniq_and_strip_private(@fullips);

  # if there's no untrusted IPs, it means we trust all the open-internet
  # relays, so we can return right now.
  return 0 unless (scalar @ips + scalar @originating > 0);

  dbg("dns: IPs found: full-external: ".join(", ", @fullexternal).
	" untrusted: ".join(", ", @ips).
	" originating: ".join(", ", @originating));

  my $trusted = $self->{main}->{conf}->{trusted_networks};

  if (scalar @ips + scalar @originating > 0) {
    # If name is foo-notfirsthop, check all addresses except for
    # the originating one.  Suitable for use with dialup lists, like the PDL.
    # note that if there's only 1 IP in the untrusted set, do NOT pop the
    # list, since it'd remove that one, and a legit user is supposed to
    # use their SMTP server (ie. have at least 1 more hop)!
    # If name is foo-lastexternal, check only the Received header just before
    # it enters our internal networks; we can trust it and it's the one that
    # passed mail between networks
    if ($set =~ /-(notfirsthop|lastexternal)$/)
    {
      # use the external IP set, instead of the trusted set; the user may have
      # specified some third-party relays as trusted.  Also, don't use
      # @originating; those headers are added by a phase of relaying through
      # a server like Hotmail, which is not going to be in dialup lists anyway.
      @ips = $self->ip_list_uniq_and_strip_private(@fullexternal);
      if ($1 eq "lastexternal") {
        @ips = (defined $ips[0]) ? ($ips[0]) : ();
      } else {
	pop @ips if (scalar @ips > 1);
      }
    }
    # If name is foo-firsttrusted, check only the Received header just
    # after it enters our trusted networks; that's the only one we can
    # trust the IP address from (since our relay added that header).
    # And if name is foo-untrusted, check any untrusted IP address.
    elsif ($set =~ /-(first|un)trusted$/)
    {
      my @tips = ();
      foreach my $ip (@originating) {
        if ($ip && !$trusted->contains_ip($ip)) {
          push(@tips, $ip);
        }
      }
      @ips = $self->ip_list_uniq_and_strip_private (@ips, @tips);
      if ($1 eq "first") {
        @ips = (defined $ips[0]) ? ($ips[0]) : ();
      } else {
        shift @ips;
      }
    }
    else
    {
      my @tips = ();
      foreach my $ip (@originating) {
        if ($ip && !$trusted->contains_ip($ip)) {
          push(@tips, $ip);
        }
      }
      # add originating IPs as untrusted IPs (if they are untrusted)
      @ips = reverse $self->ip_list_uniq_and_strip_private (@ips, @tips);

      # How many IPs max you check in the received lines
      my $checklast=$self->{main}->{conf}->{num_check_received};

      if (scalar @ips > $checklast) {
	splice (@ips, $checklast);	# remove all others
      }
    }
  }
  dbg("dns: only inspecting the following IPs: ".join(", ", @ips));

  eval {
    foreach my $ip (@ips) {
      next unless ($ip =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
      $pms->do_rbl_lookup($rule, $set, $type, $rbl_server,
			   "$4.$3.$2.$1.$rbl_server", $subtest);
    }
  };

  # note that results are not handled here, hits are handled directly
  # as DNS responses are harvested
  return 0;
}

sub check_rbl {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;
  $self->check_rbl_backend($pms, $rule, $set, $rbl_server, 'A', $subtest);
}

sub check_rbl_txt {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;
  $self->check_rbl_backend($pms, $rule, $set, $rbl_server, 'TXT', $subtest);
}

# run for first message 
sub check_rbl_sub {
  my ($self, $pms, $rule, $set, $subtest) = @_;

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 unless $pms->is_dns_available();

  $pms->register_rbl_subtest($rule, $set, $subtest);
}

# backward compatibility
sub check_rbl_results_for {
  #warn "dns: check_rbl_results_for() is deprecated, use check_rbl_sub()\n";
  check_rbl_sub(@_);
}

# this only checks the address host name and not the domain name because
# using the domain name had much worse results for dsn.rfc-ignorant.org
sub check_rbl_from_host {
  _check_rbl_addresses(@_, $_[1]->all_from_addrs());
}

# this only checks the address host name and not the domain name because
# using the domain name had much worse results for dsn.rfc-ignorant.org
sub check_rbl_envfrom {
  _check_rbl_addresses(@_, $_[1]->get('EnvelopeFrom:addr'));
}

sub _check_rbl_addresses {
  my ($self, $pms, $rule, $set, $rbl_server, @addresses) = @_;
  
  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 unless $pms->is_dns_available();

  my %hosts;
  for my $address (@addresses) {
    if ($address =~ m/\@(\S+\.\S+)/) {
      $hosts{lc($1)} = 1;
    }
  }
  return unless scalar keys %hosts;

  $pms->load_resolver();

  if (($rbl_server !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) &&
      (index($rbl_server, '.') >= 0) &&
      ($rbl_server !~ /\.$/)) {
    $rbl_server .= ".";
  }
  dbg("dns: _check_rbl_addresses RBL $rbl_server, set $set");

  for my $host (keys %hosts) {
    $pms->do_rbl_lookup($rule, $set, 'A', $rbl_server, "$host.$rbl_server");
  }
}

sub check_dns_sender {
  my ($self, $pms, $rule) = @_;

  my $host;
  for my $from ($pms->get('EnvelopeFrom:addr')) {
    next unless defined $from;

    $from =~ tr/././s;		# bug 3366
    if ($from =~ /\@(\S+\.\S+)/) {
      $host = lc($1);
      last;
    }
  }
  return 0 unless defined $host;

  # First check that DNS is available, if not do not perform this check
  # TODO: need a way to skip DNS checks as a whole in configuration
  return 0 unless $pms->is_dns_available();
  $pms->load_resolver();

  if ($host eq 'compiling.spamassassin.taint.org') {
    # only used when compiling
    return 0;
  }

  dbg("dns: checking A and MX for host $host");

  $pms->do_dns_lookup($rule, 'A', $host);
  $pms->do_dns_lookup($rule, 'MX', $host);

  # cache name of host for later checking
  $pms->{sender_host} = $host;

  return 0;
}

1;
