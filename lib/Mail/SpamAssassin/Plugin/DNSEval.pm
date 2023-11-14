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

=head1 NAME

DNSEVAL - look up URLs against DNS blocklists

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DNSEval

 rbl_headers EnvelopeFrom,Reply-To,Disposition-Notification-To
 header     RBL_IP    eval:check_rbl_headers('rbl', 'rbl.example.com.', '127.0.0.2')
 describe   RBL_IP    From address associated with spam domains
 tflags     RBL_IP    net
 reuse      RBL_IP

 Supported extra tflags from SpamAssassin 3.4.3:
  domains_only - only non-IP-address "host" components are queried
  ips_only - only IP addresses as the "host" component will be queried

=head1 DESCRIPTION

The DNSEval plugin queries dns to see if a domain or an ip address
present on one of email's headers is on a particular rbl.

=cut

package Mail::SpamAssassin::Plugin::DNSEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(reverse_ip_address idn_to_ascii compile_regexp is_fqdn_valid);

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

my $IP_ADDRESS = IP_ADDRESS;

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
    'check_rbl_ns_from',
    'check_rbl_txt',
    'check_rbl_sub',
    'check_rbl_from_host',
    'check_rbl_from_domain',
    'check_rbl_envfrom',
    'check_rbl_headers',
    'check_rbl_rcvd',
    'check_dns_sender',
  ];

  $self->set_config($mailsaobject->{conf});
  foreach(@{$self->{'evalrules'}}) {
    $self->register_eval_rule($_, $Mail::SpamAssassin::Conf::TYPE_RBL_EVALS);
  }

  return $self;
}

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=over

=item rbl_headers

 This option tells SpamAssassin in which headers to check for content
 used to query the specified rbl.
 If on the headers content there is an email address, an ip address
 or a domain name, it will be checked on the specified rbl.
 The configuration option can be overridden by passing an headers list as
 last parameter to check_rbl_headers.
 The default headers checked are:

=back

=over

=item *

EnvelopeFrom

=item *

Reply-To

=item *

Disposition-Notification-To

=item *

X-WebmailclientIP

=item *

X-Source-IP

=back

=cut

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;
    push(@cmds, {
        setting => 'rbl_headers',
        is_priv => 1,
        default => 'EnvelopeFrom,Reply-To,Disposition-Notification-To,X-WebmailclientIP,X-Source-IP',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        }
    );
    $conf->{parser}->register_commands(\@cmds);
}

# this is necessary because PMS::run_rbl_eval_tests() calls these functions
# directly as part of PMS
sub check_start {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  foreach(@{$self->{'evalrules'}}) {
    $pms->register_plugin_eval_glue($_);
  }

  # Initialize check_rbl_sub tests
  $self->_init_rbl_subs($pms);
}

sub _init_rbl_subs {
  my ($self, $pms) = @_;
  my $conf = $pms->{conf};

  # Very hacky stuff and direct rbl_evals usage for now, TODO rewrite everything
  foreach my $rule (@{$conf->{eval_to_rule}->{check_rbl_sub}||[]}) {
    next if !exists $conf->{rbl_evals}->{$rule};
    next if !$conf->{scores}->{$rule};
    # rbl_evals is [$function,[@args]]
    my $args = $conf->{rbl_evals}->{$rule}->[1];
    my ($set, $subtest) = @$args;
    if (!defined $subtest) {
      warn("dnseval: missing subtest for rule $rule\n");
      next;
    }
    if ($subtest =~ /^sb:/) {
      warn("dnseval: ignored $rule, SenderBase rules are deprecated\n");
      next;
    }
    # Compile as regex if not pure ip/bitmask (same check in process_dnsbl_result)
    if ($subtest !~ /^\d+(?:\.\d+\.\d+\.\d+)?$/) {
      my ($rec, $err) = compile_regexp($subtest, 0);
      if (!$rec) {
        warn("dnseval: invalid rule $rule subtest regexp '$subtest': $err\n");
        next;
      }
      $subtest = $rec;
    }
    dbg("dnseval: initialize check_rbl_sub for rule $rule, set $set, subtest $subtest");
    push @{$pms->{rbl_subs}{$set}}, [$subtest, $rule];
  }
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};

  return 1 if $self->{main}->{conf}->{skip_rbl_checks};
  return 1 if !$pms->is_dns_available();

  # Process relaylists only once, not everytime in check_rbl_backend
  #
  # ok, make a list of all the IPs in the untrusted set
  my @fullips = map { $_->{ip} } @{$pms->{relays_untrusted}};
  # now, make a list of all the IPs in the external set, for use in
  # notfirsthop testing.  This will often be more IPs than found
  # in @fullips.  It includes the IPs that are trusted, but
  # not in internal_networks.
  my @fullexternal = map {
	(!$_->{internal}) ? ($_->{ip}) : ()
      } @{$pms->{relays_trusted}};
  push @fullexternal, @fullips; # add untrusted set too
  # Make sure a header significantly improves results before adding here
  # X-Sender-Ip: could be worth using (very low occurence for me)
  # X-Sender: has a very low bang-for-buck for me
  my @originating;
  foreach my $header (@{$pms->{conf}->{originating_ip_headers}}) {
    my $str = $pms->get($header, undef);
    next unless defined $str && $str ne '';
    push @originating, ($str =~ m/($IP_ADDRESS)/g);
  }
  # Let's go ahead and trim away all private ips (KLC)
  # also uniq the list and strip dups. (jm)
  my @ips = $self->ip_list_uniq_and_strip_private(@fullips);
  # if there's no untrusted IPs, it means we trust all the open-internet
  # relays, so we skip checks
  if (scalar @ips + scalar @originating > 0) {
    dbg("dnseval: IPs found: full-external: ".join(", ", @fullexternal).
      " untrusted: ".join(", ", @ips).
      " originating: ".join(", ", @originating));
    @{$pms->{dnseval_fullexternal}} = @fullexternal;
    @{$pms->{dnseval_ips}} = @ips;
    @{$pms->{dnseval_originating}} = @originating;
  }

  return 1;
}

sub ip_list_uniq_and_strip_private {
  my ($self, @origips) = @_;
  my @ips;
  my %seen;
  foreach my $ip (@origips) {
    next unless $ip;
    next if exists $seen{$ip};
    $seen{$ip} = 1;
    next if $ip =~ IS_IP_PRIVATE;
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

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  if (!defined $pms->{accreditor_tag}) {
    $self->message_accreditor_tag($pms);
  }
  if ($pms->{accreditor_tag}->{$accreditor}) {
    # return undef for async status
    return $self->_check_rbl_backend($pms, $rule, $set, $rbl_server, 'A', $subtest);
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
  my $accreditor_field = $pms->get('Accreditor',undef);
  if (defined $accreditor_field) {
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

sub _check_rbl_backend {
  my ($self, $pms, $rule, $set, $rbl_server, $type, $subtest) = @_;

  return if !exists $pms->{dnseval_ips}; # no untrusted ips

  $rbl_server =~ s/\.+\z//; # strip unneeded trailing dot
  dbg("dnseval: checking RBL $rbl_server, set $set, rule $rule");

  my $trusted = $self->{main}->{conf}->{trusted_networks};
  my @ips = @{$pms->{dnseval_ips}};

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
    @ips = $self->ip_list_uniq_and_strip_private(@{$pms->{dnseval_fullexternal}});
    if ($1 eq "lastexternal") {
      @ips = defined $ips[0] ? ($ips[0]) : ();
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
    my @tips;
    foreach my $ip (@{$pms->{dnseval_originating}}) {
      if ($ip && !$trusted->contains_ip($ip)) {
        push(@tips, $ip);
      }
    }
    @ips = $self->ip_list_uniq_and_strip_private(@ips, @tips);
    if ($1 eq "first") {
      @ips = defined $ips[0] ? ($ips[0]) : ();
    } else {
      shift @ips;
    }
  }
  else
  {
    my @tips;
    foreach my $ip (@{$pms->{dnseval_originating}}) {
      if ($ip && !$trusted->contains_ip($ip)) {
        push(@tips, $ip);
      }
    }

    # add originating IPs as untrusted IPs (if they are untrusted)
    @ips = reverse $self->ip_list_uniq_and_strip_private (@ips, @tips);
  }

  # How many IPs max you check in the received lines
  my $checklast = $self->{main}->{conf}->{num_check_received};

  if (scalar @ips > $checklast) {
    splice (@ips, $checklast);	# remove all others
  }

  # Trusted relays should only be checked against nice rules (dnswls)
  if (($pms->{conf}->{tflags}->{$rule}||'') !~ /\bnice\b/) {
    # remove trusted hosts from beginning
    while (@ips && $trusted->contains_ip($ips[0])) { shift @ips }
  }

  unless (scalar @ips > 0) {
    dbg("dnseval: no untrusted IPs to check");
    return 0;
  }

  dbg("dnseval: only inspecting the following IPs: ".join(", ", @ips));

  my $queries;
  foreach my $ip (@ips) {
    if (defined(my $revip = reverse_ip_address($ip))) {
      my $ret = $pms->do_rbl_lookup($rule, $set, $type, $revip.'.'.$rbl_server, $subtest);
      $queries++ if defined $ret;
    }
  }

  # note that results are not handled here, hits are handled directly
  # as DNS responses are harvested
  return 0 if !$queries; # no query started
  return; # return undef for async status
}

sub check_rbl {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  # return undef for async status
  return $self->_check_rbl_backend($pms, $rule, $set, $rbl_server, 'A', $subtest);
}

sub check_rbl_txt {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  # return undef for async status
  return $self->_check_rbl_backend($pms, $rule, $set, $rbl_server, 'TXT', $subtest);
}

sub check_rbl_sub {
  my ($self, $pms, $rule, $set, $subtest) = @_;
  # just a dummy, _init_rbl_subs/do_rbl_lookup handles the subs

  return; # return undef for async status
}

# this only checks the address host name and not the domain name because
# using the domain name had much worse results for dsn.rfc-ignorant.org
sub check_rbl_from_host {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_; 

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  # return undef for async status
  return $self->_check_rbl_addresses($pms, $rule, $set, $rbl_server,
                                     $subtest, $pms->all_from_addrs());
}

sub check_rbl_headers {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest, $test_headers) = @_;

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  my @env_hdr;
  my $conf = $self->{main}->{conf};

  if ( defined $test_headers ) {
    @env_hdr = split(/,/, $test_headers);
  } else {
    @env_hdr = split(/,/, $conf->{rbl_headers});
  }

  my $queries;
  foreach my $rbl_headers (@env_hdr) {
    my $addr = $pms->get($rbl_headers.':addr', undef);
    if ( defined $addr && $addr =~ /\@([^\@\s]+)/ ) {
      my $ret = $self->_check_rbl_addresses($pms, $rule, $set, $rbl_server,
                                            $subtest, $addr);
      $queries++ if defined $ret;
    } else {
      my $unsplitted_host = $pms->get($rbl_headers);
      chomp($unsplitted_host);
      foreach my $host (split(/\n/, $unsplitted_host)) {
        if ($host =~ IS_IP_ADDRESS) {
          next if ($conf->{tflags}->{$rule}||'') =~ /\bdomains_only\b/;
          $host = reverse_ip_address($host);
        } else {
          next if ($conf->{tflags}->{$rule}||'') =~ /\bips_only\b/;
          next unless is_fqdn_valid($host);
          next unless $pms->{main}->{registryboundaries}->is_domain_valid($host);
        }
        my $ret = $pms->do_rbl_lookup($rule, $set, 'A', "$host.$rbl_server", $subtest);
        $queries++ if defined $ret;
      }
    }
  }

  return 0 if !$queries; # no query started
  return; # return undef for async status
}

=over 4

=item check_rbl_from_domain

This checks all the from addrs domain names as an alternate to
check_rbl_from_host.  As of v3.4.1, it has been improved to include a
subtest for a specific octet.

=back

=cut

sub check_rbl_from_domain {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  # return undef for async status
  return $self->_check_rbl_addresses($pms, $rule, $set, $rbl_server,
                                     $subtest, $pms->all_from_addrs_domains());
}

=over 4

=item check_rbl_ns_from

This checks the dns server of the from addrs domain name.
It is possible to include a subtest for a specific octet.

=back

=cut

sub check_rbl_ns_from {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;
  my $domain;
  my @nshost = ();

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 unless $pms->is_dns_available();

  dbg("dnseval: EnvelopeFrom header not found") unless defined (($pms->get("EnvelopeFrom:addr"))[0]);
  for my $from ($pms->get('EnvelopeFrom:addr')) {
    next unless defined $from;
    $from =~ tr/././s;          # bug 3366
    if ($from =~ m/ \@ ( [^\@\s]+ \. [^\@\s]+ )/x ) {
      $domain = lc($1);
      last;
    }
  }
  return 0 unless defined $domain;

  dbg("dnseval: checking NS for host $domain");

  my $obj = { dom => $domain, rule => $rule, set => $set, rbl_server => $rbl_server, subtest => $subtest };
  my $ent = {
    rulename => $rule, zone => $domain, obj => $obj, type => "URI-NS",
  };
  # dig $dom ns
  my $ret = $pms->{async}->bgsend_and_start_lookup(
    $domain, 'NS', undef, $ent,
    sub { my ($ent2,$pkt) = @_;
          $self->complete_ns_lookup($pms, $ent2, $pkt, $domain) },
    master_deadline => $pms->{master_deadline} );
  return 0 if !defined $ret; # no query started
  return; # return undef for async status
}

sub complete_ns_lookup {
  my ($self, $pms, $ent, $pkt, $host) = @_;

  my $rule = $ent->{obj}->{rule};
  my $set = $ent->{obj}->{set};
  my $rbl_server = $ent->{obj}->{rbl_server};
  my $subtest = $ent->{obj}->{subtest};

  if (!$pkt) {
    # $pkt will be undef if the DNS query was aborted (e.g. timed out)
    dbg("dnseval: complete_ns_lookup aborted %s", $ent->{key});
    return;
  }

  dbg("dnseval: complete_ns_lookup %s", $ent->{key});
  my @ns = $pkt->authority;

  foreach my $rr (@ns) {
    my $nshost = $rr->mname;
    next unless defined $nshost;
    chomp($nshost);
    if (is_fqdn_valid($nshost)) {
      if ( defined $subtest ) {
        dbg("dnseval: checking [$nshost] / $rule / $set / $rbl_server / $subtest");
      } else {
        dbg("dnseval: checking [$nshost] / $rule / $set / $rbl_server");
      }
      $pms->do_rbl_lookup($rule, $set, 'A',
        "$nshost.$rbl_server", $subtest);
    }
  }
}

=over 4

=item check_rbl_rcvd

This checks all received headers domains or ip addresses against a specific rbl.
It is possible to include a subtest for a specific octet.

=back

=cut

sub check_rbl_rcvd {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_;
  my %seen;
  my @udnsrcvd = ();

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  my $rcvd = $pms->{relays_untrusted}->[$pms->{num_relays_untrusted} - 1];
  my @dnsrcvd = ( $rcvd->{ip}, $rcvd->{by}, $rcvd->{helo}, $rcvd->{rdns} );
  # unique values
  foreach my $value (@dnsrcvd) {
    if ( ( defined $value ) && (! $seen{$value}++ ) ) {
      push @udnsrcvd, $value;
    }
  }

  my $queries;
  foreach my $host ( @udnsrcvd ) {
    if((defined $host) and ($host ne "")) {
      chomp($host);
      if ($host =~ IS_IP_ADDRESS) {
        next if ($pms->{conf}->{tflags}->{$rule}||'') =~ /\bdomains_only\b/;
        $host = reverse_ip_address($host);
      } else {
        next if ($pms->{conf}->{tflags}->{$rule}||'') =~ /\bips_only\b/;
        $host =~ s/\.$//;
        next unless is_fqdn_valid($host);
        next unless $pms->{main}->{registryboundaries}->is_domain_valid($host);
      }
      if ( defined $subtest ) {
        dbg("dnseval: checking [$host] / $rule / $set / $rbl_server / $subtest");
      } else {
        dbg("dnseval: checking [$host] / $rule / $set / $rbl_server");
      }
      my $ret = $pms->do_rbl_lookup($rule, $set, 'A', "$host.$rbl_server", $subtest);
      $queries++ if defined $ret;
    }
  }

  return 0 if !$queries; # no query started
  return; # return undef for async status
}

# this only checks the address host name and not the domain name because
# using the domain name had much worse results for dsn.rfc-ignorant.org
sub check_rbl_envfrom {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest) = @_; 

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  # return undef for async status
  return $self->_check_rbl_addresses($pms, $rule, $set, $rbl_server,
                                 $subtest, $pms->get('EnvelopeFrom:addr',undef));
}

sub _check_rbl_addresses {
  my ($self, $pms, $rule, $set, $rbl_server, $subtest, @addresses) = @_;
  
  $rbl_server =~ s/\.+\z//; # strip unneeded trailing dot

  my %hosts;
  for (@addresses) {
    next if !defined($_) || !/\@([^\@\s]+)/;
    my $address = $1;
    # strip leading & trailing dots (as seen in some e-mail addresses)
    $address =~ s/^\.+//;
    $address =~ s/\.+\z//;
    # squash duplicate dots to avoid an invalid DNS query with a null label
    # Also checks it's FQDN
    if ($address =~ tr/.//s) {
      $hosts{lc($address)} = 1;
    }
  }
  return unless scalar keys %hosts;

  my $queries;
  for my $host (keys %hosts) {
    if ($host =~ IS_IP_ADDRESS) {
      next if ($pms->{conf}->{tflags}->{$rule}||'') =~ /\bdomains_only\b/;
      $host = reverse_ip_address($host);
    } else {
      next if ($pms->{conf}->{tflags}->{$rule}||'') =~ /\bips_only\b/;
      next unless is_fqdn_valid($host);
      next unless $pms->{main}->{registryboundaries}->is_domain_valid($host);
    }
    dbg("dnseval: checking [$host] / $rule / $set / $rbl_server");
    my $ret = $pms->do_rbl_lookup($rule, $set, 'A', "$host.$rbl_server", $subtest);
    $queries++ if defined $ret;
  }

  return 0 if !$queries; # no async
  return; # return undef for async status
}

sub check_dns_sender {
  my ($self, $pms, $rule) = @_;

  return 0 if $self->{main}->{conf}->{skip_rbl_checks};
  return 0 if !$pms->is_dns_available();

  my $host;
  foreach my $from ($pms->get('EnvelopeFrom:addr', undef)) {
    next unless defined $from;
    $from =~ tr/.//s; # bug 3366
    if ($from =~ m/\@([^\@\s]+\.[^\@\s]+)/) {
      $host = lc($1);
      last;
    }
  }
  return 0 unless defined $host;

  if ($host eq 'compiling.spamassassin.taint.org') {
    # only used when compiling
    return 0;
  }

  $host = idn_to_ascii($host);
  dbg("dnseval: checking A and MX for host $host");

  my $queries;
  my $ret = $self->do_sender_lookup($pms, $rule, 'A', $host);
  $queries++ if defined $ret;
  $ret = $self->do_sender_lookup($pms, $rule, 'MX', $host);
  $queries++ if defined $ret;

  return 0 if !$queries; # no query started
  return; # return undef for async status
}

sub do_sender_lookup {
  my ($self, $pms, $rule, $type, $host) = @_;

  my $ent = {
    rulename => $rule,
    type => "DNSBL-Sender",
  };
  return $pms->{async}->bgsend_and_start_lookup(
    $host, $type, undef, $ent, sub {
      my ($ent, $pkt) = @_;
      return if !$pkt; # aborted / timed out
      $pms->rule_ready($ent->{rulename}); # mark as run, could still hit
      foreach my $answer ($pkt->answer) {
        next if !$answer;
        next if $answer->type ne 'A' && $answer->type ne 'MX';
        if ($pkt->header->rcode eq 'NXDOMAIN' ||
            $pkt->header->rcode eq 'SERVFAIL')
        {
          if (++$pms->{sender_host_fail} == 2) {
            $pms->got_hit($ent->{rulename}, "DNS: ", ruletype => "dns");
          }
        }
      }
    },
    master_deadline => $self->{master_deadline},
  );
}

# capability checks for "if can(Mail::SpamAssassin::Plugin::DNSEval::XXX)":
#
sub has_tflags_domains_only { 1 }
sub has_tflags_ips_only { 1 }

1;
