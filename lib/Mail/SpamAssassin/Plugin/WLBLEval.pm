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

package Mail::SpamAssassin::Plugin::WLBLEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;
use re 'taint';

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

  # the important bit!
  $self->register_eval_rule("check_from_in_blacklist");
  $self->register_eval_rule("check_to_in_blacklist");
  $self->register_eval_rule("check_to_in_whitelist");
  $self->register_eval_rule("check_to_in_more_spam");
  $self->register_eval_rule("check_to_in_all_spam");
  $self->register_eval_rule("check_from_in_list");
  $self->register_eval_rule("check_to_in_list");
  $self->register_eval_rule("check_from_in_whitelist");
  $self->register_eval_rule("check_forged_in_whitelist");
  $self->register_eval_rule("check_from_in_default_whitelist");
  $self->register_eval_rule("check_forged_in_default_whitelist");
  $self->register_eval_rule("check_mailfrom_matches_rcvd");
  $self->register_eval_rule("check_uri_host_listed");
  # same as: eval:check_uri_host_listed('BLACK') :
  $self->register_eval_rule("check_uri_host_in_blacklist");
  # same as: eval:check_uri_host_listed('WHITE') :
  $self->register_eval_rule("check_uri_host_in_whitelist");

  return $self;
}

sub check_from_in_blacklist {
  my ($self, $pms) = @_;
  foreach ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{blacklist_from}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_blacklist {
  my ($self, $pms) = @_;
  foreach ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{blacklist_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_whitelist {
  my ($self, $pms) = @_;
  foreach ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{whitelist_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_more_spam {
  my ($self, $pms) = @_;
  foreach ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{more_spam_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_all_spam {
  my ($self, $pms) = @_;
  foreach ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{all_spam_to}, $_)) {
      return 1;
    }
  }
}

sub check_from_in_list {
  my ($self, $pms, $list) = @_;
  my $list_ref = $self->{main}{conf}{$list};
  unless (defined $list_ref) {
    warn "eval: could not find list $list";
    return;
  }

  foreach my $addr ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($list_ref, $addr)) {
      return 1;
    }
  }

  return 0;
}

# TODO: this should be moved to a utility module off PerMsgStatus,
# rather than a plugin API; it's used in Bayes.pm as a utility
sub check_wb_list {
  my ($self, $params) = @_;

  return unless (defined $params->{permsgstatus});
  return unless (defined $params->{type});
  return unless (defined $params->{list});

  if (lc $params->{type} eq "to") {
    return $self->check_to_in_list($params->{permsgstatus}, $params->{list});
  }
  elsif (lc $params->{type} eq "from") {
    return $self->check_from_in_list($params->{permsgstatus}, $params->{list});
  }

  return;
}

sub check_to_in_list {
  my ($self,$pms,$list) = @_;
  my $list_ref = $self->{main}{conf}{$list};
  unless (defined $list_ref) {
    warn "eval: could not find list $list";
    return;
  }

  foreach my $addr ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($list_ref, $addr)) {
      return 1;
    }
  }

  return 0;
}

###########################################################################

sub check_from_in_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_whitelist($pms) unless exists $pms->{from_in_whitelist};
  return ($pms->{from_in_whitelist} > 0);
}

sub check_forged_in_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_whitelist($pms) unless exists $pms->{from_in_whitelist};
  $self->_check_from_in_default_whitelist($pms) unless exists $pms->{from_in_default_whitelist};
  return ($pms->{from_in_whitelist} < 0) && ($pms->{from_in_default_whitelist} == 0);
}

sub check_from_in_default_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_default_whitelist($pms) unless exists $pms->{from_in_default_whitelist};
  return ($pms->{from_in_default_whitelist} > 0);
}

sub check_forged_in_default_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_default_whitelist($pms) unless exists $pms->{from_in_default_whitelist};
  $self->_check_from_in_whitelist($pms) unless exists $pms->{from_in_whitelist};
  return ($pms->{from_in_default_whitelist} < 0) && ($pms->{from_in_whitelist} == 0);
}

###########################################################################

sub _check_from_in_whitelist {
  my ($self, $pms) = @_;
  my $found_match = 0;
  foreach ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{whitelist_from}, $_)) {
      $pms->{from_in_whitelist} = 1;
      return;
    }
    my $wh = $self->_check_whitelist_rcvd ($pms, $self->{main}->{conf}->{whitelist_from_rcvd}, $_);
    if ($wh == 1) {
      $pms->{from_in_whitelist} = 1;
      return;
    }
    elsif ($wh == -1) {
      $found_match = -1;
    }
  }

  $pms->{from_in_whitelist} = $found_match;
  return;
}

###########################################################################

sub _check_from_in_default_whitelist {
  my ($self, $pms) = @_;
  my $found_match = 0;
  foreach ($pms->all_from_addrs()) {
    my $wh = $self->_check_whitelist_rcvd ($pms, $self->{main}->{conf}->{def_whitelist_from_rcvd}, $_);
    if ($wh == 1) {
      $pms->{from_in_default_whitelist} = 1;
      return;
    }
    elsif ($wh == -1) {
      $found_match = -1;
    }
  }

  $pms->{from_in_default_whitelist} = $found_match;
  return;
}

###########################################################################

# check if domain name of an envelope sender address matches a domain name
# of the first untrusted relay (if any), or any trusted relay otherwise
sub check_mailfrom_matches_rcvd {
  my ($self, $pms) = @_;
  my $sender = $pms->get("EnvelopeFrom:addr");
  return 0  if $sender eq '';
  return $self->_check_addr_matches_rcvd($pms,$sender);
}

# check if domain name of a supplied e-mail address matches a domain name
# of the first untrusted relay (if any), or any trusted relay otherwise
sub _check_addr_matches_rcvd {
  my ($self, $pms, $addr) = @_;

  local $1;
  return 0  if $addr !~ / \@ ( [^\@]+ \. [^\@]+ ) \z/x;
  my $addr_domain = lc $1;

  my @relays;
  if ($pms->{num_relays_untrusted} > 0) {
    # check against the first untrusted, if present
    @relays = $pms->{relays_untrusted}->[0];
  } elsif ($pms->{num_relays_trusted} > 0) {
    # otherwise try all trusted ones, but only do so
    # if there are no untrusted relays to avoid forgery
    push(@relays, @{$pms->{relays_trusted}});
  }
  return 0  if !@relays;

  my($adrh,$adrd) =
    $self->{main}->{registryboundaries}->split_domain($addr_domain);
  my $match = 0;
  my $any_tried = 0;
  foreach my $rly (@relays) {
    my $relay_rdns = $rly->{lc_rdns};
    next  if !defined $relay_rdns || $relay_rdns eq '';
    my($rlyh,$rlyd) =
      $self->{main}->{registryboundaries}->split_domain($relay_rdns);
    $any_tried = 1;
    if ($adrd eq $rlyd) {
      dbg("rules: $addr MATCHES relay $relay_rdns ($adrd)");
      $match = 1; last;
    }
  }
  if ($any_tried && !$match) {
    dbg("rules: %s does NOT match relay(s) %s",
        $addr, join(', ', map { $_->{lc_rdns} } @relays));
  }
  return $match;
}

###########################################################################

# look up $addr and trusted relays in a whitelist with rcvd
# note if it appears to be a forgery and $addr is not in any-relay list
sub _check_whitelist_rcvd {
  my ($self, $pms, $list, $addr) = @_;

  # we can only match this if we have at least 1 trusted or untrusted header
  return 0 unless ($pms->{num_relays_untrusted}+$pms->{num_relays_trusted} > 0);

  my @relays;
  # try the untrusted one first
  if ($pms->{num_relays_untrusted} > 0) {
    @relays = $pms->{relays_untrusted}->[0];
  }
  # then try the trusted ones; the user could have whitelisted a trusted
  # relay, totally permitted
  # but do not do this if any untrusted relays, to avoid forgery -- bug 4425
  if ($pms->{num_relays_trusted} > 0 && !$pms->{num_relays_untrusted} ) {
    push (@relays, @{$pms->{relays_trusted}});
  }

  $addr = lc $addr;
  my $found_forged = 0;
  foreach my $white_addr (keys %{$list}) {
    my $regexp = qr/$list->{$white_addr}{re}/i;
    foreach my $domain (@{$list->{$white_addr}{domain}}) {
      
      if ($addr =~ $regexp) {
        my $match;
        foreach my $lastunt (@relays) {
          local $1;
          if ($domain =~ m{^ \[ (.*) \] \z}sx) {  # matching by IP address
            my($wl_ip, $rly_ip) = ($1, $lastunt->{ip});
            if (!defined $rly_ip || $rly_ip eq '') {
              # relay's IP address not provided or unparseable
            } elsif ($wl_ip =~ /^\d+\.\d+\.\d+\.\d+\z/) {
              if ($wl_ip eq $rly_ip) { $match = 1; last }  # exact match
            } elsif ($wl_ip =~ /^[\d\.]+\z/) {  # assume IPv4 classful subnet
              $wl_ip =~ s/\.*\z/./;  # enforce trailing dot
              if ($rly_ip =~ /^\Q$wl_ip\E/i) { $match = 1; last }  # subnet
            }
            # todo: handle IPv6 and CIDR notation
          } else {  # match by a rdns name
            my $rdns = $lastunt->{lc_rdns};
            if ($rdns =~ /(?:^|\.)\Q${domain}\E$/i) { $match=1; last }
          }
        }
        if ($match) {
          dbg("rules: address %s matches (def_)whitelist_from_rcvd %s %s",
              $addr, $list->{$white_addr}{re}, $domain);
          return 1;
        }
        # found address match but no relay match. note as possible forgery
        $found_forged = -1;
      }
    }
  }
  if ($found_forged) { # might be forgery. check if in list of exempted
    my $wlist = $self->{main}->{conf}->{whitelist_allows_relays};
    foreach my $fuzzy_addr (values %{$wlist}) {
      if ($addr =~ /$fuzzy_addr/i) {
        $found_forged = 0;
        last;
      }
    }
  }
  return $found_forged;
}

###########################################################################

sub _check_whitelist {
  my ($self, $list, $addr) = @_;
  $addr = lc $addr;
  if (defined ($list->{$addr})) { return 1; }
  study $addr;  # study is a no-op since perl 5.16.0, eliminating related bugs
  foreach my $regexp (values %{$list}) {
    if ($addr =~ qr/$regexp/i) {
      dbg("rules: address $addr matches whitelist or blacklist regexp: $regexp");
      return 1;
    }
  }

  return 0;
}

###########################################################################

sub check_uri_host_in_blacklist {
  my ($self, $pms) = @_;
  $self->check_uri_host_listed($pms, 'BLACK');
}

sub check_uri_host_in_whitelist {
  my ($self, $pms) = @_;
  $self->check_uri_host_listed($pms, 'WHITE');
}

sub check_uri_host_listed {
  my ($self, $pms, $subname) = @_;
  my $host_enlisted_ref = $self->_check_uri_host_listed($pms);
  if ($host_enlisted_ref) {
    my $matched_host = $host_enlisted_ref->{$subname};
    if ($matched_host) {
      dbg("rules: uri host enlisted (%s): %s", $subname, $matched_host);
      $pms->test_log("URI: $matched_host");
      return 1;
    }
  }
  return 0;
}

sub _check_uri_host_listed {
  my ($self, $pms) = @_;

  if ($pms->{'uri_host_enlisted'}) {
    return $pms->{'uri_host_enlisted'};  # just provide a cached result
  }

  my $uri_lists_href = $self->{main}{conf}{uri_host_lists};
  if (!$uri_lists_href || !%$uri_lists_href) {
    $pms->{'uri_host_enlisted'} = {};  # no URI host lists
    return $pms->{'uri_host_enlisted'};
  }

  my %host_enlisted;
  my @uri_listnames = sort keys %$uri_lists_href;
  if (would_log("dbg","rules")) {
    foreach my $nm (@uri_listnames) {
      dbg("rules: check_uri_host_listed: (%s) %s",
          $nm, join(', ', map { $uri_lists_href->{$nm}{$_} ? $_ : '!'.$_ }
                              sort keys %{$uri_lists_href->{$nm}}));
    }
  }
  # obtain a complete list of html-parsed domains
  my $uris = $pms->get_uri_detail_list();
  my %seen;
  while (my($uri,$info) = each %$uris) {
    next if $uri =~ /^mailto:/i;  # we may want to skip mailto: uris (?)
    while (my($host,$domain) = each( %{$info->{hosts}} )) {  # typically one
      next if $seen{$host};
      $seen{$host} = 1;
      local($1,$2);
      my @query_keys;
      if ($host =~ /^\[(.*)\]\z/) {  # looks like an address literal
        @query_keys = ( $1 );
      } elsif ($host =~ /^\d+\.\d+\.\d+\.\d+\z/) {  # IPv4 address
        @query_keys = ( $host );
      } elsif ($host ne '') {
        my($h) = $host;
        for (;;) {
          shift @query_keys  if @query_keys > 10;  # sanity limit, keep tail
          push(@query_keys, $h);  # sub.example.com, example.com, com
          last if $h !~ s{^([^.]*)\.(.*)\z}{$2}s;
        }
      }
      foreach my $nm (@uri_listnames) {
        my $match;
        my $verdict;
        my $hash_nm_ref = $uri_lists_href->{$nm};
        foreach my $q (@query_keys) {
          $verdict = $hash_nm_ref->{$q};
          if (defined $verdict) {
            $match = $q eq $host ? $host : "$host ($q)";
            $match = '!'  if !$verdict;
            last;
          }
        }
        if (defined $verdict) {
          $host_enlisted{$nm} = $match  if $verdict;
          dbg("rules: check_uri_host_listed %s, (%s): %s, search: %s",
              $uri, $nm, $match, join(', ',@query_keys));
        }
      }
    }
  }
  $pms->{'uri_host_enlisted'} = \%host_enlisted;
  return $pms->{'uri_host_enlisted'};
}

1;
