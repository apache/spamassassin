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

  return $self;
}

sub check_from_in_blacklist {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{blacklist_from}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_blacklist {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{blacklist_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_whitelist {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{whitelist_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_more_spam {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{more_spam_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_all_spam {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
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
  local ($_);
  foreach $_ ($pms->all_from_addrs()) {
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
  local ($_);
  foreach $_ ($pms->all_from_addrs()) {
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

# look up $addr and trusted relays in a whitelist with rcvd
# note if it appears to be a forgery and $addr is not in any-relay list
sub _check_whitelist_rcvd {
  my ($self, $pms, $list, $addr) = @_;

  # we can only match this if we have at least 1 trusted or untrusted header
  return 0 unless ($pms->{num_relays_untrusted}+$pms->{num_relays_trusted} > 0);

  my @relays = ();
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
        foreach my $lastunt (@relays) {
          my $rdns = $lastunt->{lc_rdns};
          if ($rdns =~ /(?:^|\.)\Q${domain}\E$/i) { 
            dbg("rules: address $addr matches (def_)whitelist_from_rcvd $list->{$white_addr}{re} ${domain}");
            return 1;
          }
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
  study $addr;
  foreach my $regexp (values %{$list}) {
    if ($addr =~ qr/$regexp/i) {
      dbg("rules: address $addr matches whitelist or blacklist regexp: $regexp");
      return 1;
    }
  }

  return 0;
}

1;
