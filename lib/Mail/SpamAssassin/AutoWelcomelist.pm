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

Mail::SpamAssassin::AutoWelcomelist - auto-welcomelist handler for SpamAssassin

=head1 SYNOPSIS

  (see Mail::SpamAssassin)


=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blocklists.

This class is used internally by SpamAssassin to manage the automatic
welcomelisting functionality.  Please refer to the C<Mail::SpamAssassin>
documentation for public interfaces.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::AutoWelcomelist;

use strict;
use warnings;
# use bytes;
use re 'taint';

use NetAddr::IP 4.000;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

our @ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg) = @_;

  my $conf = $main->{conf};
  my $self = {
    main          => $main,
    factor        => $conf->{auto_welcomelist_factor},
    ipv4_mask_len => $conf->{auto_welcomelist_ipv4_mask_len},
    ipv6_mask_len => $conf->{auto_welcomelist_ipv6_mask_len},
  };

  my $factory;
  if ($main->{pers_addr_list_factory}) {
    $factory = $main->{pers_addr_list_factory};
  }
  else {
    my $type = $conf->{auto_welcomelist_factory};
    if ($type =~ /^([_A-Za-z0-9:]+)$/) {
      $type = untaint_var($type);
      eval '
  	require '.$type.';
        $factory = '.$type.'->new();
        1;
      ' or do {
	my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
	warn "auto-welcomelist: $eval_stat\n";
	undef $factory;
      };
      $main->set_persistent_address_list_factory($factory) if $factory;
    }
    else {
      warn "auto-welcomelist: illegal auto_welcomelist_factory setting\n";
    }
  }

  if (!defined $factory) {
    $self->{checker} = undef;
  } else {
    $self->{checker} = $factory->new_checker($self->{main});
  }

  bless ($self, $class);
  $self;
}

###########################################################################

=item $meanscore = awl-E<gt>check_address($addr, $originating_ip, $signedby);

This method will return the mean score of all messages associated with the
given address, or undef if the address hasn't been seen before.

If B<$originating_ip> is supplied, it will be used in the lookup.

=cut

sub check_address {
  my ($self, $addr, $origip, $signedby) = @_;

  if (!defined $self->{checker}) {
    return;		# no factory defined; we can't check
  }

  $self->{entry} = undef;

  my $fulladdr = $self->pack_addr ($addr, $origip);
  my $entry = $self->{checker}->get_addr_entry ($fulladdr, $signedby);
  $self->{entry} = $entry;

  if (!$entry->{msgcount}) {
    # no entry found
    if (defined $origip) {
      # try upgrading a default entry (probably from "add-addr-to-foo")
      my $noipaddr = $self->pack_addr ($addr, undef);
      my $noipent = $self->{checker}->get_addr_entry ($noipaddr, undef);

      if (defined $noipent->{msgcount} && $noipent->{msgcount} > 0) {
	dbg("auto-welcomelist: found entry w/o IP address for $addr: replacing with $origip");
	$self->{checker}->remove_entry($noipent);
        # Now assign proper entry the count and totscore values of the
        # no-IP entry instead of assigning the whole value to avoid
        # wiping out any information added to the previous entry.
	$entry->{msgcount} = $noipent->{msgcount};
	$entry->{totscore} = $noipent->{totscore};
      }
    }
  }

  if ($entry->{msgcount} < 0 ||
      $entry->{msgcount} != $entry->{msgcount} ||  # test for NaN
      $entry->{totscore} != $entry->{totscore})
  {
    warn "auto-welcomelist: resetting bad data for ($addr, $origip), ".
         "count: $entry->{msgcount}, totscore: $entry->{totscore}\n";
    $entry->{msgcount} = $entry->{totscore} = 0;
  }

  return !$entry->{msgcount} ? undef : $entry->{totscore} / $entry->{msgcount};
}

###########################################################################

=item awl-E<gt>count();

This method will return the count of messages used in determining the
welcomelist correction.

=cut

sub count {
  my $self = shift;
  return $self->{entry}->{msgcount};
}


###########################################################################

=item awl-E<gt>add_score($score);

This method will add half the score to the current entry.  Half the
score is used, so that repeated use of the same From and IP address
combination will gradually reduce the score.

=cut

sub add_score {
  my ($self,$score) = @_;

  if (!defined $self->{checker}) {
    return;		# no factory defined; we can't check
  }
  if ($score != $score) {
    warn "auto-welcomelist: attempt to add a $score to AWL entry ignored\n";
    return;		# don't try to add a NaN
  }

  $self->{entry}->{msgcount} ||= 0;
  $self->{checker}->add_score($self->{entry}, $score);
}

###########################################################################

=item awl-E<gt>add_known_good_address($addr);

This method will add a score of -100 to the given address -- effectively
"bootstrapping" the address as being one that should be welcomelisted.

=cut

sub add_known_good_address {
  my ($self, $addr, $signedby) = @_;

  return $self->modify_address($addr, -100, $signedby);
}


###########################################################################

=item awl-E<gt>add_known_bad_address($addr);

This method will add a score of 100 to the given address -- effectively
"bootstrapping" the address as being one that should be blocklisted.

=cut

sub add_known_bad_address {
  my ($self, $addr, $signedby) = @_;

  return $self->modify_address($addr, 100, $signedby);
}

###########################################################################

sub remove_address {
  my ($self, $addr, $signedby) = @_;

  return $self->modify_address($addr, undef, $signedby);
}

###########################################################################

sub modify_address {
  my ($self, $addr, $score, $signedby) = @_;

  if (!defined $self->{checker}) {
    return;		# no factory defined; we can't check
  }

  my $fulladdr = $self->pack_addr ($addr, undef);
  my $entry = $self->{checker}->get_addr_entry ($fulladdr, $signedby);

  # remove any old entries (will remove per-ip entries as well)
  # always call this regardless, as the current entry may have 0
  # scores, but the per-ip one may have more
  $self->{checker}->remove_entry($entry);

  # remove address only, no new score to add
  if (!defined $score)  { return 1; }
  if ($score != $score) { return 1; }  # don't try to add a NaN

  # else add score. get a new entry first
  $entry = $self->{checker}->get_addr_entry ($fulladdr, $signedby);
  $self->{checker}->add_score($entry, $score);

  return 1;
}

###########################################################################

sub finish {
  my $self = shift;

  return  if !defined $self->{checker};
  $self->{checker}->finish();
}

###########################################################################

sub ip_to_awl_key {
  my ($self, $origip) = @_;

  my $result;
  local $1;
  if (!defined $origip) {
    # could not find an IP address to use
  } elsif ($origip =~ /^ (\d{1,3} \. \d{1,3}) \. \d{1,3} \. \d{1,3} $/xs) {
    my $mask_len = $self->{ipv4_mask_len};
    $mask_len = 16  if !defined $mask_len;
    # handle the default and easy cases manually
    if ($mask_len == 32) {
      $result = $origip;
    } elsif ($mask_len == 16) {
      $result = $1;
    } else {
      my $origip_obj = NetAddr::IP->new($origip . '/' . $mask_len);
      if (!defined $origip_obj) {  # invalid IPv4 address
        dbg("auto-welcomelist: bad IPv4 address $origip");
      } else {
        $result = $origip_obj->network->addr;
        $result =~s/(\.0){1,3}\z//;  # truncate zero tail
      }
    }
  } elsif (index($origip, ':') >= 0 &&  # triage
           $origip =~
           /^ [0-9a-f]{0,4} (?: : [0-9a-f]{0,4} | \. [0-9]{1,3} ){2,9} $/xsi) {
    # looks like an IPv6 address
    my $mask_len = $self->{ipv6_mask_len};
    $mask_len = 48  if !defined $mask_len;
    my $origip_obj = NetAddr::IP->new6($origip . '/' . $mask_len);
    if (!defined $origip_obj) {  # invalid IPv6 address
      dbg("auto-welcomelist: bad IPv6 address $origip");
    } elsif (NetAddr::IP->can('full6')) {  # since NetAddr::IP 4.010
      $result = $origip_obj->network->full6;  # string in a canonical form
      $result =~ s/(:0000){1,7}\z/::/;        # compress zero tail
    }
  } else {
    dbg("auto-welcomelist: bad IP address $origip");
  }
  if (defined $result && length($result) > 39) {  # just in case, keep under
    $result = substr($result,0,39);               # the awl.ip field size
  }
  if (defined $result) {
    dbg("auto-welcomelist: IP masking %s -> %s", $origip,$result);
  }
  return $result;
}

###########################################################################

sub pack_addr {
  my ($self, $addr, $origip) = @_;

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia

  if (defined $origip) {
    $origip = $self->ip_to_awl_key($origip);
  }
  if (!defined $origip) {
    # could not find an IP address to use, could be localhost mail
    # or from the user running "add-addr-to-*".
    $origip = 'none';
  }
  return $addr . "|ip=" . $origip;
}

###########################################################################

1;

=back

=cut
