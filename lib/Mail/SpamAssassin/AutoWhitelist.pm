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

Mail::SpamAssassin::AutoWhitelist - auto-whitelist handler for SpamAssassin

=head1 SYNOPSIS

  (see Mail::SpamAssassin)


=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blacklists.

This class is used internally by SpamAssassin to manage the automatic
whitelisting functionality.  Please refer to the C<Mail::SpamAssassin>
documentation for public interfaces.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::AutoWhitelist;

use strict;
use warnings;
use bytes;
use re 'taint';
use NetAddr::IP;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

use vars	qw{
  	@ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg) = @_;

  my $self = {
    'main'		=> $main,
  };

  $self->{factor} = $main->{conf}->{auto_whitelist_factor};

  my $factory;
  if ($main->{pers_addr_list_factory}) {
    $factory = $main->{pers_addr_list_factory};
  }
  else {
    my $type = $main->{conf}->{auto_whitelist_factory};
    if ($type =~ /^([_A-Za-z0-9:]+)$/) {
      $type = untaint_var($type);
      eval '
  	    require '.$type.';
            $factory = '.$type.'->new();
            1;
           '
      or do {
	my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
	warn "auto-whitelist: $eval_stat\n";
	undef $factory;
      };
      $main->set_persistent_address_list_factory($factory) if $factory;
    }
    else {
      warn "auto-whitelist: illegal auto_whitelist_factory setting\n";
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

=item $meanscore = awl->check_address($addr, $originating_ip, $signedby);

This method will return the mean score of all messages associated with the
given address, or undef if the address hasn't been seen before.

If B<$originating_ip> is supplied, it will be used in the lookup.

=cut

sub check_address {
  my ($self, $addr, $origip, $signedby) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $self->{entry} = undef;

  my $fulladdr = $self->pack_addr ($addr, $origip);
  my $entry = $self->{checker}->get_addr_entry ($fulladdr, $signedby);
  $self->{entry} = $entry;

  if (!defined $entry->{count} || $entry->{count} == 0) {
    # no entry found
    if (defined $origip) {
      # try upgrading a default entry (probably from "add-addr-to-foo")
      my $noipaddr = $self->pack_addr ($addr, undef);
      my $noipent = $self->{checker}->get_addr_entry ($noipaddr, $signedby);

      if (defined $noipent->{count} && $noipent->{count} > 0) {
	dbg("auto-whitelist: found entry w/o IP address for $addr: replacing with $origip");
	$self->{checker}->remove_entry($noipent);
        # Now assign proper entry the count and totscore values of the no ip entry
        # instead of assigning the whole value to avoid wiping out any information added
        # to the previous entry.
	$entry->{count} = $noipent->{count};
	$entry->{totscore} = $noipent->{totscore};
      }
    }
  }

  if ($entry->{count} < 0 ||
      $entry->{count} != $entry->{count} ||  # test for NaN
      $entry->{totscore} != $entry->{totscore})
  {
    warn "auto-whitelist: resetting bad data for ($addr, $origip), ".
         "count: $entry->{count}, totscore: $entry->{totscore}\n";
    $entry->{count} = $entry->{totscore} = 0;
  }

  if ($entry->{count} == 0) { return undef }

  return $entry->{totscore} / $entry->{count};
}

###########################################################################

=item awl->count();

This method will return the count of messages used in determining the
whitelist correction.

=cut

sub count {
  my $self = shift;
  return $self->{entry}->{count};
}


###########################################################################

=item awl->add_score($score);

This method will add half the score to the current entry.  Half the
score is used, so that repeated use of the same From and IP address
combination will gradually reduce the score.

=cut

sub add_score {
  my ($self,$score) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }
  if ($score != $score) {
    warn "auto-whitelist: attempt to add a $score to AWL entry ignored\n";
    return undef;		# don't try to add a NaN
  }

  $self->{entry}->{count} ||= 0;
  $self->{checker}->add_score($self->{entry}, $score);
}

###########################################################################

=item awl->add_known_good_address($addr);

This method will add a score of -100 to the given address -- effectively
"bootstrapping" the address as being one that should be whitelisted.

=cut

sub add_known_good_address {
  my ($self, $addr, $signedby) = @_;

  return $self->modify_address($addr, -100, $signedby);
}


###########################################################################

=item awl->add_known_bad_address($addr);

This method will add a score of 100 to the given address -- effectively
"bootstrapping" the address as being one that should be blacklisted.

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
    return undef;		# no factory defined; we can't check
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

  if (!defined $self->{checker}) { return undef; }
  $self->{checker}->finish();
}

###########################################################################

sub pack_addr {
  my ($self, $addr, $origip) = @_;

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia

  local $1;
  if (!defined $origip) {
    # could not find an IP address to use, could be localhost mail or from
    # the user running "add-addr-to-*".
    $origip = 'none';
  } elsif ($origip =~ /^ (\d{1,3} \. \d{1,3}) \. \d{1,3} \. \d{1,3} $/xs) {
    $origip = $1;
  } elsif ($origip =~ /:/  &&
           $origip =~
           /^ [0-9a-f]{0,4} (?: : [0-9a-f]{0,4} | \. [0-9]{1,3} ){2,9} $/xsi) {
    # looks like an IPv6 address
    my $origip_obj = NetAddr::IP->new6($origip);
    if (!defined $origip_obj) {  # invalid IPv6 address
      dbg("auto-whitelist: bad IPv6 address $origip");
      $origip = 'junk-' . $origip;
    } else {
      $origip = $origip_obj->full6;  # string in a canonical form
      $origip =~ s/(:[0-9a-f]{4}){5}\z//si;  # keep only the /48 network addr
    }
  } else {
    dbg("auto-whitelist: bad IP address $origip");
    $origip =~ s/[^0-9A-Fa-f:.]/_/gs;	# paranoia
    $origip = 'junk-' . $origip;
  }
  $origip = substr($origip,0,45)  if length($origip) > 45;  # awl.ip field
  $addr."|ip=".$origip;
}

###########################################################################

1;

=back

=cut
