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

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;

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
      $type = $1;
      eval '
  	    require '.$type.';
            $factory = '.$type.'->new();
           ';
      if ($@) { 
	warn "auto-whitelist: $@";
	undef $factory;
      }
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

=item $meanscore = awl->check_address($addr, $originating_ip);

This method will return the mean score of all messages associated with the
given address, or undef if the address hasn't been seen before.

If B<$originating_ip> is supplied, it will be used in the lookup.

=cut

sub check_address {
  my ($self, $addr, $origip) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $self->{entry} = undef;

  my $fulladdr = $self->pack_addr ($addr, $origip);
  $self->{entry} = $self->{checker}->get_addr_entry ($fulladdr);

  if (!defined $self->{entry}->{count} || $self->{entry}->{count} == 0) {
    # no entry found
    if (defined $origip) {
      # try upgrading a default entry (probably from "add-addr-to-foo")
      my $noipaddr = $self->pack_addr ($addr, undef);
      my $noipent = $self->{checker}->get_addr_entry ($noipaddr);

      if (defined $noipent->{count} && $noipent->{count} > 0) {
	dbg("auto-whitelist: found entry w/o IP address for $addr: replacing with $origip");
	$self->{checker}->remove_entry($noipent);
        # Now assign proper entry the count and totscore values of the no ip entry
        # instead of assigning the whole value to avoid wiping out any information added
        # to the previous entry.
	$self->{entry}->{count} = $noipent->{count};
	$self->{entry}->{totscore} = $noipent->{totscore};
      }
    }
  }

  if ($self->{entry}->{count} == 0) { return undef; }

  return $self->{entry}->{totscore}/$self->{entry}->{count};
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

  $self->{entry}->{count} ||= 0;
  $self->{checker}->add_score($self->{entry}, $score);
}

###########################################################################

=item awl->add_known_good_address($addr);

This method will add a score of -100 to the given address -- effectively
"bootstrapping" the address as being one that should be whitelisted.

=cut

sub add_known_good_address {
  my ($self, $addr) = @_;

  return $self->modify_address($addr, -100);
}


###########################################################################

=item awl->add_known_bad_address($addr);

This method will add a score of 100 to the given address -- effectively
"bootstrapping" the address as being one that should be blacklisted.

=cut

sub add_known_bad_address {
  my ($self, $addr) = @_;

  return $self->modify_address($addr, 100);
}

###########################################################################

sub remove_address {
  my ($self, $addr) = @_;

  return $self->modify_address($addr, undef);
}

###########################################################################

sub modify_address {
  my ($self, $addr, $score) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  my $fulladdr = $self->pack_addr ($addr, undef);
  my $entry = $self->{checker}->get_addr_entry ($fulladdr);

  # remove any old entries (will remove per-ip entries as well)
  # always call this regardless, as the current entry may have 0
  # scores, but the per-ip one may have more
  $self->{checker}->remove_entry($entry);

  # remove address only, no new score to add
  if (!defined($score)) { return 1; }

  # else add score. get a new entry first
  $entry = $self->{checker}->get_addr_entry ($fulladdr);
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

  if (!defined $origip) {
    # could not find an IP address to use, could be localhost mail or from
    # the user running "add-addr-to-*".
    $origip = 'none';
  } else {
    $origip =~ s/\.\d{1,3}\.\d{1,3}$//gs;
  }

  $origip =~ s/[^0-9\.noe]/_/gs;	# paranoia
  $addr."|ip=".$origip;
}

###########################################################################

1;

=back

=cut
