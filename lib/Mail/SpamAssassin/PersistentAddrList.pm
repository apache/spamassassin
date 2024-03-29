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

Mail::SpamAssassin::PersistentAddrList - persistent address list base class

=head1 SYNOPSIS

  my $factory = PersistentAddrListSubclass->new();
  $spamtest->set_persistent_addr_list_factory ($factory);
  ... call into SpamAssassin classes...

SpamAssassin will call:

  my $addrlist = $factory->new_checker($spamtest);
  $entry = $addrlist->get_addr_entry ($addr);
  ...

=head1 DESCRIPTION

All persistent address list implementations, used by the auto-welcomelist
code to track known-good email addresses, use this as a base class.

See C<Mail::SpamAssassin::DBBasedAddrList> for an example.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::PersistentAddrList;

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw();

###########################################################################

=item $factory = PersistentAddrListSubclass-E<gt>new();

This creates a factory object, which SpamAssassin will call to create
a new checker object for the persistent address list.

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = { };
  bless ($self, $class);
  $self;
}

###########################################################################

=item my $addrlist = $factory-E<gt>new_checker();

Create a new address-list checker object from the factory. Called by the
SpamAssassin classes.

=cut 

sub new_checker {
  my ($factory, $main) = @_;
  die "auto-welcomelist: unimplemented base method";	# override this
}

###########################################################################

=item $entry = $addrlist-E<gt>get_addr_entry ($addr);

Given an email address C<$addr>, return an entry object with the details of
that address.

The entry object is a reference to a hash, which must contain at least
two keys: C<count>, which is the count of times that address has been
encountered before; and C<totscore>, which is the total of all scores for
messages associated with that address.  From these two fields, an average
score will be calculated, and the score for the current message will be
regressed towards that mean message score.

The hash can contain whatever other data your back-end needs to store,
under other keys.

The method should never return C<undef>, or a hash that does not contain
a C<count> key and a C<totscore> key.

=cut 

sub get_addr_entry {
  my ($self, $addr, $signedby) = @_;
  my $entry = { };
  die "auto-welcomelist: unimplemented base method";	# override this
  return $entry;
}

###########################################################################

=item $entry = $addrlist-E<gt>add_score($entry, $score);

This method should add the given score to the welcomelist database for the
given entry, and then return the new entry.

=cut

sub add_score {
    my ($self, $entry, $score) = @_;
    die "auto-welcomelist: unimplemented base method"; # override this
}

###########################################################################

=item $entry = $addrlist-E<gt>remove_entry ($entry);

This method should remove the given entry from the welcomelist database.

=cut

sub remove_entry {
  my ($self, $entry) = @_;
  die "auto-welcomelist: unimplemented base method";	# override this
}

###########################################################################

=item $entry = $addrlist-E<gt>finish ();

Clean up, if necessary.  Called by SpamAssassin when it has finished
checking, or adding to, the auto-welcomelist database.

=cut

sub finish {
  my ($self) = @_;
}

###########################################################################

1;

=back

=cut
