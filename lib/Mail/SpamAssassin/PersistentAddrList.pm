# <@LICENSE>
# ====================================================================
# The Apache Software License, Version 1.1
# 
# Copyright (c) 2000 The Apache Software Foundation.  All rights
# reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
# 
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
# 
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
# 
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
# 
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
# 
# Portions of this software are based upon public domain software
# originally written at the National Center for Supercomputing Applications,
# University of Illinois, Urbana-Champaign.
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

All persistent address list implementations, used by the auto-whitelist
code to track known-good email addresses, use this as a base class.

See C<Mail::SpamAssassin::DBBasedAddrList> for an example.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::PersistentAddrList;

use strict;
use bytes;

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

=item $factory = PersistentAddrListSubclass->new();

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

=item my $addrlist = $factory->new_checker();

Create a new address-list checker object from the factory. Called by the
SpamAssassin classes.

=cut 

sub new_checker {
  my ($factory, $main) = @_;
  die "unimpled base method";	# override this
}

###########################################################################

=item $entry = $addrlist->get_addr_entry ($addr);

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
  my ($self, $addr) = @_;
  my $entry = { };
  die "unimpled base method";	# override this
  return $entry;
}

###########################################################################

=item $entry = $addrlist->add_score($entry, $score);

This method should add the given score to the whitelist database for the
given entry, and then return the new entry.

=cut

sub add_score {
    my ($self, $entry, $score) = @_;
    die "unimpled base method"; # override this
}

###########################################################################

=item $entry = $addrlist->remove_entry ($entry);

This method should remove the given entry from the whitelist database.

=cut

sub remove_entry {
  my ($self, $entry) = @_;
  die "unimpled base method";	# override this
}

###########################################################################

=item $entry = $addrlist->finish ();

Clean up, if necessary.  Called by SpamAssassin when it has finished
checking, or adding to, the auto-whitelist database.

=cut

sub finish {
  my ($self) = @_;
}

###########################################################################

1;
