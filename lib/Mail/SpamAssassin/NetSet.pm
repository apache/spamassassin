# Mail::SpamAssassin::NetSet - object to manipulate CIDR net IP addrs
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

package Mail::SpamAssassin::NetSet;

use strict;
use bytes;

use Mail::SpamAssassin::Util;

use vars qw{
  @ISA $TESTCODE $NUMTESTS
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = { };
  bless $self, $class;

  $self;
}

###########################################################################

sub add_cidr {
  my ($self, @nets) = @_;
  local ($_);

  $self->{nets} ||= [ ];
  my $numadded = 0;

  foreach (@nets) {
    my ($ip, $bits) = m#^\s*([\d\.]+)(?:/(\d+))?\s*$#;

    my $err = "illegal network address given: '$_'\n";
    if (!defined $ip) {
      warn $err; next;

    } elsif ($ip =~ /\.$/) {
      # just use string matching; much simpler than doing smart stuff with arrays ;)
      if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.$/) { $ip = "$1.$2.$3.0"; $bits = 24; }
      elsif ($ip =~ /^(\d+)\.(\d+)\.$/) { $ip = "$1.$2.0.0"; $bits = 16; }
      elsif ($ip =~ /^(\d+)\.$/) { $ip = "$1.0.0.0"; $bits = 8; }
      else {
	warn $err; next;
      }
    }

    $bits = 32 if (!defined $bits);
    my $mask = 0xFFffFFff ^ ((2 ** (32-$bits)) - 1);

    push @{$self->{nets}}, {
      mask => $mask,
      ip   => Mail::SpamAssassin::Util::my_inet_aton($ip) & $mask
    };
    $numadded++;
  }

  $numadded;
}

sub get_num_nets {
  my ($self) = @_;

  if (!exists $self->{nets}) { return 0; }
  return scalar @{$self->{nets}};
}

sub contains_ip {
  my ($self, $ip) = @_;

  if (!defined $self->{nets}) { return 0; }

  $ip = Mail::SpamAssassin::Util::my_inet_aton($ip);
  foreach my $net (@{$self->{nets}}) {
    return 1 if (($ip & $net->{mask}) == $net->{ip});
  }
  0;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

###########################################################################

1;
