# $Id: MIME.pm,v 1.8 2003/10/02 22:59:00 quinlan Exp $

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

package Mail::SpamAssassin::MIME;
use strict;
use MIME::Base64;
use Mail::SpamAssassin;

# M::SA::MIME is an object method used to encapsulate a message's MIME part
#
sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = {
    headers     => {},
    raw_headers => {},
    body_parts  => [],
    };

  bless($self,$class);

  $self;
}

# Used to find any MIME parts whose simple content-type matches a given regexp
# Searches it's own and any children parts.  Returns an array of MIME
# objects which match.
#
sub find_parts {
  my ($self, $re) = @_;

  # Didn't pass an RE?  Just abort.
  return () unless $re;

  my @ret = ();

  # If this object matches, mark it for return.
  if ( $self->{'type'} =~ /$re/ ) {
    push(@ret, $self);
  }
  elsif ( exists $self->{'body_parts'} ) {
    # This object is a subtree root.  Search all children.
    foreach my $parts ( @{$self->{'body_parts'}} ) {
      # Add the recursive results to our results
      push(@ret, $parts->find_parts($re));
    }
  }

  return @ret;
}

# Store or retrieve headers from a given MIME object
#
sub header {
  my $self   = shift;
  my $rawkey = shift;
  my $key    = lc($rawkey);

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

  if (@_) {
    my ( $decoded_value, $raw_value ) = @_;
    $raw_value = $decoded_value unless defined $raw_value;
    if ( exists $self->{'headers'}{$key} ) {
      push @{ $self->{'headers'}{$key} },     $decoded_value;
      push @{ $self->{'raw_headers'}{$key} }, $raw_value;
    }
    else {
      $self->{'headers'}{$key}     = [$decoded_value];
      $self->{'raw_headers'}{$key} = [$raw_value];
    }
    return $self->{'headers'}{$key}[-1];
  }

  my $want = wantarray;
  if ( defined($want) ) {
    if ($want) {
      return unless exists $self->{'headers'}{$key};
      return @{ $self->{'headers'}{$key} };
    }
    else {
      return '' unless exists $self->{'headers'}{$key};
      return $self->{'headers'}{$key}[-1];
    }
  }
}

# Retrieve raw headers from a given MIME object
#
sub raw_header {
  my $self = shift;
  my $key  = lc(shift);

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

  if (wantarray) {
    return unless exists $self->{'raw_headers'}{$key};
    return @{ $self->{'raw_headers'}{$key} };
  }
  else {
    return '' unless exists $self->{'raw_headers'}{$key};
    return $self->{'raw_headers'}{$key}[-1];
  }
}

# Add a MIME child part to ourselves
sub add_body_part {
  my($self, $part) = @_;

  dbg("added part, type: ".$part->{'type'});
  push @{ $self->{'body_parts'} }, $part;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__
