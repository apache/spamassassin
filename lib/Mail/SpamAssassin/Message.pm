# Mail::SpamAssassin::Message - interface to any mail message text/headers

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

package Mail::SpamAssassin::Message;

use strict;
use bytes;
use Carp;

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  my ($mail_object) = @_;

  my $self = {
    'mail_object' 	=> $mail_object,
    'metadata'		=> { },
    'is_spamassassin_wrapper_object' => 1
  };
  bless ($self, $class);
  $self;
}

###########################################################################

sub get_mail_object {
  my ($self) = @_;
  return $self->{mail_object};
}

###########################################################################

sub create_new {
  my ($self, @args) = @_;
  die "unimplemented base method";
}

sub get_pristine_header {
  my ($self, $hdr) = @_;
  die "unimplemented base method";
}

sub get_header {
  my ($self, $hdr) = @_;
  die "unimplemented base method";
}

sub put_header {
  my ($self, $hdr, $text) = @_;
  die "unimplemented base method";
}

sub get_all_headers {
  my ($self) = @_;
  die "unimplemented base method";
}

sub replace_header {
  my ($self, $hdr, $text) = @_;
  die "unimplemented base method";
}

sub delete_header {
  my ($self, $hdr) = @_;
  die "unimplemented base method";
}

sub get_body {
  my ($self) = @_;
  die "unimplemented base method";
}

sub get_pristine {
  my ($self) = @_;
  die "unimplemented base method";
}

sub replace_body {
  my ($self, $aryref) = @_;
  die "unimplemented base method";
}

sub replace_original_message {
  my ($self, $aryref) = @_;
  die "unimplemented base method";
}

###########################################################################
# extremely simple shared metadata structure.  This emulates the
# header structure of an RFC-2822 mail message, but these "headers"
# are never actually added to the mail; instead they are dropped
# as soon as the message object is destroyed, and will never
# appear in the string representation.

sub get_metadata {
  my ($self, $hdr) = @_;
  $self->{metadata}->{$hdr};
}

sub put_metadata {
  my ($self, $hdr, $text) = @_;
  $self->{metadata}->{$hdr} = $text;
}

sub get_all_metadata {
  my ($self) = @_;

  my @ret = ();
  foreach my $key (sort keys %{$self->{metadata}}) {
    push (@ret, $key, ": ", $self->{metadata}->{$key}, "\n");
  }
  return join ("", @ret);
}

sub replace_metadata {
  my ($self, $hdr, $text) = @_;
  $self->{metadata}->{$hdr} = $text;
}

sub delete_metadata {
  my ($self, $hdr) = @_;
  delete $self->{metadata}->{$hdr};
}

1;
