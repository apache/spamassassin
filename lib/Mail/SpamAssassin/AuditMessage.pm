# Mail::SpamAssassin::AuditMessage - interface to Mail::Audit message text
#
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
package Mail::SpamAssassin::AuditMessage;

use strict;
use bytes;
use Carp;

use Mail::SpamAssassin::NoMailAudit;
use Mail::SpamAssassin::Message;

use vars qw{
  @ISA
};

@ISA = qw(Mail::SpamAssassin::Message);

###########################################################################

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->{headers_pristine} = $self->get_all_headers();
  $self;
}

sub put_header {
  my ($self, $hdr, $text) = @_;
  $self->{mail_object}->put_header ($hdr, $text);
}

sub delete_header {
  my ($self, $hdr) = @_;
  $self->{mail_object}->{obj}->head->delete ($hdr);
}

sub get_all_headers {
  my ($self) = @_;
  $self->{mail_object}->header();
}

sub get_pristine {
  my ($self) = @_;
  return join ('', $self->{headers_pristine}, "\n",
		 @{ $self->get_body() });
}

sub replace_original_message {
  my ($self, $data) = @_;

  my $textarray;
  if (ref $data eq 'ARRAY') {
    $textarray = $data;
  } elsif (ref $data eq 'GLOB') {
    if (defined fileno $data) {
      $textarray = [ <$data> ];
    }
  }

  # now split into [ headerline, ... ] and [ bodyline, ... ]
  my $heads = [ ];
  my $line;
  while (defined ($line = shift @{$textarray})) {
    last if ($line =~ /^$/);
    push (@{$heads}, $line);
  }

  $self->{mail_object}->head->empty;
  $self->{mail_object}->head->header ($heads);

  # take another copy of this
  $self->{headers_pristine} = $self->get_all_headers();

  $self->replace_body ($textarray);
}

1;
