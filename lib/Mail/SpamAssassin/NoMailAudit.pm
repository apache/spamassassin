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

# Mail message object, used by SpamAssassin.  This was written to eliminate, as
# much as possible, SpamAssassin's dependency on Mail::Audit and the
# Mail::Internet, Net::SMTP, etc. module set it requires.
#
# This is more efficient (less modules, dependencies and unused code loaded),
# and fixes some bugs found in Mail::Audit, as well as working around some
# side-effects of features of Mail::Internet that we don't use.  It's also more
# lenient about the incoming message, in the spirit of the IETF dictum 'be
# liberal in what you accept'.
#
package Mail::SpamAssassin::NoMailAudit;

use strict;
use bytes;

use Mail::SpamAssassin::MIME;
use Mail::SpamAssassin::MIME::Parser;

# ---------------------------------------------------------------------------

sub new {
  my $class = shift;
  my %opts = @_;

  my $self = {
    mime_parts => Mail::SpamAssassin::MIME::Parser->parse($opts{'data'} || \*STDIN),
  };

  bless ($self, $class);
  return $self;
}

# ---------------------------------------------------------------------------

sub get_pristine_header {
  my ($self, $hdr) = @_;
  
  return $self->{mime_parts}->{pristine_headers} unless $hdr;
  my(@ret) = $self->{mime_parts}->{pristine_headers} =~ /^(?:$hdr:[ ]+(.*\n(?:\s+\S.*\n)*))/mig;
  if (@ret) {
    return wantarray ? @ret : $ret[-1];
  }
  else {
    return $self->get_header($hdr);
  }
}

#sub get { shift->get_header(@_); }
sub get_header {
  my ($self, $hdr) = @_;

  # And now pick up all the entries into a list
  # This is assumed to include a newline at the end ...
  # This is also assumed to have removed continuation bits ...
  my @hdrs;
  foreach ( $self->{'mime_parts'}->raw_header($hdr) ) {
    s/\r?\n\s+/ /g;
    push(@hdrs, $_);
  }

  if (wantarray) {
    return @hdrs;
  }
  else {
    return $hdrs[-1];
  }
}

#sub header { shift->get_all_headers(@_); }
sub get_all_headers {
  my ($self) = @_;

  my %cache = ();
  my @lines = ();

  foreach ( @{$self->{mime_parts}->{header_order}} ) {
    push(@lines, "$_: ".($self->get_header($_))[$cache{$_}++]);
  }

  if (wantarray) {
    return @lines;
  } else {
    return join ('', @lines);
  }
}

sub delete_header {
  my ($self, $hdr) = @_;
  $self->{mime_parts}->delete_header($hdr);
}

#sub body { return shift->get_body(@_); }
sub get_body {
  my ($self) = @_;
  my @ret = split(/^/m, $self->get_pristine_body());
  return \@ret;
}

# ---------------------------------------------------------------------------

sub get_pristine {
  my ($self) = @_;
  return $self->{mime_parts}->{pristine_headers} . $self->{mime_parts}->{pristine_body};
}

sub get_pristine_body {
  my ($self) = @_;
  return $self->{mime_parts}->{pristine_body};
}

sub as_string {
  my ($self) = @_;
  return $self->get_all_headers() . "\n" . $self->{mime_parts}->{pristine_body};
}

sub ignore {
  my ($self) = @_;
  exit (0) unless $self->{noexit};
}

1;
