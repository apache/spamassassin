# Mail::SpamAssassin::EncappedMessage - interface to Mail::Audit message text,
# for versions of Mail::Audit with methods to encapsulate the message text
# itself (ie. not exposing a Mail::Internet object).

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

package Mail::SpamAssassin::EncappedMessage;

use strict;
use bytes;
use Carp;


use Mail::SpamAssassin::AuditMessage;

use vars qw{
  @ISA
};

@ISA = qw(Mail::SpamAssassin::AuditMessage);

###########################################################################

sub replace_header {
  my ($self, $hdr, $text) = @_;
  $self->{mail_object}->replace_header ($hdr, $text);
}

sub get_pristine_header {
  my ($self, $hdr) = @_;
  return $self->get_header ($hdr);
}

sub get_header {
  my ($self, $hdr) = @_;

  # Jul  1 2002 jm: needed to support 2.1 and later Mail::Audits, which
  # modified the semantics of get() for no apparent reason (argh).

  if ($Mail::Audit::VERSION > 2.0) {
    return $self->{mail_object}->head->get ($hdr);
  } else {
    return $self->{mail_object}->get ($hdr);
  }
}

sub get_body {
  my ($self) = @_;
  $self->{mail_object}->body();
}

sub replace_body {
  my ($self, $aryref) = @_;

  # Jul  1 2002 jm: use MIME::Body to support newer versions of
  # Mail::Audit. protect against earlier versions that don't have is_mime()
  # method, and load the MIME::Body class using a string eval so SA
  # doesn't itself have to require the MIMETools classes.
  #
  if (eval { $self->{mail_object}->is_mime(); }) {
    my $newbody;
    # please leave the eval and use on the same line.  kluge around a bug in RPM 4.1.
    # tvd - 2003.02.25
    eval 'use MIME::Body;
      my $newbody = new MIME::Body::InCore ($aryref);
    ';
    die "MIME::Body::InCore ctor failed" unless defined ($newbody);
    return $self->{mail_object}->bodyhandle ($newbody);
  }

  return $self->{mail_object}->body ($aryref);
}

1;
