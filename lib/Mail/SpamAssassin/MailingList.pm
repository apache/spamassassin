# $Id: MailingList.pm,v 1.12 2003/01/09 23:51:56 msquadrat Exp $

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

# Eval Tests to detect genuine mailing lists.

package Mail::SpamAssassin::MailingList;
1;

package Mail::SpamAssassin::PerMsgStatus;

use strict;
use bytes;


sub detect_mailing_list {
    my ($self) = @_;
    return 1 if $self->detect_ml_ezmlm();
    return 1 if $self->detect_ml_mailman();
    return 1 if $self->detect_ml_sympa();
    return 0;
}

# EZMLM
# Mailing-List: .*run by ezmlm
# Precedence: bulk
# List-Post: <mailto:
# List-Help: <mailto:
# List-Unsubscribe: <mailto:[a-zA-Z\.-]+-unsubscribe@
# List-Subscribe: <mailto:[a-zA-Z\.-]+-subscribe@
sub detect_ml_ezmlm {
    my ($self) = @_;
    return 0 unless $self->get('mailing-list') =~ /ezmlm$/;
    return 0 unless $self->get('precedence') eq "bulk\n";
    return 0 unless $self->get('list-post') =~ /^<mailto:/;
    return 0 unless $self->get('list-help') =~ /^<mailto:/;
    return 0 unless $self->get('list-unsubscribe') =~ /<mailto:[a-zA-Z\.-]+-unsubscribe\@/;
    return 0 unless $self->get('list-subscribe') =~ /<mailto:[a-zA-Z\.-]+-subscribe\@/;
    return 1; # assume ezmlm then.
}

# MailMan (the gnu mailing list manager)
#  Precedence: bulk
#  List-Help: <mailto:
#  List-Post: <mailto:
#  List-Subscribe: .*<mailto:.*=subscribe>
#  List-Id: 
#  List-Unsubscribe: .*<mailto:.*=unsubscribe>
#  List-Archive: 
#  X-Mailman-Version: \d
#
# However, for for mailing list membership reminders, most of
# those headers are gone, so we identify on the following:
#
#  Subject: ...... mailing list memberships reminder
#  X-Mailman-Version: \d
#  Precedence: bulk
#  X-No-Archive: yes
#  X-Ack: no
#  Errors-To: 
#  X-BeenThere: 
sub detect_ml_mailman {
    my ($self) = @_;
    return 0 unless $self->get('x-mailman-version') =~ /^\d/;
    return 0 unless $self->get('precedence') eq "bulk\n";

    if ($self->get('subject') =~ /mailing list memberships reminder$/) {
        return 0 unless $self->get('errors-to');
        return 0 unless $self->get('x-beenthere');
        return 0 unless $self->get('x-no-archive') =~ /yes/;
        return 0 unless $self->get('x-ack') =~ /no/;
        return 1;
    }

    return 0 unless $self->get('list-id');
    return 0 unless $self->get('list-help') =~ /^<mailto:/;
    return 0 unless $self->get('list-post') =~ /^<mailto:/;
    return 0 unless $self->get('list-subscribe') =~ /<mailto:.*=subscribe>/;
    return 0 unless $self->get('list-unsubscribe') =~ /<mailto:.*=unsubscribe>/;
    return 0 unless $self->get('list-archive'); # maybe comment this out.
    return 1; # assume this is a valid mailman list
}

# Sympa
# Return-Path: somelist-owner@somedomain.com [...]
# Precedence: list [...]
# List-Id: <somelist@somedomain.com>
# List-Help: <mailto:sympa@somedomain.com?subject=help>
# List-Subscribe: <mailto:somedomain.com?subject=subscribe%20somelist>
# List-Unsubscribe: <mailto:sympa@somedomain.com?subject=unsubscribe%somelist>
# List-Post: <mailto:somelist@somedomain.com>
# List-Owner: <mailto:somelist-request@somedomain.com>
# [and optionally] List-Archive: <http://www.somedomain.com/wws/arc/somelist>

# NB: This isn't implemented, since there is nothing here saying "Sympa".
sub detect_ml_sympa {
    my ($self) = @_;
    return 0;
}

# Lyris
# Not implemented - need headers
sub detect_ml_lyris {
}

# ListBuilder
# Sep 17 2002 jm: turned off due to bad S/O ratio

# sub detect_ml_listbuilder {
#   my ($self, $full) = @_;
# 
#   my $reply = $self->get ('Reply-To:addr');
#   if ($reply !~ /\@lb.bcentral.com/) { return 0; }
# 
#   # Received: from unknown (HELO lbrout14.listbuilder.com) (204.71.191.9)
#   my $rcvd = $self->get('received');
#   return 0 unless ($rcvd =~ /\blbrout\d+\.listbuilder\.com\b/i);
#   return 0 unless ($rcvd =~ /\b204\.71\.191\.\d+\b/);
# 
#   # _______________________________________________________________________
#   # Powered by List Builder
#   # To unsubscribe follow the link:
#   # http://lb.bcentral.com/ex/sp?c=19511&s=76CA511711046877&m=14
#   $full = join ("\n", @{$full});
# 
#   if ($full !~ /__________________{40,}\s+Powered by List Builder\s/) { return 0; }
#   if ($full !~
#          m,\shttp://lb\.bcentral\.com/ex/sp\?c=[0-9A-Z]*&s=[0-9A-Z]*&m=[0-9A-Z]*\s,)
#          { return 0; }
# 
#   return 1;
# }

1;
