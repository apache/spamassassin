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

# Eval Tests to detect genuine mailing lists.

use strict;  # make Test::Perl::Critic happy
package Mail::SpamAssassin::MailingList; 1;

package Mail::SpamAssassin::PerMsgStatus;

use strict;
use warnings;
use bytes;
use re 'taint';

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
    return 0 unless $self->get('list-post') =~ /^<mailto:/i;
    return 0 unless $self->get('list-help') =~ /^<mailto:/i;
    return 0 unless $self->get('list-unsubscribe') =~ /<mailto:[a-zA-Z\.-]+-unsubscribe\@/i;
    return 0 unless $self->get('list-subscribe') =~ /<mailto:[a-zA-Z\.-]+-subscribe\@/i;
    return 1; # assume ezmlm then.
}

# MailMan (the gnu mailing list manager)
#  Precedence: bulk [or list for v2]
#  List-Help: <mailto:
#  List-Post: <mailto:
#  List-Subscribe: .*<mailto:.*=subscribe>
#  List-Id: 
#  List-Unsubscribe: .*<mailto:.*=unsubscribe>
#  List-Archive: 
#  X-Mailman-Version: \d
#
# However, for mailing list membership reminders, most of
# those headers are gone, so we identify on the following:
#
#  Subject: ...... mailing list memberships reminder  (v1)
#  or X-List-Administrivia: yes  (only in version 2)
#  X-Mailman-Version: \d
#  Precedence: bulk [or list for v2]
#  X-No-Archive: yes
#  Errors-To: 
#  X-BeenThere: 
sub detect_ml_mailman {
    my ($self) = @_;
    return 0 unless $self->get('x-mailman-version') =~ /^\d/;
    return 0 unless $self->get('precedence') =~ /^(?:bulk|list)$/;

    if ($self->get('x-list-administrivia') =~ /yes/ ||
        $self->get('subject') =~ /mailing list memberships reminder$/)
    {
        return 0 unless defined $self->get('errors-to',undef);
        return 0 unless defined $self->get('x-beenthere',undef);
        return 0 unless $self->get('x-no-archive') =~ /yes/;
        return 1;
    }

    return 0 unless defined $self->get('list-id',undef);
    return 0 unless $self->get('list-help') =~ /^<mailto:/i;
    return 0 unless $self->get('list-post') =~ /^<mailto:/i;
    return 0 unless $self->get('list-subscribe') =~ /<mailto:.*=subscribe>/i;
    return 0 unless $self->get('list-unsubscribe') =~ /<mailto:.*=unsubscribe>/i;
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
#   my $reply = $self->get('Reply-To:addr');
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
