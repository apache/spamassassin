=head1 NAME

Mail::SpamAssassin::Plugin::DomainKeys - perform DomainKeys verification tests

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DomainKeys [/path/to/DomainKeys.pm]

 full DOMAINKEY_DOMAIN eval:check_domainkeys_verified()

=head1 DESCRIPTION

This is the DomainKeys plugin and it needs lots more documentation.

=cut
# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::DomainKeys;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
use bytes;

# Have to do this so that RPM doesn't find these as required perl modules
BEGIN { require Mail::DomainKeys::Message; require Mail::DomainKeys::Policy; }

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::Plugin::dbg;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_domainkeys_signed");
  $self->register_eval_rule ("check_domainkeys_verified");
  $self->register_eval_rule ("check_domainkeys_signsome");
  $self->register_eval_rule ("check_domainkeys_testing");
  $self->register_eval_rule ("check_domainkeys_signall");

  return $self;
}


sub check_domainkeys_signed {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_signed};
}

sub check_domainkeys_verified {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_verified};
}

sub check_domainkeys_signsome {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  return $scan->{domainkeys_signsome};
}

sub check_domainkeys_testing {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_testing};
}

sub check_domainkeys_signall {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_signall};
}



sub _check_domainkeys {
  my ($self, $scan) = @_;

  $scan->{domainkeys_checked} = 0;
  $scan->{domainkeys_signed} = 0;
  $scan->{domainkeys_verified} = 0;
  $scan->{domainkeys_signsome} = 0;
  $scan->{domainkeys_testing} = 0;
  $scan->{domainkeys_signall} = 0;

  my $header = $scan->{msg}->get_pristine_header();
  my $body = $scan->{msg}->get_body();

  $self->sanitize_header_for_dk(\$header);

  my $message = Mail::DomainKeys::Message->load(HeadString => $header,
						 BodyReference => $body);

  if (!$message) {
    dbg("dk: cannot load message using Mail::DomainKeys::Message");
    return;
  }

  $scan->{domainkeys_checked} = 1;

  # does a sender domain header exist?
  my $domain = $message->senderdomain();
  if (!$domain) {
    dbg("dk: no sender domain");
    return;
  }

  my $timeout = 5;              # TODO: tunable timeout
  my $oldalarm;

  eval {
    local $SIG{ALRM} = sub { die "__alarm__\n" };
    $oldalarm = alarm($timeout);
    $self->_dk_lookup_trapped($scan, $message, $domain);
    alarm $oldalarm;
  };

  my $err = $@;

  if ($err) {
    alarm $oldalarm;
    if ($err =~ /^__alarm__$/) {
      dbg("dk: lookup timed out after $timeout seconds");
    } else {
      warn("dk: lookup failed: $err\n");
    }
    return 0;
  }

  my $comment = $self->_dkmsg_hdr($message);
  $comment ||= '';
  $comment =~ s/\s+/ /gs;       # no newlines please

  $scan->{dk_comment} = "DomainKeys status: $comment";
}

# perform DK lookups.  This method is trapped within a timeout alarm() scope
sub _dk_lookup_trapped {
  my ($self, $scan, $message, $domain) = @_;

  # verified
  if ($message->signed()) {
    $scan->{domainkeys_signed} = 1;
    if ($message->verify()) {
      $scan->{domainkeys_verified} = 1;
    }
  }

  my $policy = Mail::DomainKeys::Policy->fetch(Protocol => 'dns',
					       Domain => $domain);

  return unless $policy;
  dbg ("dk: fetched policy");

  # not signed and domain doesn't sign all
  if ($policy->signsome()) {
    $scan->{domainkeys_signsome} = 1;
  }

  # domain or key testing
  if ($message->testing() || $policy->testing()) {
    $scan->{domainkeys_testing} = 1;
  }

  # does policy require all mail to be signed
  if ($policy->signall()) {
    $scan->{domainkeys_signall} = 1;
  }

  my $comment = $self->_dkmsg_hdr($message);
  dbg("dk: comment is '$comment'");
}

# get the DK status "header" from the Mail::DomainKeys::Message object
sub _dkmsg_hdr {
  my ($self, $message) = @_;
  return $message->header->value();
}

sub sanitize_header_for_dk {
  my ($self, $ref) = @_;

  # remove folding, in a HTML-escape data-preserving style, so we can
  # strip headers easily
  $$ref =~ s/!/!ex;/gs;
  $$ref =~ s/\n([ \t])/!nl;$1/gs;
  my @hdrs = split(/^/m, $$ref);

  while (scalar @hdrs > 0) {
    my $last = pop @hdrs;
    next if ($last =~ /^\r?$/);

    # List all the known appended headers that may break a DK signature. Things
    # to note:
    # 
    # 1. only *appended* headers should be listed; prepended additions are fine.
    # 2. some virus-scanner headers may be better left out, since there are ISPs
    # who scan for viruses before the message leaves their SMTP relay; this is
    # not quite decided.
    #
    # TODO: there's probably loads more, and this should be user-configurable

    if ($last =~ /^ (?:
            # SpamAssassin additions, remove these so that mass-check works
            X-Spam-\S+

            # other spam filters
            |X-MailScanner(?:-SpamCheck)?
            |X-Pyzor |X-DCC-\S{2,25}-Metrics
            |X-Bogosity

            # post-delivery MUA additions
            |X-Evolution
            |X-MH-Thread-Markup

            # IMAP or POP additions
            |X-Keywords
            |(?:X-)?Status |X-Flags |Replied |Forwarded
            |Lines |Content-Length
            |X-UIDL? |X-IMAPbase

            # MTA delivery control headers
            |X-MDaemon-Deliver-To

            # other MUAs: VM and Gnus
            |X-VM-(?:Bookmark|(?:POP|IMAP)-Retrieved|Labels|Last-Modified
            |Summary-Format|VHeader|v\d-Data|Message-Order)
            |X-Gnus-Mail-Source
            |Xref
          ):/ix)
    {
      $last =~ /^([^:]+):/; dbg("dk: ignoring header '$1'");
      next;
    }

    push (@hdrs, $last); last;
  }

  $$ref = join("", @hdrs);

  # and return the remaining headers to pristine condition
  # $$ref =~ s/^\n//gs; $$ref =~ s/\n$//gs;
  $$ref =~ s/!nl;/\n/gs;
  $$ref =~ s/!ex;/!/gs;
}

1;
