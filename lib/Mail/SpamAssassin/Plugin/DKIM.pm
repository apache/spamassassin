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

=head1 NAME

Mail::SpamAssassin::Plugin::DKIM - perform DKIM verification tests

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DKIM [/path/to/DKIM.pm]

 full DOMAINKEY_DOMAIN eval:check_dkim_verified()

=head1 DESCRIPTION

This SpamAssassin plugin implements DKIM lookups, as described by the current
draft specs:

  http://mipassoc.org/dkim/specs/draft-allman-dkim-base-01.txt
  http://mipassoc.org/mass/specs/draft-allman-dkim-base-00-10dc.html

It requires the C<Mail::DKIM> CPAN module to operate. Many thanks to Jason Long
for that module.

=head1 SEE ALSO

C<Mail::DKIM>, C<Mail::SpamAssassin::Plugin>

  http://jason.long.name/dkimproxy/

=cut

package Mail::SpamAssassin::Plugin::DKIM;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;

use strict;
use warnings;
use bytes;

# Have to do this so that RPM doesn't find these as required perl modules.
# Crypt::OpenSSL::Bignum included here, since Mail::DKIM loads it in some
# situations at runtime and spews messy errors if it's not there.
BEGIN { require Mail::DKIM; require Mail::DKIM::Verifier; require Crypt::OpenSSL::Bignum; }

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_dkim_signed");
  $self->register_eval_rule ("check_dkim_verified");
  $self->register_eval_rule ("check_dkim_signsome");
  $self->register_eval_rule ("check_dkim_testing");
  $self->register_eval_rule ("check_dkim_signall");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=head1 USER SETTINGS

=over 4

=item dkim_timeout n             (default: 5)

How many seconds to wait for a DKIM query to complete, before
scanning continues without the DKIM result.

=cut

  push (@cmds, {
    setting => 'dkim_timeout',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub check_dkim_signed {
  my ($self, $scan) = @_;
  $self->_check_dkim($scan) unless $scan->{dkim_checked};
  return $scan->{dkim_signed};
}

sub check_dkim_verified {
  my ($self, $scan) = @_;
  $self->_check_dkim($scan) unless $scan->{dkim_checked};
  return $scan->{dkim_verified};
}

sub check_dkim_signsome {
  my ($self, $scan) = @_;
  $self->_check_dkim($scan) unless $scan->{dkim_checked};
  return $scan->{dkim_signsome};
}

sub check_dkim_testing {
  my ($self, $scan) = @_;
  $self->_check_dkim($scan) unless $scan->{dkim_checked};
  return $scan->{dkim_testing};
}

sub check_dkim_signall {
  my ($self, $scan) = @_;
  $self->_check_dkim($scan) unless $scan->{dkim_checked};
  return $scan->{dkim_signall};
}

# ---------------------------------------------------------------------------

sub _check_dkim {
  my ($self, $scan) = @_;

  $scan->{dkim_checked} = 1;
  $scan->{dkim_signed} = 0;
  $scan->{dkim_verified} = 0;
  $scan->{dkim_signsome} = 0;
  $scan->{dkim_testing} = 0;
  $scan->{dkim_signall} = 0;

  my $header = $scan->{msg}->get_pristine_header();
  my $body = $scan->{msg}->get_body();

  $self->sanitize_header_for_dkim(\$header);

  my $message = Mail::DKIM::Verifier->new_object();
  if (!$message) {
    dbg("dkim: cannot create Mail::DKIM::Verifier");
    return;
  }

  # headers, line-by-line with \r\n endings, as per Mail::DKIM API
  foreach my $line (split(/\n/s, $header)) {
    $line =~ s/\r?$/\r\n/s;         # ensure \r\n ending
    $message->PRINT($line);
  }
  $message->PRINT("\r\n");

  # body, line-by-line with \r\n endings.
  eval {
    foreach my $line (@{$body}) {
      $line =~ s/\r?\n$/\r\n/s;       # ensure \r\n ending
      $message->PRINT($line);
    }
  };

  if ($@) {             # intercept die() exceptions and render safe
    dbg ("dkim: verification failed, intercepted error: $@");
    return 0;           # cannot verify message
  }

  my $timeout = $scan->{conf}->{dkim_timeout};

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    dbg("dkim: performing lookup");
    $message->CLOSE();      # the action happens here

    dbg("dkim: originator address: ".($message->message_originator ? $message->message_originator->address() : 'none'));
    dbg("dkim: signature identity: ".($message->signature ? $message->signature->identity() : 'none'));

    my $result = $message->result();
    my $detail = $message->result_detail();
    dbg("dkim: result: $detail");

    my $policy;
    if ($message->message_originator && $message->message_originator->host) {
      # both of these must be populated for DKIM to look up the policy
      $policy = $message->fetch_author_policy();
    }

    if ($policy) {
      # TODO - required? (for $policy_result, see perldoc Mail::DKIM::Policy)
      my $policy_result = $policy->apply($message);
      dbg("dkim: policy result $policy_result: ".$policy->as_string());

      # extract the flags we expose, from the policy
      my $pol_o = $policy->policy();
      if ($pol_o eq '~') {
        $scan->{dkim_signsome} = 1;
      }
      elsif ($pol_o eq '-') {
        $scan->{dkim_signall} = 1;
      }
      if ($policy->testing()) {
        $scan->{dkim_testing} = 1;
      }
    }
    else {
      dbg("dkim: policy: none");
    }

    # and now extract the actual lookup results
    if ($result eq 'pass') {
      $scan->{dkim_signed} = 1;
      $scan->{dkim_verified} = 1;
    }
    elsif ($result eq 'fail') {
      $scan->{dkim_signed} = 1;
    }
    elsif ($result eq 'none') {
      # no-op, this is the default state
    }
    elsif ($result eq 'invalid') {
      # 'Returned if no valid DKIM-Signature headers were found, but there is
      # at least one invalid DKIM-Signature header. For a reason why a DKIM-
      # Signature header found in the message was invalid, see
      # $dkim->{signature_reject_reason}.'
      warn("dkim: invalid DKIM-Signature: $detail");
    }

  });

  if ($timer->timed_out()) {
    dbg("dkim: lookup timed out after $timeout seconds");
    return 0;
  }

  if ($err) {
    chomp $err;
    warn("dkim: lookup failed: $err\n");
    return 0;
  }
}

sub sanitize_header_for_dkim {
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
      $last =~ /^([^:]+):/; dbg("dkim: ignoring header '$1'");
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
