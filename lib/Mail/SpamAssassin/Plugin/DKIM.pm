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

=head1 NAME

Mail::SpamAssassin::Plugin::DKIM - perform DKIM verification tests

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DKIM [/path/to/DKIM.pm]

 full DOMAINKEY_DOMAIN eval:check_dkim_verified()

=head1 DESCRIPTION

This SpamAssassin plugin implements DKIM lookups as described by the RFC 4871,
as well as historical DomainKeys lookups, as described by RFC 4870, thanks
to the support for both types of signatures by newer versions of module
Mail::DKIM (0.22 or later).

It requires the C<Mail::DKIM> CPAN module to operate. Many thanks to Jason Long
for that module.

=head1 SEE ALSO

C<Mail::DKIM>, C<Mail::SpamAssassin::Plugin>

  http://jason.long.name/dkimproxy/
  http://tools.ietf.org/rfc/rfc4871.txt
  http://tools.ietf.org/rfc/rfc4870.txt
  http://www.ietf.org/internet-drafts/draft-ietf-dkim-ssp-01.txt
  http://www.ietf.org/internet-drafts/draft-ietf-dkim-overview-05.txt

=head1 A BRIEF INTRODUCTION TO TERMINOLOGY

B<Originator Address> is the author's e-mail address in a "From:" header field.

A message may carry one or more B<signatures> (signature header fields),
each signature carries an B<identity> (the i= tag) telling who provided it
and how it can be verified.

Only B<valid signatures> matter (i.e. verified signatures), all invalid
signatures can be and MUST be ignored (making a distinction here can provide
advantage to malicious senders or spam senders, as faking an invalid signature
is trivial).

A valid signature (one or more) whose identity matches I<Originator Address>
is called B<Originator Signature> (or sometimes a I<First-Party Signature>),
and is normally acceptable to recipients unconditionally (that doesn't say
anything about the merits of a message, it just tells the message is coming
from where it claims to be coming).

A I<valid signature> which is I<not an Originator Signature> is called a
B<Third-Party Signature> (e.g. supplied by a mailing list or re-mailer).

It is up to a recipient (the verifier) to decide which I<Third-Party
Signatures> are acceptable to him (e.g. those provided by a reputable
mailing list server with good anti-spam measures) and which are not.
Such signatures are called B<Verifier Acceptable Third-Party Signatures>.

There exists a mechanism called B<DKIM Sender Signing Practices> (SSP),
by which an I<Originator> (i.e. a mail author or his sending mailer) can
tell recipients (verifiers) about his signing practices (previously called
signing policy). An Internet Draft is approaching ratification stage,
but is not there yet. This plugin does not yet fully implement it.

Having a proof a message is coming from where it claims to be coming
is an essential stone in anti-phishing and anti-spam protection, but
is not sufficient by itself. Some B<reputation scheme> is needed, a
community-based reputation scheme would be useful, but is not available
for the time being. Currently it is up to verifiers to organize it for
themselves, e.g. in a form of I<DKIM-based whitelisting>, as provided by
this plugin. The mechanism allows to whitelist an I<Originator Signature>
as well as selected I<Third-Party Signatures>.

For details please consult RFC 4871, draft-ietf-dkim-ssp-01 (or later)
and draft-ietf-dkim-overview-05 (or later).

=cut

package Mail::SpamAssassin::Plugin::DKIM;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;

use strict;
use warnings;
use bytes;
use re 'taint';

# Have to do this so that RPM doesn't find these as required perl modules.
BEGIN { require Mail::DKIM; require Mail::DKIM::Verifier; }

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
  $self->register_eval_rule ("check_for_dkim_whitelist_from");
  $self->register_eval_rule ("check_for_def_dkim_whitelist_from");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item whitelist_from_dkim originator@example.com [signing-identity]

Use this to supplement the whitelist_from addresses with a check to make sure
the message with a given From: author's address (originator address) carries
a valid Domain Keys Identified Mail (DKIM) signature by a verifier-acceptable
signing-identity (the i= tag). Signature verification is based on a signing
identity's DKIM public key, fetched by a DNS lookup from a domain specified
in a d= tag of a signature.

In order to support multiple optional verifier-acceptable signing identities
(e.g. signatures supplied by mailing lists), only one whitelist entry
is allowed per line, exactly like C<whitelist_from_rcvd>. Multiple
C<whitelist_from_dkim> lines are allowed. File-glob style meta characters
are allowed for the From: address, just like with C<whitelist_from_rcvd>.

If no signing identity (second parameter) is specified, the only acceptable
signature will be an originator signature (not a third-party signature).
An originator signature is a signature where the signing identity matches
the originator address (i.e. the address in a From header field).  If the
signing identity does not include a localpart, then only the domains must
match; otherwise, the two addresses must be identical. Note that there is
no subdomain stripping magic, a match on domain must be exact.

The originator address is obtained from the "From:" header field, which
should be in a signed part of the message.

Since this whitelist requires a DKIM check to be made, network tests must
be enabled.

Examples of whitelisting based on an originator signature:

  whitelist_from_dkim joe@example.com
  whitelist_from_dkim *@corp.example.com
  whitelist_from_dkim *@gmail.com

Examples of whitelisting based on an third-party signatures:

  whitelist_from_dkim rick@example.net     richard@example.net
  whitelist_from_dkim rick@sub.example.net example.net
  whitelist_from_dkim jane@example.net     example.org
  whitelist_from_dkim *@*                  spamassassin.apache.org
  whitelist_from_dkim *@*                  postfix.org

(the last two examples illustrate singing by mailing lists, although the
featured mailing lists are not currently re-signing mailing list traffic)

=item def_whitelist_from_dkim originator@example.com [signing-identity]

Same as C<whitelist_from_dkim>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for abuse of public mailers which sign their mail.

=cut

  push (@cmds, {
    setting => 'whitelist_from_dkim',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2);
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $identity = '';  # when empty only originator signature is acceptable
      if (defined $2) {   # explicit additional acceptable signing identity
        $identity = $2;
        $identity = '@' . $identity  if $identity !~ /\@/;
      }
      $self->{parser}->add_to_addrlist_rcvd('whitelist_from_dkim',
                                            $address, $identity);
    }
  });

  push (@cmds, {
    setting => 'def_whitelist_from_dkim',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2);
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $identity = '';  # when empty only originator signature is acceptable
      if (defined $2) {   # explicit additional acceptable signing identity
        $identity = $2;
        $identity = '@' . $identity  if $identity !~ /\@/;
      }
      $self->{parser}->add_to_addrlist_rcvd('def_whitelist_from_dkim',
                                            $address, $identity);
    }
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item dkim_timeout n             (default: 5)

How many seconds to wait for a DKIM query to complete, before
scanning continues without the DKIM result.

=cut

  push (@cmds, {
    setting => 'dkim_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub check_dkim_signed {
  my ($self, $scan) = @_;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  return $scan->{dkim_signed};
}

sub check_dkim_verified {
  my ($self, $scan) = @_;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  return $scan->{dkim_verified};
}

sub check_dkim_signsome {
  my ($self, $scan) = @_;
  $self->_check_dkim_policy($scan) unless $scan->{dkim_checked_policy};
  return $scan->{dkim_signsome};
}

sub check_dkim_signall {
  my ($self, $scan) = @_;
  $self->_check_dkim_policy($scan) unless $scan->{dkim_checked_policy};
  return $scan->{dkim_signall};
}

# public key carries a testing flag, or fetched policy carries a testing flag
sub check_dkim_testing {
  my ($self, $scan) = @_;
  my $result = 0;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  if ($scan->{dkim_key_testing}) {
    $result = 1;
  } else {
    $self->_check_dkim_policy($scan) unless $scan->{dkim_checked_policy};
    $result = 1  if $scan->{dkim_policy_testing};
  }
  return $result;
}

sub check_for_dkim_whitelist_from {
  my ($self, $scan) = @_;
  $self->_check_dkim_whitelist($scan, 0)
    unless $scan->{dkim_whitelist_from_checked};
  $scan->{dkim_whitelist_from};
}

sub check_for_def_dkim_whitelist_from {
  my ($self, $scan) = @_;
  $self->_check_dkim_whitelist($scan, 1)
    unless $scan->{def_dkim_whitelist_from_checked};
  $scan->{def_dkim_whitelist_from};
}

# ---------------------------------------------------------------------------

sub _check_dkim_signature {
  my ($self, $scan) = @_;

  $scan->{dkim_checked_signature} = 1;
  $scan->{dkim_signed} = 0;
  $scan->{dkim_verified} = 0;
  $scan->{dkim_key_testing} = 0;

  my $timemethod = $self->{main}->time_method("check_dkim_signature");

  my $message = Mail::DKIM::Verifier->new_object();
  if (!$message) {
    dbg("dkim: cannot create Mail::DKIM::Verifier");
    return;
  }
  $scan->{dkim_object} = $message;

  # feed content of message into verifier, using \r\n endings,
  # required by Mail::DKIM API (see bug 5300)
  # note: bug 5179 comment 28: perl does silly things on non-Unix platforms
  # unless we use \015\012 instead of \r\n
  eval {
    foreach my $line (split(/\n/s, $scan->{msg}->get_pristine)) {
      $line =~ s/\r?$/\015\012/s;       # ensure \015\012 ending
      $message->PRINT($line);
    }
    1;
  } or do {  # intercept die() exceptions and render safe
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("dkim: verification failed, intercepted error: $eval_stat");
    return 0;           # cannot verify message
  };

  my $timeout = $scan->{conf}->{dkim_timeout};

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    dbg("dkim: performing public key lookup and signature verification");
    $message->CLOSE();      # the action happens here

    $scan->{dkim_address} = !$message->message_originator ? ''
                              : $message->message_originator->address();
    dbg("dkim: originator address: %s",
        $scan->{dkim_address} ? $scan->{dkim_address} : 'none');

    $scan->{dkim_identity} = '';
    if ($message->signature) {
      # i=  Identity of the user or agent (e.g., a mailing list manager) on
      #     behalf of which this message is signed (dkim-quoted-printable;
      #     OPTIONAL, default is an empty local-part followed by an "@"
      #     followed by the domain from the "d=" tag).
      $scan->{dkim_identity} = $message->signature->identity();
      if ($scan->{dkim_identity} eq '') {
        $scan->{dkim_identity} = '@' . $message->signature->domain();
      }
      dbg("dkim: signing identity: ".$scan->{dkim_identity});
    }

    my $result = $message->result();
    my $detail = $message->result_detail();
    # let the result stand out more clearly in the log, use uppercase
    dbg("dkim: signature verification result: %s",
        $detail eq 'none' ? $detail : uc $detail);

    # extract the actual lookup results
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
      # Returned if no valid DKIM-Signature headers were found,
      # but there is at least one invalid DKIM-Signature header.
      dbg("dkim: invalid DKIM-Signature: $detail");
    }

  });

  if ($timer->timed_out()) {
    dbg("dkim: public key lookup timed out after $timeout seconds");
  } elsif ($err) {
    chomp $err;
    dbg("dkim: public key lookup failed: $err");
  }
}

sub _check_dkim_policy {
  my ($self, $scan) = @_;

  $scan->{dkim_checked_policy} = 1;
  $scan->{dkim_signsome} = 0;
  $scan->{dkim_signall} = 0;
  $scan->{dkim_policy_testing} = 0;

  # must check the message first to obtain signer, domain, and verif. status
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  my $message = $scan->{dkim_object};

  my $timemethod = $self->{main}->time_method("check_dkim_policy");

  if (!$message) {
    dbg("dkim: policy: dkim object not available (programming error?)");
  } elsif (!$scan->is_dns_available()) {
    dbg("dkim: policy: not retrieved, no DNS resolving available");
  } elsif ($scan->{dkim_verified}) {  # no need to fetch policy when verifies
    # draft-allman-dkim-ssp-02: If the message contains a valid Originator
    # Signature, no Sender Signing Practices check need be performed:
    # the Verifier SHOULD NOT look up the Sender Signing Practices
    # and the message SHOULD be considered non-Suspicious.

    dbg("dkim: policy: not retrieved, signature does verify");

  } else {
    my $timeout = $scan->{conf}->{dkim_timeout};
    my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
    my $err = $timer->run_and_catch(sub {

      dbg("dkim: policy: performing lookup");

      my $policy;
      eval {
        $policy = $message->fetch_author_policy;  1;
      } or do {
        # fetching or parsing a policy may throw an error, ignore such policy
        my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
        dbg("dkim: policy: fetch or parse failed: $eval_stat");
        undef $policy;
      };
      if (!$policy) {
        dbg("dkim: policy: none");
      } else {
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
          $scan->{dkim_policy_testing} = 1;
        }
      }
    });

    if ($timer->timed_out()) {
      dbg("dkim: lookup timed out after $timeout seconds");
    } elsif ($err) {
      chomp $err;
      dbg("dkim: lookup failed: $err");
    }
  }
}

sub _check_dkim_whitelist {
  my ($self, $scan, $default) = @_;

  return unless $scan->is_dns_available();

  # trigger a DKIM check so we can get address/identity info
  unless ($self->check_dkim_verified($scan)) {
    return;
  }

  unless ($scan->{dkim_address}) {
    dbg("dkim: %swhitelist_from_dkim: could not find originator address",
        $default ? "def_" : "");
    return;
  }
  unless ($scan->{dkim_identity}) {
    dbg("dkim: %swhitelist_from_dkim: could not find signing identity",
        $default ? "def_" : "");
    return;
  }

  if ($default) {
    $scan->{def_dkim_whitelist_from_checked} = 1;
    $scan->{def_dkim_whitelist_from} =
      $self->_wlcheck_acceptable_signature($scan,'def_whitelist_from_dkim');

    if (!$scan->{def_dkim_whitelist_from}) {
      $scan->{def_dkim_whitelist_from} =
        $self->_wlcheck_originator_signature($scan,'def_whitelist_auth');
    }

  } else {
    $scan->{dkim_whitelist_from_checked} = 1;
    $scan->{dkim_whitelist_from} =
      $self->_wlcheck_acceptable_signature($scan,'whitelist_from_dkim');

    if (!$scan->{dkim_whitelist_from}) {
      $scan->{dkim_whitelist_from} =
        $self->_wlcheck_originator_signature($scan,'whitelist_auth');
    }
  }

  # if the message doesn't pass DKIM validation, it can't pass DKIM whitelist
  if ($default) {  # DEF_DKIM_WHITELIST_FROM
    if ($scan->{def_dkim_whitelist_from}) {
      if ($self->check_dkim_verified($scan)) {  # double-check just in case
        dbg("dkim: originator %s, signing identity %s, found in ".
            "def_whitelist_from_dkim and passed DKIM verification",
          $scan->{dkim_address}, $scan->{dkim_identity});
      } else {
        $scan->{def_dkim_whitelist_from} = 0;
      }
    }
#   else {
#     dbg("dkim: originator %s, signing identity %s, ".
#         "not in def_whitelist_from_dkim",
#         $scan->{dkim_address}, $scan->{dkim_identity});
#   }
  } else {  # DKIM_WHITELIST_FROM
    if ($scan->{dkim_whitelist_from}) {
      if ($self->check_dkim_verified($scan)) {  # double-check just in case
        dbg("dkim: originator %s, signing identity %s, found in ".
            "whitelist_from_dkim and passed DKIM verification",
            $scan->{dkim_address}, $scan->{dkim_identity});
      } else {
        $scan->{dkim_whitelist_from} = 0;
      }
    }
#   else {
#     dbg("dkim: originator %s, signing identity %s, ".
#         "not in whitelist_from_dkim",
#         $scan->{dkim_address}, $scan->{dkim_identity});
#   }
  }
}

# check for an originator signature(s), as well as for additional
# verifier-acceptable signatures if provided in a config as a second
# parameter on dkim whitelist entries
#
sub _wlcheck_acceptable_signature {
  my ($self, $scan, $wl) = @_;
  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = qr/$scan->{conf}->{$wl}->{$white_addr}{re}/i;
    # check for the originator signature is implied
    $self->_wlcheck_one($scan, $wl, $white_addr, undef, $re) and return 1;
    # walk through all additional verifier-acceptable signing identities
    foreach my $acceptable_identity
            (@{$scan->{conf}->{$wl}->{$white_addr}{domain}}) {
      next if !defined $acceptable_identity || $acceptable_identity eq '';
      $self->_wlcheck_one($scan, $wl, $white_addr, $acceptable_identity, $re)
        and return 1;
    }
  }
  return 0;
}

# use a traditional whitelist_from-style addrlist, the only acceptable DKIM
# signature is an Originator Signature.  Note: don't pre-parse and store the
# domains; that's inefficient memory-wise and only saves one m//
#
sub _wlcheck_originator_signature {
  my ($self, $scan, $wl) = @_;
  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = $scan->{conf}->{$wl}->{$white_addr};
    if ($scan->{dkim_address} =~ $re) {
      $self->_wlcheck_one($scan, $wl, $white_addr, undef, $re) and return 1;
    }
  }
  return 0;
}

sub _wlcheck_one {
  my ($self, $scan, $wl, $white_addr, $acceptable_identity, $re) = @_;

  # The $acceptable_identity is a verifier-acceptable signing identity.
  # When $acceptable_identity is undef or an empty string it implies an
  # originator signature check.

  my $originator = $scan->{dkim_address};
  if ($originator =~ $re) {  # originator address does match a whitelist entry
    # but does it carry a signature of a verifier-acceptable signing identity?
    my $identity = $scan->{dkim_identity};  # TODO: support multiple signatures

    local($1);
    if (!defined $acceptable_identity || $acceptable_identity eq '') {
      # checking for originator signature
      #
      # An "Originator Signature" is any Valid Signature where the signing
      # identity matches the Originator Address. If the signing identity
      # does not include a localpart, then only the domains must match;
      # otherwise, the two addresses must be identical.
      #
      my $originator_matching_part = $originator;
      if ($identity =~ /^\@/) {  # no localpart in signing identity
        $originator_matching_part =~ s/^.*?(\@[^\@]*)?$/$1/s; # strip localpart
      }
      if (lc($originator_matching_part) eq lc($identity)) {
        dbg("dkim: originator signature from %s, signing identity %s, ".
            "matches %s %s", $originator, $identity, $wl, $re);
        return 1;
      }
    }

    else {
      if ($acceptable_identity !~ /\@/) {  # ensure domain part, possibly empty
        $acceptable_identity = '@' . $acceptable_identity;
      }
      my $identity_matching_part = $identity;
      if ($acceptable_identity =~ /^\@/) {  # no localpart, just domain?
        $identity_matching_part =~ s/^.*?(\@[^\@]*)?\z/$1/s;  # strip localpart
      }
      if (lc($identity_matching_part) eq lc($acceptable_identity)) {
        dbg("dkim: originator %s, signing identity %s, ".
            "verifier-acceptable (%s), matches %s %s",
            $originator, $identity, $acceptable_identity, $wl, $re);
        return 1;
      }
    }
  }
  return 0;
}

1;
