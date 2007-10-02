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
  http://ietf.org/html.charters/dkim-charter.html

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
signing-identity (the i= tag).

Only one whitelist entry is allowed per line, as in C<whitelist_from_rcvd>.
Multiple C<whitelist_from_dkim> lines are allowed. File-glob style
meta characters are allowed for the From: address (the first parameter),
just like with C<whitelist_from_rcvd>.

If no signing identity parameter is specified, the only acceptable signature
will be an originator signature (not a third-party signature). An originator
signature is a signature where the signing identity of a signature matches
the originator address (i.e. the address in a From header field).

Since this whitelist requires a DKIM check to be made, network tests must
be enabled.

Examples of whitelisting based on an originator signature:

  whitelist_from_dkim joe@example.com
  whitelist_from_dkim *@corp.example.com
  whitelist_from_dkim *@*.example.com

Examples of whitelisting based on third-party signatures:

  whitelist_from_dkim rick@example.net     richard@example.net
  whitelist_from_dkim rick@sub.example.net example.net
  whitelist_from_dkim jane@example.net     example.org
  whitelist_from_dkim *@info.example.com   example.com
  whitelist_from_dkim *@*                  remailer.example.com

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
      my $identity = defined $2 ? $2 : ''; # empty implies originator signature
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
      my $identity = defined $2 ? $2 : ''; # empty implies originator signature
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
    dbg("dkim: originator address: ".
        ($scan->{dkim_address} ? $scan->{dkim_address} : 'none'));

    $scan->{dkim_identity} = '';
    if ($message->signature) {
      # i=  Identity of the user or agent (e.g., a mailing list manager) on
      #     behalf of which this message is signed (dkim-quoted-printable;
      #     OPTIONAL, default is an empty local-part followed by an "@"
      #     followed by the domain from the "d=" tag).
      $scan->{dkim_identity} = $message->signature->identity();
      dbg("dkim: signing identity: ".$scan->{dkim_identity}.
          ", signing domain: ".$message->signature->domain());
      if ($scan->{dkim_identity} eq '') {
        $scan->{dkim_identity} = '@' . $message->signature->domain();
      } elsif ($scan->{dkim_identity} !~ /\@/) {
        $scan->{dkim_identity} = '@' . $scan->{dkim_identity};
      }
    }

    my $result = $message->result();
    my $detail = $message->result_detail();
    # let the result stand out more clearly in the log, use uppercase
    dbg("dkim: signature verification result: ".
        ($detail eq 'none' ? $detail : uc $detail));

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
  my $verified = $self->check_dkim_verified($scan);

  return unless $verified || would_log("dbg","dkim");
  # continue if verification succeeded or we want the debug info

  unless ($scan->{dkim_address}) {
    dbg("dkim: %swhitelist_from_dkim: could not find originator address",
        $default ? "def_" : "");
    return;
  }

  my $identity = $scan->{dkim_identity};
  unless ($identity) {
  # (useless double debug line, we already reported if there is no signature)
  # dbg("dkim: %swhitelist_from_dkim: no signature", $default ? "def_" : "");
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

  # prepare summary info string to be used for logging
  my $info = $identity eq '' ? 'no' : $verified ? 'verified' : 'failed';
  my $originator_matching_part = $scan->{dkim_address};  # address in 'From'
  if ($identity =~ /^\@/) {  # empty localpart in signing identity
    local($1);
    $originator_matching_part =~ s/^.*?(\@[^\@]*)?$/$1/s;  # strip localpart
  }
  $info .= lc $identity eq lc $originator_matching_part ? ' originator'
                                                        : ' third-party';
  $info .= " signature by id $identity, originator $scan->{dkim_address}";

  # if the message doesn't pass DKIM validation, it can't pass DKIM whitelist

  if ($default) {
    if ($scan->{def_dkim_whitelist_from}) {
      dbg("dkim: $info, found in DEF_WHITELIST_FROM_DKIM" .
          ($verified ? '' : ' but ignored') );
      if (!$verified) { $scan->{def_dkim_whitelist_from} = 0 }
    } else {
      dbg("dkim: $info, not in DEF_WHITELIST_FROM_DKIM");
    }
  } else {
    if ($scan->{dkim_whitelist_from}) {
      dbg("dkim: $info, found in WHITELIST_FROM_DKIM" .
          ($verified ? '' : ' but ignored') );
      if (!$verified) { $scan->{dkim_whitelist_from} = 0 }
    } else {
      dbg("dkim: $info, not in WHITELIST_FROM_DKIM");
    }
  }
}

# check for verifier-acceptable signatures; an empty (or undefined) signing
# identity in a whitelist implies checking for an originator signature
#
sub _wlcheck_acceptable_signature {
  my ($self, $scan, $wl) = @_;
  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = qr/$scan->{conf}->{$wl}->{$white_addr}{re}/i;
    if ($scan->{dkim_address} =~ $re) {
      foreach my $acceptable_identity
              (@{$scan->{conf}->{$wl}->{$white_addr}{domain}}) {
        $self->_wlcheck_one($scan, $wl, $white_addr, $acceptable_identity, $re)
          and return 1;
      }
    }
  }
  return 0;
}

# use a traditional whitelist_from -style addrlist, the only acceptable DKIM
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

  my $matches = 0;
  my $originator = $scan->{dkim_address};  # address in a 'From' header field
  my $identity = $scan->{dkim_identity};   # TODO: support multiple signatures
  if ($originator =~ $re) {
    # originator address does match a whitelist entry (or we are debugging),
    # but does it carry a signature of a verifier-acceptable signing identity?

    # An "Originator Signature" is any Valid Signature where the signing
    # identity matches the Originator Address. If the signing identity
    # does not include a localpart, then only the domains must match;
    # otherwise, the two addresses must be identical.

    local($1,$2);
    my $originator_matching_part = $originator;
    if ($identity =~ /^\@/) {  # empty localpart in signing identity
      $originator_matching_part =~ s/^.*?(\@[^\@]*)?$/$1/s;  # strip localpart
    }
    if (!defined $acceptable_identity || $acceptable_identity eq '') {
      # checking for originator signature
      $matches = 1  if lc $identity eq lc $originator_matching_part;
    } else {  # checking for verifier-acceptable signature
      if ($acceptable_identity !~ /\@/) {
        $acceptable_identity = '@' . $acceptable_identity;
      }
      # split into local part and domain
      $identity            =~ /^ (.*?) \@ ([^\@]*) $/xs;
      my($actual_id_mbx, $actual_id_dom) = ($1,$2);
      $acceptable_identity =~ /^ (.*?) \@ ([^\@]*) $/xs;
      my($accept_id_mbx, $accept_id_dom) = ($1,$2);

      # let's take a liberty and compare local parts case-insensitively
      if ($accept_id_mbx ne '') {  # local part exists, full id must match
        $matches = 1  if lc $identity eq lc $acceptable_identity;
      } else {  # any local part in signing identity is acceptable
                # as long as domain matches or is a subdomain
        $matches = 1  if $actual_id_dom =~ /(^|\.)\Q$accept_id_dom\Q/i;
      }
    }
    if ($matches && would_log("dbg","dkim")) {
      my $verified = $self->check_dkim_verified($scan);
      my $info = $identity eq '' ? 'no' : $verified ? 'verified' : 'failed';
      dbg("dkim: $info signature by id $identity, originator $originator ".
          " matches $wl $re");
    }
  }
  return $matches;
}

1;
