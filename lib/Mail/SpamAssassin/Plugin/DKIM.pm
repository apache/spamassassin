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

This SpamAssassin plugin implements DKIM lookups as described by the current
draft specs: draft-ietf-dkim-base-10, as well as DomainKeys lookups, as
described in draft-delany-domainkeys-base-06, thanks to the support for both
types of signatures by newer versions of module Mail::DKIM (0.22 or later).

It requires the C<Mail::DKIM> CPAN module to operate. Many thanks to Jason Long
for that module.

Note that if C<Mail::DKIM> version 0.20 or later is installed, this plugin will
also perform Domain Key lookups on DomainKey-Signature headers.

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
  my @cmds = ();

=head1 USER SETTINGS

=over 4

=item whitelist_from_dkim add@ress.com [identity]

Use this to supplement the whitelist_from addresses with a check to make sure
the message has been signed by a Domain Keys Identified Mail (DKIM) signature
that can be verified against the From: domain's DKIM public key.

In order to support optional identities, only one whitelist entry is allowed
per line, exactly like C<whitelist_from_rcvd>.  Multiple C<whitelist_from_dkim>
lines are allowed.  File-glob style meta characters are allowed for the From:
address, just like with C<whitelist_from_rcvd>.  The optional identity
parameter must match from the right-most side, also like in
C<whitelist_from_rcvd>.

If no identity parameter is specified the domain of the address parameter
specified will be used instead.

The From: address is obtained from a signed part of the message (ie. the
"From:" header), not from envelope data that is possible to forge.

Since this whitelist requires an DKIM check to be made, network tests must be
enabled.

Examples:

  whitelist_from_dkim joe@example.com
  whitelist_from_dkim *@corp.example.com

  whitelist_from_dkim jane@example.net  example.org
  whitelist_from_dkim dick@example.net  richard@example.net

=item def_whitelist_from_dkim add@ress.com [identity]

Same as C<whitelist_from_dkim>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'whitelist_from_dkim',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $identity = (defined $2 ? $2 : $1);

      unless (defined $2) {
	$identity =~ s/^.*(@.*)$/$1/;
      }
      $self->{parser}->add_to_addrlist_rcvd ('whitelist_from_dkim',
						$address, $identity);
    }
  });

  push (@cmds, {
    setting => 'def_whitelist_from_dkim',,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $identity = (defined $2 ? $2 : $1);

      unless (defined $2) {
	$identity =~ s/^.*(@.*)$/$1/;
      }
      $self->{parser}->add_to_addrlist_rcvd ('def_whitelist_from_dkim',
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
  my ($self, $scanner) = @_;
  $self->_check_dkim_whitelist($scanner, 0) unless $scanner->{dkim_whitelist_from_checked};
  $scanner->{dkim_whitelist_from};
}

sub check_for_def_dkim_whitelist_from {
  my ($self, $scanner) = @_;
  $self->_check_dkim_whitelist($scanner, 1) unless $scanner->{def_dkim_whitelist_from_checked};
  $scanner->{def_dkim_whitelist_from};
}

# ---------------------------------------------------------------------------

sub _check_dkim_signature {
  my ($self, $scan) = @_;

  $scan->{dkim_checked_signature} = 1;
  $scan->{dkim_signed} = 0;
  $scan->{dkim_verified} = 0;
  $scan->{dkim_key_testing} = 0;

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
  };

  if ($@) {             # intercept die() exceptions and render safe
    dbg ("dkim: verification failed, intercepted error: $@");
    return 0;           # cannot verify message
  }

  my $timeout = $scan->{conf}->{dkim_timeout};

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    dbg("dkim: performing public key lookup and signature verification");
    $message->CLOSE();      # the action happens here

    $scan->{dkim_address} = ($message->message_originator ? $message->message_originator->address() : '');
    dbg("dkim: originator address: ".($scan->{dkim_address} ? $scan->{dkim_address} : 'none'));

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
      dbg("dkim: signature identity: ".$scan->{dkim_identity});
    }

    my $result = $message->result();
    my $detail = $message->result_detail();
    dbg("dkim: signature verification result: $detail");

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
      eval { $policy = $message->fetch_author_policy };
      if ($@ ne '') {
        # fetching or parsing a policy may throw an error, ignore such policy
        chomp($@); dbg("dkim: policy: fetch or parse failed: $@");
        undef $policy;
      }
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
  my ($self, $scanner, $default) = @_;

  return unless $scanner->is_dns_available();

  # trigger a DKIM check so we can get address/identity info,
  # if verification failed only continue if we want the debug info
  unless ($self->check_dkim_verified($scanner)) {
    unless (would_log("dbg", "dkim")) {
      return;
    }
  }

  unless ($scanner->{dkim_address}) {
    dbg("dkim: ". ($default ? "def_" : "") ."whitelist_from_dkim: could not find originator address");
    return;
  }
  unless ($scanner->{dkim_identity}) {
    dbg("dkim: ". ($default ? "def_" : "") ."whitelist_from_dkim: could not find identity");
    return;
  }

  if ($default) {
    $scanner->{def_dkim_whitelist_from_checked} = 1;
    $scanner->{def_dkim_whitelist_from} =
                    $self->_wlcheck_domain($scanner,'def_whitelist_from_dkim');

    if (!$scanner->{def_dkim_whitelist_from}) {
      $scanner->{def_dkim_whitelist_from} =
                    $self->_wlcheck_no_domain($scanner,'def_whitelist_auth');
    }
  } else {
    $scanner->{dkim_whitelist_from_checked} = 1;
    $scanner->{dkim_whitelist_from} =
                    $self->_wlcheck_domain($scanner,'whitelist_from_dkim');

    if (!$scanner->{dkim_whitelist_from}) {
      $scanner->{dkim_whitelist_from} =
                    $self->_wlcheck_no_domain($scanner,'whitelist_auth');
    }
  }

  # if the message doesn't pass DKIM validation, it can't pass an DKIM whitelist
  if ($default) {
    if ($scanner->{def_dkim_whitelist_from}) {
      if ($self->check_dkim_verified($scanner)) {
        dbg("dkim: address: $scanner->{dkim_address} identity: ".
          "$scanner->{dkim_identity} is in user's DEF_WHITELIST_FROM_DKIM and ".
          "passed DKIM verification");
      } else {
        dbg("dkim: address: $scanner->{dkim_address} identity: ".
	  "$scanner->{dkim_identity} is in user's DEF_WHITELIST_FROM_DKIM but ".
	  "failed DKIM verification");
	$scanner->{def_dkim_whitelist_from} = 0;
      }
    } else {
      dbg("dkim: address: $scanner->{dkim_address} identity: ".
	  "$scanner->{dkim_identity} is not in user's DEF_WHITELIST_FROM_DKIM");
    }
  } else {
    if ($scanner->{dkim_whitelist_from}) {
      if ($self->check_dkim_verified($scanner)) {
	dbg("dkim: address: $scanner->{dkim_address} identity: ".
	  "$scanner->{dkim_identity} is in user's WHITELIST_FROM_DKIM and ".
	  "passed DKIM verification");
      } else {
	dbg("dkim: address: $scanner->{dkim_address} identity: ".
	  "$scanner->{dkim_identity} is in user's WHITELIST_FROM_DKIM but ".
	  "failed DKIM verification");
	$scanner->{dkim_whitelist_from} = 0;
      }
    } else {
      dbg("dkim: address: $scanner->{dkim_address} identity: ".
	  "$scanner->{dkim_identity} is not in user's WHITELIST_FROM_DKIM");
    }
  }
}


sub _wlcheck_domain {
  my ($self, $scan, $wl) = @_;

  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = qr/$scan->{conf}->{$wl}->{$white_addr}{re}/i;
    foreach my $domain (@{$scan->{conf}->{$wl}->{$white_addr}{domain}}) {
      $self->_wlcheck_one_dom($scan, $wl, $white_addr, $domain, $re) and return 1;
    }
  }
  return 0;
}

sub _wlcheck_one_dom {
  my ($self, $scan, $wl, $white_addr, $domain, $re) = @_;
  if ($scan->{dkim_address} =~ $re) {
    if ($scan->{dkim_identity} =~ /(?:^|\.|(?:@(?!@)|(?=@)))\Q${domain}\E$/i)
    {
      dbg("dkim: address: $scan->{dkim_address} matches $wl $re $domain");
      return 1;
    }
  }
  return 0;
}

# use a traditional whitelist_from-style addrlist, and infer the
# domain from each address on the fly.  Note: don't pre-parse and
# store the domains; that's inefficient memory-wise and only saves 1 m//
sub _wlcheck_no_domain {
  my ($self, $scan, $wl) = @_;

  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $domain = ($white_addr =~ /\@(.*?)$/) ? $1 : $white_addr;
    my $re = $scan->{conf}->{$wl}->{$white_addr};
    $self->_wlcheck_one_dom($scan, $wl, $white_addr, $domain, $re) and return 1;
  }
  return 0;
}

1;
