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

=item dkim_timeout n             (default: 5)

How many seconds to wait for a DKIM query to complete, before
scanning continues without the DKIM result.

=cut

  push (@cmds, {
    setting => 'dkim_timeout',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

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

    $scan->{dkim_address} = ($message->message_originator ? $message->message_originator->address() : '');
    $scan->{dkim_identity} = ($message->signature ? $message->signature->identity() : '');

    dbg("dkim: originator address: ".($scan->{dkim_address} ? $scan->{dkim_address} : 'none'));
    dbg("dkim: signature identity: ".($scan->{dkim_identity} ? $scan->{dkim_identity} : 'none'));

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

sub _check_dkim_whitelist {
  my ($self, $scanner, $default) = @_;

  return unless $scanner->is_dns_available();

  # trigger an DKIM check so we can get address/identity info
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
    $scanner->{def_dkim_whitelist_from} = 0;

    # copied and butchered from the code for whitelist_from_rcvd in Evaltests.pm
    ONE: foreach my $white_addr (keys %{$scanner->{conf}->{def_whitelist_from_dkim}}) {
      my $regexp = qr/$scanner->{conf}->{def_whitelist_from_dkim}->{$white_addr}{re}/i;
      foreach my $domain (@{$scanner->{conf}->{def_whitelist_from_dkim}->{$white_addr}{domain}}) {
        if ($scanner->{dkim_address} =~ $regexp) {
	  if ($scanner->{dkim_identity} =~ /(?:^|\.|(?:@(?!@)|(?=@)))\Q${domain}\E$/i) {
	    dbg("dkim: address: $scanner->{dkim_address} matches def_whitelist_from_dkim ".
		"$scanner->{conf}->{def_whitelist_from_dkim}->{$white_addr}{re} ${domain}");
	    $scanner->{def_dkim_whitelist_from} = 1;
	    last ONE;
	  }
	}
      }
    }
  } else {
    $scanner->{dkim_whitelist_from_checked} = 1;
    $scanner->{dkim_whitelist_from} = 0;

    # copied and butchered from the code for whitelist_from_rcvd in Evaltests.pm
    ONE: foreach my $white_addr (keys %{$scanner->{conf}->{whitelist_from_dkim}}) {
      my $regexp = qr/$scanner->{conf}->{whitelist_from_dkim}->{$white_addr}{re}/i;
      foreach my $domain (@{$scanner->{conf}->{whitelist_from_dkim}->{$white_addr}{domain}}) {
        if ($scanner->{dkim_address} =~ $regexp) {
	  if ($scanner->{dkim_identity} =~ /(?:^|\.|(?:@(?!@)|(?=@)))\Q${domain}\E$/i) {
	    dbg("dkim: address: $scanner->{dkim_address} matches whitelist_from_dkim ".
		"$scanner->{conf}->{whitelist_from_dkim}->{$white_addr}{re} ${domain}");
	    $scanner->{dkim_whitelist_from} = 1;
	    last ONE;
	  }
	}
      }
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

1;
