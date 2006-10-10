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

Mail::SpamAssassin::Plugin::SPF - perform SPF verification tests

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::SPF

=head1 DESCRIPTION

This plugin checks a message against Sender Policy Framework (SPF)
records published by the domain owners in DNS to fight email address
forgery and make it easier to identify spams.

=cut

package Mail::SpamAssassin::Plugin::SPF;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  my $conf = $mailsaobject->{conf};

  $self->register_eval_rule ("check_for_spf_pass");
  $self->register_eval_rule ("check_for_spf_neutral");
  $self->register_eval_rule ("check_for_spf_fail");
  $self->register_eval_rule ("check_for_spf_softfail");
  $self->register_eval_rule ("check_for_spf_helo_pass");
  $self->register_eval_rule ("check_for_spf_helo_neutral");
  $self->register_eval_rule ("check_for_spf_helo_fail");
  $self->register_eval_rule ("check_for_spf_helo_softfail");
  $self->register_eval_rule ("check_for_spf_whitelist_from");
  $self->register_eval_rule ("check_for_def_spf_whitelist_from");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=head1 USER SETTINGS

=over 4

=item spf_timeout n		(default: 5)

How many seconds to wait for an SPF query to complete, before scanning
continues without the SPF result.

=cut

  push (@cmds, {
    setting => 'spf_timeout',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item whitelist_from_spf add@ress.com

Use this to supplement the whitelist_from addresses with a check against the
domain's SPF record. Aside from the name 'whitelist_from_spf', the syntax is
exactly the same as the syntax for 'whitelist_from'.

Just like whitelist_from, multiple addresses per line, separated by spaces,
are OK. Multiple C<whitelist_from_spf> lines are also OK.

The headers checked for whitelist_from_spf addresses are the same headers
used for SPF checks (Envelope-From, Return-Path, X-Envelope-From, etc).

Since this whitelist requires an SPF check to be made network tests must be
enabled. It is also required that your trust path be correctly configured.
See the section on C<trusted_networks> for more info on trust paths.

e.g.

  whitelist_from_spf joe@example.com fred@example.com
  whitelist_from_spf *@example.com

=item def_whitelist_from_spf add@ress.com

Same as C<whitelist_from_spf>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'whitelist_from_spf',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  push (@cmds, {
    setting => 'def_whitelist_from_spf',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  $conf->{parser}->register_commands(\@cmds);
}

# SPF support
sub check_for_spf_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_pass};
}

sub check_for_spf_neutral {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  $scanner->{spf_neutral};
}

sub check_for_spf_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  $scanner->{spf_fail};
}

sub check_for_spf_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  $scanner->{spf_softfail};
}

sub check_for_spf_helo_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_pass};
}

sub check_for_spf_helo_neutral {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  $scanner->{spf_helo_neutral};
}

sub check_for_spf_helo_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  $scanner->{spf_helo_fail};
}

sub check_for_spf_helo_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  $scanner->{spf_helo_softfail};
}

sub check_for_spf_whitelist_from {
  my ($self, $scanner) = @_;
  $self->_check_spf_whitelist($scanner) unless $scanner->{spf_whitelist_from_checked};
  $scanner->{spf_whitelist_from};
}

sub check_for_def_spf_whitelist_from {
  my ($self, $scanner) = @_;
  $self->_check_def_spf_whitelist($scanner) unless $scanner->{def_spf_whitelist_from_checked};
  $scanner->{def_spf_whitelist_from};
}

sub _check_spf {
  my ($self, $scanner, $ishelo) = @_;

  return unless $scanner->is_dns_available();

  # skip SPF checks if the A/MX records are nonexistent for the From
  # domain, anyway, to avoid crappy messages from slowing us down
  # (bug 3016)
  return if $scanner->check_for_from_dns();

  if ($ishelo) {
    # SPF HELO-checking variant
    $scanner->{spf_helo_checked} = 1;
    $scanner->{spf_helo_pass} = 0;
    $scanner->{spf_helo_neutral} = 0;
    $scanner->{spf_helo_fail} = 0;
    $scanner->{spf_helo_softfail} = 0;
    $scanner->{spf_helo_failure_comment} = undef;
  } else {
    # SPF on envelope sender (where possible)
    $scanner->{spf_checked} = 1;
    $scanner->{spf_pass} = 0;
    $scanner->{spf_neutral} = 0;
    $scanner->{spf_fail} = 0;
    $scanner->{spf_softfail} = 0;
    $scanner->{spf_failure_comment} = undef;
  }

  my $lasthop = $self->_get_relay($scanner);
  if (!defined $lasthop) {
    dbg("spf: no suitable relay for spf use found, skipping SPF". ($ishelo ? '-helo' : '') ." check");
    return;
  }

  my $ip = $lasthop->{ip};
  my $helo = $lasthop->{helo};
  $scanner->{sender} = '' unless $scanner->{sender_got};

  if ($ishelo) {
    dbg("spf: checking HELO (helo=$helo, ip=$ip)");

  } else {
    $self->_get_sender($scanner) unless $scanner->{sender_got};

    if (!$scanner->{sender}) {
      # we already dbg'd that we couldn't get an Envelope-From and can't do SPF
      return;
    }
    dbg("spf: checking EnvelopeFrom (helo=$helo, ip=$ip, envfrom=$scanner->{sender})");
  }

  # this test could probably stand to be more strict, but try to test
  # any invalid HELO hostname formats with a header rule
  if ($ishelo && ($helo =~ /^\d+\.\d+\.\d+\.\d+$/ || $helo =~ /^[^.]+$/)) {
    dbg("spf: cannot check HELO of '$helo', skipping");
    return;
  }
  if (!$helo) {
    dbg("spf: cannot get HELO, cannot use SPF");
    return;
  }

  if ($scanner->server_failed_to_respond_for_domain($helo)) {
    dbg("spf: we had a previous timeout on '$helo', skipping");
    return;
  }

  my $query;
  eval {
    require Mail::SPF::Query;
    if (!defined $Mail::SPF::Query::VERSION || $Mail::SPF::Query::VERSION < 1.996) {
      die "spf: Mail::SPF::Query 1.996 or later required, this is $Mail::SPF::Query::VERSION\n";
    }
    $query = Mail::SPF::Query->new (ip => $ip,
				    sender => $scanner->{sender},
				    helo => $helo,
				    debug => 0,
				    trusted => 0);
  };

  if ($@) {
    dbg("spf: cannot load or create Mail::SPF::Query module: $@");
    return;
  }

  my ($result, $comment);
  my $timeout = $scanner->{conf}->{spf_timeout};

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    ($result, $comment) = $query->result();

  });

  if ($err) {
    chomp $err;
    warn("spf: lookup failed: $err\n");
    return 0;
  }

  $result ||= 'timeout';	# bug 5077
  $comment ||= '';
  $comment =~ s/\s+/ /gs;	# no newlines please

  if ($ishelo) {
    if ($result eq 'pass') { $scanner->{spf_helo_pass} = 1; }
    elsif ($result eq 'neutral') { $scanner->{spf_helo_neutral} = 1; }
    elsif ($result eq 'fail') { $scanner->{spf_helo_fail} = 1; }
    elsif ($result eq 'softfail') { $scanner->{spf_helo_softfail} = 1; }

    if ($result eq 'neutral' || $result eq 'fail' || $result eq 'softfail') {
      $scanner->{spf_helo_failure_comment} = "SPF failed: $comment";
    }
  } else {
    if ($result eq 'pass') { $scanner->{spf_pass} = 1; }
    elsif ($result eq 'neutral') { $scanner->{spf_neutral} = 1; }
    elsif ($result eq 'fail') { $scanner->{spf_fail} = 1; }
    elsif ($result eq 'softfail') { $scanner->{spf_softfail} = 1; }

    if ($result eq 'neutral' || $result eq 'fail' || $result eq 'softfail') {
      $scanner->{spf_failure_comment} = "SPF failed: $comment";
    }
  }

  dbg("spf: query for $scanner->{sender}/$ip/$helo: result: $result, comment: $comment");
}

sub _get_relay {
  my ($self, $scanner) = @_;

  # dos: first external relay, not first untrusted
  return $scanner->{relays_external}->[0];
}

sub _get_sender {
  my ($self, $scanner) = @_;
  my $sender;

  $scanner->{sender_got} = 1;
  $scanner->{sender} = '';

  my $relay = $self->_get_relay($scanner);
  if (defined $relay) {
    $sender = $relay->{envfrom};
  }

  if ($sender) {
    dbg("spf: found Envelope-From in first external Received header");
  }
  else {
    # We cannot use the env-from data, since it went through 1 or more relays 
    # since the untrusted sender and they may have rewritten it.
    if ($scanner->{num_relays_trusted} > 0 && !$scanner->{conf}->{always_trust_envelope_sender}) {
      dbg("spf: relayed through one or more trusted relays, cannot use header-based Envelope-From, skipping");
      return;
    }

    # we can (apparently) use whatever the current Envelope-From was,
    # from the Return-Path, X-Envelope-From, or whatever header.
    # it's better to get it from Received though, as that is updated
    # hop-by-hop.
    $sender = $scanner->get ("EnvelopeFrom");
  }

  if (!$sender) {
    dbg("spf: cannot get Envelope-From, cannot use SPF");
    return;  # avoid setting $scanner->{sender} to undef
  }

  return $scanner->{sender} = lc $sender;
}

sub _check_spf_whitelist {
  my ($self, $scanner) = @_;

  return unless $scanner->is_dns_available();

  $scanner->{spf_whitelist_from_checked} = 1;
  $scanner->{spf_whitelist_from} = 0;

  $self->_get_sender($scanner) unless $scanner->{sender_got};

  unless ($scanner->{sender}) {
    dbg("spf: spf_whitelist_from: could not find useable envelope sender");
    return;
  }

  if (defined ($scanner->{conf}->{whitelist_from_spf}->{$scanner->{sender}})) {
    $scanner->{spf_whitelist_from} = 1;
  } else {
    study $scanner->{sender};
    foreach my $regexp (values %{$scanner->{conf}->{whitelist_from_spf}}) {
      if ($scanner->{sender} =~ qr/$regexp/i) {
        $scanner->{spf_whitelist_from} = 1;
        last;
      }
    }
  }

  # if the message doesn't pass SPF validation, it can't pass an SPF whitelist
  if ($scanner->{spf_whitelist_from}) {
    if ($self->check_for_spf_pass($scanner)) {
      dbg("spf: whitelist_from_spf: $scanner->{sender} is in user's WHITELIST_FROM_SPF and passed SPF check");
    } else {
      dbg("spf: whitelist_from_spf: $scanner->{sender} is in user's WHITELIST_FROM_SPF but failed SPF check");
      $scanner->{spf_whitelist_from} = 0;
    }
  } else {
    dbg("spf: whitelist_from_spf: $scanner->{sender} is not in user's WHITELIST_FROM_SPF");
  }
}

sub _check_def_spf_whitelist {
  my ($self, $scanner) = @_;

  return unless $scanner->is_dns_available();

  $scanner->{def_spf_whitelist_from_checked} = 1;
  $scanner->{def_spf_whitelist_from} = 0;

  $self->_get_sender($scanner) unless $scanner->{sender_got};

  unless ($scanner->{sender}) {
    dbg("spf: def_spf_whitelist_from: could not find useable envelope sender");
    return;
  }

  if (defined ($scanner->{conf}->{def_whitelist_from_spf}->{$scanner->{sender}})) {
    $scanner->{def_spf_whitelist_from} = 1;
  } else {
    study $scanner->{sender};
    foreach my $regexp (values %{$scanner->{conf}->{def_whitelist_from_spf}}) {
      if ($scanner->{sender} =~ qr/$regexp/i) {
        $scanner->{def_spf_whitelist_from} = 1;
        last;
      }
    }
  }

  # if the message doesn't pass SPF validation, it can't pass an SPF whitelist
  if ($scanner->{def_spf_whitelist_from}) {
    if ($self->check_for_spf_pass($scanner)) {
      dbg("spf: def_whitelist_from_spf: $scanner->{sender} is in DEF_WHITELIST_FROM_SPF and passed SPF check");
    } else {
      dbg("spf: def_whitelist_from_spf: $scanner->{sender} is in DEF_WHITELIST_FROM_SPF but failed SPF check");
      $scanner->{def_spf_whitelist_from} = 0;
    }
  } else {
    dbg("spf: def_whitelist_from_spf: $scanner->{sender} is not in DEF_WHITELIST_FROM_SPF");
  }
}

###########################################################################

1;

=back

=cut
