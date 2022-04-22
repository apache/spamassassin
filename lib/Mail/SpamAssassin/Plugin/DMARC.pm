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
#
# Author: Giovanni Bechis <gbechis@apache.org>

=head1 NAME

Mail::SpamAssassin::Plugin::DMARC - check DMARC policy

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::DMARC

  ifplugin Mail::SpamAssassin::Plugin::DMARC
    header DMARC_NONE eval:check_dmarc_none()
    priority DMARC_NONE 500
    describe DMARC_NONE DMARC none policy

    header DMARC_QUAR eval:check_dmarc_quarantine()
    priority DMARC_QUAR 500
    describe DMARC_QUAR DMARC quarantine policy

    header DMARC_REJECT eval:check_dmarc_reject()
    priority DMARC_REJECT 500
    describe DMARC_REJECT DMARC reject policy

    header DMARC_MISSING eval:check_dmarc_missing()
    priority DMARC_MISSING 500
    describe DMARC_MISSING Missing DMARC policy
  endif

=head1 DESCRIPTION

This plugin checks if emails matches DMARC policy, the plugin needs both DKIM
and SPF plugins enabled.

=cut

package Mail::SpamAssassin::Plugin::DMARC;

use strict;
use warnings;
use re 'taint';

my $VERSION = 0.2;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;

our @ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_DMARC => eval { require Mail::DMARC::PurePerl; };

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("DMARC: $msg", @_); }

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->set_config($mailsa->{conf});
  $self->register_eval_rule("check_dmarc_pass");
  $self->register_eval_rule("check_dmarc_reject");
  $self->register_eval_rule("check_dmarc_quarantine");
  $self->register_eval_rule("check_dmarc_none");
  $self->register_eval_rule("check_dmarc_missing");

  if (!HAS_DMARC) {
    warn "DMARC not supported, required module Mail::DMARC::PurePerl missing\n";
  }

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=over 4

=item dmarc_save_reports ( 0 | 1 ) (default: 0)

Store DMARC reports using Mail::DMARC::Store, mail-dmarc.ini must be configured to save and send DMARC reports.

=back

=cut

  push(@cmds, {
    setting => 'dmarc_save_reports',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub check_dmarc_pass {
  my ($self, $pms, $name) = @_;

  $self->_check_dmarc($pms) unless $pms->{dmarc_checked};
  return defined $pms->{dmarc_result} &&
         $pms->{dmarc_result} eq 'pass' &&
         $pms->{dmarc_policy} ne 'no policy available';
}

sub check_dmarc_reject {
  my ($self, $pms, $name) = @_;

  $self->_check_dmarc($pms) unless $pms->{dmarc_checked};
  return defined $pms->{dmarc_result} &&
         $pms->{dmarc_result} eq 'fail' &&
         $pms->{dmarc_policy} eq 'reject';
}

sub check_dmarc_quarantine {
  my ($self, $pms, $name) = @_;

  $self->_check_dmarc($pms) unless $pms->{dmarc_checked};
  return defined $pms->{dmarc_result} &&
         $pms->{dmarc_result} eq 'fail' &&
         $pms->{dmarc_policy} eq 'quarantine';
}

sub check_dmarc_none {
  my ($self, $pms, $name) = @_;

  $self->_check_dmarc($pms) unless $pms->{dmarc_checked};
  return defined $pms->{dmarc_result} &&
         $pms->{dmarc_result} eq 'fail' &&
         $pms->{dmarc_policy} eq 'none';
}

sub check_dmarc_missing {
  my ($self, $pms, $name) = @_;

  $self->_check_dmarc($pms) unless $pms->{dmarc_checked};
  return defined $pms->{dmarc_result} &&
         $pms->{dmarc_policy} eq 'no policy available';
}

sub _check_dmarc {
  my ($self, $pms, $name) = @_;

  return if !HAS_DMARC;
  return if $pms->{dmarc_checked};
  $pms->{dmarc_checked} = 1;

  my $lasthop = $pms->{relays_external}->[0];
  if (!defined $lasthop) {
    dbg("no external relay found, skipping DMARC check");
    return;
  }

  my $from_addr = ($pms->get('From:first:addr'))[0];
  return if index($from_addr, '@') == -1;

  my $mfrom_domain = ($pms->get('EnvelopeFrom:first:addr:host'))[0];
  if (!defined $mfrom_domain) {
    $mfrom_domain = ($pms->get('From:first:addr:domain'))[0];
    return if !defined $mfrom_domain;
    dbg("EnvelopeFrom header not found, using From");
  }

  my $spf_status = 'none';
  if ($pms->{spf_pass})         { $spf_status = 'pass'; }
  elsif ($pms->{spf_fail})      { $spf_status = 'fail'; }
  elsif ($pms->{spf_permerror}) { $spf_status = 'fail'; }
  elsif ($pms->{spf_none})      { $spf_status = 'fail'; }
  elsif ($pms->{spf_neutral})   { $spf_status = 'neutral'; }
  elsif ($pms->{spf_softfail})  { $spf_status = 'softfail'; }

  my $spf_helo_status = 'none';
  if ($pms->{spf_helo_pass})         { $spf_helo_status = 'pass'; }
  elsif ($pms->{spf_helo_fail})      { $spf_helo_status = 'fail'; }
  elsif ($pms->{spf_helo_permerror}) { $spf_helo_status = 'fail'; }
  elsif ($pms->{spf_helo_none})      { $spf_helo_status = 'fail'; }
  elsif ($pms->{spf_helo_neutral})   { $spf_helo_status = 'neutral'; }
  elsif ($pms->{spf_helo_softfail})  { $spf_helo_status = 'softfail'; }

  my $dmarc = Mail::DMARC::PurePerl->new();
  $dmarc->source_ip($lasthop->{ip});
  $dmarc->header_from_raw($from_addr);
  $dmarc->dkim($pms->{dkim_verifier}) if (ref($pms->{dkim_verifier}));

  my $result;
  eval {
    $dmarc->spf([
      {
        scope  => 'mfrom',
        domain => $mfrom_domain,
        result => $spf_status,
      },
      {
        scope  => 'helo',
        domain => $lasthop->{lc_helo},
        result => $spf_helo_status,
      },
    ]);
    $result = $dmarc->validate();
  };
  if ($@) {
    dbg("error while evaluating domain $mfrom_domain: $@");
    return;
  }

  if (defined($pms->{dmarc_result} = $result->result)) {
    if ($pms->{conf}->{dmarc_save_reports}) {
      my $rua = eval { $result->published()->rua(); };
      if (defined $rua && index($rua, 'mailto:') >= 0) {
        eval { $dmarc->save_aggregate(); };
        if ($@) {
          info("report could not be saved: $@");
        } else {
          dbg("report will be sent to $rua");
        }
      }
    }

    if (defined $result->reason->[0]{comment} &&
          $result->reason->[0]{comment} eq 'too many policies') {
      dbg("result: no policy available");
      $pms->{dmarc_policy} = 'no policy available';
    } elsif ($result->result ne 'none') {
      dbg("result: $result->{result}, disposition: $result->{disposition}, dkim: $result->{dkim}, spf: $result->{spf} (spf: $spf_status, spf_helo: $spf_helo_status)");
      $pms->{dmarc_policy} = $result->published->p;
    } else {
      dbg("result: no policy available");
      $pms->{dmarc_policy} = 'no policy available';
    }
  }
}

1;
