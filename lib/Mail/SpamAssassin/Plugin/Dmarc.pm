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

Mail::SpamAssassin::Plugin::Dmarc - check Dmarc policy

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::Dmarc

  ifplugin Mail::SpamAssassin::Plugin::Dmarc
    header DMARC_NONE eval:check_dmarc_none()
    priority DMARC_NONE 500
    describe DMARC_NONE Dmarc none policy

    header DMARC_QUAR eval:check_dmarc_quarantine()
    priority DMARC_QUAR 500
    describe DMARC_QUAR Dmarc quarantine policy

    header DMARC_REJECT eval:check_dmarc_reject()
    priority DMARC_REJECT 500
    describe DMARC_REJECT Dmarc reject policy

    header DMARC_MISSING eval:check_dmarc_missing()
    priority DMARC_MISSING 500
    describe DMARC_MISSING Missing Dmarc policy
  endif

=head1 DESCRIPTION

This plugin checks if emails matches Dmarc policy, the plugin needs both DKIM
and SPF plugins enabled.

=cut

package Mail::SpamAssassin::Plugin::Dmarc;

use strict;
use warnings;
use re 'taint';

my $VERSION = 0.1;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;

our @ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_DMARC => eval { require Mail::DMARC::PurePerl; };

BEGIN
{
    eval{
      import Mail::DMARC::PurePerl
    };
}

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Dmarc: @_"); }

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
        default => '0',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
        }
    );
    $conf->{parser}->register_commands(\@cmds);

}

sub check_dmarc_pass {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'pass') and ($pms->{dmarc_policy} ne 'no policy available')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_reject {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'fail') and ($pms->{dmarc_policy} eq 'reject')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_quarantine {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'fail') and ($pms->{dmarc_policy} eq 'quarantine')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_none {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'fail') and ($pms->{dmarc_policy} eq 'none')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_missing {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_policy} eq 'no policy available')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub _check_dmarc {
  my ($self,$pms,$name) = @_;
  my $spf_status = 'none';
  my $spf_helo_status = 'none';
  my ($dmarc, $lasthop, $result, $rua, $domain, $mfrom_domain);

  if (!HAS_DMARC) {
    warn "check_dmarc not supported, required module Mail::DMARC::PurePerl missing\n";
    return 0;
  }

  if((defined $pms->{dmarc_checked}) and ($pms->{dmarc_checked} eq 1)) {
    return;
  }
  $dmarc = Mail::DMARC::PurePerl->new();
  $lasthop = $pms->{relays_external}->[0];

  return if ( $pms->get('From:addr') !~ /\@/ );

  $spf_status = 'pass' if ((defined $pms->{spf_pass}) and ($pms->{spf_pass} eq 1));
  $spf_status = 'fail' if ((defined $pms->{spf_fail}) and ($pms->{spf_fail} eq 1));
  $spf_status = 'fail' if ((defined $pms->{spf_none}) and ($pms->{spf_none} eq 1));
  $spf_status = 'fail' if ((defined $pms->{spf_permerror}) and ($pms->{spf_permerror} eq 1));
  $spf_status = 'neutral' if ((defined $pms->{spf_neutral}) and ($pms->{spf_neutral} eq 1));
  $spf_status = 'softfail' if ((defined $pms->{spf_softfail}) and ($pms->{spf_softfail} eq 1));
  $spf_helo_status = 'pass' if ((defined $pms->{spf_helo_pass}) and ($pms->{spf_helo_pass} eq 1));
  $spf_helo_status = 'fail' if ((defined $pms->{spf_helo_fail}) and ($pms->{spf_helo_fail} eq 1));
  $spf_helo_status = 'fail' if ((defined $pms->{spf_helo_permerror}) and ($pms->{spf_helo_permerror} eq 1));
  $spf_helo_status = 'fail' if ((defined $pms->{spf_helo_none}) and ($pms->{spf_helo_none} eq 1));
  $spf_helo_status = 'neutral' if ((defined $pms->{spf_helo_neutral}) and ($pms->{spf_helo_neutral} eq 1));
  $spf_helo_status = 'softfail' if ((defined $pms->{spf_helo_softfail}) and ($pms->{spf_helo_softfail} eq 1));

  $mfrom_domain = $pms->get('From:domain');
  return if not defined $mfrom_domain;
  $dmarc->source_ip($lasthop->{ip});
  $dmarc->header_from_raw($pms->get('From:addr'));
  $dmarc->dkim($pms->{dkim_verifier}) if (ref($pms->{dkim_verifier}));
  eval {
    $dmarc->spf([
      {
        scope  => 'mfrom',
        domain => "$mfrom_domain",
        result => "$spf_status",
      },
      {
        scope  => 'helo',
        domain => "$lasthop->{lc_helo}",
        result => "$spf_helo_status",
      },
    ]);
    $result = $dmarc->validate();
  };
  if ($@) {
    if(defined $domain) {
      dbg("Dmarc error while evaluating domain $domain: $@");
    } else {
      dbg("Dmarc error: $@");
    }
    return;
  }

  if(($pms->{conf}->{dmarc_save_reports} == 1) and (defined $result->result)) {
    $rua = eval { $result->published()->rua(); };
    if (defined $rua and $rua =~ /mailto\:/) {
      eval {
        $dmarc->save_aggregate();
      };
      if ( my $error = $@ ) {
        dbg("Dmarc report could not be saved: $error");
      } else {
        dbg("Dmarc report will be sent to $rua");
      }
    }
  }

  $pms->{dmarc_result} = $result->result;
  if ((defined $result->reason) and (defined $result->reason->[0]{comment}) and ($result->reason->[0]{comment} eq "too many policies")) {
    dbg("result: no policy available");
    $pms->{dmarc_policy} = "no policy available";
    return;
  }
  if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} ne 'none')) {
    dbg("result: " . $pms->{dmarc_result} . ", disposition: " . $result->disposition . ", dkim: " . $result->dkim . ", spf: " . $result->spf . " ( spf: $spf_status, spf_helo: $spf_helo_status)");
    $pms->{dmarc_policy} = $result->published->p;
  } else {
    dbg("result: no policy available");
    $pms->{dmarc_policy} = "no policy available";
  }
  $pms->{dmarc_checked} = 1;
  undef $result;
  undef $dmarc;
}

1;
