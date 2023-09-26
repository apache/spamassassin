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
    header DMARC_PASS eval:check_dmarc_pass()
    describe DMARC_PASS DMARC pass policy
    tflags DMARC_PASS net nice
    score DMARC_PASS -0.001

    header DMARC_REJECT eval:check_dmarc_reject()
    describe DMARC_REJECT DMARC reject policy
    tflags DMARC_REJECT net
    score DMARC_REJECT 0.001

    header DMARC_QUAR eval:check_dmarc_quarantine()
    describe DMARC_QUAR DMARC quarantine policy
    tflags DMARC_QUAR net
    score DMARC_QUAR 0.001

    header DMARC_NONE eval:check_dmarc_none()
    describe DMARC_NONE DMARC none policy
    tflags DMARC_NONE net
    score DMARC_NONE 0.001

    header DMARC_MISSING eval:check_dmarc_missing()
    describe DMARC_MISSING Missing DMARC policy
    tflags DMARC_MISSING net
    score DMARC_MISSING 0.001
  endif

=head1 DESCRIPTION

This plugin checks if emails match DMARC policy, the plugin needs both DKIM
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

sub dbg { my $msg = shift; Mail::SpamAssassin::Logger::dbg("DMARC: $msg", @_); }
sub info { my $msg = shift; Mail::SpamAssassin::Logger::info("DMARC: $msg", @_); }

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->set_config($mailsa->{conf});
  $self->register_eval_rule("check_dmarc_pass", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_dmarc_reject", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_dmarc_quarantine", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_dmarc_none", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_dmarc_missing", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

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
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  # Force waiting of SPF and DKIM results
  $pms->{dmarc_async_queue} = [];
}

sub _check_eval {
  my ($self, $pms, $result) = @_;

  if (exists $pms->{dmarc_async_queue}) {
    my $rulename = $pms->get_current_eval_rule_name();
    push @{$pms->{dmarc_async_queue}}, sub {
      if ($result->()) {
        $pms->got_hit($rulename, '', ruletype => 'header');
      } else {
        $pms->rule_ready($rulename);
      }
    };
    return; # return undef for async status
  }

  $self->_check_dmarc($pms);
  # make sure not to return undef, as this is not async anymore
  return $result->() || 0;
}

sub check_dmarc_pass {
  my ($self, $pms, $name) = @_;

  my $result = sub {
    defined $pms->{dmarc_result} &&
      $pms->{dmarc_result} eq 'pass' &&
      $pms->{dmarc_policy} ne 'no policy available';
  };

  return $self->_check_eval($pms, $result);
}

sub check_dmarc_reject {
  my ($self, $pms, $name) = @_;

  my $result = sub {
    defined $pms->{dmarc_result} &&
      $pms->{dmarc_result} eq 'fail' &&
      $pms->{dmarc_policy} eq 'reject';
  };

  return $self->_check_eval($pms, $result);
}

sub check_dmarc_quarantine {
  my ($self, $pms, $name) = @_;

  my $result = sub {
    defined $pms->{dmarc_result} &&
      $pms->{dmarc_result} eq 'fail' &&
      $pms->{dmarc_policy} eq 'quarantine';
  };

  return $self->_check_eval($pms, $result);
}

sub check_dmarc_none {
  my ($self, $pms, $name) = @_;

  my $result = sub {
    defined $pms->{dmarc_result} &&
      $pms->{dmarc_result} eq 'fail' &&
      $pms->{dmarc_policy} eq 'none';
  };

  return $self->_check_eval($pms, $result);
}

sub check_dmarc_missing {
  my ($self, $pms, $name) = @_;

  my $result = sub {
    defined $pms->{dmarc_result} &&
      $pms->{dmarc_policy} eq 'no policy available';
  };

  return $self->_check_eval($pms, $result);
}

sub check_tick {
  my ($self, $opts) = @_;

  $self->_check_async_queue($opts->{permsgstatus});
}

sub check_cleanup {
  my ($self, $opts) = @_;

  # Finish it whether SPF and DKIM is ready or not
  $self->_check_async_queue($opts->{permsgstatus}, 1);
}

sub _check_async_queue {
  my ($self, $pms, $finish) = @_;

  return unless exists $pms->{dmarc_async_queue};

  # Check if SPF or DKIM is ready
  if ($finish || ($pms->{spf_checked} && $pms->{dkim_checked_signature})) {
    $self->_check_dmarc($pms);
    $_->() foreach (@{$pms->{dmarc_async_queue}});
    # No more async queueing needed.  If any evals are called later, they
    # will act on the results directly.
    delete $pms->{dmarc_async_queue};
  }
}

sub _check_dmarc {
  my ($self, $pms, $name) = @_;

  return unless $pms->is_dns_available();

  # Load DMARC module
  if (!exists $self->{has_mail_dmarc}) {
    my $eval_stat;
    eval {
      require Mail::DMARC::PurePerl;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };
    if (!defined($eval_stat)) {
      dbg("using Mail::DMARC::PurePerl for DMARC checks");
      $self->{has_mail_dmarc} = 1;
    } else {
      dbg("cannot load Mail::DMARC::PurePerl: module: $eval_stat");
      dbg("Mail::DMARC::PurePerl is required for DMARC checks, DMARC checks disabled");
      $self->{has_mail_dmarc} = undef;
    }
  }

  return if !$self->{has_mail_dmarc};
  return if $pms->{dmarc_checked};
  $pms->{dmarc_checked} = 1;

  my $lasthop = $pms->{relays_external}->[0];
  if (!defined $lasthop) {
    dbg("no external relay found, skipping DMARC check");
    return;
  }

  my $from_addr = ($pms->get('From:first:addr'))[0];
  return if not defined $from_addr;
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

  my $suppl_attrib = $pms->{msg}->{suppl_attrib};
  if (defined $suppl_attrib && exists $suppl_attrib->{dkim_signatures}) {
    my $dkim_signatures = $suppl_attrib->{dkim_signatures};
    foreach my $signature ( @$dkim_signatures ) {
      $dmarc->dkim( domain => $signature->domain, result => $signature->result );
      dbg("DKIM result for domain " . $signature->domain . ": " . $signature->result);
    }
  } else {
    $dmarc->dkim($pms->{dkim_verifier}) if (ref($pms->{dkim_verifier}));
  }

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

  my $dmarc_arc_verified = 0;
  if (($result->result ne 'pass') and (ref($pms->{arc_verifier}) and ($pms->{arc_verifier}->result))) {
    undef $result;
    $dmarc_arc_verified = 1;
    # if DMARC fails retry by reading data from AAR headers
    # use Mail::SpamAssassin::Plugin::AuthRes if available to read ARC signature details
    my @spf_parsed = sort { ( $a->{authres_parsed}{spf}{arc_index} // 0 ) <=> ( $b->{authres_parsed}{spf}{arc_index} // 0 ) } @{$pms->{authres_parsed}{spf}};
    my $old_arc_index = 0;
    foreach my $spf_parse ( @spf_parsed ) {
      last if not defined $spf_parse->{arc_index};
      last if $old_arc_index > $spf_parse->{arc_index};
      dbg("Evaluate DMARC using AAR spf information for index $spf_parse->{arc_index}");
      if(exists $spf_parse->{properties}{smtp}{mailfrom}) {
        my $mfrom_dom = $spf_parse->{properties}{smtp}{mailfrom};
        if($mfrom_dom =~ /\@(.*)/) {
          $mfrom_dom = $1;
        }
        $dmarc->spf([
          {
            scope  => 'mfrom',
            domain => $mfrom_dom,
            result => $spf_parse->{result},
          }
        ]);
      }
      if(exists $spf_parse->{properties}{smtp}{helo}) {
        $dmarc->spf([
          {
            scope  => 'helo',
            domain => $spf_parse->{properties}{smtp}{helo},
            result => $spf_parse->{result},
          }
        ]);
      }
      $old_arc_index = $spf_parse->{arc_index};
    }

    my @tmp_arc_seals;
    my @arc_seals;
    if(defined $pms->{arc_verifier}{seals}) {
      @tmp_arc_seals = @{$pms->{arc_verifier}{seals}};
      @arc_seals = sort { ( $a->{arc_verifier}{seals}{tags_by_name}{i}{value} // 0 ) <=> ( $b->{arc_verifier}{seals}{tags_by_name}{i}{value} // 0 ) } @tmp_arc_seals;
      foreach my $seals ( @arc_seals ) {
        if(exists($seals->{tags_by_name}{d}) and exists($pms->{arc_author_domains}->{$mfrom_domain})) {
          dbg("Evaluate DMARC using AAR dkim information for index $seals->{tags_by_name}{i}{value} on domain $mfrom_domain and selector $seals->{tags_by_name}{s}{value}. Result is $seals->{verify_result}");
          my $arc_result = $seals->{verify_result};
          if($seals->{verify_result} eq 'invalid') {
            $arc_result = 'permerror';
          }
          $dmarc->dkim(domain => $mfrom_domain, selector => $seals->{tags_by_name}{s}{value}, result => $arc_result);
          last;
        }
      }
    }

    eval { $result = $dmarc->validate(); };
  }

  # Report that DMARC failed but it has been overridden because of AAR headers
  if(ref($pms->{arc_verifier}) and ($pms->{arc_verifier}->result) and ($dmarc_arc_verified)) {
    $result->reason->[0]{type} = 'local_policy';
    $result->reason->[0]{comment} = "arc=" . $pms->{arc_verifier}->result;
    my $cnt = 1;
    foreach my $seals ( @{$pms->{arc_verifier}{seals}} ) {
      if(exists($seals->{tags_by_name}{d}) and exists($seals->{tags_by_name}{s})) {
        $result->reason->[0]{comment} .= " as[$cnt].d=$seals->{tags_by_name}{d}{value} as[$cnt].s=$seals->{tags_by_name}{s}{value}";
        $cnt++;
      }
    }
    if($cnt gt 1) {
      $result->reason->[0]{comment} .= " remote-ip[1]=$lasthop->{ip}";
    }
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
      dbg("result: no policy available (too many policies)");
      $pms->{dmarc_policy} = 'no policy available';
    } elsif ($result->result eq 'pass') {
      dbg("result: pass");
      $pms->{dmarc_policy} = $result->published->p;
    } elsif ($result->result ne 'none') {
      dbg("result: $result->{result}, disposition: $result->{disposition}, dkim: $result->{dkim}, spf: $result->{spf} (spf: $spf_status, spf_helo: $spf_helo_status)");
      $pms->{dmarc_policy} = $result->disposition;
    } else {
      dbg("result: no policy available");
      $pms->{dmarc_policy} = 'no policy available';
    }
  }
}

1;

