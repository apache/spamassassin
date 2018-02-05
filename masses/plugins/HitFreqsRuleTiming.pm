# HitFreqsRuleTiming - SpamAssassin rule timing plugin
# (derived from attachment 3055 on bug 4517)
#
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

package HitFreqsRuleTiming;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;

use Time::HiRes qw(time);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my $class = shift;
    my $mailsaobject = shift;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    $mailsaobject->{rule_timing} = {
      duration => { },
      runs => { },
      max => { },
    };
    $mailsaobject->{RuleTimingTotal} = 0;
    bless ($self, $class);
}

sub start_rules {
    my ($self, $options) = @_;

    $options->{permsgstatus}->{RuleTimingStart} = Time::HiRes::time();
}

sub ran_rule {
    my $time = Time::HiRes::time();
    my ($self, $options) = @_;

    my $permsg = $options->{permsgstatus};
    my $mailsa = $permsg->{main};
    my $name = $options->{rulename};

    my $duration = $time - $permsg->{RuleTimingStart};
    $permsg->{RuleTimingStart} = $time;

    unless ($mailsa->{rule_timing}{duration}{$name}) {
        $mailsa->{rule_timing}{duration}{$name} = 0;
        $mailsa->{rule_timing}{max}{$name} = 0;
    }

    # TODO: record all runs and compute std dev

    $mailsa->{RuleTimingTotal} += $duration;
    $mailsa->{rule_timing}{runs}{$name}++;
    $mailsa->{rule_timing}{duration}{$name} += $duration;
    $mailsa->{rule_timing}{max}{$name} = $duration
        if $duration > $mailsa->{rule_timing}{max}{$name};
}

sub finish {
    my $self = shift;
    my $mailsa = $self->{main};
    my $total = $mailsa->{RuleTimingTotal};

    $total = 0.00000001 if $total == 0;

    # take a ref to speed up the sorting
    my $dur_ref = $mailsa->{rule_timing}{duration};

    my $s = '';
    foreach my $rule (sort {
        $dur_ref->{$b} <=> $dur_ref->{$a}
      } keys %{$dur_ref})
    {
        $s .= sprintf "T %30s %9.4f %9.4f %4d %5.2f%%\n", $rule,
            $mailsa->{rule_timing}{duration}->{$rule},
            $mailsa->{rule_timing}{max}->{$rule},
            $mailsa->{rule_timing}{runs}->{$rule},
            ($mailsa->{rule_timing}{duration}->{$rule} / $total) * 100
          ;
    }

    my $sl = $s;
    $s =~ s/\s+\S+$//gm;  # revert to v1 format

    my $cwd;
    chomp($cwd = `pwd`);
    warn "HitFreqsRuleTiming: writing timing data to $cwd/timing.log\n";
    open (OUT, ">timing.log") or warn "cannot write to $cwd/timing.log\n";
    print OUT "v1\n";       # forward compatibility
    print OUT $s;
    close OUT or warn "cannot write to $cwd/timing.log\n";

    if (would_log("dbg", "rules")) {  # write more readable format to debug log
      $sl =~ s/^T //gm;
      $sl = (sprintf "Total time: %9.4f s\n", $total) . "rulename ovl(s) max(s) #run %tot\n" . $sl;
      dbg("rules: timing: $sl");
    }

    $self->SUPER::finish();
}

1;
