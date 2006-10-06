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

use Time::HiRes qw(gettimeofday tv_interval);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

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
    bless ($self, $class);
}

sub start_rules {
    my ($self, $options) = @_;

    $options->{permsgstatus}->{RuleTimingStart} = [gettimeofday()];
}

sub ran_rule {
    my @now = gettimeofday();
    my ($self, $options) = @_;

    my $permsg = $options->{permsgstatus};
    my $mailsa = $permsg->{main};
    my $name = $options->{rulename};

    my $duration = tv_interval($permsg->{RuleTimingStart}, \@now);
    @{$permsg->{RuleTimingStart}} = @now;

    unless ($mailsa->{rule_timing}{duration}{$name}) {
        $mailsa->{rule_timing}{duration}{$name} = 0;
        $mailsa->{rule_timing}{max}{$name} = 0;
    }

    # TODO: record all runs and compute std dev

    $mailsa->{rule_timing}{runs}{$name}++;
    $mailsa->{rule_timing}{duration}{$name} += $duration;
    $mailsa->{rule_timing}{max}{$name} = $duration
        if $duration > $mailsa->{rule_timing}{max}{$name};
}

sub finish {
    my $self = shift;
    my $mailsa = $self->{main};

    # take a ref to speed up the sorting
    my $dur_ref = $mailsa->{rule_timing}{duration};

    my $s = '';
    foreach my $rule (sort {
        $dur_ref->{$b} <=> $dur_ref->{$a}
      } keys %{$dur_ref})
    {
        $s .= sprintf "T %30s %8.3f %8.3f %4d\n", $rule,
            $mailsa->{rule_timing}{duration}->{$rule},
            $mailsa->{rule_timing}{max}->{$rule},
            $mailsa->{rule_timing}{runs}->{$rule};
    }

    open (OUT, ">timing.log") or warn "cannot write to timing.log";
    print OUT "v1\n";       # forward compatibility
    print OUT $s;
    close OUT or warn "cannot write to timing.log";

    $self->SUPER::finish();
}

1;
