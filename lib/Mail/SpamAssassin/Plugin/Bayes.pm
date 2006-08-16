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

package Mail::SpamAssassin::Plugin::Bayes;

use Mail::SpamAssassin::Plugin;
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

  # the important bit!
  $self->register_eval_rule("check_bayes");

  return $self;
}

sub check_bayes {
  my ($self, $pms, $fulltext, $min, $max) = @_;

  return 0 if (!$pms->{conf}->{use_bayes} || !$pms->{conf}->{use_bayes_rules});

  if (!exists ($pms->{bayes_score})) {
    $pms->{bayes_score} = $self->{main}->{bayes_scanner}->scan ($pms, $pms->{msg});
  }

  if (defined $pms->{bayes_score} &&
      ($min == 0 || $pms->{bayes_score} > $min) &&
      ($max eq "undef" || $pms->{bayes_score} <= $max))
  {
      if ($pms->{conf}->{detailed_bayes_score}) {
        $pms->test_log(sprintf ("score: %3.4f, hits: %s",
                                 $pms->{bayes_score},
                                 $pms->{bayes_hits}));
      }
      else {
        $pms->test_log(sprintf ("score: %3.4f", $pms->{bayes_score}));
      }
      return 1;
  }

  return 0;
}

1;
