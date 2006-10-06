# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::RabinKarpBody;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use RabinKarpAccel;
use Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor;

use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};

  my $basextor = Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor->new(
            $self->{main});
  $basextor->extract_bases($conf);

  $conf->{skip_body_rules} = { };
  $self->setup_test_set ($conf, $conf->{body_tests}, 'body');
}

sub setup_test_set {
  my ($self, $conf, $test_set, $ruletype) = @_;
  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->setup_test_set_pri($conf, $test_set->{$pri}, $ruletype.'_'.$nicepri);
  }
}

sub setup_test_set_pri {
  my ($self, $conf, $rules, $ruletype) = @_;

  $conf->{$ruletype}->{rkhashes} = { };
  foreach my $base (keys %{$conf->{base_string}->{$ruletype}}) {
    next unless (length $base > 4);
    my @rules = split(' ', $conf->{base_string}->{$ruletype}->{$base});
    RabinKarpAccel::add_bitvec($conf->{$ruletype}->{rkhashes}, lc $base, [ @rules ]);
    foreach my $rule (@rules) {
      $conf->{skip_body_rules}->{$rule} = 1;
    }
  }
}

###########################################################################

sub run_body_hack {
  my ($self, $params) = @_;

  return unless ($params->{ruletype} eq 'body');

  my $pri = $params->{priority};
  my $nicepri = $params->{priority}; $nicepri =~ s/-/neg/g;
  my $ruletype = ($params->{ruletype}.'_'.$nicepri);
  my $scanner = $params->{permsgstatus};
  my $conf = $scanner->{conf};

  my $rkhashes = $conf->{$ruletype}->{rkhashes};
  if (!$rkhashes || (scalar keys %{$conf->{$ruletype}->{rkhashes}} <= 0))
  {
    dbg("zoom: run_body_hack for $ruletype skipped, no rules");
    return;
  }

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  my $scoresptr = $conf->{scores};

  dbg("zoom: run_body_hack for $ruletype start");

  {
    no strict "refs";
    foreach my $line (@{$params->{lines}})
    {
      my $results = RabinKarpAccel::scan_string($rkhashes, lc $line);
      next unless $results;

      my %alreadydone = ();
      foreach my $rulename (@{$results})
      {
        # only try each rule once per line
	next if exists $alreadydone{$rulename};
	$alreadydone{$rulename} = undef;

        # ignore 0-scored rules, of course
	next unless $scoresptr->{$rulename};

        # TODO: it would be very useful to provide an optional
        # means of instrumenting the ruleset, so that we can
        # find out when the base matched but the full RE didn't.

	# if ($do_dbg) {
	# dbg("zoom: base found for $rulename: $line");
	# }

        # run the real regexp -- on this line alone
        &{'Mail::SpamAssassin::PerMsgStatus::'.$rulename.'_one_line_body_test'}
                    ($scanner, $line);
      }
    }
    use strict "refs";
  }

  dbg("zoom: run_body_hack for $ruletype done");
}

###########################################################################

1;
