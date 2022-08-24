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

package Mail::SpamAssassin::Plugin::P595Body;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor;
use Mail::SpamAssassin::Plugin::OneLineBodyRuleType;
use Mail::SpamAssassin::Util qw(qr_to_string);

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->{one_line_body} = Mail::SpamAssassin::Plugin::OneLineBodyRuleType->new();

  if ($] < 5.009005) {
    die "this plugin requires perl 5.9.5 or later";
  }

  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};

  my $main = $self->{main};

  $conf->{skip_body_rules}   ||= { };
  $self->setup_test_set ($conf, $conf->{body_tests}, 'body');
}

sub setup_test_set {
  my ($self, $conf, $test_set, $ruletype) = @_;
  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->setup_test_set_pri($conf, $test_set->{$pri},
                    $ruletype.'_'.$nicepri, $pri);
  }
}

sub setup_test_set_pri {
  my ($self, $conf, $rules, $ruletype, $pri) = @_;

  my $alternates = [];
  while (my ($rule, $pat) = each %{$conf->{body_tests}->{$pri}}) {
    # ignore rules marked for ReplaceTags work!
    next if ($conf->{replace_rules}->{$rule});
    # ignore regex capture template rules
    next if ($conf->{capture_rules}->{$rule});
    next if ($conf->{capture_template_rules}->{$rule});

    #$pat = Mail::SpamAssassin::Util::regexp_remove_delimiters($pat);
    $pat = qr_to_string($conf->{test_qrs}->{$rule});
    next unless !$pat;

    # use the REGMARK feature:
    # see http://taint.org/2006/11/16/154546a.html#comment-1011
    #
    push @{$alternates}, "$pat(*:$rule)";

    # TODO: need a cleaner way to do this.  I expect when rule types
    # are implementable in plugins, I can do it that way
    $conf->{skip_body_rules}->{$rule} = 1;
  }

  my $sub = '
    sub {
        our $REGMARK;
        our @matched = ();
        $_[0] =~ m#('.join('|', @{$alternates}).')(?{
            push @matched, $REGMARK;
          })(*FAIL)#;
        return @matched;
      }
  ';
  # warn "JMD $sub";

  $conf->{$ruletype}->{trie_re_sub} = eval $sub;
  if ($@) { warn "REGMARK sub compilation failed: $@"; }
}

###########################################################################

# delegate these to the OneLineBodyRuleType object
sub check_start {
  my ($self, $params) = @_;
  $self->{one_line_body}->check_start($params);
}

sub check_rules_at_priority {
  my ($self, $params) = @_;
  $self->{one_line_body}->check_rules_at_priority($params);
}

sub check_cleanup {
  my ($self, $params) = @_;
  $self->{one_line_body}->check_cleanup($params);
}

###########################################################################

sub run_body_fast_scan {
  my ($self, $params) = @_;

  return unless ($params->{ruletype} eq 'body');

  my $pri = $params->{priority};
  my $nicepri = $params->{priority}; $nicepri =~ s/-/neg/g;
  my $ruletype = ($params->{ruletype}.'_'.$nicepri);
  my $scanner = $params->{permsgstatus};
  my $conf = $scanner->{conf};

  my $trie_re_sub = $conf->{$ruletype}->{trie_re_sub};
  if (!$trie_re_sub)
  {
    dbg("zoom: run_body_fast_scan for $ruletype skipped, no rules");
    return;
  }

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  my $scoresptr = $conf->{scores};

  dbg("zoom: run_body_fast_scan for $ruletype start");

  {
    no strict "refs";
    foreach my $line (@{$params->{lines}})
    {
      my @caught = $trie_re_sub->($line);
      next unless (scalar @caught > 0);

      my %alreadydone;
      foreach my $rulename (@caught) {
        {
          next if not defined $rulename;
          # only try each rule once per line
          next if exists $alreadydone{$rulename};
          $alreadydone{$rulename} = undef;

          # ignore 0-scored rules, of course
          next unless $scoresptr->{$rulename};

          $scanner->got_hit($rulename, "BODY: ", ruletype => "p595_body");
        }
      }
    }
    use strict "refs";
  }

  dbg("zoom: run_body_fast_scan for $ruletype done");
}

sub finish {
  my ($self) = @_;

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  return unless $do_dbg;

  my $miss = $self->{rule2xs_misses};
  foreach my $r (sort { $miss->{$a} <=> $miss->{$b} } keys %{$miss}) {
    dbg("zoom: %s misses for rule2xs rule %s", $miss->{$r},$r);
  }
}

###########################################################################

1;
